//! Userspace TCP over the tailnet: a smoltcp interface whose "wire" is the
//! WireGuard tunnel. Packets smoltcp transmits are queued for the runtime to
//! encapsulate for the owning peer; packets the node decrypts are queued for
//! smoltcp to receive.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, TcpPacket,
};

/// The tunnel's inner MTU, which is also what peers expect of Tailscale.
pub const MTU: usize = 1280;
/// Packets either direction may queue before new ones are dropped. TCP
/// retransmits what is dropped; nothing grows without bound.
const QUEUE_LIMIT: usize = 128;
const SOCKET_BUFFER: usize = 64 * 1024;
/// Any address works: with `Medium::Ip` smoltcp only needs *a* route for
/// destinations outside its own /32.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);

#[derive(Default)]
struct Tunnel {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Tunnel);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if self.0.tx.len() < QUEUE_LIMIT {
            self.0.tx.push_back(packet);
        }
        result
    }
}

impl Device for Tunnel {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.tx.len() >= QUEUE_LIMIT {
            return None;
        }
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(self)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        (self.tx.len() < QUEUE_LIMIT).then_some(Tx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

/// A TCP socket of one particular [`NetStack`]. A handle outlives its stack
/// when the node is replaced; lookups through a stale handle find nothing
/// instead of panicking.
#[derive(Clone, Copy)]
pub struct TcpHandle {
    stack: u64,
    socket: SocketHandle,
}

struct TcpFrame {
    source: IpEndpoint,
    destination: IpEndpoint,
    fin_end: Option<i32>,
    ack: Option<i32>,
}
fn tcp_frame(bytes: &[u8]) -> Option<TcpFrame> {
    let ip = Ipv4Packet::new_checked(bytes).ok()?;
    if ip.next_header() != IpProtocol::Tcp
        || ip.more_frags()
        || ip.frag_offset() != 0
        || !ip.verify_checksum()
    {
        return None;
    }
    let source = IpAddress::Ipv4(ip.src_addr());
    let destination = IpAddress::Ipv4(ip.dst_addr());
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    if !tcp.verify_checksum(&source, &destination) {
        return None;
    }
    Some(TcpFrame {
        source: IpEndpoint::new(source, tcp.src_port()),
        destination: IpEndpoint::new(destination, tcp.dst_port()),
        fin_end: tcp.fin().then(|| {
            tcp.seq_number()
                .0
                .wrapping_add(tcp.payload().len() as i32)
                .wrapping_add(1)
        }),
        ack: (tcp.ack() && !tcp.rst()).then(|| tcp.ack_number().0),
    })
}
pub struct NetStack {
    id: u64,
    device: Tunnel,
    iface: Option<Interface>,
    pub sockets: SocketSet<'static>,
    address: Option<Ipv4Addr>,
    pub close_failed: bool,
    fins: HashMap<SocketHandle, (i32, bool)>,
}

impl NetStack {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            device: Tunnel::default(),
            iface: None,
            sockets: SocketSet::new(Vec::new()),
            address: None,
            close_failed: false,
            fins: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn address(&self) -> Option<Ipv4Addr> {
        self.address
    }

    /// Adopt this node's tailnet address. A changed address resets the
    /// interface, which ends any connection bound to the old one.
    pub fn set_address(&mut self, address: Ipv4Addr, now_ms: u64, seed: u64) {
        if self.address == Some(address) {
            return;
        }
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut self.device, instant(now_ms));
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), 32));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY);
        for (_, socket) in self.sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(socket) = socket;
            // Passive listeners are wildcard-bound and remain valid on the
            // new interface. Reset a half-open accept back to listening too.
            let listen = matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived)
                .then(|| socket.listen_endpoint());
            socket.abort();
            if let Some(endpoint) = listen {
                let _ = socket.listen(endpoint);
            }
        }
        self.fins.clear();
        self.iface = Some(iface);
        self.address = Some(address);
    }

    /// Queue a decrypted packet for smoltcp.
    pub fn deliver(&mut self, packet: &[u8]) {
        if self.device.rx.len() < QUEUE_LIMIT {
            if let Some(frame) = tcp_frame(packet)
                && let Some(ack) = frame.ack
            {
                for (handle, socket) in self.sockets.iter() {
                    let smoltcp::socket::Socket::Tcp(socket) = socket;
                    if socket.local_endpoint() == Some(frame.destination)
                        && socket.remote_endpoint() == Some(frame.source)
                        && let Some((expected, acknowledged)) = self.fins.get_mut(&handle)
                        && *expected == ack
                    {
                        *acknowledged = true;
                    }
                }
            }
            self.device.rx.push_back(packet.to_vec());
        }
    }

    /// Run smoltcp and hand back what it transmitted.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        if let Some(iface) = self.iface.as_mut() {
            iface.poll(instant(now_ms), &mut self.device, &mut self.sockets);
        } else {
            self.device.rx.clear();
        }
        let packets: Vec<Vec<u8>> = self.device.tx.drain(..).collect();
        for packet in &packets {
            if let Some(frame) = tcp_frame(packet)
                && let Some(end) = frame.fin_end
            {
                for (handle, socket) in self.sockets.iter() {
                    let smoltcp::socket::Socket::Tcp(socket) = socket;
                    if socket.local_endpoint() == Some(frame.source)
                        && socket.remote_endpoint() == Some(frame.destination)
                    {
                        self.fins.entry(handle).or_insert((end, false));
                    }
                }
            }
        }
        packets
    }

    /// Open a TCP connection. It completes asynchronously as packets flow.
    pub fn connect(
        &mut self,
        remote: Ipv4Addr,
        port: u16,
        local_port: u16,
    ) -> Result<TcpHandle, String> {
        if self.sockets.iter().count() >= 16 {
            return Err("TCP session capacity reached".into());
        }
        let first = local_port.max(49152);
        let local_port = (0..16u32)
            .map(|offset| 49152 + ((u32::from(first) - 49152 + offset) % 16384) as u16)
            .find(|candidate| {
                !self.sockets.iter().any(|(_, socket)| {
                    let smoltcp::socket::Socket::Tcp(socket) = socket;
                    socket
                        .local_endpoint()
                        .is_some_and(|endpoint| endpoint.port == *candidate)
                        || socket.listen_endpoint().port == *candidate
                })
            })
            .ok_or("no free TCP source port")?;
        let iface = self
            .iface
            .as_mut()
            .ok_or("this node has no tailnet address yet")?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(25)));
        socket
            .connect(iface.context(), (IpAddress::Ipv4(remote), port), local_port)
            .map_err(|error| format!("TCP connect: {error}"))?;
        Ok(TcpHandle {
            stack: self.id,
            socket: self.sockets.add(socket),
        })
    }

    pub fn close_outcome(&mut self, handle: TcpHandle) -> Option<bool> {
        let acknowledged = self
            .fins
            .get(&handle.socket)
            .is_some_and(|(_, acknowledged)| *acknowledged);
        let Some(socket) = self.tcp(handle) else {
            return Some(false);
        };
        match socket.state() {
            tcp::State::Closed => Some(acknowledged && socket.send_queue() == 0),
            tcp::State::FinWait2 | tcp::State::TimeWait
                if acknowledged && socket.send_queue() == 0 =>
            {
                Some(true)
            }
            _ => None,
        }
    }
    pub fn drained(&self) -> bool {
        self.sockets.iter().all(|(_, socket)| {
            let smoltcp::socket::Socket::Tcp(socket) = socket;
            socket.state() == tcp::State::Listen
        })
    }
    pub fn remote_addresses(&self) -> Vec<Ipv4Addr> {
        self.sockets
            .iter()
            .filter_map(|(_, socket)| {
                let smoltcp::socket::Socket::Tcp(socket) = socket;
                socket
                    .remote_endpoint()
                    .map(|endpoint| match endpoint.addr {
                        IpAddress::Ipv4(address) => address,
                    })
            })
            .collect()
    }
    pub fn listen(&mut self, port: u16) -> Result<TcpHandle, String> {
        if self.sockets.iter().count() >= 16 {
            return Err("TCP session capacity reached".into());
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket
            .listen(port)
            .map_err(|e| format!("TCP listen: {e}"))?;
        Ok(TcpHandle {
            stack: self.id,
            socket: self.sockets.add(socket),
        })
    }
    pub fn tcp(&mut self, handle: TcpHandle) -> Option<&mut tcp::Socket<'static>> {
        (handle.stack == self.id).then(|| self.sockets.get_mut::<tcp::Socket>(handle.socket))
    }

    /// Abort and forget a socket. Each handle is removed at most once.
    pub fn remove(&mut self, handle: TcpHandle) {
        if handle.stack == self.id {
            self.sockets.get_mut::<tcp::Socket>(handle.socket).abort();
            self.sockets.remove(handle.socket);
            self.fins.remove(&handle.socket);
        }
    }
}

fn instant(now_ms: u64) -> Instant {
    Instant::from_millis(now_ms as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drain_distinguishes_a_reset_from_acknowledged_final_data() {
        for reset in [false, true] {
            let mut local = NetStack::new(1);
            let mut remote = NetStack::new(2);
            local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
            remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
            let accepted = remote.listen(2222).unwrap();
            let client = local
                .connect("100.64.0.2".parse().unwrap(), 2222, 49152)
                .unwrap();
            for now in 0..10 {
                for bytes in local.poll(now) {
                    remote.deliver(&bytes);
                }
                for bytes in remote.poll(now) {
                    local.deliver(&bytes);
                }
            }
            assert_eq!(local.tcp(client).unwrap().state(), tcp::State::Established);
            local.tcp(client).unwrap().send_slice(b"final").unwrap();
            local.tcp(client).unwrap().close();
            let final_packets = local.poll(10);
            assert!(!final_packets.is_empty());
            if reset {
                remote.tcp(accepted).unwrap().abort();
            } else {
                for bytes in final_packets {
                    remote.deliver(&bytes);
                }
            }
            for now in 11..100 {
                for bytes in remote.poll(now) {
                    local.deliver(&bytes);
                }
                for bytes in local.poll(now) {
                    remote.deliver(&bytes);
                }
            }
            assert_eq!(local.close_outcome(client), Some(!reset));
        }
    }
    #[test]
    fn wrapping_source_port_selection_preserves_active_four_tuples() {
        let mut net = NetStack::new(1);
        net.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        let remote = "100.64.0.2".parse().unwrap();
        let first = net.connect(remote, 2222, 49152).unwrap();
        let last = net.connect(remote, 2222, 65535).unwrap();
        let wrapped = net.connect(remote, 2222, 49152).unwrap();
        assert_eq!(
            net.tcp(first).unwrap().local_endpoint().unwrap().port,
            49152
        );
        assert_eq!(net.tcp(last).unwrap().local_endpoint().unwrap().port, 65535);
        assert_eq!(
            net.tcp(wrapped).unwrap().local_endpoint().unwrap().port,
            49153
        );
    }
    #[test]
    fn address_changes_keep_passive_listeners_and_end_old_connections() {
        let mut net = NetStack::new(1);
        net.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        let listener = net.listen(2222).unwrap();
        let outgoing = net
            .connect("100.64.0.2".parse().unwrap(), 2222, 49152)
            .unwrap();
        net.set_address("100.64.0.3".parse().unwrap(), 1, 1);
        assert_eq!(net.tcp(listener).unwrap().state(), tcp::State::Listen);
        assert_eq!(net.tcp(listener).unwrap().listen_endpoint().port, 2222);
        assert_eq!(net.tcp(outgoing).unwrap().state(), tcp::State::Closed);
    }
}
