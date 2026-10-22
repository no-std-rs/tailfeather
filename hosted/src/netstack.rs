//! Userspace TCP over the tailnet: a smoltcp interface whose "wire" is the
//! WireGuard tunnel. Packets smoltcp transmits are queued for the runtime to
//! encapsulate for the owning peer; packets the node decrypts are queued for
//! smoltcp to receive.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

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
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(self)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(self))
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

pub struct NetStack {
    id: u64,
    device: Tunnel,
    iface: Option<Interface>,
    pub sockets: SocketSet<'static>,
    address: Option<Ipv4Addr>,
}

impl NetStack {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            device: Tunnel::default(),
            iface: None,
            sockets: SocketSet::new(Vec::new()),
            address: None,
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
            socket.abort();
        }
        self.iface = Some(iface);
        self.address = Some(address);
    }

    /// Queue a decrypted packet for smoltcp.
    pub fn deliver(&mut self, packet: &[u8]) {
        if self.device.rx.len() < QUEUE_LIMIT {
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
        self.device.tx.drain(..).collect()
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
        }
    }
}

fn instant(now_ms: u64) -> Instant {
    Instant::from_millis(now_ms as i64)
}
