//! Userspace TCP over the tailnet: a smoltcp interface whose "wire" is the
//! WireGuard tunnel. Packets smoltcp transmits are queued for the runtime to
//! encapsulate for the owning peer; packets the node decrypts are queued for
//! smoltcp to receive.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "ipv6")]
use core::net::Ipv6Addr;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use heapless::{Deque, Vec};
use smoltcp::iface::SocketStorage;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, TcpPacket,
};

/// The tunnel's inner MTU, which is also what peers expect of Tailscale.
pub const MTU: usize = 1280;
/// Packets either direction may queue before new ones are dropped. TCP
/// retransmits what is dropped; nothing grows without bound.
const LISTEN_BACKLOG: usize = 4;

pub struct TcpListener<const N: usize = 16> {
    pub port: u16,
    pending: Vec<TcpHandle, N>,
    backlog: usize,
}
/// Any address works: with `Medium::Ip` smoltcp only needs *a* route for
/// destinations outside its own /32.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
/// The same for IPv6: Tailscale's service address, never actually reached.
#[cfg(feature = "ipv6")]
const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53);

/// An address smoltcp can use; IPv6 only with the `ipv6` feature.
fn stack_address(address: IpAddr) -> Option<IpAddress> {
    match address {
        IpAddr::V4(address) => Some(IpAddress::Ipv4(address)),
        #[cfg(feature = "ipv6")]
        IpAddr::V6(address) => Some(IpAddress::Ipv6(address)),
        #[cfg(not(feature = "ipv6"))]
        IpAddr::V6(_) => None,
    }
}

fn core_address(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
        #[cfg(feature = "ipv6")]
        IpAddress::Ipv6(address) => IpAddr::V6(address),
    }
}

pub trait PacketQueue<const Q: usize>: Default + IntoIterator<Item = Packet> {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn pop_front(&mut self) -> Option<Packet>;
    fn push_back(&mut self, packet: Packet);
    fn clear(&mut self);
    fn iter(&self) -> impl Iterator<Item = &Packet>;
}
impl<const Q: usize> PacketQueue<Q> for Deque<Packet, Q> {
    fn len(&self) -> usize {
        Deque::len(self)
    }
    fn pop_front(&mut self) -> Option<Packet> {
        Deque::pop_front(self)
    }
    fn push_back(&mut self, packet: Packet) {
        let _ = Deque::push_back(self, packet);
    }
    fn clear(&mut self) {
        Deque::clear(self);
    }
    fn iter(&self) -> impl Iterator<Item = &Packet> {
        Deque::iter(self)
    }
}
#[cfg(feature = "alloc")]
impl<const Q: usize> PacketQueue<Q> for alloc::collections::VecDeque<Packet> {
    fn len(&self) -> usize {
        Self::len(self)
    }
    fn pop_front(&mut self) -> Option<Packet> {
        Self::pop_front(self)
    }
    fn push_back(&mut self, packet: Packet) {
        if self.len() < Q {
            Self::push_back(self, packet);
        }
    }
    fn clear(&mut self) {
        Self::clear(self);
    }
    fn iter(&self) -> impl Iterator<Item = &Packet> {
        Self::iter(self)
    }
}
struct Tunnel<const Q: usize, B: PacketQueue<Q>> {
    rx: B,
    tx: B,
}
impl<const Q: usize, B: PacketQueue<Q>> Default for Tunnel<Q, B> {
    fn default() -> Self {
        Self {
            rx: B::default(),
            tx: B::default(),
        }
    }
}

pub type Packet = Vec<u8, MTU>;

struct Rx(Packet);
struct Tx<'a, const Q: usize, B: PacketQueue<Q>>(&'a mut Tunnel<Q, B>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<const Q: usize, B: PacketQueue<Q>> TxToken for Tx<'_, Q, B> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = Packet::new();
        packet
            .resize_default(len)
            .expect("smoltcp respects the device MTU");
        let result = f(&mut packet);
        self.0.tx.push_back(packet);
        result
    }
}

impl<const Q: usize, B: PacketQueue<Q>> Device for Tunnel<Q, B> {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a, Q, B>
    where
        Self: 'a;

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_, Q, B>)> {
        if self.tx.len() >= Q {
            return None;
        }
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(self)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_, Q, B>> {
        (self.tx.len() < Q).then_some(Tx(self))
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
    generation: u64,
}

struct TcpFrame {
    source: IpEndpoint,
    destination: IpEndpoint,
    fin_end: Option<i32>,
    ack: Option<i32>,
    reset: bool,
}
/// The addresses and TCP segment of an unfragmented IPv4 or (with the
/// `ipv6` feature) extension-free IPv6 TCP packet.
fn tcp_segment(bytes: &[u8]) -> Option<(IpAddress, IpAddress, &[u8])> {
    match bytes.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(bytes).ok()?;
            if ip.next_header() != IpProtocol::Tcp
                || ip.more_frags()
                || ip.frag_offset() != 0
                || !ip.verify_checksum()
            {
                return None;
            }
            let payload = bytes.get(usize::from(ip.header_len())..usize::from(ip.total_len()))?;
            Some((
                IpAddress::Ipv4(ip.src_addr()),
                IpAddress::Ipv4(ip.dst_addr()),
                payload,
            ))
        }
        #[cfg(feature = "ipv6")]
        6 => {
            let ip = smoltcp::wire::Ipv6Packet::new_checked(bytes).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let payload = bytes.get(40..40 + usize::from(ip.payload_len()))?;
            Some((
                IpAddress::Ipv6(ip.src_addr()),
                IpAddress::Ipv6(ip.dst_addr()),
                payload,
            ))
        }
        _ => None,
    }
}

fn tcp_frame(bytes: &[u8]) -> Option<TcpFrame> {
    let (source, destination, segment) = tcp_segment(bytes)?;
    let tcp = TcpPacket::new_checked(segment).ok()?;
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
        reset: tcp.rst(),
    })
}
struct Fin {
    socket: SocketHandle,
    end: i32,
    seen_ack: bool,
    acknowledged: bool,
    reset: bool,
    was_last_ack: bool,
}

// Only FIN bookkeeping needs a second checked parse. Ordinary data/ACKs are
// checked by smoltcp once, avoiding redundant checksums on the hot path.
fn fin_hint(packet: &[u8]) -> bool {
    let Some(first) = packet.first() else {
        return false;
    };
    let offset = if first >> 4 == 6 {
        40
    } else {
        usize::from(first & 0x0f) * 4
    };
    packet.get(offset + 13).is_some_and(|flags| flags & 1 != 0)
}

pub struct NetStack<
    'a,
    const N: usize = 16,
    const Q: usize = 2,
    B: PacketQueue<Q> = Deque<Packet, Q>,
> {
    id: u64,
    device: Tunnel<Q, B>,
    iface: Option<Interface>,
    sockets: SocketSet<'a>,
    pool: Pool<'a, N>,
    live: Vec<(SocketHandle, u64), N>,
    generation: u64,
    address: Option<Ipv4Addr>,
    #[cfg(feature = "ipv6")]
    address6: Option<Ipv6Addr>,
    /// Where the next automatically chosen source port search starts.
    next_port: u16,
    pub close_failed: bool,
    fins: Vec<Fin, N>,
    received_fins: Vec<(SocketHandle, i32, bool), N>,
}

/// Heap-backed socket and packet storage with the hosted adapter's budgets.
#[cfg(feature = "alloc")]
pub type OwnedStack = NetStack<'static, 16, 128, alloc::collections::VecDeque<Packet>>;

/// Caller-owned metadata and byte queues for an allocation-free TCP stack.
pub struct Storage<'a, const N: usize, const BUFFER: usize> {
    sockets: [SocketStorage<'a>; N],
    rx: [[u8; BUFFER]; N],
    tx: [[u8; BUFFER]; N],
}
impl<const N: usize, const BUFFER: usize> Storage<'_, N, BUFFER> {
    pub const fn new() -> Self {
        Self {
            sockets: [const { SocketStorage::EMPTY }; N],
            rx: [[0; BUFFER]; N],
            tx: [[0; BUFFER]; N],
        }
    }
}
impl<const N: usize, const BUFFER: usize> Default for Storage<'_, N, BUFFER> {
    fn default() -> Self {
        Self::new()
    }
}

enum Pool<'a, const N: usize> {
    Borrowed(Vec<tcp::Socket<'a>, N>),
    /// Receive and send buffer bytes allocated per connection.
    #[cfg(feature = "alloc")]
    Owned(usize),
}

/// Default per-connection receive and send buffer of the heap-backed stack.
/// It is also the largest window either direction can keep in flight:
/// 4 MiB sustains about 1.6 Gbit/s at 20 ms of round trip. Buffers are
/// zero-allocated, so the operating system commits pages only as a
/// connection actually fills its window.
#[cfg(feature = "alloc")]
pub const OWNED_BUFFER: usize = 4 << 20;

#[cfg(feature = "alloc")]
impl<const N: usize, const Q: usize> NetStack<'static, N, Q, alloc::collections::VecDeque<Packet>> {
    pub fn new(id: u64) -> Self {
        Self::with_buffer_size(id, OWNED_BUFFER)
    }

    /// Allocate `bytes` of receive and of send buffer per connection. Above
    /// 64 KiB the stack negotiates TCP window scaling.
    pub fn with_buffer_size(id: u64, bytes: usize) -> Self {
        assert!(bytes > 0, "TCP buffers must be nonzero");
        Self::build(
            id,
            SocketSet::new(alloc::vec::Vec::new()),
            Pool::Owned(bytes),
        )
    }
}

impl<'a, const N: usize, const Q: usize, B: PacketQueue<Q>> NetStack<'a, N, Q, B> {
    pub fn with_storage<const BUFFER: usize>(
        id: u64,
        storage: &'a mut Storage<'a, N, BUFFER>,
    ) -> Self {
        assert!(
            N > 0 && Q > 0 && BUFFER > 0,
            "TCP capacities must be nonzero"
        );
        let mut free = Vec::new();
        for (rx, tx) in storage.rx.iter_mut().zip(storage.tx.iter_mut()) {
            let _ = free.push(tcp::Socket::new(
                tcp::SocketBuffer::new(&mut rx[..]),
                tcp::SocketBuffer::new(&mut tx[..]),
            ));
        }
        Self::build(
            id,
            SocketSet::new(&mut storage.sockets[..]),
            Pool::Borrowed(free),
        )
    }

    fn build(id: u64, sockets: SocketSet<'a>, pool: Pool<'a, N>) -> Self {
        assert!(N > 0 && Q > 0, "TCP capacities must be nonzero");
        Self {
            id,
            device: Tunnel::default(),
            iface: None,
            sockets,
            pool,
            live: Vec::new(),
            generation: 0,
            address: None,
            #[cfg(feature = "ipv6")]
            address6: None,
            next_port: 49152,
            close_failed: false,
            fins: Vec::new(),
            received_fins: Vec::new(),
        }
    }

    fn socket(&mut self) -> Result<tcp::Socket<'a>, &'static str> {
        if self.live.len() >= N {
            return Err("TCP session capacity reached");
        }
        let mut socket = match &mut self.pool {
            Pool::Borrowed(free) => free.pop().ok_or("TCP session capacity reached")?,
            #[cfg(feature = "alloc")]
            Pool::Owned(bytes) => tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; *bytes]),
                tcp::SocketBuffer::new(vec![0; *bytes]),
            ),
        };
        socket.set_nagle_enabled(false);
        Ok(socket)
    }

    fn recycle(&mut self, mut socket: tcp::Socket<'a>) {
        socket.abort();
        match &mut self.pool {
            Pool::Borrowed(free) => {
                let _ = free.push(socket);
            }
            #[cfg(feature = "alloc")]
            Pool::Owned(_) => {}
        }
    }

    fn insert(&mut self, socket: tcp::Socket<'a>) -> TcpHandle {
        self.generation = self.generation.wrapping_add(1);
        let socket = self.sockets.add(socket);
        let _ = self.live.push((socket, self.generation));
        TcpHandle {
            stack: self.id,
            socket,
            generation: self.generation,
        }
    }

    #[cfg(feature = "std")]
    pub fn trace(&self) {
        for (_, socket) in self.sockets.iter() {
            let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
            if socket.state() != tcp::State::Listen {
                std::eprintln!(
                    "tailnet TCP {:?} -> {:?}: {:?} send={} recv={}",
                    socket.local_endpoint(),
                    socket.remote_endpoint(),
                    socket.state(),
                    socket.send_queue(),
                    socket.recv_queue()
                );
            }
        }
    }

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
        // A fresh starting point per interface, so a restarted node does not
        // retrace its previous run's ports either.
        self.next_port = 49152 + (seed % 16384) as u16;
        let mut iface = Interface::new(config, &mut self.device, instant(now_ms));
        let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY);
        #[cfg(feature = "ipv6")]
        let _ = iface.routes_mut().add_default_ipv6_route(GATEWAY6);
        for (_, socket) in self.sockets.iter_mut() {
            let socket = tcp::Socket::downcast_mut(socket).expect("TCP-only stack");
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
        self.received_fins.clear();
        self.iface = Some(iface);
        self.address = Some(address);
        self.update_addresses();
    }

    /// This node's tailnet IPv6 address, when it has one.
    #[cfg(feature = "ipv6")]
    pub fn ipv6_address(&self) -> Option<Ipv6Addr> {
        self.address6
    }

    /// Adopt, change or drop this node's tailnet IPv6 address. Connections
    /// bound to a previous IPv6 address end; IPv4 ones and listeners stay.
    /// It takes effect once the node also has an IPv4 address.
    #[cfg(feature = "ipv6")]
    pub fn set_ipv6_address(&mut self, address: Option<Ipv6Addr>) {
        if self.address6 == address {
            return;
        }
        if let Some(old) = self.address6 {
            let old = Some(IpAddress::Ipv6(old));
            for (handle, socket) in self.sockets.iter_mut() {
                let socket = tcp::Socket::downcast_mut(socket).expect("TCP-only stack");
                if socket.state() != tcp::State::Listen
                    && socket.local_endpoint().map(|endpoint| endpoint.addr) == old
                {
                    let listen = (socket.state() == tcp::State::SynReceived)
                        .then(|| socket.listen_endpoint());
                    socket.abort();
                    if let Some(endpoint) = listen {
                        let _ = socket.listen(endpoint);
                    }
                    self.fins.retain(|fin| fin.socket != handle);
                    self.received_fins.retain(|(key, _, _)| *key != handle);
                }
            }
        }
        self.address6 = address;
        self.update_addresses();
    }

    /// Give the interface exactly this node's current addresses.
    fn update_addresses(&mut self) {
        let Some(iface) = self.iface.as_mut() else {
            return;
        };
        let address = self.address;
        #[cfg(feature = "ipv6")]
        let address6 = self.address6;
        iface.update_ip_addrs(|addresses| {
            addresses.clear();
            if let Some(address) = address {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), 32));
            }
            #[cfg(feature = "ipv6")]
            if let Some(address) = address6 {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(address), 128));
            }
        });
    }

    /// Remove the local address, sockets and packets after revocation or shutdown.
    pub fn clear_address(&mut self) {
        self.abort_all();
        self.fins.clear();
        self.received_fins.clear();
        self.device.rx.clear();
        self.device.tx.clear();
        self.iface = None;
        self.address = None;
        #[cfg(feature = "ipv6")]
        {
            self.address6 = None;
        }
    }

    /// Queue a decrypted packet for smoltcp.
    pub fn deliver(&mut self, packet: &[u8]) {
        if self.device.rx.len() >= Q || packet.len() > MTU {
            return;
        }
        if (!self.fins.is_empty() || fin_hint(packet))
            && let Some(frame) = tcp_frame(packet)
        {
            for (handle, socket) in self.sockets.iter() {
                let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
                if socket.local_endpoint() != Some(frame.destination)
                    || socket.remote_endpoint() != Some(frame.source)
                {
                    continue;
                }
                if let Some(fin) = self.fins.iter_mut().find(|fin| fin.socket == handle) {
                    fin.seen_ack |= frame.ack == Some(fin.end);
                    fin.reset |= frame.reset;
                }
                if let Some(end) = frame.fin_end
                    && !self.received_fins.iter().any(|(key, _, _)| *key == handle)
                {
                    let _ = self.received_fins.push((handle, end, false));
                }
            }
        }
        if let Ok(packet) = Packet::from_slice(packet) {
            self.device.rx.push_back(packet);
        }
    }

    /// Run timers and ingress without moving the backing packet arena.
    pub fn poll_stack(&mut self, now_ms: u64) {
        for fin in &mut self.fins {
            fin.was_last_ack =
                self.sockets.get::<tcp::Socket>(fin.socket).state() == tcp::State::LastAck;
        }
        if let Some(iface) = self.iface.as_mut() {
            iface.poll(instant(now_ms), &mut self.device, &mut self.sockets);
        } else {
            self.device.rx.clear();
        }
        for fin in &mut self.fins {
            let socket = self.sockets.get::<tcp::Socket>(fin.socket);
            if socket.state() == tcp::State::Closed && fin.reset {
                fin.acknowledged = false;
            } else if fin.seen_ack
                && (matches!(socket.state(), tcp::State::FinWait2 | tcp::State::TimeWait)
                    || socket.state() == tcp::State::Closed && fin.was_last_ack && !fin.reset)
            {
                fin.acknowledged = true;
            }
            fin.seen_ack = false;
            fin.reset = false;
        }
    }

    /// Detach one transmit packet while retaining the packet ring's allocation.
    pub fn take_transmit(&mut self) -> Option<Packet> {
        let packet = self.device.tx.pop_front()?;
        self.note_transmit(&packet);
        Some(packet)
    }

    fn note_transmit(&mut self, packet: &[u8]) {
        if (!self.received_fins.is_empty() || fin_hint(packet))
            && let Some(frame) = tcp_frame(packet)
        {
            for (handle, socket) in self.sockets.iter() {
                let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
                if socket.local_endpoint() != Some(frame.source)
                    || socket.remote_endpoint() != Some(frame.destination)
                {
                    continue;
                }
                if let Some(end) = frame.fin_end
                    && !self.fins.iter().any(|fin| fin.socket == handle)
                {
                    let _ = self.fins.push(Fin {
                        socket: handle,
                        end,
                        seen_ack: false,
                        acknowledged: false,
                        reset: false,
                        was_last_ack: false,
                    });
                }
                if let Some(ack) = frame.ack
                    && let Some((_, end, sent)) = self
                        .received_fins
                        .iter_mut()
                        .find(|(key, _, _)| *key == handle)
                    && *end == ack
                {
                    *sent = true;
                }
            }
        }
    }

    /// Convenience collector for synchronous adapters. Async drivers drain
    /// bounded bursts with `take_transmit` to avoid moving a fixed arena.
    pub fn poll(&mut self, now_ms: u64) -> B {
        self.poll_stack(now_ms);
        let packets = core::mem::take(&mut self.device.tx);
        for packet in packets.iter() {
            self.note_transmit(packet);
        }
        packets
    }

    /// Open a TCP connection. It completes asynchronously as packets flow.
    ///
    /// `local_port` in the ephemeral range (49152-65535) is the first source
    /// port tried. Any other value, such as 0, lets the stack pick: it rotates
    /// through the range like Linux instead of reusing the lowest free port.
    /// Reusing a just-closed connection's four-tuple would meet the peer's
    /// TIME_WAIT for it, which ignores the new SYN for up to a minute.
    pub fn connect(
        &mut self,
        remote: impl Into<IpAddr>,
        port: u16,
        local_port: u16,
    ) -> Result<TcpHandle, &'static str> {
        let remote = stack_address(remote.into()).ok_or("IPv6 needs the `ipv6` feature")?;
        if self.live.len() >= N {
            return Err("TCP session capacity reached");
        }
        let first = if local_port >= 49152 {
            local_port
        } else {
            self.next_port
        };
        let local_port = (0..=N as u32)
            .map(|offset| 49152 + ((u32::from(first) - 49152 + offset) % 16384) as u16)
            .find(|candidate| {
                !self.sockets.iter().any(|(_, socket)| {
                    let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
                    socket
                        .local_endpoint()
                        .is_some_and(|endpoint| endpoint.port == *candidate)
                        || socket.listen_endpoint().port == *candidate
                })
            })
            .ok_or("no free TCP source port")?;
        if self.iface.is_none() {
            return Err("this node has no tailnet address yet");
        }
        // Always send from this node's own address of the remote's family;
        // left unbound, smoltcp would fall back to a loopback source.
        let source = match remote {
            IpAddress::Ipv4(_) => self.address.map(IpAddress::Ipv4),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => self.address6.map(IpAddress::Ipv6),
        }
        .ok_or("this node has no tailnet address of that family")?;
        let mut socket = self.socket()?;
        let iface = self.iface.as_mut().unwrap();
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(25)));
        if socket
            .connect(iface.context(), (remote, port), (source, local_port))
            .is_err()
        {
            self.recycle(socket);
            return Err("invalid TCP connection endpoint");
        }
        self.next_port = if local_port == u16::MAX {
            49152
        } else {
            local_port + 1
        };
        Ok(self.insert(socket))
    }

    pub fn close_outcome(&mut self, handle: TcpHandle) -> Option<bool> {
        let acknowledged = self
            .fins
            .iter()
            .find(|fin| fin.socket == handle.socket)
            .is_some_and(|fin| fin.acknowledged);
        let receive_acked = self
            .received_fins
            .iter()
            .find(|(key, _, _)| *key == handle.socket)
            .is_none_or(|(_, _, sent)| *sent);
        let Some(socket) = self.tcp(handle) else {
            return Some(false);
        };
        match socket.state() {
            tcp::State::Closed => Some(acknowledged && socket.send_queue() == 0),
            tcp::State::FinWait2 | tcp::State::TimeWait
                if acknowledged && receive_acked && socket.send_queue() == 0 =>
            {
                Some(true)
            }
            _ => None,
        }
    }
    pub fn drained(&self) -> bool {
        self.sockets.iter().all(|(_, socket)| {
            let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
            socket.state() == tcp::State::Listen
        })
    }
    pub fn remote_addresses(&self) -> Vec<IpAddr, N> {
        self.sockets
            .iter()
            .filter_map(|(_, socket)| {
                let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
                Some(core_address(socket.remote_endpoint()?.addr))
            })
            .collect()
    }
    pub fn listen(&mut self, port: u16) -> Result<TcpHandle, &'static str> {
        if self.live.len() >= N {
            return Err("TCP session capacity reached");
        }
        let mut socket = self.socket()?;
        if socket.listen(port).is_err() {
            self.recycle(socket);
            return Err("invalid TCP listener port");
        }
        Ok(self.insert(socket))
    }
    /// smoltcp consumes a listening socket as soon as a SYN arrives. Reserve
    /// several sockets before polling packets, otherwise simultaneous SYNs
    /// receive RST while the only listener completes its first handshake.
    pub fn listen_backlog(&mut self, port: u16) -> Result<TcpListener<N>, &'static str> {
        self.listen_with_backlog(port, LISTEN_BACKLOG.min(N))
    }
    /// Reserve the caller's SYN backlog within this stack's socket arena.
    pub fn listen_with_backlog(
        &mut self,
        port: u16,
        backlog: usize,
    ) -> Result<TcpListener<N>, &'static str> {
        if backlog == 0 || backlog > N {
            return Err("invalid TCP listener backlog");
        }
        let first = self.listen(port)?;
        let mut listener = TcpListener {
            port,
            pending: Vec::new(),
            backlog,
        };
        let _ = listener.pending.push(first);
        self.refill_listener(&mut listener);
        Ok(listener)
    }
    fn refill_listener(&mut self, listener: &mut TcpListener<N>) {
        while listener.pending.len() < listener.backlog {
            match self.listen(listener.port) {
                Ok(handle) => {
                    let _ = listener.pending.push(handle);
                }
                Err(_) => break, // Existing connections retain their slots.
            }
        }
    }
    pub fn accept_one(&mut self, listener: &mut TcpListener<N>) -> Option<TcpHandle> {
        listener.pending.retain(|handle| {
            if self.tcp(*handle).is_some_and(|socket| {
                matches!(
                    socket.state(),
                    tcp::State::Listen
                        | tcp::State::SynReceived
                        | tcp::State::Established
                        | tcp::State::CloseWait
                )
            }) {
                true
            } else {
                self.remove(*handle);
                false
            }
        });
        self.refill_listener(listener);
        let index = listener.pending.iter().position(|handle| {
            self.tcp(*handle).is_some_and(|socket| {
                matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            })
        })?;
        let handle = listener.pending.remove(index);
        self.refill_listener(listener);
        Some(handle)
    }

    pub fn register_accept_waker(&mut self, listener: &TcpListener<N>, waker: &core::task::Waker) {
        for handle in &listener.pending {
            if let Some(socket) = self.tcp(*handle) {
                socket.register_recv_waker(waker);
                socket.register_send_waker(waker);
            }
        }
    }

    pub fn deadline(&mut self, now_ms: u64) -> Option<u64> {
        self.iface
            .as_mut()?
            .poll_at(instant(now_ms), &self.sockets)
            .map(|at| at.total_millis().max(0) as u64)
    }

    pub fn socket_count(&self) -> usize {
        self.live.len()
    }

    pub fn abort_all(&mut self) {
        while let Some((socket, generation)) = self.live.last().copied() {
            self.remove(TcpHandle {
                stack: self.id,
                socket,
                generation,
            });
        }
    }

    pub fn accept_ready(&mut self, listener: &mut TcpListener<N>) -> Vec<TcpHandle, N> {
        let mut ready = Vec::new();
        listener.pending.retain(
            |handle| match self.tcp(*handle).map(|socket| socket.state()) {
                Some(tcp::State::Established | tcp::State::CloseWait) => {
                    let _ = ready.push(*handle);
                    false
                }
                Some(tcp::State::Listen | tcp::State::SynReceived) => true,
                _ => {
                    self.remove(*handle);
                    false
                }
            },
        );
        self.refill_listener(listener);
        ready
    }
    pub fn remove_listener(&mut self, listener: &mut TcpListener<N>) {
        while let Some(handle) = listener.pending.pop() {
            self.remove(handle);
        }
    }
    pub fn tcp(&mut self, handle: TcpHandle) -> Option<&mut tcp::Socket<'a>> {
        self.valid(handle)
            .then(|| self.sockets.get_mut::<tcp::Socket>(handle.socket))
    }

    /// The current peer endpoint, retaining it across a write-side half-close.
    /// Removed, reset and address-revoked sockets cannot expose a stale peer.
    pub fn remote_endpoint(&self, handle: TcpHandle) -> Option<SocketAddr> {
        if !self.valid(handle) {
            return None;
        }
        let socket = self.sockets.get::<tcp::Socket>(handle.socket);
        if socket.state() == tcp::State::Closed {
            return None;
        }
        let endpoint = socket.remote_endpoint()?;
        Some(SocketAddr::new(core_address(endpoint.addr), endpoint.port))
    }

    fn valid(&self, handle: TcpHandle) -> bool {
        handle.stack == self.id
            && self
                .live
                .iter()
                .any(|(key, generation)| *key == handle.socket && *generation == handle.generation)
    }

    /// Abort and forget a socket. Each handle is removed at most once.
    pub fn remove(&mut self, handle: TcpHandle) {
        if self.valid(handle) {
            let socket = match self.sockets.remove(handle.socket) {
                smoltcp::socket::Socket::Tcp(socket) => socket,
                #[allow(unreachable_patterns)]
                _ => unreachable!("TCP-only stack"),
            };
            self.recycle(socket);
            self.fins.retain(|fin| fin.socket != handle.socket);
            self.received_fins
                .retain(|(key, _, _)| *key != handle.socket);
            self.live.retain(|(key, _)| *key != handle.socket);
        }
    }
}

fn instant(now_ms: u64) -> Instant {
    Instant::from_millis(now_ms.min(i64::MAX as u64) as i64)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn exchange(local: &mut OwnedStack, remote: &mut OwnedStack, times: core::ops::Range<u64>) {
        for now in times {
            for bytes in local.poll(now) {
                remote.deliver(&bytes);
            }
            for bytes in remote.poll(now) {
                local.deliver(&bytes);
            }
        }
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn one_listener_serves_both_families_and_an_ipv6_change_ends_only_ipv6() {
        let local6: Ipv6Addr = "fd7a:115c:a1e0::1".parse().unwrap();
        let remote6: Ipv6Addr = "fd7a:115c:a1e0::2".parse().unwrap();
        let mut local = OwnedStack::new(1);
        let mut remote = OwnedStack::new(2);
        // The IPv6 address may arrive before the IPv4 one creates the interface.
        local.set_ipv6_address(Some(local6));
        local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
        remote.set_ipv6_address(Some(remote6));
        assert_eq!(remote.ipv6_address(), Some(remote6));
        let mut listener = remote.listen_backlog(2222).unwrap();

        let over6 = local.connect(remote6, 2222, 49152).unwrap();
        let over4 = local
            .connect("100.64.0.2".parse::<Ipv4Addr>().unwrap(), 2222, 49153)
            .unwrap();
        exchange(&mut local, &mut remote, 0..10);
        assert_eq!(
            local.remote_endpoint(over6),
            Some(SocketAddr::new(remote6.into(), 2222))
        );
        let mut peers = std::vec::Vec::new();
        while let Some(accepted) = remote.accept_one(&mut listener) {
            peers.push(remote.remote_endpoint(accepted).unwrap());
        }
        peers.sort();
        assert_eq!(
            peers,
            [
                "100.64.0.1:49153".parse().unwrap(),
                SocketAddr::new(local6.into(), 49152),
            ]
        );
        let mut remotes = local.remote_addresses();
        remotes.sort();
        assert_eq!(remotes, [IpAddr::from([100, 64, 0, 2]), remote6.into()]);

        // Data and a closing FIN round-trip over IPv6, so FIN bookkeeping
        // reads IPv6 headers too.
        local.tcp(over6).unwrap().send_slice(b"over ipv6").unwrap();
        local.tcp(over6).unwrap().close();
        exchange(&mut local, &mut remote, 10..100);
        assert_eq!(local.close_outcome(over6), Some(true));

        // A new IPv6 address ends what was bound to the old one only.
        let fresh = local.connect(remote6, 2222, 49160).unwrap();
        exchange(&mut local, &mut remote, 100..110);
        assert_eq!(local.tcp(fresh).unwrap().state(), tcp::State::Established);
        local.set_ipv6_address(Some("fd7a:115c:a1e0::9".parse().unwrap()));
        assert_eq!(local.tcp(fresh).unwrap().state(), tcp::State::Closed);
        assert_eq!(local.tcp(over4).unwrap().state(), tcp::State::Established);
        // Without an IPv6 address there is no source to connect from.
        local.set_ipv6_address(None);
        assert!(local.connect(remote6, 2222, 49170).is_err());
    }

    #[test]
    fn automatic_source_ports_rotate_instead_of_reusing_a_closed_tuple() {
        let mut net = OwnedStack::new(1);
        net.set_address("100.64.0.1".parse().unwrap(), 0, 7);
        let remote: Ipv4Addr = "100.64.0.2".parse().unwrap();
        let mut seen = std::vec::Vec::new();
        for _ in 0..4 {
            let handle = net.connect(remote, 2222, 0).unwrap();
            let port = net.tcp(handle).unwrap().local_endpoint().unwrap().port;
            // Closed at once, as a short request is: its port is free again,
            // but the peer may still hold the tuple in TIME_WAIT.
            net.remove(handle);
            seen.push(port);
        }
        assert!(seen.iter().all(|port| *port >= 49152), "{seen:?}");
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "a freed port came straight back: {seen:?}"
        );
        // The cursor wraps within the ephemeral range.
        net.next_port = u16::MAX;
        let last = net.connect(remote, 2222, 0).unwrap();
        assert_eq!(
            net.tcp(last).unwrap().local_endpoint().unwrap().port,
            u16::MAX
        );
        let wrapped = net.connect(remote, 2222, 0).unwrap();
        assert_eq!(
            net.tcp(wrapped).unwrap().local_endpoint().unwrap().port,
            49152
        );
    }

    #[cfg(not(feature = "ipv6"))]
    #[test]
    fn ipv6_connections_need_the_feature() {
        let mut local = OwnedStack::new(1);
        local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        let remote: core::net::Ipv6Addr = "fd7a:115c:a1e0::2".parse().unwrap();
        assert!(local.connect(remote, 2222, 49152).is_err());
    }
    #[test]
    fn remote_endpoints_survive_half_close_but_not_reset_revocation_or_handle_reuse() {
        for reset in [true, false] {
            let mut local = OwnedStack::new(1);
            let mut remote = OwnedStack::new(2);
            local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
            remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
            let accepted = remote.listen(2222).unwrap();
            assert_eq!(remote.remote_endpoint(accepted), None);
            let client = local
                .connect(
                    "100.64.0.2".parse::<core::net::Ipv4Addr>().unwrap(),
                    2222,
                    49152,
                )
                .unwrap();
            for now in 0..10 {
                for bytes in local.poll(now) {
                    remote.deliver(&bytes);
                }
                for bytes in remote.poll(now) {
                    local.deliver(&bytes);
                }
            }
            let endpoint = "100.64.0.2:2222".parse().unwrap();
            assert_eq!(local.remote_endpoint(client), Some(endpoint));
            assert_eq!(
                remote.remote_endpoint(accepted),
                Some("100.64.0.1:49152".parse().unwrap())
            );
            assert_eq!(remote.remote_endpoint(client), None, "foreign stack handle");
            local.tcp(client).unwrap().close();
            assert_eq!(local.remote_endpoint(client), Some(endpoint));
            if reset {
                local.tcp(client).unwrap().abort();
            } else {
                local.clear_address();
            }
            assert_eq!(local.remote_endpoint(client), None);
            local.remove(client);
            local.set_address("100.64.0.1".parse().unwrap(), 10, 3);
            let replacement = local
                .connect(
                    "100.64.0.3".parse::<core::net::Ipv4Addr>().unwrap(),
                    2223,
                    49152,
                )
                .unwrap();
            assert_eq!(
                local.remote_endpoint(client),
                None,
                "reused socket slot must not revive the old handle"
            );
            assert_eq!(
                local.remote_endpoint(replacement),
                Some("100.64.0.3:2223".parse().unwrap())
            );
        }
    }

    #[test]
    fn drain_distinguishes_a_reset_from_acknowledged_final_data() {
        for reset in [false, true] {
            let mut local = OwnedStack::new(1);
            let mut remote = OwnedStack::new(2);
            local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
            remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
            let accepted = remote.listen(2222).unwrap();
            let client = local
                .connect(
                    "100.64.0.2".parse::<core::net::Ipv4Addr>().unwrap(),
                    2222,
                    49152,
                )
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
        let mut net = OwnedStack::new(1);
        net.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        let remote: Ipv4Addr = "100.64.0.2".parse().unwrap();
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
        let mut net = OwnedStack::new(1);
        net.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        let listener = net.listen(2222).unwrap();
        let outgoing = net
            .connect(
                "100.64.0.2".parse::<core::net::Ipv4Addr>().unwrap(),
                2222,
                49152,
            )
            .unwrap();
        net.set_address("100.64.0.3".parse().unwrap(), 1, 1);
        assert_eq!(net.tcp(listener).unwrap().state(), tcp::State::Listen);
        assert_eq!(net.tcp(listener).unwrap().listen_endpoint().port, 2222);
        assert_eq!(net.tcp(outgoing).unwrap().state(), tcp::State::Closed);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod backlog_tests {
    use super::*;
    #[test]
    fn simultaneous_syns_survive_before_the_runtime_can_accept() {
        for backlog in [4, 16] {
            let mut server = NetStack::<32, 128, alloc::collections::VecDeque<Packet>>::new(1);
            let mut client = NetStack::<32, 128, alloc::collections::VecDeque<Packet>>::new(2);
            server.set_address("100.64.0.1".parse().unwrap(), 0, 1);
            client.set_address("100.64.0.2".parse().unwrap(), 0, 2);
            let mut listener = server.listen_with_backlog(2222, backlog).unwrap();
            let connections = (0..backlog as u16)
                .map(|n| {
                    client
                        .connect(
                            "100.64.0.1".parse::<core::net::Ipv4Addr>().unwrap(),
                            2222,
                            49152 + n,
                        )
                        .unwrap()
                })
                .collect::<alloc::vec::Vec<_>>();
            // Deliver all SYNs in one packet batch before the accept task runs.
            for now in 0..30 {
                for packet in client.poll(now) {
                    server.deliver(&packet);
                }
                for packet in server.poll(now) {
                    client.deliver(&packet);
                }
            }
            assert!(
                connections
                    .iter()
                    .all(|h| client.tcp(*h).unwrap().state() == tcp::State::Established)
            );
            assert_eq!(server.accept_ready(&mut listener).len(), backlog);
            assert_eq!(listener.pending.len(), backlog);
        }
    }
}

#[cfg(test)]
mod fixed_storage_tests {
    use super::*;

    #[test]
    fn invalid_opens_recycle_storage_and_stale_handles_cannot_remove_reused_slots() {
        let mut storage = Storage::<1, 512>::new();
        let mut stack = NetStack::<1, 2>::with_storage(1, &mut storage);
        assert!(stack.listen(0).is_err());
        let old = stack.listen(2222).unwrap();
        stack.remove(old);
        let current = stack.listen(3333).unwrap();
        assert!(stack.tcp(old).is_none());
        stack.remove(old);
        assert_eq!(stack.tcp(current).unwrap().listen_endpoint().port, 3333);
    }

    #[test]
    fn failed_handshakes_replenish_the_async_listener_backlog() {
        let mut storage = Storage::<4, 512>::new();
        let mut stack = NetStack::<4, 2>::with_storage(1, &mut storage);
        let mut listener = stack.listen_backlog(2222).unwrap();
        for handle in &listener.pending {
            stack.tcp(*handle).unwrap().abort();
        }
        assert!(stack.accept_one(&mut listener).is_none());
        assert_eq!(listener.pending.len(), 4);
        assert!(
            listener
                .pending
                .iter()
                .all(|handle| stack.tcp(*handle).unwrap().state() == tcp::State::Listen)
        );
    }

    #[test]
    fn an_out_of_window_fin_ack_cannot_turn_a_reset_into_a_successful_drain() {
        let mut a = Storage::<4, 512>::new();
        let mut b = Storage::<4, 512>::new();
        let mut local = NetStack::<4, 8>::with_storage(1, &mut a);
        let mut remote = NetStack::<4, 8>::with_storage(2, &mut b);
        local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
        remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
        let accepted = remote.listen(2222).unwrap();
        let client = local
            .connect(
                "100.64.0.2".parse::<core::net::Ipv4Addr>().unwrap(),
                2222,
                49152,
            )
            .unwrap();
        for now in 0..10 {
            for bytes in local.poll(now) {
                remote.deliver(&bytes);
            }
            for bytes in remote.poll(now) {
                local.deliver(&bytes);
            }
        }
        local.tcp(client).unwrap().send_slice(b"final").unwrap();
        local.tcp(client).unwrap().close();
        for bytes in local.poll(10) {
            remote.deliver(&bytes);
        }
        let mut ack = remote
            .poll(30)
            .into_iter()
            .chain(remote.poll(60))
            .find(|bytes| tcp_frame(bytes).is_some_and(|frame| frame.ack.is_some()))
            .unwrap();
        {
            let mut ip = Ipv4Packet::new_checked(&mut ack[..]).unwrap();
            let source = IpAddress::Ipv4(ip.src_addr());
            let destination = IpAddress::Ipv4(ip.dst_addr());
            let mut tcp = TcpPacket::new_checked(ip.payload_mut()).unwrap();
            tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(
                tcp.seq_number().0.wrapping_add(1_000_000),
            ));
            tcp.fill_checksum(&source, &destination);
        }
        local.deliver(&ack);
        remote.tcp(accepted).unwrap().abort();
        for bytes in remote.poll(61) {
            local.deliver(&bytes);
        }
        local.poll(62);
        assert_eq!(local.close_outcome(client), Some(false));
        local.deliver(&ack);
        local.poll(63);
        assert_eq!(local.close_outcome(client), Some(false));
    }
}
