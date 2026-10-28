//! Userspace TCP over the tailnet: a smoltcp interface whose "wire" is the
//! WireGuard tunnel. Packets smoltcp transmits are queued for the runtime to
//! encapsulate for the owning peer; packets the node decrypts are queued for
//! smoltcp to receive.

#[cfg(feature = "alloc")]
use alloc::vec;
use core::net::{Ipv4Addr, SocketAddrV4};
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
    let offset = usize::from(first & 0x0f) * 4;
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
    #[cfg(feature = "alloc")]
    Owned,
}

#[cfg(feature = "alloc")]
impl<const N: usize, const Q: usize> NetStack<'static, N, Q, alloc::collections::VecDeque<Packet>> {
    pub fn new(id: u64) -> Self {
        Self::build(id, SocketSet::new(alloc::vec::Vec::new()), Pool::Owned)
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
            Pool::Owned => tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
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
            Pool::Owned => {}
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
        let mut iface = Interface::new(config, &mut self.device, instant(now_ms));
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), 32));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY);
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
    pub fn connect(
        &mut self,
        remote: Ipv4Addr,
        port: u16,
        local_port: u16,
    ) -> Result<TcpHandle, &'static str> {
        if self.live.len() >= N {
            return Err("TCP session capacity reached");
        }
        let first = local_port.max(49152);
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
        let mut socket = self.socket()?;
        let iface = self.iface.as_mut().unwrap();
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(25)));
        if socket
            .connect(iface.context(), (IpAddress::Ipv4(remote), port), local_port)
            .is_err()
        {
            self.recycle(socket);
            return Err("invalid TCP connection endpoint");
        }
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
    pub fn remote_addresses(&self) -> Vec<Ipv4Addr, N> {
        self.sockets
            .iter()
            .filter_map(|(_, socket)| {
                let socket = tcp::Socket::downcast(socket).expect("TCP-only stack");
                #[allow(unreachable_patterns)]
                match socket.remote_endpoint()?.addr {
                    IpAddress::Ipv4(address) => Some(address),
                    _ => None,
                }
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
    pub fn remote_endpoint(&self, handle: TcpHandle) -> Option<SocketAddrV4> {
        if !self.valid(handle) {
            return None;
        }
        let socket = self.sockets.get::<tcp::Socket>(handle.socket);
        if socket.state() == tcp::State::Closed {
            return None;
        }
        let endpoint = socket.remote_endpoint()?;
        match endpoint.addr {
            IpAddress::Ipv4(address) => Some(SocketAddrV4::new(address, endpoint.port)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
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
                .connect("100.64.0.3".parse().unwrap(), 2223, 49152)
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
        let mut net = OwnedStack::new(1);
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
        let mut net = OwnedStack::new(1);
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
                        .connect("100.64.0.1".parse().unwrap(), 2222, 49152 + n)
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
