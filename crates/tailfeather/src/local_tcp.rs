//! Bounded userspace TCP over caller-supplied IPv4 packets.
//!
//! This is a sans-I/O adapter: callers feed decrypted packets in and collect
//! complete reply packets out. It owns no operating-system socket and performs
//! no allocation. Five socket slots are intended for four claimed sessions and
//! one continuously replenished listener.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

/// Buffer carried in each direction by one TCP socket.
pub const STREAM_BUFFER: usize = 8192;
/// Largest IPv4 packet accepted or emitted by the local stack.
pub const MTU: usize = crate::tunnel::budget::INNER_MTU;
/// Tailfeather SSH layout: four sessions plus one listening socket.
pub const SSH_SOCKET_COUNT: usize = 5;
pub const SSH_SESSION_COUNT: usize = SSH_SOCKET_COUNT - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoSockets,
    EmptyBuffer,
    AlreadyListening,
    NotListening,
    InvalidPacket,
    Ipv6Unsupported,
    OutputTooSmall,
    InvalidStream,
    WouldBlock,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSockets => f.write_str("local TCP storage has no sockets"),
            Self::EmptyBuffer => f.write_str("local TCP byte queues are empty"),
            Self::AlreadyListening => f.write_str("local TCP stack is already listening"),
            Self::NotListening => f.write_str("local TCP stack is not listening"),
            Self::InvalidPacket => f.write_str("packet is not a valid IPv4 packet for this node"),
            Self::Ipv6Unsupported => f.write_str("IPv6 local TCP is not supported"),
            Self::OutputTooSmall => f.write_str("IPv4 transmit buffer is smaller than the MTU"),
            Self::InvalidStream => f.write_str("local TCP stream is not active"),
            Self::WouldBlock => f.write_str("local TCP stream would block"),
        }
    }
}

/// Identifier for one claim of a connection slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamId {
    index: usize,
    generation: u64,
}

impl StreamId {
    pub const fn index(self) -> usize {
        self.index
    }
}

/// Result of one packet-stack poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poll {
    /// Bytes of a complete IPv4 packet written to the caller's output buffer.
    pub transmitted: usize,
    /// Earliest monotonic millisecond at which timer work is due.
    pub deadline_ms: Option<u64>,
}

/// Caller-owned arena for socket metadata and all TCP byte queues.
pub struct Storage<'a, const N: usize, const BUFFER: usize = STREAM_BUFFER> {
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

/// An allocation-free raw-IPv4 TCP stack borrowing [`Storage`].
pub struct Stack<'a, const N: usize> {
    iface: Interface,
    sockets: SocketSet<'a>,
    handles: heapless::Vec<SocketHandle, N>,
    claimed: [bool; N],
    generations: [u64; N],
    port: Option<u16>,
}

impl<'a, const N: usize> Stack<'a, N> {
    /// Construct a stack for the node's assigned Tailnet IPv4 address.
    /// `random_seed` seeds TCP initial sequence numbers and must not be reused
    /// as a secret key.
    pub fn new<const BUFFER: usize>(
        storage: &'a mut Storage<'a, N, BUFFER>,
        assigned_ipv4: [u8; 4],
        random_seed: u64,
        now_ms: u64,
    ) -> Result<Self, Error> {
        if N == 0 {
            return Err(Error::NoSockets);
        }
        if BUFFER == 0 {
            return Err(Error::EmptyBuffer);
        }
        let mut device = PacketDevice::empty();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut iface = Interface::new(config, &mut device, instant(now_ms));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::from(assigned_ipv4)),
                    32,
                ))
                .expect("one address fits smoltcp's fixed interface storage");
        });

        let mut sockets = SocketSet::new(&mut storage.sockets[..]);
        let mut handles = heapless::Vec::new();
        for (rx, tx) in storage.rx.iter_mut().zip(storage.tx.iter_mut()) {
            let rx = tcp::SocketBuffer::new(&mut rx[..]);
            let tx = tcp::SocketBuffer::new(&mut tx[..]);
            handles
                .push(sockets.add(tcp::Socket::new(rx, tx)))
                .map_err(|_| Error::NoSockets)?;
        }
        Ok(Self {
            iface,
            sockets,
            handles,
            claimed: [false; N],
            generations: [0; N],
            port: None,
        })
    }

    /// Listen on every unclaimed slot. Multiple same-port listening sockets are
    /// how the fixed set retains capacity while earlier slots are connected.
    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        if self.port.is_some() {
            return Err(Error::AlreadyListening);
        }
        self.port = Some(port);
        self.replenish();
        Ok(())
    }

    /// Feed one decrypted IPv4 packet and optionally emit one response packet.
    /// IPv6 local TCP is rejected distinctly so a runtime can distinguish
    /// this adapter's unsupported family from malformed input.
    pub fn ingest_ip(
        &mut self,
        packet: &[u8],
        output: &mut [u8],
        now_ms: u64,
    ) -> Result<Poll, Error> {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => self.ingest_ipv4(packet, output, now_ms),
            Some(6) => Err(Error::Ipv6Unsupported),
            _ => Err(Error::InvalidPacket),
        }
    }

    /// Feed one decrypted IPv4 packet and optionally emit one response packet.
    pub fn ingest_ipv4(
        &mut self,
        packet: &[u8],
        output: &mut [u8],
        now_ms: u64,
    ) -> Result<Poll, Error> {
        if output.len() < MTU {
            return Err(Error::OutputTooSmall);
        }
        if packet.len() < 20 || packet[0] >> 4 != 4 || packet.len() > MTU {
            return Err(Error::InvalidPacket);
        }
        let assigned = self.iface.ipv4_addr().ok_or(Error::InvalidPacket)?;
        if packet.get(16..20) != Some(assigned.octets().as_slice()) {
            return Err(Error::InvalidPacket);
        }
        self.poll(Some(packet), output, now_ms)
    }

    /// Poll timers and queued TCP output without supplying an ingress packet.
    pub fn poll_transmit(&mut self, output: &mut [u8], now_ms: u64) -> Result<Poll, Error> {
        if output.len() < MTU {
            return Err(Error::OutputTooSmall);
        }
        self.poll(None, output, now_ms)
    }

    fn poll(
        &mut self,
        packet: Option<&[u8]>,
        output: &mut [u8],
        now_ms: u64,
    ) -> Result<Poll, Error> {
        if self.port.is_none() {
            return Err(Error::NotListening);
        }
        let mut device = PacketDevice::new(packet, output);
        self.iface
            .poll(instant(now_ms), &mut device, &mut self.sockets);
        let transmitted = device.transmitted();
        self.replenish();
        let deadline_ms = self
            .iface
            .poll_at(instant(now_ms), &self.sockets)
            .map(|deadline| deadline.total_millis().max(0) as u64);
        Ok(Poll {
            transmitted,
            deadline_ms,
        })
    }

    /// Claim the next established connection. At most `N - 1` streams may be
    /// claimed; an excess connection is reset and its slot immediately listens
    /// again, preserving the final listener.
    pub fn accept(&mut self) -> Option<StreamId> {
        let limit = N.saturating_sub(1);
        let active = self.claimed.iter().filter(|claimed| **claimed).count();
        for (index, handle) in self.handles.iter().copied().enumerate() {
            if self.claimed[index] {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if socket.state() != tcp::State::Established {
                continue;
            }
            if active >= limit {
                socket.abort();
                self.replenish();
                return None;
            }
            self.claimed[index] = true;
            self.generations[index] = self.generations[index].wrapping_add(1);
            return Some(StreamId {
                index,
                generation: self.generations[index],
            });
        }
        None
    }

    pub fn is_active(&self, id: StreamId) -> bool {
        self.handle(id)
            .is_some_and(|handle| self.sockets.get::<tcp::Socket>(handle).is_active())
    }

    /// The Tailnet IPv4 address at the other end of a claimed stream.
    pub fn remote_ipv4(&self, id: StreamId) -> Option<[u8; 4]> {
        let handle = self.handle(id)?;
        #[allow(unreachable_patterns)]
        match self
            .sockets
            .get::<tcp::Socket>(handle)
            .remote_endpoint()?
            .addr
        {
            IpAddress::Ipv4(address) => Some(address.octets()),
            _ => None,
        }
    }

    /// Nonblocking stream receive.
    pub fn read(&mut self, id: StreamId, output: &mut [u8]) -> Result<usize, Error> {
        let handle = self.handle(id).ok_or(Error::InvalidStream)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.can_recv() {
            return if socket.may_recv() {
                Err(Error::WouldBlock)
            } else {
                Ok(0)
            };
        }
        socket.recv_slice(output).map_err(|_| Error::WouldBlock)
    }

    /// Nonblocking stream send. A short write is normal backpressure.
    pub fn write(&mut self, id: StreamId, input: &[u8]) -> Result<usize, Error> {
        let handle = self.handle(id).ok_or(Error::InvalidStream)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.can_send() {
            return Err(Error::WouldBlock);
        }
        socket.send_slice(input).map_err(|_| Error::WouldBlock)
    }

    pub fn close(&mut self, id: StreamId) -> Result<(), Error> {
        let handle = self.handle(id).ok_or(Error::InvalidStream)?;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
        Ok(())
    }

    pub fn reset(&mut self, id: StreamId) -> Result<(), Error> {
        let handle = self.handle(id).ok_or(Error::InvalidStream)?;
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        self.claimed[id.index] = false;
        self.replenish();
        Ok(())
    }

    /// Replace the local Tailnet address and discard every socket bound to the
    /// previous one. The listener is replenished immediately at the same port.
    pub fn rebind_ipv4(&mut self, assigned_ipv4: [u8; 4]) {
        for handle in self.handles.iter().copied() {
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
        }
        self.claimed.fill(false);
        self.iface.update_ip_addrs(|addresses| {
            addresses.clear();
            addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::from(assigned_ipv4)),
                    32,
                ))
                .expect("one address fits smoltcp's fixed interface storage");
        });
        self.replenish();
    }

    fn handle(&self, id: StreamId) -> Option<SocketHandle> {
        if !self.claimed.get(id.index).copied().unwrap_or(false)
            || self.generations[id.index] != id.generation
        {
            return None;
        }
        self.handles.get(id.index).copied()
    }

    fn replenish(&mut self) {
        let Some(port) = self.port else { return };
        for (index, handle) in self.handles.iter().copied().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if self.claimed[index] && !socket.is_active() {
                self.claimed[index] = false;
            }
            if !self.claimed[index] && !socket.is_open() {
                let _ = socket.listen(port);
            }
        }
        let has_listener = self
            .handles
            .iter()
            .copied()
            .enumerate()
            .any(|(index, handle)| {
                !self.claimed[index]
                    && self.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Listen
            });
        if !has_listener {
            // A half-open handshake must not consume the final listening slot.
            // Prefer aborting an unclaimed non-established socket so a fully
            // completed handshake can still be accepted by the caller.
            let victim = self
                .handles
                .iter()
                .copied()
                .enumerate()
                .find(|(index, handle)| {
                    !self.claimed[*index]
                        && self.sockets.get::<tcp::Socket>(*handle).state()
                            != tcp::State::Established
                })
                .or_else(|| {
                    self.handles
                        .iter()
                        .copied()
                        .enumerate()
                        .find(|(index, _)| !self.claimed[*index])
                });
            if let Some((_, handle)) = victim {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                socket.abort();
                let _ = socket.listen(port);
            }
        }
    }
}

fn instant(now_ms: u64) -> Instant {
    Instant::from_millis(now_ms.min(i64::MAX as u64) as i64)
}

struct PacketDevice<'a> {
    rx: Option<&'a [u8]>,
    tx: &'a mut [u8],
    tx_len: Option<usize>,
}

impl PacketDevice<'static> {
    fn empty() -> Self {
        Self {
            rx: None,
            tx: &mut [],
            tx_len: None,
        }
    }
}

impl<'a> PacketDevice<'a> {
    fn new(rx: Option<&'a [u8]>, tx: &'a mut [u8]) -> Self {
        Self {
            rx,
            tx,
            tx_len: None,
        }
    }

    fn transmitted(&self) -> usize {
        self.tx_len.unwrap_or(0)
    }
}

struct PacketRx<'a>(&'a [u8]);
struct PacketTx<'a> {
    buffer: &'a mut [u8],
    len: &'a mut Option<usize>,
}

impl RxToken for PacketRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0)
    }
}

impl TxToken for PacketTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = f(&mut self.buffer[..len]);
        *self.len = Some(len);
        result
    }
}

impl Device for PacketDevice<'_> {
    type RxToken<'a>
        = PacketRx<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx_len.is_some() {
            return None;
        }
        let rx = self.rx.take()?;
        Some((
            PacketRx(rx),
            PacketTx {
                buffer: self.tx,
                len: &mut self.tx_len,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx_len.is_some() || self.tx.is_empty() {
            return None;
        }
        Some(PacketTx {
            buffer: self.tx,
            len: &mut self.tx_len,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    const CLIENT: Ipv4Address = Ipv4Address::new(100, 64, 0, 8);
    const SERVER: Ipv4Address = Ipv4Address::new(100, 64, 0, 9);

    fn segment(
        output: &mut [u8],
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        payload: &[u8],
    ) -> usize {
        segment_to(output, SERVER, control, seq, ack, payload)
    }

    fn segment_to(
        output: &mut [u8],
        destination: Ipv4Address,
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        payload: &[u8],
    ) -> usize {
        segment_with_options_to(
            output,
            destination,
            control,
            seq,
            ack,
            8192,
            Some(1200),
            payload,
        )
    }

    fn segment_with_window(
        output: &mut [u8],
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        window_len: u16,
        payload: &[u8],
    ) -> usize {
        segment_with_options(output, control, seq, ack, window_len, Some(1200), payload)
    }

    fn segment_with_options(
        output: &mut [u8],
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        window_len: u16,
        max_seg_size: Option<u16>,
        payload: &[u8],
    ) -> usize {
        segment_with_options_to(
            output,
            SERVER,
            control,
            seq,
            ack,
            window_len,
            max_seg_size,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn segment_with_options_to(
        output: &mut [u8],
        destination: Ipv4Address,
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        window_len: u16,
        max_seg_size: Option<u16>,
        payload: &[u8],
    ) -> usize {
        let tcp = TcpRepr {
            src_port: 40000,
            dst_port: 22,
            control,
            seq_number: seq,
            ack_number: ack,
            window_len,
            window_scale: None,
            max_seg_size,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: CLIENT,
            dst_addr: destination,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let len = ip.buffer_len() + tcp.header_len() + payload.len();
        ip.emit(
            &mut Ipv4Packet::new_unchecked(&mut output[..len]),
            &ChecksumCapabilities::default(),
        );
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut output[ip.buffer_len()..len]),
            &CLIENT.into(),
            &destination.into(),
            &ChecksumCapabilities::default(),
        );
        len
    }

    fn tcp(packet: &[u8]) -> TcpPacket<&[u8]> {
        let ip = Ipv4Packet::new_checked(packet).unwrap();
        TcpPacket::new_checked(ip.payload()).unwrap()
    }

    fn syn_from(output: &mut [u8], source_port: u16, sequence: u32) -> usize {
        let tcp = TcpRepr {
            src_port: source_port,
            dst_port: 22,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(sequence as i32),
            ack_number: None,
            window_len: 8192,
            window_scale: None,
            max_seg_size: Some(1200),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: CLIENT,
            dst_addr: SERVER,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.header_len(),
            hop_limit: 64,
        };
        let len = ip.buffer_len() + tcp.header_len();
        ip.emit(
            &mut Ipv4Packet::new_unchecked(&mut output[..len]),
            &ChecksumCapabilities::default(),
        );
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut output[ip.buffer_len()..len]),
            &CLIENT.into(),
            &SERVER.into(),
            &ChecksumCapabilities::default(),
        );
        len
    }

    fn establish<const N: usize>(
        stack: &mut Stack<'_, N>,
        ingress: &mut [u8; MTU],
        egress: &mut [u8; MTU],
    ) -> (StreamId, TcpSeqNumber) {
        let syn_len = segment(ingress, TcpControl::Syn, TcpSeqNumber(100), None, &[]);
        let syn_ack = stack.ingest_ipv4(&ingress[..syn_len], egress, 1).unwrap();
        let syn_ack_tcp = tcp(&egress[..syn_ack.transmitted]);
        let server_next = syn_ack_tcp.seq_number() + 1;
        let ack_len = segment(
            ingress,
            TcpControl::None,
            TcpSeqNumber(101),
            Some(server_next),
            &[],
        );
        stack.ingest_ipv4(&ingress[..ack_len], egress, 2).unwrap();
        (
            stack.accept().expect("completed handshake is claimable"),
            server_next,
        )
    }

    #[test]
    fn caller_storage_is_the_complete_socket_arena() {
        let storage = Storage::<SSH_SOCKET_COUNT>::new();
        assert_eq!(storage.rx.len(), SSH_SOCKET_COUNT);
        assert_eq!(storage.tx.len(), SSH_SOCKET_COUNT);
        assert_eq!(storage.rx[0].len(), STREAM_BUFFER);
        assert_eq!(MTU, crate::tunnel::budget::INNER_MTU);
    }

    #[test]
    fn small_console_queues_complete_a_handshake_and_carry_data() {
        let mut storage = Storage::<2, 1024>::new();
        assert_eq!(storage.rx[0].len(), 1024);
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0; MTU];
        let mut egress = [0; MTU];
        let (stream, server_next) = establish(&mut stack, &mut ingress, &mut egress);
        let length = segment(
            &mut ingress,
            TcpControl::None,
            TcpSeqNumber(101),
            Some(server_next),
            b"console\n",
        );
        stack
            .ingest_ipv4(&ingress[..length], &mut egress, 3)
            .unwrap();
        let mut bytes = [0; 16];
        let read = stack.read(stream, &mut bytes).unwrap();
        assert_eq!(&bytes[..read], b"console\n");
        assert_eq!(stack.write(stream, b"ready\n"), Ok(6));
        assert!(stack.poll_transmit(&mut egress, 4).unwrap().transmitted > 0);
        let mut empty = Storage::<2, 0>::new();
        assert!(matches!(
            Stack::new(&mut empty, SERVER.octets(), 7, 0),
            Err(Error::EmptyBuffer)
        ));
    }

    #[test]
    fn listen_and_validation_are_explicit() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, [100, 64, 0, 9], 7, 0).unwrap();
        let mut output = [0; MTU];
        assert_eq!(
            stack.poll_transmit(&mut output, 0),
            Err(Error::NotListening)
        );
        stack.listen(22).unwrap();
        assert_eq!(stack.listen(22), Err(Error::AlreadyListening));
        assert_eq!(
            stack.ingest_ipv4(&[0; 20], &mut output, 0),
            Err(Error::InvalidPacket)
        );
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        assert_eq!(
            stack.ingest_ip(&ipv6, &mut output, 0),
            Err(Error::Ipv6Unsupported)
        );

        let mut other = [0u8; 20];
        other[0] = 0x45;
        other[16..20].copy_from_slice(&[100, 64, 0, 10]);
        assert_eq!(
            stack.ingest_ipv4(&other, &mut output, 0),
            Err(Error::InvalidPacket)
        );
    }

    #[test]
    fn half_open_handshakes_cannot_consume_the_final_listener() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];

        for index in 0..SSH_SOCKET_COUNT {
            let len = syn_from(&mut ingress, 40_000 + index as u16, 100 + index as u32);
            stack
                .ingest_ipv4(&ingress[..len], &mut egress, index as u64 + 1)
                .unwrap();
        }

        let listeners = stack
            .handles
            .iter()
            .copied()
            .filter(|handle| {
                stack.sockets.get::<tcp::Socket>(*handle).state() == tcp::State::Listen
            })
            .count();
        assert_eq!(listeners, 1);
    }

    #[test]
    fn five_slots_bound_claimed_sessions_to_four() {
        assert_eq!(SSH_SOCKET_COUNT, SSH_SESSION_COUNT + 1);
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, [100, 64, 0, 9], 7, 0).unwrap();
        stack.listen(22).unwrap();
        assert!(stack.accept().is_none());
        assert!(stack.claimed.iter().all(|claimed| !claimed));
    }

    #[test]
    fn rebinding_discards_old_streams_and_listens_on_the_new_address() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let (stream, _) = establish(&mut stack, &mut ingress, &mut egress);
        assert!(stack.is_active(stream));

        let replacement = Ipv4Address::new(100, 64, 0, 10);
        stack.rebind_ipv4(replacement.octets());
        assert!(!stack.is_active(stream));

        let old_syn = segment(&mut ingress, TcpControl::Syn, TcpSeqNumber(200), None, &[]);
        assert_eq!(
            stack.ingest_ipv4(&ingress[..old_syn], &mut egress, 3),
            Err(Error::InvalidPacket)
        );
        let new_syn = segment_to(
            &mut ingress,
            replacement,
            TcpControl::Syn,
            TcpSeqNumber(200),
            None,
            &[],
        );
        let response = stack
            .ingest_ipv4(&ingress[..new_syn], &mut egress, 4)
            .unwrap();
        assert!(response.transmitted != 0);
        assert!(tcp(&egress[..response.transmitted]).syn());
    }

    #[test]
    fn reused_slot_rejects_stale_stream_id() {
        let mut storage = Storage::<2>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let (old, _) = establish(&mut stack, &mut ingress, &mut egress);
        stack.reset(old).unwrap();
        let (new, _) = establish(&mut stack, &mut ingress, &mut egress);
        assert_eq!(old.index(), new.index());
        assert_ne!(old, new);
        assert!(stack.is_active(new));
        assert!(!stack.is_active(old));
        assert_eq!(stack.remote_ipv4(old), None);
        assert_eq!(stack.read(old, &mut ingress), Err(Error::InvalidStream));
        assert_eq!(stack.write(old, b"stale"), Err(Error::InvalidStream));
        assert_eq!(stack.close(old), Err(Error::InvalidStream));
        assert_eq!(stack.reset(old), Err(Error::InvalidStream));
        assert!(stack.is_active(new));
    }

    #[test]
    fn handshake_fragmented_input_and_backpressure_use_caller_packets() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];

        let syn_len = segment(&mut ingress, TcpControl::Syn, TcpSeqNumber(100), None, &[]);
        let syn_ack = stack
            .ingest_ipv4(&ingress[..syn_len], &mut egress, 1)
            .unwrap();
        assert!(syn_ack.transmitted > 0);
        let syn_ack_tcp = tcp(&egress[..syn_ack.transmitted]);
        assert!(syn_ack_tcp.syn());
        assert!(syn_ack_tcp.ack());
        assert_eq!(syn_ack_tcp.ack_number(), TcpSeqNumber(101));
        let server_next = syn_ack_tcp.seq_number() + 1;

        let ack_len = segment(
            &mut ingress,
            TcpControl::None,
            TcpSeqNumber(101),
            Some(server_next),
            &[],
        );
        stack
            .ingest_ipv4(&ingress[..ack_len], &mut egress, 2)
            .unwrap();
        let stream = stack
            .accept()
            .expect("the completed handshake is claimable");
        assert_eq!(stack.remote_ipv4(stream), Some(CLIENT.octets()));

        let first_len = segment(
            &mut ingress,
            TcpControl::Psh,
            TcpSeqNumber(101),
            Some(server_next),
            b"hel",
        );
        stack
            .ingest_ipv4(&ingress[..first_len], &mut egress, 3)
            .unwrap();
        let second_len = segment(
            &mut ingress,
            TcpControl::Psh,
            TcpSeqNumber(104),
            Some(server_next),
            b"lo",
        );
        stack
            .ingest_ipv4(&ingress[..second_len], &mut egress, 4)
            .unwrap();
        let mut received = [0u8; 8];
        assert_eq!(stack.read(stream, &mut received).unwrap(), 5);
        assert_eq!(&received[..5], b"hello");
        assert_eq!(stack.read(stream, &mut received), Err(Error::WouldBlock));

        assert_eq!(stack.write(stream, b"world").unwrap(), 5);
        let sent = stack.poll_transmit(&mut egress, 5).unwrap();
        assert!(sent.transmitted > 0);
        assert_eq!(tcp(&egress[..sent.transmitted]).payload(), b"world");
        assert!(sent.deadline_ms.is_some());

        stack.reset(stream).unwrap();
        assert!(!stack.is_active(stream));
    }

    #[test]
    fn advertised_mss_fits_the_wireguard_inner_mtu() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let syn_len = segment_with_options(
            &mut ingress,
            TcpControl::Syn,
            TcpSeqNumber(100),
            None,
            8192,
            None,
            &[],
        );
        let syn_ack = stack
            .ingest_ipv4(&ingress[..syn_len], &mut egress, 1)
            .unwrap();
        let ip = Ipv4Packet::new_checked(&egress[..syn_ack.transmitted]).unwrap();
        let packet = TcpPacket::new_checked(ip.payload()).unwrap();
        let repr = TcpRepr::parse(
            &packet,
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
            &ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr.max_seg_size, Some((MTU - 40) as u16));
    }

    #[test]
    fn unacknowledged_output_retransmits_at_the_reported_deadline() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let (stream, _server_next) = establish(&mut stack, &mut ingress, &mut egress);

        assert_eq!(stack.write(stream, b"retry").unwrap(), 5);
        let first = stack.poll_transmit(&mut egress, 3).unwrap();
        let first_tcp = tcp(&egress[..first.transmitted]);
        assert_eq!(first_tcp.payload(), b"retry");
        let first_seq = first_tcp.seq_number();
        let deadline = first.deadline_ms.expect("TCP retransmit timer is armed");
        assert!(deadline > 3);

        let early = stack.poll_transmit(&mut egress, deadline - 1).unwrap();
        assert_eq!(early.transmitted, 0);
        let retry = stack.poll_transmit(&mut egress, deadline).unwrap();
        let retry_tcp = tcp(&egress[..retry.transmitted]);
        assert_eq!(retry_tcp.seq_number(), first_seq);
        assert_eq!(retry_tcp.payload(), b"retry");
    }

    #[test]
    fn zero_window_applies_bounded_backpressure_until_window_update() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let (stream, server_next) = establish(&mut stack, &mut ingress, &mut egress);

        let zero_window = segment_with_window(
            &mut ingress,
            TcpControl::None,
            TcpSeqNumber(101),
            Some(server_next),
            0,
            &[],
        );
        stack
            .ingest_ipv4(&ingress[..zero_window], &mut egress, 3)
            .unwrap();
        let full = [0x5a; STREAM_BUFFER];
        assert_eq!(stack.write(stream, &full).unwrap(), STREAM_BUFFER);
        assert_eq!(stack.write(stream, b"blocked"), Err(Error::WouldBlock));
        assert_eq!(stack.poll_transmit(&mut egress, 4).unwrap().transmitted, 0);

        let opened = segment_with_window(
            &mut ingress,
            TcpControl::None,
            TcpSeqNumber(101),
            Some(server_next),
            1200,
            &[],
        );
        let sent = stack
            .ingest_ipv4(&ingress[..opened], &mut egress, 5)
            .unwrap();
        assert!(sent.transmitted > 0);
        assert!(!tcp(&egress[..sent.transmitted]).payload().is_empty());
    }

    #[test]
    fn orderly_close_and_peer_reset_release_streams() {
        let mut storage = Storage::<SSH_SOCKET_COUNT>::new();
        let mut stack = Stack::new(&mut storage, SERVER.octets(), 7, 0).unwrap();
        stack.listen(22).unwrap();
        let mut ingress = [0u8; MTU];
        let mut egress = [0u8; MTU];
        let (stream, _server_next) = establish(&mut stack, &mut ingress, &mut egress);

        stack.close(stream).unwrap();
        let closing = stack.poll_transmit(&mut egress, 3).unwrap();
        let fin = tcp(&egress[..closing.transmitted]);
        assert!(fin.fin());

        stack.reset(stream).unwrap();
        assert!(!stack.is_active(stream));
        assert_eq!(stack.read(stream, &mut [0; 1]), Err(Error::InvalidStream));

        let (replacement, server_next) = establish(&mut stack, &mut ingress, &mut egress);
        let rst_len = segment(
            &mut ingress,
            TcpControl::Rst,
            TcpSeqNumber(101),
            Some(server_next),
            &[],
        );
        stack
            .ingest_ipv4(&ingress[..rst_len], &mut egress, 4)
            .unwrap();
        assert!(!stack.is_active(replacement));
        assert_eq!(
            stack.read(replacement, &mut [0; 1]),
            Err(Error::InvalidStream)
        );
    }
}
