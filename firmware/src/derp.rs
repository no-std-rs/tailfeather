//! Two bounded Embassy DERP workers. They own sockets and framing; the tunnel
//! actor remains the sole owner of `Node` and exchanges only explicit commands
//! and decoded events with them.

#![allow(
    clippy::too_many_arguments,
    reason = "the fixed-capacity DERP worker receives its disjoint static arenas explicitly"
)]

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpEndpoint, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use embedded_tls::TlsConnection;
use heapless::String;
use log::{info, warn};
use static_cell::StaticCell;

use tailfeather::Endpoint;
use tailfeather::control::tls::{RsaWorkspace, Suite, TLS_READ_BUFFER};
use tailfeather::derp::{Client, Frame, FrameType, frame};
use tailfeather::keys::{NodePrivate, NodePublic};

use crate::tunnel::HwRng;

pub const SLOTS: usize = 2;
const FRAME_BUFFER: usize = frame::HEADER_LEN + frame::MAX_FRAME;
// DERP reads stream into a separate authentication/frame arena, so 256 bytes
// remains sufficient on the receive side. Keep the proven small TLS records,
// but let the TCP transmit queue hold every record for one framed WireGuard
// packet so they do not wait for individual Wi-Fi acknowledgements.
const TCP_RX_BUFFER: usize = 256;
const TLS_TX_BUFFER: usize = 256;
const TCP_TX_BUFFER: usize = FRAME_BUFFER + 128;
const CONNECT_LIVENESS: Duration = Duration::from_secs(90);
const ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

static TCP_RX: StaticCell<[[u8; TCP_RX_BUFFER]; SLOTS]> = StaticCell::new();
static TCP_TX: StaticCell<[[u8; TCP_TX_BUFFER]; SLOTS]> = StaticCell::new();
static TLS_READ: StaticCell<[[u8; TLS_READ_BUFFER]; SLOTS]> = StaticCell::new();
static TLS_WRITE: StaticCell<[[u8; TLS_TX_BUFFER]; SLOTS]> = StaticCell::new();
static FRAMES: StaticCell<[[u8; FRAME_BUFFER]; SLOTS]> = StaticCell::new();
// RSA verification scratch is needed only while opening TLS. Serializing the
// two handshakes retains both live DERP sessions without permanently reserving
// duplicate 1.5 KiB arithmetic arenas.
static RSA_WORKSPACE: Mutex<CriticalSectionRawMutex, RsaWorkspace> =
    Mutex::new(RsaWorkspace::new());

static COMMANDS: [Channel<CriticalSectionRawMutex, Command, 1>; SLOTS] =
    [const { Channel::new() }; SLOTS];
static DISCONNECTS: [Signal<CriticalSectionRawMutex, u16>; SLOTS] =
    [const { Signal::new() }; SLOTS];
static PREFERENCES: [Signal<CriticalSectionRawMutex, (u16, bool)>; SLOTS] =
    [const { Signal::new() }; SLOTS];
static NOTICES: Channel<CriticalSectionRawMutex, Notice, 1> = Channel::new();
static INBOUND_ACKS: [Channel<CriticalSectionRawMutex, (), 1>; SLOTS] =
    [const { Channel::new() }; SLOTS];

struct PacketBuffer {
    bytes: [u8; tailfeather::node::MAX_ACTION_PACKET],
    len: usize,
}

impl PacketBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; tailfeather::node::MAX_ACTION_PACKET],
            len: 0,
        }
    }

    fn replace(&mut self, packet: &[u8]) -> bool {
        if packet.len() > self.bytes.len() {
            return false;
        }
        self.bytes.fill(0);
        self.bytes[..packet.len()].copy_from_slice(packet);
        self.len = packet.len();
        true
    }

    fn clear(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }
}

static INBOUND: [Mutex<CriticalSectionRawMutex, PacketBuffer>; SLOTS] =
    [const { Mutex::new(PacketBuffer::new()) }; SLOTS];
static OUTBOUND: [Mutex<CriticalSectionRawMutex, PacketBuffer>; SLOTS] =
    [const { Mutex::new(PacketBuffer::new()) }; SLOTS];
static OUTBOUND_BUSY: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
static OUTBOUND_ENQUEUED: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
static OUTBOUND_SENT: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
static OUTBOUND_DROPPED: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];

#[allow(
    clippy::large_enum_variant,
    reason = "the bounded connect metadata avoids heap indirection"
)]
pub enum Command {
    Connect {
        region: u16,
        endpoint: Endpoint,
        identity: NodePrivate,
        preferred: bool,
    },
    Send {
        region: u16,
        peer: NodePublic,
    },
}

pub enum Notice {
    Connected {
        slot: usize,
        region: u16,
    },
    Disconnected {
        slot: usize,
        region: u16,
    },
    Packet {
        slot: usize,
        region: u16,
        peer: NodePublic,
    },
    /// The relay no longer holds a connection for this peer, so relaying to it
    /// through this region is dead until it comes back.
    PeerGone {
        region: u16,
        peer: NodePublic,
    },
}

/// What one inbound frame turned out to be. Every frame gets a disposition;
/// "fall through and ignore" is how `Ping` and `PeerGone` became silent gaps.
enum Inbound {
    Packet {
        peer: NodePublic,
        len: usize,
    },
    PeerGone {
        peer: NodePublic,
    },
    /// Answered or deliberately ignored; nothing for the actor to do.
    Handled,
    /// The server is going away and will take a reconnect.
    Restarting,
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Dns,
    Connect,
    Tls,
    Io,
    Protocol,
}

type Secure<'a> = TlsConnection<'a, TcpSocket<'a>, Suite>;

enum Stream<'a> {
    Secure(Secure<'a>),
    #[cfg(feature = "test-insecure-control")]
    Plain(TcpSocket<'a>),
}

impl Stream<'_> {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, Failure> {
        match self {
            Self::Secure(stream) => stream.read(out).await.map_err(|_| Failure::Io),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(stream) => stream.read(out).await.map_err(|_| Failure::Io),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        match self {
            Self::Secure(stream) => stream.write_all(bytes).await.map_err(|_| Failure::Io),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(stream) => stream.write_all(bytes).await.map_err(|_| Failure::Io),
        }
    }

    async fn flush(&mut self) -> Result<(), Failure> {
        match self {
            Self::Secure(stream) => stream.flush().await.map_err(|_| Failure::Io),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(stream) => stream.flush().await.map_err(|_| Failure::Io),
        }
    }
}

struct Connection<'a> {
    region: u16,
    stream: Stream<'a>,
    client: Option<Client>,
    frame_buffer: &'a mut [u8; FRAME_BUFFER],
    filled: usize,
    /// Payload bytes still to discard from an oversized frame.
    ///
    /// `next_packet` is cancellable in the worker's receive race, so this
    /// belongs to the connection rather than its discard future. Resuming the
    /// read then continues at the payload boundary instead of parsing it as a
    /// new frame header.
    discard_remaining: Option<usize>,
    /// A Pong owed to a Ping already consumed from the stream.
    ///
    /// The inbound read races an outbound command in the worker's `select`, so
    /// a write started inside it can be cancelled half-sent -- which desynchro-
    /// nises the framing -- or dropped entirely, which the server reads as a
    /// dead client. The answer is parked here and written outside the race.
    pending_pong: Option<([u8; frame::HEADER_LEN + frame::PING_LEN], usize)>,
}

impl Connection<'_> {
    async fn fill_frame(&mut self) -> Result<Frame, Failure> {
        loop {
            if self.discard_remaining.is_some() {
                self.discard().await?;
                continue;
            }
            while self.filled < frame::HEADER_LEN {
                let read = self
                    .stream
                    .read(&mut self.frame_buffer[self.filled..])
                    .await?;
                if read == 0 {
                    return Err(Failure::Io);
                }
                self.filled += read;
            }
            let parsed =
                Frame::parse(&self.frame_buffer[..self.filled]).map_err(|_| Failure::Protocol)?;
            if !parsed.fits() {
                // Well-formed but larger than this buffer — a long health message,
                // say. Skip past it and read the next frame. Treating this as a
                // protocol error used to drop the session and mark the region
                // failed, which cost a reconnect for something harmless.
                self.frame_buffer
                    .copy_within(frame::HEADER_LEN..self.filled, 0);
                self.filled -= frame::HEADER_LEN;
                self.discard_remaining = Some(parsed.length);
                self.discard().await?;
                warn!(
                    "control stage=derp-frame state=skipped kind={} len={}",
                    parsed.kind.to_byte(),
                    parsed.length
                );
                continue;
            }
            let total = frame::HEADER_LEN + parsed.length;
            while self.filled < total {
                let read = self
                    .stream
                    .read(&mut self.frame_buffer[self.filled..])
                    .await?;
                if read == 0 {
                    return Err(Failure::Io);
                }
                self.filled += read;
            }
            return Ok(parsed);
        }
    }

    /// Read and throw away the payload already staged for discard, leaving the
    /// stream aligned on the next frame.
    async fn discard(&mut self) -> Result<(), Failure> {
        loop {
            let remaining = self
                .discard_remaining
                .expect("discard is called only with an oversized frame pending");
            let dropped = self.filled.min(remaining);
            self.frame_buffer.copy_within(dropped..self.filled, 0);
            self.filled -= dropped;
            let remaining = remaining - dropped;
            if remaining == 0 {
                self.discard_remaining = None;
                return Ok(());
            }
            // Save progress before the cancellable read below. The bytes in
            // `frame_buffer` are already shifted, so this makes the next
            // `fill_frame` resume exactly where this attempt stopped.
            self.discard_remaining = Some(remaining);
            // Nothing buffered is left to drop, so the next read starts clean.
            let read = self.stream.read(self.frame_buffer.as_mut_slice()).await?;
            if read == 0 {
                return Err(Failure::Io);
            }
            self.filled = read;
        }
    }

    fn payload(&self, frame: Frame) -> &[u8] {
        &self.frame_buffer[frame::HEADER_LEN..frame::HEADER_LEN + frame.length]
    }

    fn consume(&mut self, frame: Frame) {
        let total = frame::HEADER_LEN + frame.length;
        self.frame_buffer.copy_within(total..self.filled, 0);
        self.filled -= total;
    }

    async fn next_packet(&mut self, out: &mut [u8]) -> Result<Inbound, Failure> {
        let frame = self.fill_frame().await?;
        match frame.kind {
            FrameType::RecvPacket => {
                let (peer, packet) = Client::read_packet(frame, self.payload(frame))
                    .map_err(|_| Failure::Protocol)?;
                let destination = out.get_mut(..packet.len()).ok_or(Failure::Protocol)?;
                destination.copy_from_slice(packet);
                let len = packet.len();
                self.consume(frame);
                Ok(Inbound::Packet { peer, len })
            }
            FrameType::Ping => {
                // A server that gets no pong concludes the client is dead and
                // drops it, which reads on this side as an unexplained
                // disconnect every couple of minutes.
                let mut pong = [0; frame::HEADER_LEN + frame::PING_LEN];
                let len = Client::write_pong(frame, self.payload(frame), &mut pong)
                    .map_err(|_| Failure::Protocol)?;
                self.consume(frame);
                self.pending_pong = Some((pong, len));
                Ok(Inbound::Handled)
            }
            FrameType::PeerGone => {
                let peer = Client::read_peer_gone(frame, self.payload(frame))
                    .map_err(|_| Failure::Protocol)?;
                self.consume(frame);
                Ok(Inbound::PeerGone { peer })
            }
            FrameType::Restarting => {
                // Scheduled, not a fault: end the session so the usual
                // reconnect runs instead of waiting for the socket to die.
                self.consume(frame);
                Ok(Inbound::Restarting)
            }
            _ => {
                self.consume(frame);
                Ok(Inbound::Handled)
            }
        }
    }

    /// Write the Pong owed for an already-consumed Ping, if any.
    ///
    /// Called from outside the worker's cancellable read so the frame is
    /// written whole.
    async fn flush_pending_pong(&mut self) -> Result<(), Failure> {
        let Some((pong, len)) = self.pending_pong.take() else {
            return Ok(());
        };
        self.stream.write_all(&pong[..len]).await?;
        self.stream.flush().await
    }

    async fn send(&mut self, peer: &NodePublic, packet: &[u8]) -> Result<(), Failure> {
        let mut out = [0; FRAME_BUFFER];
        let len = self
            .client
            .as_ref()
            .ok_or(Failure::Protocol)?
            .send_packet(peer, packet, &mut out)
            .map_err(|_| Failure::Protocol)?;
        self.stream.write_all(&out[..len]).await?;
        // embedded-tls may retain a short application write in its record
        // buffer. DERP packets are latency-sensitive and frequently have no
        // following write to force that record out, so every complete frame is
        // an explicit flush boundary.
        self.stream.flush().await
    }

    async fn set_preferred(&mut self, preferred: bool) -> Result<(), Failure> {
        let mut out = [0; 16];
        let len =
            Client::write_note_preferred(preferred, &mut out).map_err(|_| Failure::Protocol)?;
        self.stream.write_all(&out[..len]).await
    }
}

pub fn start(spawner: Spawner, stack: Stack<'static>) {
    let mut tcp_rx = TCP_RX.init([[0; TCP_RX_BUFFER]; SLOTS]).iter_mut();
    let mut tcp_tx = TCP_TX.init([[0; TCP_TX_BUFFER]; SLOTS]).iter_mut();
    let mut tls_read = TLS_READ.init([[0; TLS_READ_BUFFER]; SLOTS]).iter_mut();
    let mut tls_write = TLS_WRITE.init([[0; TLS_TX_BUFFER]; SLOTS]).iter_mut();
    let mut frames = FRAMES.init([[0; FRAME_BUFFER]; SLOTS]).iter_mut();
    for slot in 0..SLOTS {
        spawner.spawn(
            worker(
                slot,
                stack,
                tcp_rx.next().unwrap(),
                tcp_tx.next().unwrap(),
                tls_read.next().unwrap(),
                tls_write.next().unwrap(),
                frames.next().unwrap(),
            )
            .expect("exactly two DERP workers"),
        );
    }
}

pub fn try_command(slot: usize, command: Command) -> bool {
    COMMANDS[slot].try_send(command).is_ok()
}

pub fn request_disconnect(slot: usize, region: u16) {
    DISCONNECTS[slot].signal(region);
}

pub fn set_preferred(slot: usize, region: u16, preferred: bool) {
    PREFERENCES[slot].signal((region, preferred));
}

/// Copy an outbound packet into its slot before queuing only small metadata.
/// Keeping ownership out of the channel prevents the same MTU-sized value from
/// being retained in the channel, tunnel future, and DERP worker future.
pub fn try_send_packet(slot: usize, region: u16, peer: NodePublic, packet: &[u8]) -> bool {
    if OUTBOUND_BUSY[slot].swap(true, Ordering::AcqRel) {
        note_dropped(slot, region);
        return false;
    }
    let stored = OUTBOUND[slot]
        .try_lock()
        .is_ok_and(|mut buffer| buffer.replace(packet));
    if !stored || !try_command(slot, Command::Send { region, peer }) {
        if let Ok(mut buffer) = OUTBOUND[slot].try_lock() {
            buffer.clear();
        }
        OUTBOUND_BUSY[slot].store(false, Ordering::Release);
        note_dropped(slot, region);
        return false;
    }
    let count = OUTBOUND_ENQUEUED[slot].fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        info!(
            "metric=derp-send-enqueued slot={slot} region={region} count={count} kind={} len={}",
            packet.first().copied().unwrap_or(0),
            packet.len()
        );
    }
    true
}

// There is deliberately no awaiting `send_packet` here. The tunnel actor is
// the only task that drains `NOTICES`, and a worker parks on `INBOUND_ACKS`
// after every delivered packet — so an actor waiting for a worker's outbound
// slot can be waiting on the very worker that is waiting on it. Callers use
// `try_send_packet` and drop on refusal; WireGuard retransmits.

/// Count a packet the worker's one outbound slot could not take.
///
/// Dropping is bounded and expected under burst; what is not acceptable is
/// dropping *silently*, so the running total is visible in the log the same way
/// the enqueued and completed counts are.
fn note_dropped(slot: usize, region: u16) {
    let count = OUTBOUND_DROPPED[slot].fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        info!("metric=derp-send-dropped slot={slot} region={region} count={count}");
    }
}

fn release_outbound(slot: usize) {
    if let Ok(mut buffer) = OUTBOUND[slot].try_lock() {
        buffer.clear();
    }
    OUTBOUND_BUSY[slot].store(false, Ordering::Release);
}

pub fn with_packet<R>(slot: usize, use_packet: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let mut buffer = INBOUND.get(slot)?.try_lock().ok()?;
    let result = use_packet(&buffer.bytes[..buffer.len]);
    buffer.clear();
    drop(buffer);
    INBOUND_ACKS[slot].try_send(()).ok()?;
    Some(result)
}

pub async fn next_notice() -> Notice {
    NOTICES.receive().await
}

#[embassy_executor::task(pool_size = 2)]
async fn worker(
    slot: usize,
    stack: Stack<'static>,
    tcp_rx: &'static mut [u8; TCP_RX_BUFFER],
    tcp_tx: &'static mut [u8; TCP_TX_BUFFER],
    tls_read: &'static mut [u8; TLS_READ_BUFFER],
    tls_write: &'static mut [u8; TLS_TX_BUFFER],
    frame_buffer: &'static mut [u8; FRAME_BUFFER],
) {
    let mut pending = None;
    loop {
        let command = match pending.take() {
            Some(command) => command,
            None => COMMANDS[slot].receive().await,
        };
        let (region, endpoint, identity, preferred) = match command {
            Command::Connect {
                region,
                endpoint,
                identity,
                preferred,
            } => (region, endpoint, identity, preferred),
            Command::Send { .. } => {
                release_outbound(slot);
                continue;
            }
        };
        let mut rng = HwRng(esp_hal::rng::Rng::new());
        info!("control stage=derp-tls state=connecting slot={slot} region={region}");
        let mut connection = match select(
            select(
                connect(
                    stack,
                    region,
                    &endpoint,
                    &identity,
                    preferred,
                    &mut rng,
                    tcp_rx,
                    tcp_tx,
                    tls_read,
                    tls_write,
                    frame_buffer,
                ),
                Timer::after(CONNECT_LIVENESS),
            ),
            DISCONNECTS[slot].wait(),
        )
        .await
        {
            Either::First(Either::First(Ok(connection))) => connection,
            Either::First(Either::First(Err(_)))
            | Either::First(Either::Second(()))
            | Either::Second(_) => {
                warn!("control stage=derp-tls state=failed slot={slot} region={region}");
                Timer::after(Duration::from_secs(1)).await;
                NOTICES.send(Notice::Disconnected { slot, region }).await;
                continue;
            }
        };
        info!("control stage=derp-tls state=connected slot={slot} region={region}");
        NOTICES.send(Notice::Connected { slot, region }).await;

        loop {
            if DISCONNECTS[slot]
                .try_take()
                .is_some_and(|target| target == region)
            {
                NOTICES.send(Notice::Disconnected { slot, region }).await;
                break;
            }
            // A Ping consumed by the previous iteration owes a Pong. Writing it
            // here, before the read re-enters the cancellable select, keeps the
            // frame whole and the server's keepalive satisfied.
            if !matches!(
                select(connection.flush_pending_pong(), Timer::after(WRITE_TIMEOUT),).await,
                Either::First(Ok(()))
            ) {
                Timer::after(Duration::from_secs(1)).await;
                NOTICES.send(Notice::Disconnected { slot, region }).await;
                break;
            }
            let mut inbound = INBOUND[slot].lock().await;
            // A retransmit burst can keep the relay socket continuously
            // readable. Poll outbound commands first so the response to the
            // packet just acknowledged cannot be starved by the next inbound
            // frame while the tunnel actor applies bounded backpressure.
            match select(
                select(
                    COMMANDS[slot].receive(),
                    select(DISCONNECTS[slot].wait(), PREFERENCES[slot].wait()),
                ),
                select(
                    connection.next_packet(&mut inbound.bytes),
                    Timer::after(RECEIVE_LIVENESS),
                ),
            )
            .await
            {
                Either::Second(Either::First(Ok(Inbound::Packet { peer, len }))) => {
                    inbound.len = len;
                    drop(inbound);
                    NOTICES.send(Notice::Packet { slot, region, peer }).await;
                    INBOUND_ACKS[slot].receive().await;
                }
                Either::Second(Either::First(Ok(Inbound::PeerGone { peer }))) => {
                    drop(inbound);
                    NOTICES.send(Notice::PeerGone { region, peer }).await;
                }
                Either::Second(Either::First(Ok(Inbound::Handled))) => {}
                Either::Second(Either::First(Ok(Inbound::Restarting))) => {
                    drop(inbound);
                    info!("control stage=derp state=server-restarting slot={slot} region={region}");
                    NOTICES.send(Notice::Disconnected { slot, region }).await;
                    break;
                }
                Either::Second(Either::First(Err(_))) | Either::Second(Either::Second(())) => {
                    Timer::after(Duration::from_secs(1)).await;
                    NOTICES.send(Notice::Disconnected { slot, region }).await;
                    break;
                }
                Either::First(Either::First(Command::Send {
                    region: target,
                    peer,
                })) if target == connection.region => {
                    drop(inbound);
                    let outbound = OUTBOUND[slot].lock().await;
                    let result = select(
                        connection.send(&peer, &outbound.bytes[..outbound.len]),
                        Timer::after(WRITE_TIMEOUT),
                    )
                    .await;
                    drop(outbound);
                    release_outbound(slot);
                    if matches!(result, Either::First(Ok(()))) {
                        let count = OUTBOUND_SENT[slot].fetch_add(1, Ordering::Relaxed) + 1;
                        if count.is_power_of_two() {
                            info!(
                                "metric=derp-send-complete slot={slot} region={region} count={count}"
                            );
                        }
                    } else {
                        Timer::after(Duration::from_secs(1)).await;
                        NOTICES.send(Notice::Disconnected { slot, region }).await;
                        break;
                    }
                }
                Either::First(Either::Second(Either::First(target))) if target == region => {
                    drop(inbound);
                    NOTICES.send(Notice::Disconnected { slot, region }).await;
                    break;
                }
                Either::First(Either::Second(Either::Second((target, preferred))))
                    if target == region =>
                {
                    drop(inbound);
                    if !matches!(
                        select(
                            connection.set_preferred(preferred),
                            Timer::after(WRITE_TIMEOUT),
                        )
                        .await,
                        Either::First(Ok(()))
                    ) {
                        NOTICES.send(Notice::Disconnected { slot, region }).await;
                        break;
                    }
                }
                Either::First(Either::First(command @ Command::Connect { .. })) => {
                    drop(inbound);
                    pending = Some(command);
                    NOTICES.send(Notice::Disconnected { slot, region }).await;
                    break;
                }
                Either::First(Either::First(Command::Send { .. })) => {
                    drop(inbound);
                    release_outbound(slot);
                }
                Either::First(_) => {}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect<'a>(
    stack: Stack<'static>,
    region: u16,
    endpoint: &Endpoint,
    identity: &NodePrivate,
    preferred: bool,
    rng: &mut HwRng,
    tcp_rx: &'a mut [u8],
    tcp_tx: &'a mut [u8],
    tls_read: &'a mut [u8],
    tls_write: &'a mut [u8],
    frame_buffer: &'a mut [u8; FRAME_BUFFER],
) -> Result<Connection<'a>, Failure> {
    let addresses = stack
        .dns_query(endpoint.host.as_str(), DnsQueryType::A)
        .await
        .map_err(|_| Failure::Dns)?;
    let mut socket = TcpSocket::new(stack, tcp_rx, tcp_tx);
    let mut connected = false;
    for address in addresses {
        let embassy_net::IpAddress::Ipv4(address) = address;
        match select(
            socket.connect(IpEndpoint::new(address.into(), endpoint.port)),
            Timer::after(ADDRESS_CONNECT_TIMEOUT),
        )
        .await
        {
            Either::First(Ok(())) => {
                connected = true;
                break;
            }
            Either::First(Err(_)) | Either::Second(()) => socket.abort(),
        }
    }
    if !connected {
        return Err(Failure::Connect);
    }

    #[cfg(feature = "test-insecure-control")]
    let plaintext = endpoint.port != 443;
    #[cfg(not(feature = "test-insecure-control"))]
    let plaintext = false;
    let mut stream = if plaintext {
        #[cfg(feature = "test-insecure-control")]
        {
            Stream::Plain(socket)
        }
        #[cfg(not(feature = "test-insecure-control"))]
        unreachable!()
    } else {
        let url = secure_url(endpoint)?;
        let authority = tailfeather::control::authority::Authority::parse(&url, false)
            .map_err(|_| Failure::Protocol)?;
        // The map's insecure marker is effective only in lab firmware. A
        // production image always verifies the DERP certificate.
        #[cfg(feature = "test-insecure-control")]
        let insecure = endpoint.insecure_for_tests;
        #[cfg(not(feature = "test-insecure-control"))]
        let insecure = false;
        let stream = if insecure {
            #[cfg(feature = "test-insecure-control")]
            {
                crate::control::insecure_derp_tls(socket, &authority, tls_read, tls_write)
                    .await
                    .map_err(|_| Failure::Tls)?
            }
            #[cfg(not(feature = "test-insecure-control"))]
            unreachable!()
        } else {
            let mut rsa = RSA_WORKSPACE.lock().await;
            let stream = crate::control::verified_tls(
                socket,
                &authority,
                tls_read,
                tls_write,
                &mut rsa,
                crate::control::ControlStage::DerpTls,
            )
            .await
            .map_err(|_| Failure::Tls)?;
            drop(rsa);
            stream
        };
        Stream::Secure(stream)
    };
    info!("control stage=derp-tls state=connected region={region}");

    let authority = authority(endpoint)?;
    let mut request = [0; 256];
    let request = tailfeather::derp::client::write_upgrade_request(&authority, &mut request)
        .map_err(|_| Failure::Protocol)?;
    stream.write_all(request).await?;
    stream.flush().await?;
    info!("control stage=derp-upgrade state=requested region={region}");

    let mut filled = 0;
    let header_len = loop {
        match tailfeather::derp::client::parse_upgrade(&frame_buffer[..filled]) {
            Ok(end) => break end,
            Err(tailfeather::derp::Error::Incomplete) => {}
            Err(_) => return Err(Failure::Protocol),
        }
        let read = stream.read(&mut frame_buffer[filled..]).await?;
        if read == 0 {
            return Err(Failure::Io);
        }
        filled += read;
    };
    frame_buffer.copy_within(header_len..filled, 0);
    filled -= header_len;
    info!("control stage=derp-upgrade state=accepted region={region}");

    let mut connection = Connection {
        region,
        stream,
        client: None,
        frame_buffer,
        filled,
        discard_remaining: None,
        pending_pong: None,
    };
    let server_frame = connection.fill_frame().await?;
    let server = Client::read_server_key(server_frame, connection.payload(server_frame))
        .map_err(|_| Failure::Protocol)?;
    connection.consume(server_frame);
    info!("control stage=derp-handshake state=server-key region={region}");
    let mut out = [0; 256];
    let len = Client::write_client_info(identity, &identity.public(), &server, rng, &mut out)
        .map_err(|_| Failure::Protocol)?;
    connection.stream.write_all(&out[..len]).await?;
    connection.stream.flush().await?;
    info!("control stage=derp-handshake state=client-info region={region}");
    let info_frame = connection.fill_frame().await?;
    let mut info = [0; 512];
    connection.client = Some(
        Client::read_server_info(
            identity,
            &server,
            info_frame,
            connection.payload(info_frame),
            &mut info,
        )
        .map_err(|_| Failure::Protocol)?,
    );
    connection.consume(info_frame);
    info!("control stage=derp-handshake state=server-info region={region}");
    let len = Client::write_note_preferred(preferred, &mut out).map_err(|_| Failure::Protocol)?;
    connection.stream.write_all(&out[..len]).await?;
    connection.stream.flush().await?;
    Ok(connection)
}

fn authority(endpoint: &Endpoint) -> Result<String<160>, Failure> {
    let mut result = String::new();
    result
        .push_str(endpoint.host.as_str())
        .map_err(|_| Failure::Protocol)?;
    if endpoint.port != 443 {
        write!(result, ":{}", endpoint.port).map_err(|_| Failure::Protocol)?;
    }
    Ok(result)
}

fn secure_url(endpoint: &Endpoint) -> Result<String<160>, Failure> {
    let mut result = String::new();
    result.push_str("https://").map_err(|_| Failure::Protocol)?;
    let tls_name = endpoint
        .tls_name
        .as_ref()
        .map_or(endpoint.host.as_str(), |name| name.as_str());
    result.push_str(tls_name).map_err(|_| Failure::Protocol)?;
    if endpoint.port != 443 {
        write!(result, ":{}", endpoint.port).map_err(|_| Failure::Protocol)?;
    }
    Ok(result)
}
const RECEIVE_LIVENESS: Duration = Duration::from_secs(90);
