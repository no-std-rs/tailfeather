//! Embassy adapters for the allocation-free control transport.

use core::cell::Cell;
use core::fmt::Write as _;

use embassy_futures::select::{Either, select};
use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpEndpoint, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use embedded_tls::{TlsClock, TlsConfig, TlsConnection, TlsContext};
use heapless::String;
use log::{info, warn};
use static_cell::StaticCell;

use tailfeather::control::authority::Authority;
use tailfeather::control::tls::{
    RsaWorkspace, Suite, TLS_READ_BUFFER, TLS_WRITE_BUFFER, VerifyingProvider,
};
use tailfeather::control::transport::{H2_BUFFER, Http2, MapEvent, MapStream};
use tailfeather::control::{Hostinfo, MapRequest, RegisterRequest, RegisterResponse};
use tailfeather::netmap::Netmap;
use tailfeather::state::TwoSlot;
use tailfeather::{ControlCommand, ControlEvent, Node, NodeAction, NodeStatus};

use crate::flash::FlashSlots;
use crate::tunnel::{HwRng, LISTEN_PORT, PEERS};

// TCP only has to stage fragments; the TLS layer owns the complete-record
// buffer. Keeping these at two KiB avoids retaining a second TLS record.
const TCP_RX_BUFFER: usize = 512;
const TCP_TX_BUFFER: usize = 512;
const BOOTSTRAP_LIVENESS: Duration = Duration::from_secs(90);
const MAP_LIVENESS: Duration = Duration::from_secs(90);
/// The generated registration and map JSON bodies fit within 864 bytes. Keep only
/// that bounded wire image for reconnects instead of retaining two full 4 KiB
/// construction buffers in the control task future.
const RECOVERY_BODY: usize = 864;

static TCP_RX: StaticCell<[u8; TCP_RX_BUFFER]> = StaticCell::new();
static TCP_TX: StaticCell<[u8; TCP_TX_BUFFER]> = StaticCell::new();
static TLS_READ: StaticCell<[u8; TLS_READ_BUFFER]> = StaticCell::new();
static TLS_WRITE: StaticCell<[u8; TLS_WRITE_BUFFER]> = StaticCell::new();
static H2_READ: StaticCell<[u8; H2_BUFFER]> = StaticCell::new();
// Keep one HPACK/stream state slot across reconnects so async futures borrow
// it instead of reserving multiple copies in the control task's static frame.
static H2_CONNECTION: StaticCell<micro_h2::Connection> = StaticCell::new();
static RSA_WORKSPACE: StaticCell<RsaWorkspace> = StaticCell::new();
static RECOVERY: StaticCell<RecoveryConfig> = StaticCell::new();
static MAP_STREAM: StaticCell<MapStream<PEERS>> = StaticCell::new();
// Keep the staged map in RTC-fast SRAM so main SRAM remains available for the
// P-256 work done by the control TLS handshake.
#[esp_hal::ram(unstable(rtc_fast))]
static STAGING: StaticCell<Netmap<PEERS>> = StaticCell::new();
const STUN_PACKETS: usize = 2;
const STUN_BUFFER: usize = 256;
static STUN_RX_META: StaticCell<[PacketMetadata; STUN_PACKETS]> = StaticCell::new();
static STUN_TX_META: StaticCell<[PacketMetadata; STUN_PACKETS]> = StaticCell::new();
static STUN_RX: StaticCell<[u8; STUN_BUFFER]> = StaticCell::new();
static STUN_TX: StaticCell<[u8; STUN_BUFFER]> = StaticCell::new();

static TRUSTED_TIME: critical_section::Mutex<Cell<Option<(u64, u64)>>> =
    critical_section::Mutex::new(Cell::new(None));

fn set_trusted_time(unix_seconds: u64) {
    let monotonic_ms = Instant::now().as_millis();
    critical_section::with(|cs| {
        let time = TRUSTED_TIME.borrow(cs);
        if time.get().is_none() {
            time.set(Some((unix_seconds, monotonic_ms)));
        }
    });
}

type SecureStream<'a> = TlsConnection<'a, TcpSocket<'a>, Suite>;
type SecureHttp2<'a> =
    Http2<SecureStream<'a>, &'a mut [u8; H2_BUFFER], &'a mut micro_h2::Connection>;

#[cfg(feature = "test-insecure-control")]
type PlainHttp2<'a> = Http2<TcpSocket<'a>, &'a mut [u8; H2_BUFFER], &'a mut micro_h2::Connection>;

enum Link<'a> {
    Secure(SecureHttp2<'a>),
    #[cfg(feature = "test-insecure-control")]
    Plain(PlainHttp2<'a>),
}

impl Link<'_> {
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        body: &[u8],
        response: &mut [u8],
    ) -> Result<(u16, usize), Failure> {
        match self {
            Self::Secure(http2) => http2
                .request(method, path, authority, body, response)
                .await
                .map_err(|error| transport_failure(ControlStage::Registration, error)),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(http2) => http2
                .request(method, path, authority, body, response)
                .await
                .map_err(|error| plain_transport_failure(ControlStage::Registration, error)),
        }
    }

    async fn start_map(
        &mut self,
        authority: &str,
        body: &[u8],
        map: &mut MapStream<PEERS>,
    ) -> Result<(), Failure> {
        match self {
            Self::Secure(http2) => MapStream::start_in(map, http2, authority, body)
                .await
                .map_err(|error| transport_failure(ControlStage::MapRequest, error)),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(http2) => MapStream::start_in(map, http2, authority, body)
                .await
                .map_err(|error| plain_transport_failure(ControlStage::MapRequest, error)),
        }
    }

    async fn next_map(
        &mut self,
        map: &mut MapStream<PEERS>,
        staging: &mut Netmap<PEERS>,
    ) -> Result<MapEvent, Failure> {
        match self {
            Self::Secure(http2) => map
                .next(http2, staging)
                .await
                .map_err(|error| transport_failure(ControlStage::MapParsing, error)),
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(http2) => map
                .next(http2, staging)
                .await
                .map_err(|error| plain_transport_failure(ControlStage::MapParsing, error)),
        }
    }

    async fn endpoint_update(
        &mut self,
        map: &mut MapStream<PEERS>,
        staging: &mut Netmap<PEERS>,
        authority: &str,
        body: &[u8],
    ) -> Result<(), Failure> {
        match self {
            Self::Secure(http2) => {
                tailfeather::control::transport::send_endpoint_update(
                    http2, map, staging, authority, body,
                )
                .await
                .map_err(|error| transport_failure(ControlStage::EndpointPublication, error))?;
            }
            #[cfg(feature = "test-insecure-control")]
            Self::Plain(http2) => {
                tailfeather::control::transport::send_endpoint_update(
                    http2, map, staging, authority, body,
                )
                .await
                .map_err(|error| {
                    plain_transport_failure(ControlStage::EndpointPublication, error)
                })?;
            }
        }
        Ok(())
    }
}

pub struct Session<'a> {
    link: Link<'a>,
    staging: Option<&'static mut Netmap<PEERS>>,
}

struct RecoveryConfig {
    identity: tailfeather::keys::Identity,
    registration_body: heapless::Vec<u8, RECOVERY_BODY>,
    map_body: heapless::Vec<u8, RECOVERY_BODY>,
}

impl RecoveryConfig {
    fn new(identity: tailfeather::keys::Identity) -> Self {
        Self {
            identity,
            registration_body: heapless::Vec::new(),
            map_body: heapless::Vec::new(),
        }
    }
}

pub enum Notice {
    Map(&'static mut Netmap<PEERS>),
    NodeKeyExpired,
}

static NOTICES: Channel<CriticalSectionRawMutex, Notice, 1> = Channel::new();
static RETURNED: Channel<CriticalSectionRawMutex, &'static mut Netmap<PEERS>, 1> = Channel::new();
static BOOTSTRAP: Channel<CriticalSectionRawMutex, BootstrapNotice, 1> = Channel::new();
static ROTATION_STATE: Signal<CriticalSectionRawMutex, tailfeather::PersistState> = Signal::new();
static ROTATION_RESULT: Signal<CriticalSectionRawMutex, bool> = Signal::new();

pub enum BootstrapNotice {
    Ready(&'static mut Node<PEERS>),
}

pub async fn next_bootstrap() -> BootstrapNotice {
    BOOTSTRAP.receive().await
}

pub async fn next_notice() -> Notice {
    NOTICES.receive().await
}

pub fn return_lease(lease: &'static mut Netmap<PEERS>) {
    if RETURNED.try_send(lease).is_err() {
        panic!("control task must await its map lease");
    }
}

/// Rotate an expired key in the node-owning task, while the control task
/// persists the resulting state. Resetting then returns both actors to the
/// normal bootstrap protocol with the durable replacement identity.
pub async fn rotate_expired_node_key(node: &mut Node<PEERS>, rng: &mut HwRng) -> ! {
    node.stage_node_key_rotation(rng)
        .expect("an active control session can rotate its expired node key");
    assert!(matches!(
        node.poll(crate::tunnel::now_ms()),
        Ok(Some(NodeAction::Control(ControlCommand::Disconnect)))
    ));
    loop {
        let state = take_rotation_state(node);
        let generation = state.generation();
        ROTATION_STATE.signal(state);
        let saved = ROTATION_RESULT.wait().await;
        node.persistence_result(generation, saved)
            .expect("the rotated node key generation matches");
        if saved {
            core::future::pending::<()>().await;
            unreachable!("a persisted node-key rotation resets the device");
        }
        Timer::after(Duration::from_secs(1)).await;
    }
}

/// Extract a small durable state before the async handoff so the tunnel task
/// does not retain the large [`NodeAction`] enum across an await point.
fn take_rotation_state(node: &mut Node<PEERS>) -> tailfeather::PersistState {
    let Some(NodeAction::PersistState(state)) = node
        .poll(crate::tunnel::now_ms())
        .expect("a staged node key requires persistence")
    else {
        panic!("a staged node key must provide a persistent state");
    };
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlStage {
    Resolve,
    KeyConnect,
    KeyTls,
    KeyRequest,
    NoiseConnect,
    NoiseTls,
    NoiseHandshake,
    Http2Start,
    Registration,
    MapRequest,
    MapHeaders,
    MapFraming,
    MapParsing,
    Stun,
    EndpointPublication,
    DerpTls,
    Persistence,
}

impl ControlStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::KeyConnect => "key-connect",
            Self::KeyTls => "key-tls",
            Self::KeyRequest => "key-request",
            Self::NoiseConnect => "noise-connect",
            Self::NoiseTls => "noise-tls",
            Self::NoiseHandshake => "noise-handshake",
            Self::Http2Start => "http2-start",
            Self::Registration => "registration",
            Self::MapRequest => "map-request",
            Self::MapHeaders => "map-headers",
            Self::MapFraming => "map-framing",
            Self::MapParsing => "map-parsing",
            Self::Stun => "stun",
            Self::EndpointPublication => "endpoint-publication",
            Self::DerpTls => "derp-tls",
            Self::Persistence => "persistence",
        }
    }
}

#[allow(
    dead_code,
    reason = "variant payloads are retained for serial Debug diagnostics"
)]
#[derive(Debug, Clone, Copy)]
pub enum TransportReason {
    TlsIo(embedded_tls::TlsError),
    #[cfg(feature = "test-insecure-control")]
    TcpIo(embassy_net::tcp::Error),
    UnexpectedEof,
    Noise(tailfeather::noise::Error),
    Http2(micro_h2::Error),
    Netmap(tailfeather::netmap::Error),
    NoServerKey,
    Key(tailfeather::keys::DecodeError),
    UnexpectedStatus(u16),
    ResponseTooLong,
    FrameTooLarge,
    InterleavedStream(u32),
    StreamEnded,
}

#[allow(
    dead_code,
    reason = "variant payloads are retained for serial Debug diagnostics"
)]
#[derive(Debug, Clone, Copy)]
pub enum FailureReason {
    Dns(embassy_net::dns::Error),
    NoAddress,
    Connect(embassy_net::tcp::ConnectError),
    Tls(embedded_tls::TlsError),
    Transport(TransportReason),
    NodeKeyExpired,
    Protocol,
    Persistence,
}

#[derive(Debug, Clone, Copy)]
pub struct Failure {
    pub stage: ControlStage,
    pub reason: FailureReason,
}

impl Failure {
    const fn protocol(stage: ControlStage) -> Self {
        Self {
            stage,
            reason: FailureReason::Protocol,
        }
    }

    const fn persistence() -> Self {
        Self {
            stage: ControlStage::Persistence,
            reason: FailureReason::Persistence,
        }
    }
}

fn transport_failure(
    stage: ControlStage,
    error: tailfeather::control::transport::Error<embedded_tls::TlsError>,
) -> Failure {
    use tailfeather::control::transport::Error;
    let stage = match error {
        Error::UnexpectedStatus(_) if stage == ControlStage::MapParsing => ControlStage::MapHeaders,
        Error::FrameTooLarge if stage == ControlStage::MapParsing => ControlStage::MapFraming,
        Error::Netmap(tailfeather::netmap::Error::FrameTooLarge) => ControlStage::MapFraming,
        Error::Netmap(_) => ControlStage::MapParsing,
        _ => stage,
    };
    let reason = match error {
        Error::Io(error) => TransportReason::TlsIo(error),
        Error::UnexpectedEof => TransportReason::UnexpectedEof,
        Error::Noise(error) => TransportReason::Noise(error),
        Error::Http2(error) => TransportReason::Http2(error),
        Error::Netmap(error) => TransportReason::Netmap(error),
        Error::NoServerKey => TransportReason::NoServerKey,
        Error::Key(error) => TransportReason::Key(error),
        Error::UnexpectedStatus(status) => TransportReason::UnexpectedStatus(status),
        Error::ResponseTooLong => TransportReason::ResponseTooLong,
        Error::FrameTooLarge => TransportReason::FrameTooLarge,
        Error::InterleavedStream(stream) => TransportReason::InterleavedStream(stream),
        Error::StreamEnded => TransportReason::StreamEnded,
    };
    Failure {
        stage,
        reason: FailureReason::Transport(reason),
    }
}

#[cfg(feature = "test-insecure-control")]
fn plain_transport_failure(
    stage: ControlStage,
    error: tailfeather::control::transport::Error<embassy_net::tcp::Error>,
) -> Failure {
    use tailfeather::control::transport::Error;
    let stage = match error {
        Error::UnexpectedStatus(_) if stage == ControlStage::MapParsing => ControlStage::MapHeaders,
        Error::FrameTooLarge if stage == ControlStage::MapParsing => ControlStage::MapFraming,
        Error::Netmap(tailfeather::netmap::Error::FrameTooLarge) => ControlStage::MapFraming,
        Error::Netmap(_) => ControlStage::MapParsing,
        _ => stage,
    };
    let reason = match error {
        Error::Io(error) => TransportReason::TcpIo(error),
        Error::UnexpectedEof => TransportReason::UnexpectedEof,
        Error::Noise(error) => TransportReason::Noise(error),
        Error::Http2(error) => TransportReason::Http2(error),
        Error::Netmap(error) => TransportReason::Netmap(error),
        Error::NoServerKey => TransportReason::NoServerKey,
        Error::Key(error) => TransportReason::Key(error),
        Error::UnexpectedStatus(status) => TransportReason::UnexpectedStatus(status),
        Error::ResponseTooLong => TransportReason::ResponseTooLong,
        Error::FrameTooLarge => TransportReason::FrameTooLarge,
        Error::InterleavedStream(stream) => TransportReason::InterleavedStream(stream),
        Error::StreamEnded => TransportReason::StreamEnded,
    };
    Failure {
        stage,
        reason: FailureReason::Transport(reason),
    }
}

struct DeviceClock;

impl TlsClock for DeviceClock {
    fn now() -> Option<u64> {
        let monotonic_ms = Instant::now().as_millis();
        critical_section::with(|cs| TRUSTED_TIME.borrow(cs).get()).map(|(base, base_ms)| {
            base.saturating_add(monotonic_ms.saturating_sub(base_ms) / 1_000)
        })
    }
}

struct TlsRng(esp_hal::rng::Rng);

impl rand_core::RngCore for TlsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.0.read(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.read(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TlsRng {}

// The lab-only DERP path may use an HTTPS relay whose certificate is marked
// InsecureForTests by its map. Keep this provider out of production builds.
#[cfg(feature = "test-insecure-control")]
struct InsecureDerpProvider {
    rng: TlsRng,
    verifier: embedded_tls::NoVerify,
}

#[cfg(feature = "test-insecure-control")]
impl embedded_tls::CryptoProvider for InsecureDerpProvider {
    type CipherSuite = Suite;
    type Signature =
        <VerifyingProvider<'static, TlsRng, DeviceClock> as embedded_tls::CryptoProvider>::Signature;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl embedded_tls::TlsVerifier<Self::CipherSuite>, embedded_tls::TlsError>
    {
        Ok(&mut self.verifier)
    }
}

struct Buffers {
    tcp_rx: &'static mut [u8; TCP_RX_BUFFER],
    tcp_tx: &'static mut [u8; TCP_TX_BUFFER],
    tls_read: &'static mut [u8; TLS_READ_BUFFER],
    tls_write: &'static mut [u8; TLS_WRITE_BUFFER],
    h2_read: &'static mut [u8; H2_BUFFER],
    h2_connection: &'static mut micro_h2::Connection,
    rsa: &'static mut RsaWorkspace,
}

struct StunBuffers {
    rx_meta: &'static mut [PacketMetadata; STUN_PACKETS],
    rx: &'static mut [u8; STUN_BUFFER],
    tx_meta: &'static mut [PacketMetadata; STUN_PACKETS],
    tx: &'static mut [u8; STUN_BUFFER],
}

#[allow(clippy::too_many_arguments)]
async fn bootstrap<'a>(
    stack: Stack<'static>,
    node: &mut Node<PEERS>,
    control: &Authority,
    rng: &mut HwRng,
    store: &mut TwoSlot<FlashSlots<'static>>,
    provisional_time: u64,
    buffers: &'a mut Buffers,
    stun_buffers: &mut StunBuffers,
    staging: &mut Netmap<PEERS>,
    recovery: &mut RecoveryConfig,
    map: &mut MapStream<PEERS>,
) -> Result<Link<'a>, Failure> {
    // A failed enrollment or key-rotation save leaves the node deliberately
    // blocked in `WaitingForPersistence`. Retry that durable write before
    // starting another control session.
    persist_pending(node, store)?;
    info!(
        "control stage={} state=start",
        ControlStage::Resolve.as_str()
    );
    let addresses = resolve(stack, control).await?;
    let authority = http_authority(control)?;
    info!(
        "control stage={} state=ready",
        ControlStage::Resolve.as_str()
    );

    set_trusted_time(provisional_time);
    let server_key = fetch_key(
        stack,
        addresses.as_slice(),
        control,
        authority.as_str(),
        buffers,
    )
    .await?;
    let mut link = open_link(
        stack,
        addresses.as_slice(),
        control,
        authority.as_str(),
        &server_key,
        node.identity(),
        rng,
        &mut *buffers.tcp_rx,
        &mut *buffers.tcp_tx,
        &mut *buffers.tls_read,
        &mut *buffers.tls_write,
        &mut *buffers.h2_read,
        &mut *buffers.h2_connection,
        &mut *buffers.rsa,
    )
    .await?;
    if !register(&mut link, node, control, authority.as_str(), rng).await? {
        if !matches!(
            node.poll(crate::tunnel::now_ms()),
            Ok(Some(NodeAction::Control(ControlCommand::Disconnect)))
        ) {
            return Err(Failure::protocol(ControlStage::Registration));
        }
        node.handle_control_event(ControlEvent::Disconnected)
            .map_err(|_| Failure::protocol(ControlStage::Registration))?;
        persist_pending(node, store)?;
        // `Node`'s WireGuard device owns the old private key. The durable
        // rotation is therefore completed by booting with the replacement
        // identity, rather than reusing this session's device.
        esp_hal::system::software_reset();
    }

    let local = stack
        .config_v4()
        .ok_or_else(|| Failure::protocol(ControlStage::MapRequest))?
        .address
        .address();
    let mut endpoint = String::<64>::new();
    write!(endpoint, "{local}:{LISTEN_PORT}")
        .map_err(|_| Failure::protocol(ControlStage::MapRequest))?;
    let endpoints = [endpoint.as_str()];
    write_recovery_map_body(node, &endpoints, 0, &mut recovery.map_body)?;
    info!(
        "control stage={} state=start",
        ControlStage::MapRequest.as_str()
    );
    link.start_map(authority.as_str(), recovery.map_body.as_slice(), map)
        .await?;
    info!(
        "control stage={} state=streaming",
        ControlStage::MapRequest.as_str()
    );
    node.seed_staging(staging);
    info!(
        "control stage={} state=awaiting-frame",
        ControlStage::MapHeaders.as_str()
    );
    loop {
        match select(link.next_map(map, staging), Timer::after(MAP_LIVENESS)).await {
            Either::First(Ok(MapEvent::Applied)) => break,
            Either::First(Ok(MapEvent::KeepAlive)) => {}
            Either::First(Err(error)) => return Err(error),
            Either::Second(()) => {
                return Err(Failure {
                    stage: ControlStage::MapHeaders,
                    reason: FailureReason::Transport(TransportReason::StreamEnded),
                });
            }
        }
    }
    info!(
        "control stage={} state=applied",
        ControlStage::MapParsing.as_str()
    );
    let action = node
        .handle_control_event(ControlEvent::MapFinished {
            lease: &mut *staging,
            result: Ok(()),
        })
        .map_err(|_| Failure::protocol(ControlStage::MapParsing))?;
    emit_action(action.as_ref());
    node.seed_staging(&mut *staging);

    info!("control stage={} state=start", ControlStage::Stun.as_str());
    let mut recovery_reflexive = None;
    if let Some((region, reflexive)) = probe_stun(stack, node, rng, stun_buffers).await {
        recovery_reflexive = Some(reflexive);
        info!(
            "control stage={} state=selected region={region}",
            ControlStage::Stun.as_str()
        );
        node.prefer_derp(region)
            .map_err(|_| Failure::protocol(ControlStage::Stun))?;
        publish_endpoints(
            &mut link,
            map,
            staging,
            node,
            authority.as_str(),
            EndpointPublication {
                local,
                reflexive: Some(reflexive),
                preferred_derp: region,
            },
        )
        .await?;
    } else {
        warn!(
            "control stage={} state=no-response",
            ControlStage::Stun.as_str()
        );
        // Some networks block every UDP STUN reply. The DERP map came over the
        // authenticated control channel, so retain availability by selecting
        // its first usable region when no measured home exists.
        let fallback = node
            .netmap()
            .derp
            .iter()
            .find(|region| region.can_be_home())
            .map(|region| region.id);
        if node.netmap().home_derp == 0
            && let Some(region) = fallback
        {
            node.prefer_derp(region)
                .map_err(|_| Failure::protocol(ControlStage::Stun))?;
            info!(
                "control stage={} state=selected region={region} source=fallback",
                ControlStage::Stun.as_str()
            );
            // A preferred DERP is load-bearing peer reachability metadata, not
            // merely a STUN optimization. If UDP replies are blocked, publish
            // the authenticated fallback together with the LAN candidate so
            // other clients can still put this node in their WireGuard engine.
            publish_endpoints(
                &mut link,
                map,
                staging,
                node,
                authority.as_str(),
                EndpointPublication {
                    local,
                    reflexive: None,
                    preferred_derp: region,
                },
            )
            .await?;
        }
    }
    if !map.has_pending_update() {
        node.seed_staging(staging);
    }

    let mut reflexive_text = String::<64>::new();
    if let Some(reflexive) = recovery_reflexive {
        write!(reflexive_text, "{reflexive}")
            .map_err(|_| Failure::protocol(ControlStage::MapRequest))?;
    }
    let final_endpoints = [endpoint.as_str(), reflexive_text.as_str()];
    let final_count =
        usize::from(!reflexive_text.is_empty() && endpoint.as_str() != reflexive_text.as_str()) + 1;
    write_recovery_map_body(
        node,
        &final_endpoints[..final_count],
        node.netmap().home_derp,
        &mut recovery.map_body,
    )?;

    write_recovery_registration_body(node, &mut recovery.registration_body)?;
    Ok(link)
}

fn write_recovery_map_body(
    node: &Node<PEERS>,
    endpoints: &[&str],
    preferred_derp: u16,
    saved: &mut heapless::Vec<u8, RECOVERY_BODY>,
) -> Result<(), Failure> {
    let node_key = node.identity().node.public();
    let disco_key = node.identity().disco.public();
    let request = MapRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &node_key,
        disco_key: &disco_key,
        hostinfo: Hostinfo {
            hostname: crate::TS_HOSTNAME,
            routable_ips: &tailfeather::control::EXIT_NODE_ROUTES,
            preferred_derp,
            peer_api_port: Some(tailfeather_gateway::peerapi::PORT),
            ..Default::default()
        },
        stream: true,
        omit_peers: false,
        read_only: false,
        endpoints,
    };
    let mut body = [0; tailfeather::node::MAX_CONTROL_BODY];
    let body = request
        .write(&mut body)
        .map_err(|_| Failure::protocol(ControlStage::MapRequest))?;
    saved.clear();
    saved
        .extend_from_slice(body)
        .map_err(|_| Failure::protocol(ControlStage::MapRequest))?;
    Ok(())
}

/// Registration body used after enrollment. Its auth field is intentionally
/// empty, so neither a transient reconnect nor a control-session recovery can
/// resend the one-time provisioning key.
fn write_recovery_registration_body(
    node: &Node<PEERS>,
    saved: &mut heapless::Vec<u8, RECOVERY_BODY>,
) -> Result<(), Failure> {
    let node_key = node.identity().node.public();
    let request = RegisterRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &node_key,
        old_node_key: None,
        auth_key: "",
        hostinfo: Hostinfo {
            hostname: crate::TS_HOSTNAME,
            routable_ips: &tailfeather::control::EXIT_NODE_ROUTES,
            peer_api_port: Some(tailfeather_gateway::peerapi::PORT),
            ..Default::default()
        },
        ephemeral: false,
    };
    let mut body = [0; tailfeather::node::MAX_CONTROL_BODY];
    let body = request
        .write(&mut body)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    saved.clear();
    saved
        .extend_from_slice(body)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    Ok(())
}

async fn recover_session<'a>(
    stack: Stack<'static>,
    control: &Authority,
    rng: &mut HwRng,
    buffers: &'a mut Buffers,
    recovery: &RecoveryConfig,
    map: &mut MapStream<PEERS>,
) -> Result<Link<'a>, Failure> {
    info!(
        "control stage={} state=recovering",
        ControlStage::Resolve.as_str()
    );
    let addresses = resolve(stack, control).await?;
    let authority = http_authority(control)?;
    let server_key = fetch_key(
        stack,
        addresses.as_slice(),
        control,
        authority.as_str(),
        buffers,
    )
    .await?;
    let mut link = open_link(
        stack,
        addresses.as_slice(),
        control,
        authority.as_str(),
        &server_key,
        &recovery.identity,
        rng,
        &mut *buffers.tcp_rx,
        &mut *buffers.tcp_tx,
        &mut *buffers.tls_read,
        &mut *buffers.tls_write,
        &mut *buffers.h2_read,
        &mut *buffers.h2_connection,
        &mut *buffers.rsa,
    )
    .await?;

    info!(
        "control stage={} state=recovering auth=omitted",
        ControlStage::Registration.as_str()
    );
    let mut response = [0; 4096];
    let (status, len) = link
        .request(
            "POST",
            tailfeather::control::register::PATH,
            authority.as_str(),
            recovery.registration_body.as_slice(),
            &mut response,
        )
        .await?;
    if status != 200 {
        return Err(Failure {
            stage: ControlStage::Registration,
            reason: FailureReason::Transport(TransportReason::UnexpectedStatus(status)),
        });
    }
    let response = core::str::from_utf8(&response[..len])
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    let response = RegisterResponse::parse(response);
    if !response.is_success() {
        return Err(Failure::protocol(ControlStage::Registration));
    }
    if response.node_key_expired {
        return Err(Failure {
            stage: ControlStage::Registration,
            reason: FailureReason::NodeKeyExpired,
        });
    }
    info!("state=registered recovery=true");
    link.start_map(authority.as_str(), recovery.map_body.as_slice(), map)
        .await?;
    info!(
        "control stage={} state=recovered",
        ControlStage::MapRequest.as_str()
    );
    Ok(link)
}

async fn probe_stun(
    stack: Stack<'static>,
    node: &Node<PEERS>,
    rng: &mut HwRng,
    buffers: &mut StunBuffers,
) -> Option<(u16, core::net::SocketAddrV4)> {
    let mut socket = UdpSocket::new(
        stack,
        &mut *buffers.rx_meta,
        &mut *buffers.rx,
        &mut *buffers.tx_meta,
        &mut *buffers.tx,
    );
    socket.bind(LISTEN_PORT).ok()?;

    let mut best: Option<(u64, u16, core::net::SocketAddrV4)> = None;
    let mut response = [0; STUN_BUFFER];
    for region in node
        .netmap()
        .derp
        .iter()
        .filter(|region| region.can_be_home())
    {
        let Some(relay) = region.nodes.iter().find(|node| node.stun_port != 0) else {
            continue;
        };
        let addresses = match stack
            .dns_query(relay.host_name.as_str(), DnsQueryType::A)
            .await
        {
            Ok(addresses) => addresses,
            Err(_) => continue,
        };
        let Some(address) = addresses.into_iter().next() else {
            continue;
        };
        let embassy_net::IpAddress::Ipv4(address) = address;
        let endpoint = IpEndpoint::new(address.into(), relay.stun_port);
        let mut transaction = [0; tailfeather::stun::TRANSACTION_ID_LEN];
        rng.0.read(&mut transaction);
        let request = tailfeather::stun::request(transaction);
        let started = Instant::now();
        if socket.send_to(&request, endpoint).await.is_err() {
            continue;
        }
        let (len, source) = match select(
            socket.recv_from(&mut response),
            Timer::after(Duration::from_millis(400)),
        )
        .await
        {
            Either::First(Ok(received)) => received,
            Either::First(Err(_)) | Either::Second(()) => continue,
        };
        if source.endpoint != endpoint {
            continue;
        }
        let Ok((address, port)) = tailfeather::stun::response(&response[..len], transaction) else {
            continue;
        };
        let elapsed = Instant::now().duration_since(started).as_millis();
        let reflexive = core::net::SocketAddrV4::new(address.into(), port);
        if best.is_none_or(|(best_ms, ..)| elapsed < best_ms) {
            best = Some((elapsed, region.id, reflexive));
        }
    }
    best.map(|(_, region, endpoint)| (region, endpoint))
}

struct EndpointPublication {
    local: embassy_net::Ipv4Address,
    reflexive: Option<core::net::SocketAddrV4>,
    preferred_derp: u16,
}

async fn publish_endpoints(
    link: &mut Link<'_>,
    map: &mut MapStream<PEERS>,
    staging: &mut Netmap<PEERS>,
    node: &Node<PEERS>,
    authority: &str,
    publication: EndpointPublication,
) -> Result<(), Failure> {
    info!(
        "control stage={} state=start endpoints={}",
        ControlStage::EndpointPublication.as_str(),
        if publication.reflexive.is_some() {
            "reflexive"
        } else {
            "local"
        }
    );
    let mut local_text = String::<64>::new();
    write!(local_text, "{}:{LISTEN_PORT}", publication.local)
        .map_err(|_| Failure::protocol(ControlStage::EndpointPublication))?;
    let mut reflexive_text = String::<64>::new();
    if let Some(reflexive) = publication.reflexive {
        write!(reflexive_text, "{reflexive}")
            .map_err(|_| Failure::protocol(ControlStage::EndpointPublication))?;
    }
    let endpoints = [local_text.as_str(), reflexive_text.as_str()];
    let endpoint_count =
        usize::from(!reflexive_text.is_empty() && local_text.as_str() != reflexive_text.as_str())
            + 1;
    let node_key = node.identity().node.public();
    let disco_key = node.identity().disco.public();
    let request = MapRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &node_key,
        disco_key: &disco_key,
        hostinfo: Hostinfo {
            hostname: crate::TS_HOSTNAME,
            routable_ips: &tailfeather::control::EXIT_NODE_ROUTES,
            preferred_derp: publication.preferred_derp,
            peer_api_port: Some(tailfeather_gateway::peerapi::PORT),
            ..Default::default()
        },
        stream: false,
        omit_peers: true,
        read_only: false,
        endpoints: &endpoints[..endpoint_count],
    };
    let mut body = [0; tailfeather::node::MAX_CONTROL_BODY];
    let body = request
        .write(&mut body)
        .map_err(|_| Failure::protocol(ControlStage::EndpointPublication))?;
    link.endpoint_update(map, staging, authority, body).await?;
    info!(
        "control stage={} state=published",
        ControlStage::EndpointPublication.as_str()
    );
    Ok(())
}

async fn register(
    link: &mut Link<'_>,
    node: &mut Node<PEERS>,
    control: &Authority,
    authority: &str,
    rng: &mut HwRng,
) -> Result<bool, Failure> {
    info!(
        "control stage={} state=start enrolled={}",
        ControlStage::Registration.as_str(),
        node.is_enrolled()
    );
    let node_key = node.identity().node.public();
    let request = RegisterRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &node_key,
        old_node_key: node.rotation_old_node_key(),
        auth_key: node.registration_auth_key(crate::TS_AUTH_KEY),
        hostinfo: Hostinfo {
            hostname: crate::TS_HOSTNAME,
            routable_ips: &tailfeather::control::EXIT_NODE_ROUTES,
            peer_api_port: Some(tailfeather_gateway::peerapi::PORT),
            ..Default::default()
        },
        ephemeral: false,
    };
    let mut request_body = [0; tailfeather::node::MAX_CONTROL_BODY];
    let request_body = request
        .write(&mut request_body)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    node.set_control_endpoint(
        tailfeather::Endpoint::new(control.host(), control.port())
            .map_err(|_| Failure::protocol(ControlStage::Registration))?,
    );
    node.set_registration_body(request_body)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    match node
        .poll(crate::tunnel::now_ms())
        .map_err(|_| Failure::protocol(ControlStage::Registration))?
    {
        Some(NodeAction::Control(ControlCommand::Connect { .. })) => {}
        _ => return Err(Failure::protocol(ControlStage::Registration)),
    }
    let action = node
        .handle_control_event(ControlEvent::Connected)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    let Some(NodeAction::Control(ControlCommand::Register { body })) = action else {
        return Err(Failure::protocol(ControlStage::Registration));
    };
    let mut response = [0; 4096];
    let (status, len) = link
        .request(
            "POST",
            tailfeather::control::register::PATH,
            authority,
            body.as_slice(),
            &mut response,
        )
        .await?;
    if status != 200 {
        return Err(Failure {
            stage: ControlStage::Registration,
            reason: FailureReason::Transport(TransportReason::UnexpectedStatus(status)),
        });
    }
    let response = core::str::from_utf8(&response[..len])
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    let response = RegisterResponse::parse(response);
    if !response.is_success() {
        return Err(Failure::protocol(ControlStage::Registration));
    }
    if response.node_key_expired {
        node.stage_node_key_rotation(rng)
            .map_err(|_| Failure::persistence())?;
        info!("state=node-key-rotation-staged");
        return Ok(false);
    }
    let was_enrolled = node.is_enrolled();
    let was_rotating = node.rotation_old_node_key().is_some();
    let action = node
        .handle_control_event(ControlEvent::Registered)
        .map_err(|_| Failure::protocol(ControlStage::Registration))?;
    info!("state=registered");
    info!(
        "control stage={} state=complete status={status}",
        ControlStage::Registration.as_str()
    );
    if was_enrolled && !was_rotating {
        if !matches!(
            action,
            Some(NodeAction::Control(ControlCommand::RequestMap))
        ) {
            return Err(Failure::protocol(ControlStage::Registration));
        }
    } else if !matches!(
        action,
        Some(NodeAction::StatusChanged(NodeStatus::Registered))
    ) {
        return Err(Failure::protocol(ControlStage::Registration));
    }
    Ok(was_enrolled && !was_rotating)
}

fn persist_pending(
    node: &mut Node<PEERS>,
    store: &mut TwoSlot<FlashSlots<'static>>,
) -> Result<(), Failure> {
    if !node.requires_persistence() {
        return Ok(());
    }
    let Some(NodeAction::PersistState(state)) = node
        .poll(crate::tunnel::now_ms())
        .map_err(|_| Failure::persistence())?
    else {
        return Err(Failure::persistence());
    };
    let generation = state.generation();
    let saved = store.save(&state).is_ok();
    node.persistence_result(generation, saved)
        .map_err(|_| Failure::persistence())?;
    if saved {
        Ok(())
    } else {
        Err(Failure::persistence())
    }
}

async fn resolve(
    stack: Stack<'static>,
    control: &Authority,
) -> Result<heapless::Vec<IpEndpoint, 4>, Failure> {
    let addresses = stack
        .dns_query(control.host(), DnsQueryType::A)
        .await
        .map_err(|error| Failure {
            stage: ControlStage::Resolve,
            reason: FailureReason::Dns(error),
        })?;
    let mut endpoints = heapless::Vec::new();
    for address in addresses {
        let embassy_net::IpAddress::Ipv4(address) = address;
        endpoints
            .push(IpEndpoint::new(address.into(), control.port()))
            .map_err(|_| Failure::protocol(ControlStage::Resolve))?;
    }
    if endpoints.is_empty() {
        Err(Failure {
            stage: ControlStage::Resolve,
            reason: FailureReason::NoAddress,
        })
    } else {
        Ok(endpoints)
    }
}

fn http_authority(control: &Authority) -> Result<String<160>, Failure> {
    let mut result = String::new();
    result
        .push_str(control.host())
        .map_err(|_| Failure::protocol(ControlStage::Resolve))?;
    let default = if control.is_secure() { 443 } else { 80 };
    if control.port() != default {
        write!(result, ":{}", control.port())
            .map_err(|_| Failure::protocol(ControlStage::Resolve))?;
    }
    Ok(result)
}

async fn tcp<'a>(
    stack: Stack<'static>,
    addresses: &[IpEndpoint],
    rx: &'a mut [u8],
    tx: &'a mut [u8],
    stage: ControlStage,
) -> Result<TcpSocket<'a>, Failure> {
    let mut socket = TcpSocket::new(stack, rx, tx);
    let mut last_error = None;
    for address in addresses {
        match socket.connect(*address).await {
            Ok(()) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
        socket.abort();
    }
    Err(Failure {
        stage,
        reason: last_error
            .map(FailureReason::Connect)
            .unwrap_or(FailureReason::NoAddress),
    })
}

pub(crate) async fn verified_tls<'a>(
    socket: TcpSocket<'a>,
    control: &Authority,
    read: &'a mut [u8],
    write: &'a mut [u8],
    rsa: &mut RsaWorkspace,
    stage: ControlStage,
) -> Result<SecureStream<'a>, Failure> {
    let private_root = (!crate::TS_CONTROL_CA_DER.is_empty()).then_some(crate::TS_CONTROL_CA_DER);
    let config = TlsConfig::new()
        .with_server_name(control.host())
        .enable_rsa_signatures();
    let mut tls = TlsConnection::new(socket, read, write);
    tls.open(TlsContext::new(
        &config,
        VerifyingProvider::<_, DeviceClock>::new(
            TlsRng(esp_hal::rng::Rng::new()),
            private_root,
            rsa,
        ),
    ))
    .await
    .map_err(|error| {
        warn!("tls-open error={error:?}");
        Failure {
            stage,
            reason: FailureReason::Tls(error),
        }
    })?;
    Ok(tls)
}

#[cfg(feature = "test-insecure-control")]
pub(crate) async fn insecure_derp_tls<'a>(
    socket: TcpSocket<'a>,
    authority: &Authority,
    read: &'a mut [u8],
    write: &'a mut [u8],
) -> Result<SecureStream<'a>, Failure> {
    let config = TlsConfig::new()
        .with_server_name(authority.host())
        .enable_rsa_signatures();
    let mut tls = TlsConnection::new(socket, read, write);
    tls.open(TlsContext::new(
        &config,
        InsecureDerpProvider {
            rng: TlsRng(esp_hal::rng::Rng::new()),
            verifier: embedded_tls::NoVerify,
        },
    ))
    .await
    .map_err(|error| {
        warn!("insecure test DERP tls-open error={error:?}");
        Failure {
            stage: ControlStage::DerpTls,
            reason: FailureReason::Tls(error),
        }
    })?;
    Ok(tls)
}

async fn fetch_key(
    stack: Stack<'static>,
    addresses: &[IpEndpoint],
    control: &Authority,
    authority: &str,
    buffers: &mut Buffers,
) -> Result<tailfeather::keys::MachinePublic, Failure> {
    info!(
        "control stage={} state=start",
        ControlStage::KeyConnect.as_str()
    );
    let socket = tcp(
        stack,
        addresses,
        &mut *buffers.tcp_rx,
        &mut *buffers.tcp_tx,
        ControlStage::KeyConnect,
    )
    .await?;
    info!(
        "control stage={} state=connected",
        ControlStage::KeyConnect.as_str()
    );
    if control.is_secure() {
        info!(
            "control stage={} state=start",
            ControlStage::KeyTls.as_str()
        );
        let mut stream = verified_tls(
            socket,
            control,
            &mut *buffers.tls_read,
            &mut *buffers.tls_write,
            &mut *buffers.rsa,
            ControlStage::KeyTls,
        )
        .await?;
        info!(
            "control stage={} state=verified",
            ControlStage::KeyTls.as_str()
        );
        crate::stack::log_used("key-tls-verified");
        info!(
            "control stage={} state=start",
            ControlStage::KeyRequest.as_str()
        );
        let key = tailfeather::control::transport::fetch_server_key(&mut stream, authority)
            .await
            .map_err(|error| transport_failure(ControlStage::KeyRequest, error))?;
        info!(
            "control stage={} state=complete status=200",
            ControlStage::KeyRequest.as_str()
        );
        let mut socket = match stream.close().await {
            Ok(socket) => socket,
            Err((socket, error)) => {
                warn!("key-tls-close error={error:?}");
                socket
            }
        };
        socket.close();
        if let Err(error) = embedded_io_async::Write::flush(&mut socket).await {
            warn!("key-tcp-close error={error:?}");
        }
        Ok(key)
    } else {
        #[cfg(feature = "test-insecure-control")]
        {
            let mut stream = socket;
            let key = tailfeather::control::transport::fetch_server_key(&mut stream, authority)
                .await
                .map_err(|error| plain_transport_failure(ControlStage::KeyRequest, error))?;
            stream.close();
            if let Err(error) = embedded_io_async::Write::flush(&mut stream).await {
                warn!("key-tcp-close error={error:?}");
            }
            Ok(key)
        }
        #[cfg(not(feature = "test-insecure-control"))]
        {
            let _ = socket;
            Err(Failure::protocol(ControlStage::KeyRequest))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_link<'a>(
    stack: Stack<'static>,
    addresses: &[IpEndpoint],
    control: &Authority,
    authority: &str,
    server_key: &tailfeather::keys::MachinePublic,
    identity: &tailfeather::keys::Identity,
    rng: &mut HwRng,
    tcp_rx: &'a mut [u8],
    tcp_tx: &'a mut [u8],
    tls_read: &'a mut [u8],
    tls_write: &'a mut [u8],
    h2_read: &'a mut [u8; H2_BUFFER],
    h2_connection: &'a mut micro_h2::Connection,
    rsa: &'a mut RsaWorkspace,
) -> Result<Link<'a>, Failure> {
    info!(
        "control stage={} state=quiescing delay_ms=2000",
        ControlStage::NoiseConnect.as_str()
    );
    Timer::after(Duration::from_secs(2)).await;
    info!(
        "control stage={} state=start",
        ControlStage::NoiseConnect.as_str()
    );
    let socket = tcp(stack, addresses, tcp_rx, tcp_tx, ControlStage::NoiseConnect).await?;
    info!(
        "control stage={} state=connected",
        ControlStage::NoiseConnect.as_str()
    );
    crate::stack::log_used("noise-connect-connected");
    if control.is_secure() {
        info!(
            "control stage={} state=start",
            ControlStage::NoiseTls.as_str()
        );
        let tls = verified_tls(
            socket,
            control,
            tls_read,
            tls_write,
            rsa,
            ControlStage::NoiseTls,
        )
        .await?;
        info!(
            "control stage={} state=verified",
            ControlStage::NoiseTls.as_str()
        );
        crate::stack::log_used("noise-tls-verified");
        info!(
            "control stage={} state=start",
            ControlStage::NoiseHandshake.as_str()
        );
        let noise =
            tailfeather::control::transport::establish(tls, authority, identity, server_key, rng)
                .await
                .map_err(|error| transport_failure(ControlStage::NoiseHandshake, error))?;
        info!(
            "control stage={} state=complete",
            ControlStage::NoiseHandshake.as_str()
        );
        crate::stack::log_used("noise-handshake-complete");
        info!(
            "control stage={} state=start",
            ControlStage::Http2Start.as_str()
        );
        let http2 = noise
            .into_https2_with_storage(h2_read, h2_connection)
            .await
            .map_err(|error| transport_failure(ControlStage::Http2Start, error))?;
        info!(
            "control stage={} state=complete",
            ControlStage::Http2Start.as_str()
        );
        crate::stack::log_used("http2-start-complete");
        Ok(Link::Secure(http2))
    } else {
        #[cfg(feature = "test-insecure-control")]
        {
            let noise = tailfeather::control::transport::establish(
                socket, authority, identity, server_key, rng,
            )
            .await
            .map_err(|error| plain_transport_failure(ControlStage::NoiseHandshake, error))?;
            Ok(Link::Plain(
                noise
                    .into_http2_with_storage(h2_read, h2_connection)
                    .await
                    .map_err(|error| plain_transport_failure(ControlStage::Http2Start, error))?,
            ))
        }
        #[cfg(not(feature = "test-insecure-control"))]
        {
            let _ = (
                socket,
                authority,
                server_key,
                identity,
                rng,
                h2_read,
                h2_connection,
            );
            Err(Failure::protocol(ControlStage::NoiseHandshake))
        }
    }
}

pub fn emit_action(action: Option<&NodeAction>) {
    let Some(NodeAction::StatusChanged(status)) = action else {
        return;
    };
    match status {
        NodeStatus::AwaitingRouteApproval => info!("state=awaiting-route-approval"),
        NodeStatus::MapActive | NodeStatus::MapChanged => info!("state=map-active"),
        NodeStatus::DerpConnected => info!("state=derp-connected"),
        NodeStatus::ExitReady => info!("state=exit-ready"),
        _ => {}
    }
}

/// Own the large TLS/Noise/HTTP2 future for its whole lifetime. Keeping both
/// bootstrap and streaming in this task means Embassy reserves one maximum
/// control frame instead of retaining a bootstrap frame in the packet actor
/// alongside a second long-poll frame.
#[embassy_executor::task]
pub async fn run(
    stack: Stack<'static>,
    node: &'static mut Node<PEERS>,
    authority: Authority,
    mut store: TwoSlot<FlashSlots<'static>>,
    provisional_time: u64,
) {
    let mut rng = HwRng(esp_hal::rng::Rng::new());
    // These buffers are initialized once for the lifetime of the task. Failed
    // futures only reborrow them, so a transient bootstrap failure never calls
    // `StaticCell::init` twice and never needs a reboot to reclaim storage.
    let mut buffers = Buffers {
        tcp_rx: TCP_RX.init([0; TCP_RX_BUFFER]),
        tcp_tx: TCP_TX.init([0; TCP_TX_BUFFER]),
        tls_read: TLS_READ.init([0; TLS_READ_BUFFER]),
        tls_write: TLS_WRITE.init([0; TLS_WRITE_BUFFER]),
        h2_read: H2_READ.init([0; H2_BUFFER]),
        h2_connection: H2_CONNECTION.init_with(micro_h2::Connection::new),
        rsa: RSA_WORKSPACE.init_with(RsaWorkspace::new),
    };
    let mut stun_buffers = StunBuffers {
        rx_meta: STUN_RX_META.init([PacketMetadata::EMPTY; STUN_PACKETS]),
        rx: STUN_RX.init([0; STUN_BUFFER]),
        tx_meta: STUN_TX_META.init([PacketMetadata::EMPTY; STUN_PACKETS]),
        tx: STUN_TX.init([0; STUN_BUFFER]),
    };
    let staging = STAGING.init(Netmap::new());
    let map = MAP_STREAM.init_with(MapStream::new);
    // Recovery request images live outside the async task frame. In
    // particular, increasing the bounded netmap token storage must not steal
    // the P-256 handshake's stack headroom.
    let recovery = RECOVERY.init(RecoveryConfig::new(node.identity().clone()));
    let mut retry_seconds = 1u64;
    let link = loop {
        let attempt = select(
            bootstrap(
                stack,
                node,
                &authority,
                &mut rng,
                &mut store,
                provisional_time,
                &mut buffers,
                &mut stun_buffers,
                &mut *staging,
                &mut *recovery,
                &mut *map,
            ),
            Timer::after(BOOTSTRAP_LIVENESS),
        )
        .await;
        match attempt {
            Either::First(Ok(established)) => break established,
            Either::Second(()) => {
                warn!("control stage=bootstrap error=liveness-timeout retry_s={retry_seconds}");
                let _ = node.handle_control_event(ControlEvent::Disconnected);
                Timer::after(Duration::from_secs(retry_seconds)).await;
                retry_seconds = (retry_seconds * 2).min(60);
            }
            Either::First(Err(error)) => {
                warn!(
                    "control stage={} error={:?} retry_s={retry_seconds}",
                    error.stage.as_str(),
                    error.reason
                );
                let _ = node.handle_control_event(ControlEvent::Disconnected);
                Timer::after(Duration::from_secs(retry_seconds)).await;
                retry_seconds = (retry_seconds * 2).min(60);
            }
        }
    };
    retry_seconds = 1;
    BOOTSTRAP.send(BootstrapNotice::Ready(node)).await;
    let mut session = Session {
        link,
        staging: Some(staging),
    };

    loop {
        let recovered_staging = loop {
            let staging = session.staging.take().expect("one control map lease");
            match select(
                session.link.next_map(&mut *map, staging),
                Timer::after(MAP_LIVENESS),
            )
            .await
            {
                Either::First(Ok(MapEvent::KeepAlive)) => session.staging = Some(staging),
                Either::First(Ok(MapEvent::Applied)) => {
                    NOTICES.send(Notice::Map(staging)).await;
                    session.staging = Some(RETURNED.receive().await);
                }
                Either::First(Err(error)) => {
                    warn!(
                        "control stage={} error={:?} recovery_s={retry_seconds}",
                        error.stage.as_str(),
                        error.reason
                    );
                    break staging;
                }
                Either::Second(()) => {
                    warn!(
                        "control stage={} error=map-liveness-timeout recovery_s={retry_seconds}",
                        ControlStage::MapHeaders.as_str()
                    );
                    break staging;
                }
            }
        };

        // Dropping the failed link releases its borrows of the one-time static
        // buffers. A new session then reborrows the same storage; identity is
        // preserved and the saved registration body has an empty auth field.
        drop(session);
        let link = loop {
            Timer::after(Duration::from_secs(retry_seconds)).await;
            let node_key_expired = {
                let attempt = select(
                    recover_session(
                        stack,
                        &authority,
                        &mut rng,
                        &mut buffers,
                        recovery,
                        &mut *map,
                    ),
                    Timer::after(BOOTSTRAP_LIVENESS),
                )
                .await;
                match attempt {
                    Either::First(Ok(recovered)) => {
                        retry_seconds = 1;
                        break recovered;
                    }
                    Either::First(Err(Failure {
                        reason: FailureReason::NodeKeyExpired,
                        ..
                    })) => true,
                    Either::First(Err(error)) => {
                        warn!(
                            "control stage={} error={:?} retry_s={retry_seconds}",
                            error.stage.as_str(),
                            error.reason
                        );
                        retry_seconds = (retry_seconds * 2).min(60);
                        false
                    }
                    Either::Second(()) => {
                        warn!(
                            "control stage=recovery error=liveness-timeout retry_s={retry_seconds}"
                        );
                        retry_seconds = (retry_seconds * 2).min(60);
                        false
                    }
                }
            };
            if node_key_expired {
                info!("state=node-key-expired recovery=true");
                NOTICES.send(Notice::NodeKeyExpired).await;
                loop {
                    let state = ROTATION_STATE.wait().await;
                    let saved = store.save(&state).is_ok();
                    ROTATION_RESULT.signal(saved);
                    if saved {
                        esp_hal::system::software_reset();
                    }
                    warn!("control stage=persistence error=save-failed retrying=true");
                }
            }
        };
        session = Session {
            link,
            staging: Some(recovered_staging),
        };
    }
}
