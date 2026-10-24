//! The transport-agnostic, cooperative node state machine.
//!
//! [`Node`] owns protocol state, while callers own sockets, streams, storage,
//! clocks, and executors. Each input produces at most one explicit action.

use core::net::{SocketAddr, SocketAddrV4};

use heapless::{String, Vec};
use zeroize::Zeroize;

use crate::keys::{DiscoPrivate, Identity, MachinePrivate, NodePrivate, NodePublic};
use crate::netmap::{Netmap, Peer};
use crate::tunnel::{self, Action as TunnelAction, Device, Instant, PeerId, Tai64n};

/// Largest packet carried by a node action.
pub const MAX_ACTION_PACKET: usize = tunnel::MAX_DATAGRAM_LEN;
/// Largest bounded control request body.
pub const MAX_CONTROL_BODY: usize = 2048;

/// A DNS name and TCP port. DNS resolution belongs to the transport adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String<128>,
    pub port: u16,
    /// Optional TLS/SNI name when it differs from the address resolved for
    /// the TCP connection.
    pub tls_name: Option<String<{ crate::netmap::MAX_DERP_HOSTNAME }>>,
    /// Test relay marker from the DERP map. Production adapters still verify TLS.
    pub insecure_for_tests: bool,
}

impl Endpoint {
    pub fn new(host: &str, port: u16) -> Result<Self, NodeError> {
        Ok(Self {
            host: String::try_from(host).map_err(|_| NodeError::Capacity)?,
            port,
            tls_name: None,
            insecure_for_tests: false,
        })
    }

    pub fn with_tls_name(mut self, tls_name: &str) -> Result<Self, NodeError> {
        self.tls_name = Some(String::try_from(tls_name).map_err(|_| NodeError::Capacity)?);
        Ok(self)
    }
}

/// An owned bounded value which clears its initialized bytes on drop and never
/// exposes them through `Debug`.
pub struct SecretBuffer<const N: usize>(Vec<u8, N>);

impl<const N: usize> SecretBuffer<N> {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, NodeError> {
        let mut value = Vec::new();
        value
            .extend_from_slice(bytes)
            .map_err(|_| NodeError::Capacity)?;
        Ok(Self(value))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const N: usize> Drop for SecretBuffer<N> {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl<const N: usize> core::fmt::Debug for SecretBuffer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBuffer(redacted)")
    }
}

/// Work for the caller's control-plane task.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "bounded owned commands replace heap indirection"
)]
pub enum ControlCommand {
    Connect {
        endpoint: Endpoint,
    },
    Register {
        body: SecretBuffer<MAX_CONTROL_BODY>,
    },
    RequestMap,
    Disconnect,
}

/// Work for the caller's DERP task. Payload storage is bounded and zeroized.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "bounded owned commands replace heap indirection"
)]
pub enum DerpCommand {
    Connect {
        region: u16,
        endpoint: Endpoint,
    },
    Send {
        region: u16,
        peer: NodePublic,
        packet: SecretBuffer<MAX_ACTION_PACKET>,
    },
    Disconnect {
        region: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    WaitingForPersistence,
    Disconnected,
    Connecting,
    Registering,
    Registered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    PersistenceRequired,
    Offline,
    Connecting,
    Registered,
    MapChanged,
    AwaitingRouteApproval,
    MapActive,
    DerpConnected,
    ExitReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    Capacity,
    InvalidState,
    /// The peer is known but has no usable path right now: no healthy direct
    /// endpoint, no home region, and nothing learned from inbound relay
    /// traffic. Expected while a peer is still settling, and distinct from
    /// [`NodeError::InvalidState`] so that a genuine bookkeeping fault stays
    /// visible instead of hiding in the same log line.
    NoPath,
    /// The sender is not in this node's peer table at all, which on a bounded
    /// device usually means the netmap was truncated rather than that anything
    /// is wrong. Distinct from [`NodeError::InvalidState`] because the two
    /// were indistinguishable in the log, and a peer evicted for capacity read
    /// exactly like a state-machine fault.
    UnknownPeer,
    Persistence,
    StaleGeneration,
    Tunnel(tunnel::Error),
    Disco(crate::disco::Error),
}

impl From<tunnel::Error> for NodeError {
    fn from(value: tunnel::Error) -> Self {
        Self::Tunnel(value)
    }
}

impl From<crate::disco::Error> for NodeError {
    fn from(value: crate::disco::Error) -> Self {
        Self::Disco(value)
    }
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Capacity => "a bounded node value is full",
            Self::InvalidState => "event is invalid in the current node state",
            Self::NoPath => "no direct endpoint or DERP region reaches the peer",
            Self::UnknownPeer => "sender is not a retained peer; the netmap may be truncated",
            Self::Persistence => "persisted state is corrupt or unknown",
            Self::StaleGeneration => "persistence acknowledgement is stale",
            Self::Tunnel(_) => "tunnel protocol error",
            Self::Disco(_) => "disco protocol error",
        })
    }
}

impl core::error::Error for NodeError {}

/// Versioned caller-owned persistent state.
///
/// Auth keys, netmaps, and tunnel session keys are intentionally absent.
pub struct PersistState {
    generation: u64,
    trusted_time_floor: u64,
    enrolled: bool,
    rotation_old: Option<NodePublic>,
    authority_hash: [u8; 16],
    legacy: bool,
    blob: [u8; Self::BLOB_LEN],
}

impl PersistState {
    const MAGIC: [u8; 4] = *b"TFST";
    pub(crate) const VERSION: u8 = 3;
    const PAYLOAD_LEN: usize = 4 + 1 + 8 + 8 + 1 + 16 + 1 + 32 * 4;
    const CHECKSUM_LEN: usize = 16;
    pub const BLOB_LEN: usize = Self::PAYLOAD_LEN + Self::CHECKSUM_LEN;
    pub(crate) const V2_PAYLOAD_LEN: usize = 4 + 1 + 8 + 8 + 1 + 16 + 32 * 3;
    pub(crate) const V2_BLOB_LEN: usize = Self::V2_PAYLOAD_LEN + Self::CHECKSUM_LEN;
    pub(crate) const LEGACY_PAYLOAD_LEN: usize = 4 + 1 + 8 + 8 + 32 * 3;
    pub(crate) const LEGACY_BLOB_LEN: usize = Self::LEGACY_PAYLOAD_LEN + Self::CHECKSUM_LEN;

    fn encode(
        identity: &Identity,
        generation: u64,
        trusted_time_floor: u64,
        enrolled: bool,
        authority_hash: [u8; 16],
        rotation_old: Option<&NodePublic>,
    ) -> Self {
        let mut blob = [0; Self::BLOB_LEN];
        blob[..4].copy_from_slice(&Self::MAGIC);
        blob[4] = Self::VERSION;
        blob[5..13].copy_from_slice(&generation.to_le_bytes());
        blob[13..21].copy_from_slice(&trusted_time_floor.to_le_bytes());
        blob[21] = u8::from(enrolled);
        blob[22..38].copy_from_slice(&authority_hash);
        blob[38] = u8::from(rotation_old.is_some());
        blob[39..71].copy_from_slice(&identity.machine.to_bytes());
        blob[71..103].copy_from_slice(&identity.node.to_bytes());
        blob[103..135].copy_from_slice(&identity.disco.to_bytes());
        if let Some(old) = rotation_old {
            blob[135..167].copy_from_slice(old.as_bytes());
        }
        let checksum = tunnel::crypto::hash(&[&blob[..Self::PAYLOAD_LEN]]);
        blob[Self::PAYLOAD_LEN..].copy_from_slice(&checksum[..Self::CHECKSUM_LEN]);
        Self {
            generation,
            trusted_time_floor,
            enrolled,
            authority_hash,
            rotation_old: rotation_old.cloned(),
            legacy: false,
            blob,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeError> {
        if bytes.len() < 5 || bytes[..4] != Self::MAGIC {
            return Err(NodeError::Persistence);
        }
        if bytes[4] == 1 {
            if bytes.len() != Self::LEGACY_BLOB_LEN {
                return Err(NodeError::Persistence);
            }
            let checksum = tunnel::crypto::hash(&[&bytes[..Self::LEGACY_PAYLOAD_LEN]]);
            if !tunnel::crypto::ct_eq(
                &checksum[..Self::CHECKSUM_LEN],
                &bytes[Self::LEGACY_PAYLOAD_LEN..],
            ) {
                return Err(NodeError::Persistence);
            }
            let generation = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
            let trusted_time_floor = u64::from_le_bytes(bytes[13..21].try_into().unwrap());
            if generation == 0 {
                return Err(NodeError::Persistence);
            }
            let mut key = [0; 32];
            key.copy_from_slice(&bytes[21..53]);
            let machine = MachinePrivate::from_bytes(key);
            key.copy_from_slice(&bytes[53..85]);
            let node = NodePrivate::from_bytes(key);
            key.copy_from_slice(&bytes[85..117]);
            let disco = DiscoPrivate::from_bytes(key);
            key.zeroize();
            let identity = Identity {
                machine,
                node,
                disco,
            };
            let mut state = Self::encode(
                &identity,
                generation,
                trusted_time_floor,
                false,
                [0; 16],
                None,
            );
            state.legacy = true;
            return Ok(state);
        }
        if bytes[4] == 2 {
            if bytes.len() != Self::V2_BLOB_LEN {
                return Err(NodeError::Persistence);
            }
            let checksum = tunnel::crypto::hash(&[&bytes[..Self::V2_PAYLOAD_LEN]]);
            if !tunnel::crypto::ct_eq(
                &checksum[..Self::CHECKSUM_LEN],
                &bytes[Self::V2_PAYLOAD_LEN..],
            ) {
                return Err(NodeError::Persistence);
            }
            let generation = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
            let trusted_time_floor = u64::from_le_bytes(bytes[13..21].try_into().unwrap());
            let enrolled = match bytes[21] {
                0 => false,
                1 => true,
                _ => return Err(NodeError::Persistence),
            };
            if generation == 0 {
                return Err(NodeError::Persistence);
            }
            let mut authority_hash = [0; 16];
            authority_hash.copy_from_slice(&bytes[22..38]);
            let mut key = [0; 32];
            key.copy_from_slice(&bytes[38..70]);
            let machine = MachinePrivate::from_bytes(key);
            key.copy_from_slice(&bytes[70..102]);
            let node = NodePrivate::from_bytes(key);
            key.copy_from_slice(&bytes[102..134]);
            let disco = DiscoPrivate::from_bytes(key);
            key.zeroize();
            return Ok(Self::encode(
                &Identity {
                    machine,
                    node,
                    disco,
                },
                generation,
                trusted_time_floor,
                enrolled,
                authority_hash,
                None,
            ));
        }
        if bytes.len() != Self::BLOB_LEN || bytes[4] != Self::VERSION {
            return Err(NodeError::Persistence);
        }
        let checksum = tunnel::crypto::hash(&[&bytes[..Self::PAYLOAD_LEN]]);
        if !tunnel::crypto::ct_eq(&checksum[..Self::CHECKSUM_LEN], &bytes[Self::PAYLOAD_LEN..]) {
            return Err(NodeError::Persistence);
        }
        let mut blob = [0; Self::BLOB_LEN];
        blob.copy_from_slice(bytes);
        let generation = u64::from_le_bytes(blob[5..13].try_into().unwrap());
        let trusted_time_floor = u64::from_le_bytes(blob[13..21].try_into().unwrap());
        let enrolled = match blob[21] {
            0 => false,
            1 => true,
            _ => return Err(NodeError::Persistence),
        };
        let mut authority_hash = [0; 16];
        authority_hash.copy_from_slice(&blob[22..38]);
        let rotation_old = match blob[38] {
            0 => None,
            1 => {
                let mut key = [0; 32];
                key.copy_from_slice(&blob[135..167]);
                Some(NodePublic::from_bytes(key))
            }
            _ => return Err(NodeError::Persistence),
        };
        if generation == 0 {
            return Err(NodeError::Persistence);
        }
        Ok(Self {
            generation,
            trusted_time_floor,
            enrolled,
            authority_hash,
            rotation_old,
            legacy: false,
            blob,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn trusted_time_floor(&self) -> u64 {
        self.trusted_time_floor
    }
    pub fn enrolled(&self) -> bool {
        self.enrolled
    }
    pub fn authority_hash(&self) -> [u8; 16] {
        self.authority_hash
    }
    pub fn node_public(&self) -> NodePublic {
        self.identity().node.public()
    }

    fn identity(&self) -> Identity {
        let mut key = [0; 32];
        key.copy_from_slice(&self.blob[39..71]);
        let machine = MachinePrivate::from_bytes(key);
        key.copy_from_slice(&self.blob[71..103]);
        let node = NodePrivate::from_bytes(key);
        key.copy_from_slice(&self.blob[103..135]);
        let disco = DiscoPrivate::from_bytes(key);
        key.zeroize();
        Identity {
            machine,
            node,
            disco,
        }
    }
}

impl Drop for PersistState {
    fn drop(&mut self) {
        self.blob.zeroize();
    }
}

impl core::fmt::Debug for PersistState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersistState")
            .field("generation", &self.generation)
            .field("trusted_time_floor", &self.trusted_time_floor)
            .field("enrolled", &self.enrolled)
            .field("authority_hash", &self.authority_hash)
            .field("blob", &"redacted")
            .finish()
    }
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "bounded owned actions replace heap indirection"
)]
pub enum NodeAction {
    DirectTransmit {
        peer: NodePublic,
        endpoint: SocketAddr,
        packet: SecretBuffer<MAX_ACTION_PACKET>,
    },
    Control(ControlCommand),
    Derp(DerpCommand),
    DeliveredIpv4 {
        peer: NodePublic,
        packet: SecretBuffer<MAX_ACTION_PACKET>,
    },
    PersistState(PersistState),
    StatusChanged(NodeStatus),
}

/// Control events contain decoded protocol-level data, never stream handles.
pub enum ControlEvent<'a, const PEERS: usize = 32> {
    Connected,
    Registered,
    Disconnected,
    /// `lease` is the exact caller-owned staging map. On success it is swapped
    /// with the live map; on error it is returned untouched.
    MapFinished {
        lease: &'a mut Netmap<PEERS>,
        result: Result<(), crate::netmap::Error>,
    },
}

/// DERP framing is consumed by the session task; the node only sees peers.
pub enum DerpEvent<'a> {
    Connected {
        region: u16,
    },
    Disconnected {
        region: u16,
    },
    Packet {
        region: u16,
        peer: NodePublic,
        payload: &'a [u8],
    },
}

#[derive(Clone)]
struct PeerPath {
    key: NodePublic,
    /// Endpoints last advertised by the control plane. Discovery candidates
    /// must not make an unchanged control delta look like an endpoint change.
    control_endpoints: Vec<SocketAddrV4, { crate::netmap::MAX_ENDPOINTS }>,
    /// Current probe candidates, from control or authenticated CallMeMaybe.
    /// `direct` may instead be a NAT-translated source learned from traffic.
    advertised: Vec<SocketAddrV4, { crate::netmap::MAX_ENDPOINTS }>,
    direct: Option<SocketAddr>,
    direct_healthy: bool,
    /// Try a newly advertised endpoint once before falling back to DERP. A
    /// direct-only peer keeps using its only candidate for all traffic.
    direct_probe_pending: bool,
    home_derp: u16,
    /// The DERP region through which authenticated traffic most recently
    /// arrived. It is immediately usable for replies even before a new peer's
    /// control-plane HomeDERP field has caught up.
    relay_region: Option<u16>,
    disco: Option<crate::keys::DiscoPublic>,
    disco_tx: Option<crate::disco::TxId>,
    disco_deadline_ms: u64,
    disco_attempts: u8,
}

struct PendingDerp {
    region: u16,
    peer: NodePublic,
    packet: SecretBuffer<MAX_ACTION_PACKET>,
}

pub struct Node<const PEERS: usize = 32> {
    identity: Identity,
    netmap: Netmap<PEERS>,
    tunnel: Device<PEERS>,
    paths: Vec<PeerPath, PEERS>,
    registration: RegistrationState,
    generation: u64,
    trusted_time_floor: u64,
    enrolled: bool,
    rotation_old: Option<NodePublic>,
    authority_hash: [u8; 16],
    persist_in_flight: bool,
    control_disconnect_pending: bool,
    control_endpoint: Option<Endpoint>,
    registration_body: Option<SecretBuffer<MAX_CONTROL_BODY>>,
    connected_derp: Vec<u16, 2>,
    derp_connecting: Vec<u16, 2>,
    derp_disconnecting: Vec<u16, 2>,
    derp_last_failed: Option<u16>,
    active_peer_derp: Option<u16>,
    pending_derp: Option<PendingDerp>,
    reconnect_at_ms: u64,
    reconnect_backoff_s: u8,
    /// Whether peers may be reached over direct UDP. See
    /// [`Node::set_direct_paths`].
    direct_paths: bool,
    /// Whether WireGuard handshakes start only once there is traffic for a
    /// peer. See [`Node::set_initiate_on_demand`].
    initiate_on_demand: bool,
}

impl<const PEERS: usize> Node<PEERS> {
    /// Create a replacement identity only for an explicit factory reset.
    pub fn factory_reset(identity: Identity, generation: u64) -> Self {
        Self::factory_reset_for_authority(identity, generation, [0; 16])
    }

    /// Create a replacement identity bound to one normalized control
    /// authority. Restoring it for a different server is refused.
    pub fn factory_reset_for_authority(
        identity: Identity,
        generation: u64,
        authority_hash: [u8; 16],
    ) -> Self {
        let generation = generation.max(1);
        let tunnel = Device::new(identity.node.to_bytes());
        Self {
            identity,
            netmap: Netmap::new(),
            tunnel,
            paths: Vec::new(),
            registration: RegistrationState::WaitingForPersistence,
            generation,
            trusted_time_floor: 0,
            enrolled: false,
            rotation_old: None,
            authority_hash,
            persist_in_flight: false,
            control_disconnect_pending: false,
            control_endpoint: None,
            registration_body: None,
            connected_derp: Vec::new(),
            derp_connecting: Vec::new(),
            derp_disconnecting: Vec::new(),
            derp_last_failed: None,
            active_peer_derp: None,
            pending_derp: None,
            reconnect_at_ms: 0,
            reconnect_backoff_s: 1,
            direct_paths: true,
            initiate_on_demand: false,
        }
    }

    /// Restore an identity. Unknown or corrupt state fails closed.
    pub fn restore(state: &PersistState) -> Result<Self, NodeError> {
        let identity = state.identity();
        let mut node =
            Self::factory_reset_for_authority(identity, state.generation, state.authority_hash);
        node.trusted_time_floor = state.trusted_time_floor;
        node.enrolled = state.enrolled;
        node.rotation_old = state.rotation_old;
        node.registration = RegistrationState::Disconnected;
        Ok(node)
    }

    /// Restore only when state belongs to the configured control authority.
    /// Version-one state is bound and rewritten at the next generation.
    pub fn restore_for_authority(
        state: &PersistState,
        authority_hash: [u8; 16],
    ) -> Result<Self, NodeError> {
        if state.authority_hash != authority_hash && !state.legacy {
            return Err(NodeError::Persistence);
        }
        let mut node = Self::restore(state)?;
        if state.legacy {
            node.authority_hash = authority_hash;
            node.generation = node
                .generation
                .checked_add(1)
                .ok_or(NodeError::Persistence)?;
            node.registration = RegistrationState::WaitingForPersistence;
        }
        Ok(node)
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn netmap(&self) -> &Netmap<PEERS> {
        &self.netmap
    }
    pub fn registration_state(&self) -> RegistrationState {
        self.registration
    }
    pub fn requires_persistence(&self) -> bool {
        self.registration == RegistrationState::WaitingForPersistence
    }
    pub fn is_enrolled(&self) -> bool {
        self.enrolled
    }
    pub fn rotation_old_node_key(&self) -> Option<&NodePublic> {
        self.rotation_old.as_ref()
    }

    /// Stage a fresh node key and its predecessor as one durable rotation.
    ///
    /// An active control session may discover expiry after registration, so a
    /// registered node is allowed to stage the same durable replacement.
    pub fn stage_node_key_rotation(
        &mut self,
        rng: &mut impl crate::keys::Rng,
    ) -> Result<(), NodeError> {
        if !self.enrolled
            || self.rotation_old.is_some()
            || !matches!(
                self.registration,
                RegistrationState::Registering | RegistrationState::Registered
            )
        {
            return Err(NodeError::InvalidState);
        }
        self.rotation_old = Some(self.identity.node.public());
        self.identity.node = NodePrivate::generate(rng);
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(NodeError::Persistence)?;
        self.registration = RegistrationState::WaitingForPersistence;
        self.persist_in_flight = false;
        self.control_disconnect_pending = true;
        Ok(())
    }
    /// Select the credential for a registration request. After enrollment the
    /// empty string is returned even though the reusable key remains embedded
    /// in firmware for dual-slot disaster recovery.
    pub fn registration_auth_key<'a>(&self, provisioned: &'a str) -> &'a str {
        if self.enrolled { "" } else { provisioned }
    }
    pub fn trusted_time_floor(&self) -> u64 {
        self.trusted_time_floor
    }

    /// Apply the relay selected by the platform's authenticated STUN probes.
    /// The next staged delta inherits it unless the control plane explicitly
    /// sends a replacement `HomeDERP`.
    pub fn prefer_derp(&mut self, region: u16) -> Result<(), NodeError> {
        if region == 0
            || self
                .netmap
                .derp
                .region(region)
                .is_none_or(|region| !region.can_be_home())
        {
            return Err(NodeError::InvalidState);
        }
        self.netmap.home_derp = region;
        Ok(())
    }

    /// Allow or forbid direct UDP paths to peers.
    ///
    /// A node with no UDP socket at all — a browser, which has only WebSockets
    /// — disables them and becomes relay-only: no disco probes, no
    /// [`NodeAction::DirectTransmit`], and no direct candidates staged from a
    /// `CallMeMaybe`. Every packet, handshakes included, goes to the peer's
    /// DERP region, and disco pings that arrive over DERP are still answered
    /// over DERP so peers see the relay path as alive. Datagrams handed to
    /// [`Node::handle_direct_from`] are ignored, so an adapter that still
    /// drains an old socket cannot learn a direct path or answer over UDP. Such a node should
    /// publish no endpoints and a preferred DERP region, so that peers reach
    /// it through that region.
    pub fn set_direct_paths(&mut self, enabled: bool) {
        self.direct_paths = enabled;
        if !enabled {
            for path in self.paths.iter_mut() {
                Self::forget_direct(path);
            }
        }
    }

    pub fn direct_paths(&self) -> bool {
        self.direct_paths
    }

    /// Start WireGuard handshakes only with peers this node has traffic for.
    ///
    /// By default every netmap peer is an initiator, which suits a gateway
    /// that most peers reach anyway. A client in a large tailnet that talks to
    /// one peer would instead handshake with all of them, and over DERP that
    /// means a relay connection per region. With this enabled, peers start as
    /// responders and become initiators — which also makes this node
    /// responsible for rekeying them — the first time
    /// [`Node::encapsulate_ipv4`] has a packet for them. That first packet is
    /// refused with [`tunnel::Error::NoSession`]; the handshake follows from
    /// [`Node::poll_tunnel`], and the sender's own retransmission carries the
    /// data. Enable it before the first netmap is applied.
    pub fn set_initiate_on_demand(&mut self, enabled: bool) {
        self.initiate_on_demand = enabled;
    }

    fn forget_direct(path: &mut PeerPath) {
        path.direct = None;
        path.direct_healthy = false;
        path.direct_probe_pending = false;
        path.disco_tx = None;
        path.disco_attempts = 0;
    }

    pub fn set_control_endpoint(&mut self, endpoint: Endpoint) {
        self.control_endpoint = Some(endpoint);
    }

    /// Supply the next encoded registration request. It remains caller-owned
    /// until moved into a command and is zeroized after the control task drops
    /// it.
    pub fn set_registration_body(&mut self, body: &[u8]) -> Result<(), NodeError> {
        self.registration_body = Some(SecretBuffer::try_from_slice(body)?);
        Ok(())
    }

    /// Set an authenticated, nondecreasing wall-clock floor. The new floor must
    /// be atomically persisted before control traffic resumes.
    pub fn advance_trusted_time(&mut self, unix_seconds: u64) -> Result<(), NodeError> {
        if unix_seconds < self.trusted_time_floor {
            return Err(NodeError::Persistence);
        }
        if unix_seconds > self.trusted_time_floor {
            let generation = self
                .generation
                .checked_add(1)
                .ok_or(NodeError::Persistence)?;
            self.trusted_time_floor = unix_seconds;
            self.generation = generation;
            self.control_disconnect_pending |= matches!(
                self.registration,
                RegistrationState::Connecting
                    | RegistrationState::Registering
                    | RegistrationState::Registered
            );
            self.registration = RegistrationState::WaitingForPersistence;
            self.persist_in_flight = false;
        }
        Ok(())
    }

    /// Poll persistence and reconnect deadlines.
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<NodeAction>, NodeError> {
        if self.control_disconnect_pending {
            self.control_disconnect_pending = false;
            return Ok(Some(NodeAction::Control(ControlCommand::Disconnect)));
        }
        if self.registration == RegistrationState::WaitingForPersistence {
            if self.persist_in_flight {
                return Ok(None);
            }
            self.persist_in_flight = true;
            return Ok(Some(NodeAction::PersistState(PersistState::encode(
                &self.identity,
                self.generation,
                self.trusted_time_floor,
                self.enrolled,
                self.authority_hash,
                self.rotation_old.as_ref(),
            ))));
        }
        if self.registration == RegistrationState::Disconnected && now_ms >= self.reconnect_at_ms {
            let endpoint = self
                .control_endpoint
                .clone()
                .ok_or(NodeError::InvalidState)?;
            self.registration = RegistrationState::Connecting;
            return Ok(Some(NodeAction::Control(ControlCommand::Connect {
                endpoint,
            })));
        }
        Ok(None)
    }

    /// A failed atomic save never unlocks control traffic.
    pub fn persistence_result(
        &mut self,
        generation: u64,
        saved: bool,
    ) -> Result<Option<NodeAction>, NodeError> {
        if generation != self.generation {
            return Err(NodeError::StaleGeneration);
        }
        if self.registration != RegistrationState::WaitingForPersistence || !self.persist_in_flight
        {
            return Err(NodeError::InvalidState);
        }
        self.persist_in_flight = false;
        if !saved {
            return Ok(Some(NodeAction::StatusChanged(
                NodeStatus::PersistenceRequired,
            )));
        }
        self.registration = RegistrationState::Disconnected;
        Ok(Some(NodeAction::StatusChanged(NodeStatus::Offline)))
    }

    pub fn control_failed(&mut self, now_ms: u64, jitter_ms: u16) {
        let seconds = self.reconnect_backoff_s.clamp(1, 60);
        self.reconnect_at_ms =
            now_ms.saturating_add(u64::from(seconds) * 1000 + u64::from(jitter_ms));
        self.reconnect_backoff_s = seconds.saturating_mul(2).min(60);
        self.control_disconnect_pending = false;
        if self.registration != RegistrationState::WaitingForPersistence {
            self.registration = RegistrationState::Disconnected;
        }
    }

    pub fn handle_control_event(
        &mut self,
        event: ControlEvent<'_, PEERS>,
    ) -> Result<Option<NodeAction>, NodeError> {
        match event {
            ControlEvent::Connected if self.registration == RegistrationState::Connecting => {
                let body = self
                    .registration_body
                    .take()
                    .ok_or(NodeError::InvalidState)?;
                self.registration = RegistrationState::Registering;
                Ok(Some(NodeAction::Control(ControlCommand::Register { body })))
            }
            ControlEvent::Registered if self.registration == RegistrationState::Registering => {
                self.reconnect_backoff_s = 1;
                if self.enrolled {
                    if self.rotation_old.take().is_some() {
                        self.generation = self
                            .generation
                            .checked_add(1)
                            .ok_or(NodeError::Persistence)?;
                        self.registration = RegistrationState::WaitingForPersistence;
                        self.persist_in_flight = false;
                        self.control_disconnect_pending = true;
                        Ok(Some(NodeAction::StatusChanged(NodeStatus::Registered)))
                    } else {
                        self.registration = RegistrationState::Registered;
                        Ok(Some(NodeAction::Control(ControlCommand::RequestMap)))
                    }
                } else {
                    // The auth key must never cross the wire again after the
                    // first successful enrollment. Persist that fact before a
                    // map request or reconnect can happen.
                    self.enrolled = true;
                    self.generation = self
                        .generation
                        .checked_add(1)
                        .ok_or(NodeError::Persistence)?;
                    self.registration = RegistrationState::WaitingForPersistence;
                    self.persist_in_flight = false;
                    self.control_disconnect_pending = true;
                    Ok(Some(NodeAction::StatusChanged(NodeStatus::Registered)))
                }
            }
            ControlEvent::Disconnected
                if self.registration == RegistrationState::WaitingForPersistence =>
            {
                self.control_disconnect_pending = false;
                Ok(Some(NodeAction::StatusChanged(
                    NodeStatus::PersistenceRequired,
                )))
            }
            ControlEvent::Disconnected => {
                self.registration = RegistrationState::Disconnected;
                Ok(Some(NodeAction::StatusChanged(NodeStatus::Offline)))
            }
            ControlEvent::MapFinished {
                lease,
                result: Ok(()),
            } if self.registration != RegistrationState::WaitingForPersistence => {
                core::mem::swap(&mut self.netmap, lease);
                self.reconcile_peers()?;
                let status = if !self.netmap.packet_filter.is_valid() {
                    NodeStatus::MapChanged
                } else if !self.netmap.default_routes_approved() {
                    NodeStatus::AwaitingRouteApproval
                } else {
                    NodeStatus::MapActive
                };
                Ok(Some(NodeAction::StatusChanged(status)))
            }
            ControlEvent::MapFinished { result: Err(_), .. } => Ok(None),
            _ => Err(NodeError::InvalidState),
        }
    }

    /// Seed the one caller-owned staging lease before a streaming update.
    pub fn seed_staging(&self, lease: &mut Netmap<PEERS>) {
        lease.copy_from(&self.netmap);
    }

    /// Install the first map from a replacement control stream while keeping
    /// the existing tunnel sessions and path state alive through the outage.
    pub fn adopt_reconnected_map(&mut self, lease: &mut Netmap<PEERS>) -> Result<(), NodeError> {
        if self.registration == RegistrationState::WaitingForPersistence {
            return Err(NodeError::InvalidState);
        }
        self.registration = RegistrationState::Registered;
        self.reconnect_backoff_s = 1;
        core::mem::swap(&mut self.netmap, lease);
        self.reconcile_peers()
    }

    fn reconcile_peers(&mut self) -> Result<(), NodeError> {
        if self.netmap.home_derp != 0
            && self
                .netmap
                .derp
                .region(self.netmap.home_derp)
                .is_none_or(|region| !region.can_be_home())
        {
            self.netmap.home_derp = self
                .netmap
                .derp
                .iter()
                .find(|region| region.can_be_home())
                .map_or(0, |region| region.id);
        }
        self.tunnel.retain_peers(|key| {
            self.netmap
                .peers
                .iter()
                .any(|peer| peer.node_key.as_bytes() == key)
        });
        let mut next_paths = Vec::new();
        for peer in self.netmap.peers.iter() {
            if self
                .tunnel
                .peer_by_public_key(peer.node_key.as_bytes())
                .is_none()
            {
                let id = self.tunnel.add_peer(*peer.node_key.as_bytes(), None)?;
                self.tunnel.set_initiating(id, !self.initiate_on_demand)?;
            }
            let mut path = Self::path(peer);
            if let Some(previous) = self.paths.iter().find(|previous| previous.key == path.key) {
                // Preserve an authenticated, possibly NAT-translated source only
                // while the control plane continues to advertise the same path.
                // A changed or removed endpoint invalidates the old health bit.
                if previous.control_endpoints == path.control_endpoints {
                    path.direct = previous.direct;
                    path.direct_healthy = previous.direct_healthy;
                    path.direct_probe_pending = previous.direct_probe_pending;
                    if previous.disco == path.disco {
                        path.advertised = previous.advertised.clone();
                        path.disco_tx = previous.disco_tx;
                        path.disco_deadline_ms = previous.disco_deadline_ms;
                        path.disco_attempts = previous.disco_attempts;
                    }
                }
                path.relay_region = previous.relay_region;
            }
            if !self.direct_paths {
                Self::forget_direct(&mut path);
            }
            next_paths.push(path).map_err(|_| NodeError::Capacity)?;
        }
        self.paths = next_paths;
        if self
            .pending_derp
            .as_ref()
            .is_some_and(|pending| !self.paths.iter().any(|path| path.key == pending.peer))
        {
            self.pending_derp = None;
        }
        if self
            .active_peer_derp
            .is_some_and(|region| !self.paths.iter().any(|path| path.home_derp == region))
        {
            self.active_peer_derp = None;
            self.pending_derp = None;
        }
        Ok(())
    }

    fn path(peer: &Peer) -> PeerPath {
        let mut advertised = Vec::new();
        for endpoint in &peer.endpoints {
            let _ = advertised.push(*endpoint);
        }
        let direct = advertised.first().copied().map(SocketAddr::V4);
        PeerPath {
            key: peer.node_key,
            control_endpoints: advertised.clone(),
            advertised,
            direct,
            direct_healthy: false,
            direct_probe_pending: direct.is_some(),
            home_derp: peer.home_derp,
            relay_region: None,
            disco: peer.disco_key,
            disco_tx: None,
            disco_deadline_ms: 0,
            disco_attempts: 0,
        }
    }

    fn route_packet(&mut self, id: PeerId, packet: &[u8]) -> Result<NodeAction, NodeError> {
        let key = NodePublic::from_bytes(
            self.tunnel
                .peer_public_key(id)
                .ok_or(NodeError::InvalidState)?,
        );
        let direct_paths = self.direct_paths;
        let path = self
            .paths
            .iter_mut()
            .find(|p| p.key == key)
            .ok_or(NodeError::InvalidState)?;
        let handshake = matches!(
            packet.first().copied(),
            Some(tunnel::messages::TYPE_INITIATION | tunnel::messages::TYPE_RESPONSE)
        );
        let probe_direct = handshake
            && direct_paths
            && !path.direct_healthy
            && path.direct.is_some()
            && (path.direct_probe_pending || path.home_derp == 0);
        if probe_direct {
            path.direct_probe_pending = false;
        }
        if let Some(endpoint) = path.direct.filter(|_| {
            direct_paths
                && (path.direct_healthy
                    || probe_direct
                    || (path.home_derp == 0 && path.relay_region.is_none()))
        }) {
            return Ok(NodeAction::DirectTransmit {
                peer: key,
                endpoint,
                packet: SecretBuffer::try_from_slice(packet)?,
            });
        }
        let region = if path.home_derp != 0
            && (path.relay_region.is_none() || self.connected_derp.contains(&path.home_derp))
        {
            path.home_derp
        } else {
            path.relay_region.unwrap_or(0)
        };
        self.route_relay(key, region, packet)
    }

    fn route_relay(
        &mut self,
        key: NodePublic,
        region: u16,
        packet: &[u8],
    ) -> Result<NodeAction, NodeError> {
        if region == 0 {
            return Err(NodeError::NoPath);
        }
        if !self.connected_derp.contains(&region) {
            if self.pending_derp.is_some() {
                return Err(NodeError::Capacity);
            }
            self.active_peer_derp = Some(region);
            self.pending_derp = Some(PendingDerp {
                region,
                peer: key,
                packet: SecretBuffer::try_from_slice(packet)?,
            });
            return self.poll_derp()?.ok_or(NodeError::InvalidState);
        }
        // A queued packet is the in-progress handoff. Keep its region
        // required while the old connected region drains, otherwise a packet
        // for that old region can switch the required set back and strand the
        // queued packet.
        if self.pending_derp.is_none() {
            self.active_peer_derp = Some(region);
        }
        Ok(NodeAction::Derp(DerpCommand::Send {
            region,
            peer: key,
            packet: SecretBuffer::try_from_slice(packet)?,
        }))
    }

    fn observe_direct(&mut self, id: PeerId, source: SocketAddr) -> Result<(), NodeError> {
        let key = NodePublic::from_bytes(
            self.tunnel
                .peer_public_key(id)
                .ok_or(NodeError::InvalidState)?,
        );
        let path = self
            .paths
            .iter_mut()
            .find(|path| path.key == key)
            .ok_or(NodeError::InvalidState)?;
        Self::learn_direct_path(path, source, false);
        Ok(())
    }

    fn learn_direct_path(path: &mut PeerPath, source: SocketAddr, probe_completed: bool) {
        // Traffic on the existing working path does not answer a probe of
        // refreshed candidates. Keep that round, including its transaction,
        // until a matching pong or a newly observed path completes it.
        let preserve_probe = path.direct_healthy
            && path.direct == Some(source)
            && path.direct_probe_pending
            && !probe_completed;
        path.direct = Some(source);
        path.direct_healthy = true;
        if !preserve_probe {
            path.direct_probe_pending = false;
            path.disco_tx = None;
            path.disco_attempts = 0;
        }
    }

    fn observe_relay(&mut self, peer: NodePublic, region: u16) -> Result<(), NodeError> {
        let path = self
            .paths
            .iter_mut()
            .find(|path| path.key == peer)
            .ok_or(NodeError::InvalidState)?;
        // An authenticated WireGuard packet arriving over DERP is stronger
        // reachability evidence than a direct endpoint learned earlier. The
        // peer may have just lost UDP; keep the response on the working relay
        // until a later authenticated direct packet proves UDP works again.
        path.direct_healthy = false;
        path.direct_probe_pending = false;
        path.relay_region = Some(region);
        Ok(())
    }

    /// Forget that a peer was reachable through a region, because the relay
    /// itself says it no longer holds a connection for that peer.
    ///
    /// The region stays in the map and stays connected — other peers may still
    /// be there. Only this peer's learned relay is cleared, so the next packet
    /// falls back to its advertised home region or a direct path instead of
    /// being written into a relay that will discard it.
    pub fn forget_relay(&mut self, peer: &NodePublic, region: u16) {
        if let Some(path) = self
            .paths
            .iter_mut()
            .find(|path| &path.key == peer && path.relay_region == Some(region))
        {
            path.relay_region = None;
            // Let the direct candidate be tried once more: a peer that dropped
            // off the relay has often moved rather than vanished.
            if path.direct.is_some() {
                path.direct_probe_pending = true;
                // A prior discovery round may have exhausted every advertised
                // endpoint. PeerGone makes that same candidate eligible again,
                // so clear the completed/in-flight round as well.
                path.disco_tx = None;
                path.disco_deadline_ms = 0;
                path.disco_attempts = 0;
            }
        }
        if self.active_peer_derp == Some(region)
            && !self
                .paths
                .iter()
                .any(|path| path.relay_region == Some(region))
        {
            self.active_peer_derp = None;
        }
    }

    /// Mark a formerly working direct path unhealthy so subsequent packets use
    /// the peer's home DERP, when one is advertised, until authenticated direct
    /// traffic is seen again.
    pub fn mark_direct_unhealthy(&mut self, peer: &NodePublic) -> Result<(), NodeError> {
        let path = self
            .paths
            .iter_mut()
            .find(|path| &path.key == peer)
            .ok_or(NodeError::InvalidState)?;
        path.direct_healthy = false;
        path.direct_probe_pending = false;
        Ok(())
    }

    /// Ask an authenticated peer to probe our current endpoints. CallMeMaybe
    /// travels only over DERP so both NATs can open their outbound mappings.
    /// The platform supplies the same endpoints it published to control.
    /// At most the first eight candidates are advertised, as in the decoder.
    pub fn call_me_maybe(
        &mut self,
        peer: &NodePublic,
        endpoints: &[SocketAddr],
        rng: &mut impl crate::disco::packet::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        if !self.direct_paths || endpoints.is_empty() {
            return Ok(None);
        }
        let path = self
            .paths
            .iter()
            .find(|path| &path.key == peer)
            .ok_or(NodeError::UnknownPeer)?;
        let disco = path.disco.ok_or(NodeError::InvalidState)?;
        let region = path.relay_region.unwrap_or(path.home_derp);
        let mut candidates = Vec::new();
        for endpoint in endpoints.iter().take(crate::disco::message::MAX_ENDPOINTS) {
            candidates.push(*endpoint).unwrap();
        }
        let message = crate::disco::Message::CallMeMaybe(crate::disco::CallMeMaybe {
            endpoints: candidates,
        });
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let len = message.encode(&mut plaintext)?;
        let mut packet = [0; crate::disco::MAX_PACKET];
        let len = crate::disco::seal(
            &self.identity.disco,
            &self.identity.disco.public(),
            &disco,
            &plaintext[..len],
            rng,
            &mut packet,
        )?;
        self.route_relay(*peer, region, &packet[..len]).map(Some)
    }

    /// Emit at most one authenticated direct-path probe. Three unanswered
    /// attempts bound each discovery round before DERP fallback takes over.
    /// Peers observed on a relay get a fresh round after a ten-second pause,
    /// allowing a previously blocked or expired NAT mapping to recover.
    pub fn poll_disco(
        &mut self,
        now_ms: u64,
        rng: &mut impl crate::disco::packet::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        if !self.direct_paths {
            return Ok(None);
        }
        for path in &mut self.paths {
            if !path.direct_healthy
                && path.relay_region.is_some()
                && !path.advertised.is_empty()
                && usize::from(path.disco_attempts) >= path.advertised.len().saturating_mul(3)
                && now_ms >= path.disco_deadline_ms.saturating_add(10_000)
            {
                path.disco_attempts = 0;
                path.disco_tx = None;
            }
        }
        let Some(index) = self.paths.iter().position(|path| {
            (!path.direct_healthy || path.direct_probe_pending)
                && !path.advertised.is_empty()
                && path.disco.is_some()
                && usize::from(path.disco_attempts) < path.advertised.len().saturating_mul(3)
                && (path.disco_tx.is_none() || now_ms >= path.disco_deadline_ms)
        }) else {
            return Ok(None);
        };

        let mut tx_id = [0; 12];
        rng.fill_bytes(&mut tx_id);
        let peer = self.paths[index].key;
        let endpoint_index =
            usize::from(self.paths[index].disco_attempts) % self.paths[index].advertised.len();
        let endpoint = SocketAddr::V4(self.paths[index].advertised[endpoint_index]);
        let disco = self.paths[index].disco.ok_or(NodeError::InvalidState)?;
        let ping = crate::disco::Message::Ping(crate::disco::Ping {
            tx_id,
            node_key: Some(self.identity.node.public()),
        });
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let plaintext_len = ping.encode(&mut plaintext)?;
        let mut packet = [0; crate::disco::MAX_PACKET];
        let packet_len = crate::disco::seal(
            &self.identity.disco,
            &self.identity.disco.public(),
            &disco,
            &plaintext[..plaintext_len],
            rng,
            &mut packet,
        )?;
        self.paths[index].disco_tx = Some(tx_id);
        self.paths[index].disco_deadline_ms = now_ms.saturating_add(1_000);
        self.paths[index].disco_attempts += 1;
        Ok(Some(NodeAction::DirectTransmit {
            peer,
            endpoint,
            packet: SecretBuffer::try_from_slice(&packet[..packet_len])?,
        }))
    }

    /// Return one due DERP connection command. DNS and TCP remain the adapter's
    /// responsibility.
    pub fn poll_derp(&mut self) -> Result<Option<NodeAction>, NodeError> {
        if let Some(region) = self.connected_derp.iter().copied().find(|region| {
            !self.derp_region_required(*region) && !self.derp_disconnecting.contains(region)
        }) {
            self.derp_disconnecting
                .push(region)
                .map_err(|_| NodeError::Capacity)?;
            return Ok(Some(NodeAction::Derp(DerpCommand::Disconnect { region })));
        }
        if let Some((index, region)) = self
            .derp_connecting
            .iter()
            .copied()
            .enumerate()
            .find(|(_, region)| !self.derp_region_required(*region))
        {
            self.derp_connecting.swap_remove(index);
            if !self.derp_disconnecting.contains(&region) {
                self.derp_disconnecting
                    .push(region)
                    .map_err(|_| NodeError::Capacity)?;
            }
            return Ok(Some(NodeAction::Derp(DerpCommand::Disconnect { region })));
        }
        if !self.derp_disconnecting.is_empty() {
            return Ok(None);
        }
        let required = self.required_derp_regions();
        let eligible = |region: &u16| {
            *region != 0
                && !self.connected_derp.contains(region)
                && !self.derp_connecting.contains(region)
        };
        let Some(region) = required
            .iter()
            .copied()
            .find(|region| eligible(region) && Some(*region) != self.derp_last_failed)
            .or_else(|| required.iter().copied().find(eligible))
        else {
            return Ok(None);
        };
        let relay = self
            .netmap
            .derp
            .region(region)
            .and_then(|region| region.nodes.iter().find(|node| node.port != 0))
            .ok_or(NodeError::InvalidState)?;
        let mut endpoint = Endpoint::new(relay.host_name.as_str(), relay.port)?
            .with_tls_name(self.netmap.derp.cert_name(relay))?;
        endpoint.insecure_for_tests = relay.insecure_for_tests();
        self.derp_connecting
            .push(region)
            .map_err(|_| NodeError::Capacity)?;
        Ok(Some(NodeAction::Derp(DerpCommand::Connect {
            region,
            endpoint,
        })))
    }

    fn derp_region_required(&self, region: u16) -> bool {
        self.required_derp_regions().contains(&region)
    }

    fn required_derp_regions(&self) -> Vec<u16, 2> {
        let mut required = Vec::new();
        if self.netmap.home_derp != 0 {
            let _ = required.push(self.netmap.home_derp);
        }
        let active_peer_derp = self
            .paths
            .iter()
            .filter_map(|path| path.relay_region)
            .find(|region| *region != 0 && !required.contains(region));
        // What the peers themselves name as their home. This outranks the
        // compatibility rendezvous below: on a tailnet with dozens of regions
        // the first map entry is almost never where the peers are, so
        // connecting there means tearing the slot down again as soon as real
        // traffic starts — extra round trips, and `Capacity` drops for a
        // second peer caught mid-handoff.
        let peer_home_derp = self
            .paths
            .iter()
            .map(|path| path.home_derp)
            .find(|region| *region != 0 && !required.contains(region));
        // Headscale can temporarily advertise the first DERP-map region to
        // other peers while the node's own map already carries its measured
        // HomeDERP. Keep that deterministic compatibility rendezvous as the
        // last resort, for when no peer has told us anything at all.
        let compatibility_derp = self
            .netmap
            .derp
            .iter()
            .filter(|region| region.can_be_home())
            .map(|region| region.id)
            .find(|region| *region != 0 && !required.contains(region));
        let peer_derp = self
            .active_peer_derp
            .filter(|region| !required.contains(region))
            .or(active_peer_derp)
            .or(peer_home_derp)
            .or(compatibility_derp);
        if let Some(peer_derp) = peer_derp.filter(|region| !required.contains(region)) {
            let _ = required.push(peer_derp);
        }
        required
    }

    /// Control-plane conditions for enabling the IPv4 forwarding path. Wi-Fi
    /// and NAT initialization are firmware-owned conditions checked by the
    /// actor before it emits `exit-ready`.
    pub fn exit_control_ready(&self) -> bool {
        self.netmap.has_assigned_ipv4()
            && self.netmap.packet_filter.is_valid()
            && self.netmap.default_routes_approved()
            && self.netmap.home_derp != 0
            && self.connected_derp.contains(&self.netmap.home_derp)
    }

    pub fn handle_derp_event(
        &mut self,
        event: DerpEvent<'_>,
        now_ms: u64,
        rng: &mut (impl tunnel::Rng + crate::disco::packet::Rng),
    ) -> Result<Option<NodeAction>, NodeError> {
        match event {
            DerpEvent::Connected { region } => {
                if self.derp_last_failed == Some(region) {
                    self.derp_last_failed = None;
                }
                if let Some(index) = self.derp_connecting.iter().position(|item| *item == region) {
                    self.derp_connecting.swap_remove(index);
                }
                if self.derp_disconnecting.contains(&region) || !self.derp_region_required(region) {
                    if !self.derp_disconnecting.contains(&region) {
                        self.derp_disconnecting
                            .push(region)
                            .map_err(|_| NodeError::Capacity)?;
                    }
                    return Ok(Some(NodeAction::Derp(DerpCommand::Disconnect { region })));
                }
                if !self.connected_derp.contains(&region) {
                    self.connected_derp
                        .push(region)
                        .map_err(|_| NodeError::Capacity)?;
                }
                if self
                    .pending_derp
                    .as_ref()
                    .is_some_and(|pending| pending.region == region)
                {
                    let pending = self.pending_derp.take().unwrap();
                    return Ok(Some(NodeAction::Derp(DerpCommand::Send {
                        region: pending.region,
                        peer: pending.peer,
                        packet: pending.packet,
                    })));
                }
                Ok(Some(NodeAction::StatusChanged(NodeStatus::DerpConnected)))
            }
            DerpEvent::Disconnected { region } => {
                if self.derp_region_required(region) {
                    self.derp_last_failed = Some(region);
                } else if self.derp_last_failed == Some(region) {
                    self.derp_last_failed = None;
                }
                if let Some(index) = self.connected_derp.iter().position(|item| *item == region) {
                    self.connected_derp.swap_remove(index);
                }
                if let Some(index) = self.derp_connecting.iter().position(|item| *item == region) {
                    self.derp_connecting.swap_remove(index);
                }
                if let Some(index) = self
                    .derp_disconnecting
                    .iter()
                    .position(|item| *item == region)
                {
                    self.derp_disconnecting.swap_remove(index);
                }
                if let Some(nodes) = self
                    .netmap
                    .derp
                    .region_mut(region)
                    .map(|region| region.nodes.as_mut_slice())
                    && nodes.len() > 1
                {
                    nodes.rotate_left(1);
                }
                self.poll_derp()
            }
            DerpEvent::Packet {
                region,
                peer,
                payload,
            } => {
                if crate::disco::is_disco(payload) {
                    return self.handle_disco_via_derp(region, peer, payload, rng);
                }
                let expected = self
                    .tunnel
                    .peer_by_public_key(peer.as_bytes())
                    .ok_or(NodeError::UnknownPeer)?;
                let mut out = [0; MAX_ACTION_PACKET];
                let action = self.tunnel.handle_udp_from_peer(
                    expected,
                    payload,
                    Instant(now_ms),
                    rng,
                    &mut out,
                )?;
                self.observe_relay(peer, region)?;
                match action {
                    TunnelAction::None => Ok(None),
                    TunnelAction::Authenticated { .. } => Ok(None),
                    TunnelAction::Send { data, .. } => {
                        Ok(Some(NodeAction::Derp(DerpCommand::Send {
                            region,
                            peer,
                            packet: SecretBuffer::try_from_slice(data)?,
                        })))
                    }
                    TunnelAction::Receive { packet, .. } => Ok(Some(NodeAction::DeliveredIpv4 {
                        peer,
                        packet: SecretBuffer::try_from_slice(packet)?,
                    })),
                }
            }
        }
    }

    /// CallMeMaybe is the one disco message defined to travel only over DERP.
    /// Bind its authenticated disco sender to the DERP-attributed node key
    /// before accepting any candidate, then let the normal bounded direct
    /// probe loop establish whether that candidate really works.
    fn handle_disco_via_derp(
        &mut self,
        region: u16,
        peer: NodePublic,
        datagram: &[u8],
        rng: &mut impl crate::disco::packet::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        let claimed = crate::disco::packet::sender_key(datagram)?;
        let index = self
            .paths
            .iter()
            .position(|path| path.key == peer && path.disco == Some(claimed))
            .ok_or(NodeError::UnknownPeer)?;
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let opened = crate::disco::open(&self.identity.disco, &claimed, datagram, &mut plaintext)?;
        match crate::disco::Message::decode(&plaintext[..opened.len])? {
            // A relay-only node has nothing to probe a candidate with.
            crate::disco::Message::CallMeMaybe(_) if !self.direct_paths => Ok(None),
            crate::disco::Message::CallMeMaybe(call) => {
                let mut endpoints = Vec::new();
                for endpoint in call
                    .endpoints
                    .iter()
                    .copied()
                    .filter_map(|endpoint| match endpoint {
                        SocketAddr::V4(endpoint) => Some(endpoint),
                        SocketAddr::V6(_) => None,
                    })
                {
                    let _ = endpoints.push(endpoint);
                }
                if let Some(endpoint) = endpoints.first().copied() {
                    self.paths[index].advertised = endpoints;
                    // Candidate advertisements are not evidence that the
                    // authenticated direct path stopped working. Keep that
                    // path (including a NAT-translated source absent from the
                    // advertisement) while probing the new candidates.
                    if !self.paths[index].direct_healthy {
                        self.paths[index].direct = Some(SocketAddr::V4(endpoint));
                    }
                    self.paths[index].direct_probe_pending = true;
                    self.paths[index].disco_tx = None;
                    self.paths[index].disco_attempts = 0;
                }
                Ok(None)
            }
            crate::disco::Message::Ping(ping) => {
                if ping.node_key.is_some_and(|node| node != peer) {
                    return Err(NodeError::InvalidState);
                }
                // A disco ping can be mirrored over DERP while direct path
                // discovery is in progress. Answer over the same authenticated
                // relay; the synthetic address is never learned as a UDP path.
                let pong = crate::disco::Message::Pong(crate::disco::Pong {
                    tx_id: ping.tx_id,
                    src: SocketAddr::V4(core::net::SocketAddrV4::new(
                        core::net::Ipv4Addr::new(127, 3, 3, 40),
                        region,
                    )),
                });
                let mut encoded = [0; crate::disco::MAX_PACKET];
                let encoded_len = pong.encode(&mut encoded)?;
                let mut packet = [0; crate::disco::MAX_PACKET];
                let packet_len = crate::disco::seal(
                    &self.identity.disco,
                    &self.identity.disco.public(),
                    &claimed,
                    &encoded[..encoded_len],
                    rng,
                    &mut packet,
                )?;
                Ok(Some(NodeAction::Derp(DerpCommand::Send {
                    region,
                    peer,
                    packet: SecretBuffer::try_from_slice(&packet[..packet_len])?,
                })))
            }
            // A pong received over DERP proves the relay path, not a direct
            // endpoint, so it must not mark any UDP candidate healthy.
            crate::disco::Message::Pong(_) => Ok(None),
        }
    }

    pub fn handle_direct(
        &mut self,
        datagram: &[u8],
        now_ms: u64,
        rng: &mut impl tunnel::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        let mut out = [0; MAX_ACTION_PACKET];
        match self
            .tunnel
            .handle_udp(datagram, Instant(now_ms), rng, &mut out)?
        {
            TunnelAction::None => Ok(None),
            TunnelAction::Authenticated { .. } => Ok(None),
            TunnelAction::Send { peer, data } => self.route_packet(peer, data).map(Some),
            TunnelAction::Receive { peer, packet } => {
                let key = NodePublic::from_bytes(
                    self.tunnel
                        .peer_public_key(peer)
                        .ok_or(NodeError::InvalidState)?,
                );
                Ok(Some(NodeAction::DeliveredIpv4 {
                    peer: key,
                    packet: SecretBuffer::try_from_slice(packet)?,
                }))
            }
        }
    }

    /// Process a direct datagram and mark its authenticated peer's source as a
    /// healthy direct path before routing any response.
    pub fn handle_direct_from(
        &mut self,
        datagram: &[u8],
        source: SocketAddr,
        now_ms: u64,
        rng: &mut (impl tunnel::Rng + crate::disco::packet::Rng),
    ) -> Result<Option<NodeAction>, NodeError> {
        if !self.direct_paths {
            return Ok(None);
        }
        if crate::disco::is_disco(datagram) {
            return self.handle_disco_from(datagram, source, rng);
        }
        let mut out = [0; MAX_ACTION_PACKET];
        match self
            .tunnel
            .handle_udp(datagram, Instant(now_ms), rng, &mut out)?
        {
            TunnelAction::None => Ok(None),
            TunnelAction::Authenticated { peer } => {
                self.observe_direct(peer, source)?;
                Ok(None)
            }
            TunnelAction::Send { peer, data } => {
                self.observe_direct(peer, source)?;
                self.route_packet(peer, data).map(Some)
            }
            TunnelAction::Receive { peer, packet } => {
                self.observe_direct(peer, source)?;
                let key = NodePublic::from_bytes(
                    self.tunnel
                        .peer_public_key(peer)
                        .ok_or(NodeError::InvalidState)?,
                );
                Ok(Some(NodeAction::DeliveredIpv4 {
                    peer: key,
                    packet: SecretBuffer::try_from_slice(packet)?,
                }))
            }
        }
    }

    fn handle_disco_from(
        &mut self,
        datagram: &[u8],
        source: SocketAddr,
        rng: &mut impl crate::disco::packet::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        let claimed = crate::disco::packet::sender_key(datagram)?;
        if !self.paths.iter().any(|path| path.disco == Some(claimed)) {
            return Err(NodeError::UnknownPeer);
        }
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let opened = crate::disco::open(&self.identity.disco, &claimed, datagram, &mut plaintext)?;
        match crate::disco::Message::decode(&plaintext[..opened.len])? {
            crate::disco::Message::Pong(pong) => {
                let index = self
                    .paths
                    .iter()
                    .position(|path| {
                        path.disco == Some(claimed) && path.disco_tx == Some(pong.tx_id)
                    })
                    .ok_or(NodeError::InvalidState)?;
                Self::learn_direct_path(&mut self.paths[index], source, true);
                Ok(None)
            }
            crate::disco::Message::Ping(ping) => {
                let index = self
                    .disco_path_index(claimed, ping.node_key)
                    .ok_or(NodeError::InvalidState)?;
                Self::learn_direct_path(&mut self.paths[index], source, false);
                let peer = self.paths[index].key;
                let pong = crate::disco::Message::Pong(crate::disco::Pong {
                    tx_id: ping.tx_id,
                    src: source,
                });
                let mut encoded = [0; crate::disco::MAX_PACKET];
                let encoded_len = pong.encode(&mut encoded)?;
                let mut packet = [0; crate::disco::MAX_PACKET];
                let packet_len = crate::disco::seal(
                    &self.identity.disco,
                    &self.identity.disco.public(),
                    &claimed,
                    &encoded[..encoded_len],
                    rng,
                    &mut packet,
                )?;
                Ok(Some(NodeAction::DirectTransmit {
                    peer,
                    endpoint: source,
                    packet: SecretBuffer::try_from_slice(&packet[..packet_len])?,
                }))
            }
            crate::disco::Message::CallMeMaybe(_) => Err(NodeError::InvalidState),
        }
    }

    fn disco_path_index(
        &self,
        disco: crate::keys::DiscoPublic,
        node: Option<NodePublic>,
    ) -> Option<usize> {
        if let Some(node) = node {
            return self
                .paths
                .iter()
                .position(|path| path.disco == Some(disco) && path.key == node);
        }
        let mut matches = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| path.disco == Some(disco))
            .map(|(index, _)| index);
        let index = matches.next()?;
        matches.next().is_none().then_some(index)
    }

    /// Encrypt an inner IPv4 packet for a configured peer.
    pub fn encapsulate_ipv4(
        &mut self,
        peer: &NodePublic,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<Option<NodeAction>, NodeError> {
        let id = self
            .tunnel
            .peer_by_public_key(peer.as_bytes())
            .ok_or(NodeError::InvalidState)?;
        if self.initiate_on_demand {
            self.tunnel.set_initiating(id, true)?;
        }
        let mut out = [0; MAX_ACTION_PACKET];
        match self
            .tunnel
            .encapsulate(id, packet, Instant(now_ms), &mut out)?
        {
            TunnelAction::None => Ok(None),
            TunnelAction::Authenticated { .. } => Err(NodeError::InvalidState),
            TunnelAction::Send { peer, data } => self.route_packet(peer, data).map(Some),
            TunnelAction::Receive { .. } => Err(NodeError::InvalidState),
        }
    }

    /// Poll WireGuard keepalive and session-expiry timers.
    pub fn poll_tunnel_timers(&mut self, now_ms: u64) -> Result<Option<NodeAction>, NodeError> {
        let mut out = [0; MAX_ACTION_PACKET];
        match self.tunnel.poll_timers(Instant(now_ms), &mut out) {
            TunnelAction::None => Ok(None),
            TunnelAction::Authenticated { .. } => Err(NodeError::InvalidState),
            TunnelAction::Send { peer, data } => self.route_packet(peer, data).map(Some),
            TunnelAction::Receive { .. } => Err(NodeError::InvalidState),
        }
    }

    pub fn poll_tunnel(
        &mut self,
        now_ms: u64,
        tai64n: &Tai64n,
        rng: &mut impl tunnel::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        let mut out = [0; MAX_ACTION_PACKET];
        match self
            .tunnel
            .poll_handshakes(Instant(now_ms), tai64n, rng, &mut out)
        {
            TunnelAction::None => Ok(None),
            TunnelAction::Authenticated { .. } => Err(NodeError::InvalidState),
            TunnelAction::Send { peer, data } => self.route_packet(peer, data).map(Some),
            TunnelAction::Receive { .. } => Err(NodeError::InvalidState),
        }
    }
}

/// Static-dispatch adapter for control and DERP connections.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Error;
    type Stream<'a>: embedded_io_async::Read + embedded_io_async::Write
    where
        Self: 'a;

    async fn connect<'a>(
        &'a mut self,
        endpoint: &Endpoint,
    ) -> Result<Self::Stream<'a>, Self::Error>;
}

/// A session owns its stream and has no reference to a [`Node`].
pub struct ControlSession<S> {
    stream: S,
}

impl<S> ControlSession<S> {
    pub async fn connect<'a, T: Transport>(
        transport: &'a mut T,
        endpoint: &Endpoint,
    ) -> Result<ControlSession<T::Stream<'a>>, T::Error> {
        Ok(ControlSession {
            stream: transport.connect(endpoint).await?,
        })
    }
    pub fn stream(&mut self) -> &mut S {
        &mut self.stream
    }
}

/// A DERP session has the same ownership boundary as a control session.
pub struct DerpSession<S> {
    stream: S,
}

impl<S> DerpSession<S> {
    pub async fn connect<'a, T: Transport>(
        transport: &'a mut T,
        endpoint: &Endpoint,
    ) -> Result<DerpSession<T::Stream<'a>>, T::Error> {
        Ok(DerpSession {
            stream: transport.connect(endpoint).await?,
        })
    }
    pub fn stream(&mut self) -> &mut S {
        &mut self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Counter(u8);
    impl crate::keys::Rng for Counter {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }
    impl tunnel::Rng for Counter {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            crate::keys::Rng::fill_bytes(self, out);
        }
    }
    impl crate::disco::packet::Rng for Counter {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            crate::keys::Rng::fill_bytes(self, out);
        }
    }

    #[test]
    fn persistence_must_be_acknowledged_before_connecting() {
        let mut node = Node::<4>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        node.set_control_endpoint(Endpoint::new("control.example", 443).unwrap());
        let state = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => panic!("persistence must be first"),
        };
        assert!(node.poll(0).unwrap().is_none());
        node.persistence_result(state.generation(), true).unwrap();
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ));
    }

    #[test]
    fn control_failures_cannot_bypass_required_persistence() {
        let mut node = Node::<4>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        node.set_control_endpoint(Endpoint::new("control.example", 443).unwrap());
        let state = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        };

        node.control_failed(100, 7);
        assert!(node.requires_persistence());
        assert!(matches!(
            node.handle_control_event(ControlEvent::Disconnected)
                .unwrap(),
            Some(NodeAction::StatusChanged(NodeStatus::PersistenceRequired))
        ));
        assert!(node.requires_persistence());
        assert!(node.poll(2_000).unwrap().is_none());

        node.persistence_result(state.generation(), true).unwrap();
        assert!(matches!(
            node.poll(2_000).unwrap(),
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ));
    }

    #[test]
    fn corrupt_state_fails_closed() {
        assert!(PersistState::from_bytes(&[0; PersistState::BLOB_LEN]).is_err());

        let identity = Identity::generate(&mut Counter(9));
        let state = PersistState::encode(&identity, 1, 0, false, [3; 16], None);
        let mut corrupt = [0; PersistState::BLOB_LEN];
        corrupt.copy_from_slice(state.as_bytes());
        corrupt[42] ^= 1;
        assert!(PersistState::from_bytes(&corrupt).is_err());
    }

    #[test]
    fn persisted_identity_is_bound_to_the_control_authority() {
        let authority = [7; 16];
        let mut node = Node::<1>::factory_reset_for_authority(
            Identity::generate(&mut Counter(1)),
            3,
            authority,
        );
        let state = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        };
        assert!(Node::<1>::restore_for_authority(&state, authority).is_ok());
        assert!(Node::<1>::restore_for_authority(&state, [8; 16]).is_err());
    }

    #[test]
    fn version_one_state_preserves_identity_and_migrates_for_the_current_authority() {
        let identity = Identity::generate(&mut Counter(20));
        let expected = identity.node.public();
        let mut legacy = [0; PersistState::LEGACY_BLOB_LEN];
        legacy[..4].copy_from_slice(b"TFST");
        legacy[4] = 1;
        legacy[5..13].copy_from_slice(&5u64.to_le_bytes());
        legacy[13..21].copy_from_slice(&99u64.to_le_bytes());
        legacy[21..53].copy_from_slice(&identity.machine.to_bytes());
        legacy[53..85].copy_from_slice(&identity.node.to_bytes());
        legacy[85..117].copy_from_slice(&identity.disco.to_bytes());
        let checksum = tunnel::crypto::hash(&[&legacy[..PersistState::LEGACY_PAYLOAD_LEN]]);
        legacy[PersistState::LEGACY_PAYLOAD_LEN..].copy_from_slice(&checksum[..16]);

        let state = PersistState::from_bytes(&legacy).unwrap();
        let authority = [4; 16];
        let mut node = Node::<1>::restore_for_authority(&state, authority).unwrap();
        assert_eq!(node.identity().node.public(), expected);
        assert!(node.requires_persistence());
        let migrated = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        };
        assert_eq!(migrated.generation(), 6);
        assert_eq!(migrated.authority_hash(), authority);
        assert_eq!(migrated.as_bytes()[4], PersistState::VERSION);
    }

    #[test]
    fn default_node_fits_device_budget() {
        assert!(
            core::mem::size_of::<Node<32>>() <= 64 * 1024,
            "Node<32> is {} bytes",
            core::mem::size_of::<Node<32>>()
        );
        assert!(
            core::mem::size_of::<Netmap<32>>() <= 32 * 1024,
            "Netmap<32> is {} bytes",
            core::mem::size_of::<Netmap<32>>()
        );
    }

    #[test]
    fn registration_and_map_lease_lifecycle_is_explicit() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        node.set_control_endpoint(Endpoint::new("control.example", 443).unwrap());
        node.set_registration_body(b"synthetic registration")
            .unwrap();

        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ));
        let register = node
            .handle_control_event(ControlEvent::Connected)
            .unwrap()
            .unwrap();
        match register {
            NodeAction::Control(ControlCommand::Register { body }) => {
                assert_eq!(body.as_slice(), b"synthetic registration");
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            node.handle_control_event(ControlEvent::Registered).unwrap(),
            Some(NodeAction::StatusChanged(NodeStatus::Registered))
        ));
        assert!(node.is_enrolled());
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Disconnect))
        ));
        let enrolled = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        };
        assert!(enrolled.enrolled());
        node.persistence_result(enrolled.generation(), true)
            .unwrap();
        node.set_registration_body(b"registration without auth")
            .unwrap();
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ));
        node.handle_control_event(ControlEvent::Connected).unwrap();
        assert!(matches!(
            node.handle_control_event(ControlEvent::Registered).unwrap(),
            Some(NodeAction::Control(ControlCommand::RequestMap))
        ));

        let mut lease = Netmap::<2>::new();
        lease
            .peers
            .upsert(Peer::new(7, NodePrivate::from_bytes([77; 32]).public()))
            .unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Err(crate::netmap::Error::Json),
        })
        .unwrap();
        assert!(node.netmap().peers.is_empty());
        assert_eq!(lease.peers.len(), 1);

        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert_eq!(node.netmap().peers.len(), 1);
        assert!(
            lease.peers.is_empty(),
            "the same lease now holds the old map"
        );
    }

    #[test]
    fn trusted_time_disconnects_and_blocks_maps_until_persisted() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        node.set_control_endpoint(Endpoint::new("control.example", 443).unwrap());
        node.set_registration_body(b"{}").unwrap();
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();
        node.poll(0).unwrap();
        node.handle_control_event(ControlEvent::Connected).unwrap();
        node.handle_control_event(ControlEvent::Registered).unwrap();

        node.advance_trusted_time(1_000).unwrap();
        let mut lease = Netmap::new();
        assert_eq!(
            node.handle_control_event(ControlEvent::MapFinished {
                lease: &mut lease,
                result: Ok(()),
            })
            .unwrap_err(),
            NodeError::InvalidState
        );
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Disconnect))
        ));
        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::PersistState(_))
        ));
    }

    #[test]
    fn auth_key_is_suppressed_as_soon_as_enrollment_succeeds() {
        let mut node = Node::<1>::factory_reset(Identity::generate(&mut Counter(2)), 1);
        assert_eq!(
            node.registration_auth_key("provisioned-credential"),
            "provisioned-credential"
        );
        node.registration = RegistrationState::Registering;
        node.handle_control_event(ControlEvent::Registered).unwrap();
        assert_eq!(node.registration_auth_key("provisioned-credential"), "");
        let debug = std::format!("{:?}", node.poll(0).unwrap());
        assert!(!debug.contains("provisioned-credential"));
    }

    #[test]
    fn node_key_rotation_is_staged_and_cleared_durably() {
        let mut node = Node::<1>::factory_reset(Identity::generate(&mut Counter(30)), 4);
        node.enrolled = true;
        node.registration = RegistrationState::Registered;
        let old = node.identity.node.public();
        node.stage_node_key_rotation(&mut Counter(40)).unwrap();
        assert_eq!(node.rotation_old_node_key(), Some(&old));
        assert_ne!(node.identity.node.public(), old);

        assert!(matches!(
            node.poll(0).unwrap(),
            Some(NodeAction::Control(ControlCommand::Disconnect))
        ));
        node.handle_control_event(ControlEvent::Disconnected)
            .unwrap();
        let staged = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        };
        let mut restored = Node::<1>::restore(&staged).unwrap();
        assert_eq!(restored.rotation_old_node_key(), Some(&old));

        restored.registration = RegistrationState::Registering;
        assert!(matches!(
            restored
                .handle_control_event(ControlEvent::Registered)
                .unwrap(),
            Some(NodeAction::StatusChanged(NodeStatus::Registered))
        ));
        assert!(restored.rotation_old_node_key().is_none());
        assert!(restored.requires_persistence());
    }

    #[test]
    fn a_new_direct_endpoint_is_probed_before_derp_fallback() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let endpoint: core::net::SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, NodePrivate::from_bytes([77; 32]).public());
        peer.home_derp = 9;
        peer.endpoints.push(endpoint).unwrap();
        lease.peers.upsert(peer).unwrap();
        let cert_name = lease.derp.intern_cert_name("certificate.example").unwrap();
        let mut nodes = heapless::Vec::new();
        nodes
            .push(crate::netmap::DerpNode {
                host_name: heapless::String::try_from("derp.example").unwrap(),
                cert_name: Some(cert_name),
                port: 443,
                stun_port: 3478,
            })
            .unwrap();
        lease
            .derp
            .insert(crate::netmap::DerpRegion {
                id: 9,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            })
            .unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        assert!(matches!(
            node.poll_tunnel(0, &[0; 12], &mut Counter(1)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint: sent, .. }) if sent == SocketAddr::V4(endpoint)
        ));
        let Some(NodeAction::Derp(DerpCommand::Connect {
            region: 9,
            endpoint,
        })) = node
            .poll_tunnel(tunnel::timers::REKEY_TIMEOUT_MS, &[1; 12], &mut Counter(2))
            .unwrap()
        else {
            panic!("DERP fallback must connect");
        };
        assert_eq!(endpoint.host.as_str(), "derp.example");
        assert_eq!(
            endpoint.tls_name.as_ref().map(|name| name.as_str()),
            Some("certificate.example")
        );
        assert!(matches!(
            node.handle_derp_event(DerpEvent::Connected { region: 9 }, 0, &mut Counter(3))
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Send { region: 9, .. }))
        ));
    }

    #[test]
    fn disco_learns_a_path_only_from_an_authenticated_expected_pong() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let peer_disco = DiscoPrivate::from_bytes([88; 32]);
        let peer_disco_public = peer_disco.public();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, NodePrivate::from_bytes([77; 32]).public());
        peer.disco_key = Some(peer_disco_public);
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        let probe = node.poll_disco(0, &mut Counter(9)).unwrap().unwrap();
        let NodeAction::DirectTransmit { packet, .. } = probe else {
            unreachable!()
        };
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let opened = crate::disco::open(
            &peer_disco,
            &node.identity.disco.public(),
            packet.as_slice(),
            &mut plaintext,
        )
        .unwrap();
        let crate::disco::Message::Ping(ping) =
            crate::disco::Message::decode(&plaintext[..opened.len]).unwrap()
        else {
            unreachable!()
        };

        let pong = crate::disco::Message::Pong(crate::disco::Pong {
            tx_id: ping.tx_id,
            src: "203.0.113.20:41641".parse().unwrap(),
        });
        let encoded_len = pong.encode(&mut plaintext).unwrap();
        let mut datagram = [0; crate::disco::MAX_PACKET];
        let datagram_len = crate::disco::seal(
            &peer_disco,
            &peer_disco_public,
            &node.identity.disco.public(),
            &plaintext[..encoded_len],
            &mut Counter(20),
            &mut datagram,
        )
        .unwrap();
        let source = "198.51.100.4:40000".parse().unwrap();
        assert!(
            node.handle_direct_from(&datagram[..datagram_len], source, 10, &mut Counter(30),)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.paths[0].direct, Some(source));
        assert!(node.paths[0].direct_healthy);
    }

    #[test]
    fn disco_rotates_candidates_preserves_deltas_and_skips_exhausted_peers() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let first: SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let second: SocketAddrV4 = "198.51.100.10:41641".parse().unwrap();
        let later: SocketAddrV4 = "203.0.113.10:41641".parse().unwrap();
        let first_disco = DiscoPrivate::from_bytes([87; 32]).public();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, NodePrivate::from_bytes([77; 32]).public());
        peer.disco_key = Some(first_disco);
        peer.endpoints.push(first).unwrap();
        peer.endpoints.push(second).unwrap();
        lease.peers.upsert(peer).unwrap();
        let mut peer = Peer::new(8, NodePrivate::from_bytes([78; 32]).public());
        peer.disco_key = Some(DiscoPrivate::from_bytes([88; 32]).public());
        peer.endpoints.push(later).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        assert_eq!(
            node.disco_path_index(
                first_disco,
                Some(NodePrivate::from_bytes([99; 32]).public())
            ),
            None,
            "a modern ping must not fall back to its disco key when its node key is wrong"
        );

        assert!(matches!(
            node.poll_disco(0, &mut Counter(9)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == SocketAddr::V4(first)
        ));
        let transaction = node.paths[0].disco_tx;
        node.seed_staging(&mut lease);
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert_eq!(node.paths[0].disco_attempts, 1);
        assert_eq!(node.paths[0].disco_tx, transaction);
        assert!(matches!(
            node.poll_disco(1_000, &mut Counter(10)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == SocketAddr::V4(second)
        ));

        node.paths[0].disco_attempts = 6;
        assert!(matches!(
            node.poll_disco(2_000, &mut Counter(11)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == SocketAddr::V4(later)
        ));
    }

    #[test]
    fn peer_gone_restarts_exhausted_direct_discovery() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let peer_key = NodePrivate::from_bytes([77; 32]).public();
        let endpoint: SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, peer_key);
        peer.disco_key = Some(DiscoPrivate::from_bytes([88; 32]).public());
        peer.endpoints.push(endpoint).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        node.paths[0].relay_region = Some(9);
        node.paths[0].direct_probe_pending = false;
        node.paths[0].disco_tx = Some([0x55; 12]);
        node.paths[0].disco_deadline_ms = 10_000;
        node.paths[0].disco_attempts = 3;

        node.forget_relay(&peer_key, 9);

        assert!(node.paths[0].direct_probe_pending);
        assert_eq!(node.paths[0].disco_tx, None);
        assert_eq!(node.paths[0].disco_attempts, 0);
        assert!(matches!(
            node.poll_disco(0, &mut Counter(9)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint: got, .. })
                if got == SocketAddr::V4(endpoint)
        ));
    }

    #[test]
    fn call_me_maybe_preserves_an_authenticated_working_direct_path() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let peer_key = NodePrivate::from_bytes([77; 32]).public();
        let peer_disco = DiscoPrivate::from_bytes([88; 32]);
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, peer_key);
        peer.disco_key = Some(peer_disco.public());
        peer.home_derp = 9;
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        let source: SocketAddr = "198.51.100.10:50123".parse().unwrap();
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let mut datagram = [0; crate::disco::MAX_PACKET];
        let ping = crate::disco::Message::Ping(crate::disco::Ping {
            tx_id: [3; 12],
            node_key: Some(peer_key),
        });
        let len = ping.encode(&mut plaintext).unwrap();
        let len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..len],
            &mut Counter(20),
            &mut datagram,
        )
        .unwrap();
        let ping_datagram = datagram;
        let ping_len = len;
        node.handle_direct_from(&datagram[..len], source, 10, &mut Counter(30))
            .unwrap();
        assert!(node.paths[0].direct_healthy);
        let advertised: SocketAddrV4 = "203.0.113.20:41641".parse().unwrap();
        let mut endpoints = heapless::Vec::new();
        endpoints.push(SocketAddr::V4(advertised)).unwrap();
        let message = crate::disco::Message::CallMeMaybe(crate::disco::CallMeMaybe { endpoints });
        let len = message.encode(&mut plaintext).unwrap();
        let len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..len],
            &mut Counter(40),
            &mut datagram,
        )
        .unwrap();
        node.handle_derp_event(
            DerpEvent::Packet {
                region: 9,
                peer: peer_key,
                payload: &datagram[..len],
            },
            20,
            &mut Counter(50),
        )
        .unwrap();
        assert_eq!(node.paths[0].advertised.as_slice(), &[advertised]);
        assert_eq!(node.paths[0].direct, Some(source));
        assert!(node.paths[0].direct_healthy);
        // An unrelated control delta still contains the original control
        // endpoints, not the candidates just received through discovery.
        node.seed_staging(&mut lease);
        lease.peers.get_mut(7).unwrap().home_derp = 10;
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert_eq!(node.paths[0].direct, Some(source));
        assert!(node.paths[0].direct_healthy);
        assert_eq!(node.paths[0].advertised.as_slice(), &[advertised]);
        let id = node.tunnel.peer_by_public_key(peer_key.as_bytes()).unwrap();
        // A rekey handshake stays on the working path and must not cancel
        // the independently requested candidate probe.
        assert!(
            matches!(node.route_packet(id, &[tunnel::messages::TYPE_INITIATION]).unwrap(),
            NodeAction::DirectTransmit { endpoint, .. } if endpoint == source)
        );
        // Both authenticated WireGuard traffic and disco pings from the
        // current endpoint must leave refreshed-candidate discovery intact.
        node.observe_direct(id, source).unwrap();
        node.handle_direct_from(&ping_datagram[..ping_len], source, 21, &mut Counter(55))
            .unwrap();
        assert!(matches!(node.poll_disco(21, &mut Counter(60)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == SocketAddr::V4(advertised)));
        let tx_id = node.paths[0].disco_tx.unwrap();
        node.seed_staging(&mut lease);
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        node.observe_direct(id, source).unwrap();
        node.handle_direct_from(&ping_datagram[..ping_len], source, 22, &mut Counter(65))
            .unwrap();
        assert_eq!(node.paths[0].disco_tx, Some(tx_id));
        assert_eq!(node.paths[0].disco_attempts, 1);
        assert!(
            matches!(node.route_packet(id, &[tunnel::messages::TYPE_DATA]).unwrap(),
            NodeAction::DirectTransmit { endpoint, .. } if endpoint == source)
        );
        let pong = crate::disco::Message::Pong(crate::disco::Pong {
            tx_id: node.paths[0].disco_tx.unwrap(),
            src: SocketAddr::V4(advertised),
        });
        let len = pong.encode(&mut plaintext).unwrap();
        let len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..len],
            &mut Counter(80),
            &mut datagram,
        )
        .unwrap();
        node.handle_direct_from(
            &datagram[..len],
            SocketAddr::V4(advertised),
            1022,
            &mut Counter(90),
        )
        .unwrap();
        assert_eq!(node.paths[0].direct, Some(SocketAddr::V4(advertised)));
        assert!(node.paths[0].direct_healthy);
        assert!(!node.paths[0].direct_probe_pending);
        assert_eq!(node.paths[0].disco_tx, None);
        node.seed_staging(&mut lease);
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert_eq!(node.paths[0].direct, Some(SocketAddr::V4(advertised)));
        assert!(node.paths[0].direct_healthy);
        node.mark_direct_unhealthy(&peer_key).unwrap();
        assert!(matches!(node.poll_disco(1023, &mut Counter(100)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == SocketAddr::V4(advertised)));
    }

    #[test]
    fn authenticated_call_me_maybe_from_derp_stages_a_bounded_direct_probe() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let peer_key = NodePrivate::from_bytes([77; 32]).public();
        let peer_disco = DiscoPrivate::from_bytes([88; 32]);
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, peer_key);
        peer.disco_key = Some(peer_disco.public());
        peer.home_derp = 9;
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        let candidate: SocketAddr = "198.51.100.20:50123".parse().unwrap();
        let mut endpoints = heapless::Vec::new();
        endpoints.push(candidate).unwrap();
        let message = crate::disco::Message::CallMeMaybe(crate::disco::CallMeMaybe { endpoints });
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let plaintext_len = message.encode(&mut plaintext).unwrap();
        let mut datagram = [0; crate::disco::MAX_PACKET];
        let datagram_len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..plaintext_len],
            &mut Counter(20),
            &mut datagram,
        )
        .unwrap();

        assert!(
            node.handle_derp_event(
                DerpEvent::Packet {
                    region: 9,
                    peer: peer_key,
                    payload: &datagram[..datagram_len],
                },
                10,
                &mut Counter(30),
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(node.paths[0].direct, Some(candidate));
        assert!(matches!(
            node.poll_disco(10, &mut Counter(40)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint, .. }) if endpoint == candidate
        ));
        assert_eq!(
            node.handle_direct_from(
                &datagram[..datagram_len],
                "203.0.113.10:40000".parse().unwrap(),
                10,
                &mut Counter(41),
            )
            .err(),
            Some(NodeError::InvalidState)
        );
        assert_eq!(node.paths[0].direct, Some(candidate));

        let tx_id = [0x5a; 12];
        let ping = crate::disco::Message::Ping(crate::disco::Ping {
            tx_id,
            node_key: Some(peer_key),
        });
        let ping_len = ping.encode(&mut plaintext).unwrap();
        let ping_datagram_len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..ping_len],
            &mut Counter(50),
            &mut datagram,
        )
        .unwrap();
        let action = node
            .handle_derp_event(
                DerpEvent::Packet {
                    region: 9,
                    peer: peer_key,
                    payload: &datagram[..ping_datagram_len],
                },
                11,
                &mut Counter(60),
            )
            .unwrap()
            .unwrap();
        let NodeAction::Derp(DerpCommand::Send {
            region,
            peer,
            packet,
        }) = action
        else {
            panic!("a DERP disco ping must be answered over DERP");
        };
        assert_eq!(region, 9);
        assert_eq!(peer, peer_key);
        let mut opened = [0; crate::disco::MAX_PACKET];
        let pong = crate::disco::open(
            &peer_disco,
            &node.identity.disco.public(),
            packet.as_slice(),
            &mut opened,
        )
        .unwrap();
        assert!(matches!(
            crate::disco::Message::decode(&opened[..pong.len]).unwrap(),
            crate::disco::Message::Pong(crate::disco::Pong { tx_id: got, .. }) if got == tx_id
        ));

        let stranger = NodePrivate::from_bytes([99; 32]).public();
        assert_eq!(
            node.handle_derp_event(
                DerpEvent::Packet {
                    region: 9,
                    peer: stranger,
                    payload: &datagram[..datagram_len],
                },
                11,
                &mut Counter(50),
            )
            .err(),
            // Not `InvalidState`: nothing is wrong with this node's state. The
            // sender is simply not a peer we hold, which on a bounded device is
            // ordinarily a truncated netmap rather than a fault.
            Some(NodeError::UnknownPeer)
        );
    }

    #[test]
    fn a_direct_only_peer_keeps_retrying_its_advertised_endpoint() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let endpoint: core::net::SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, NodePrivate::from_bytes([77; 32]).public());
        peer.endpoints.push(endpoint).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        for (now, timestamp) in [(0, [0; 12]), (tunnel::timers::REKEY_TIMEOUT_MS, [1; 12])] {
            assert!(matches!(
                node.poll_tunnel(now, &timestamp, &mut Counter(1)).unwrap(),
                Some(NodeAction::DirectTransmit { endpoint: sent, .. }) if sent == SocketAddr::V4(endpoint)
            ));
        }
    }

    #[test]
    fn an_unhealthy_direct_only_peer_keeps_sending_data_directly() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let key = NodePrivate::from_bytes([77; 32]).public();
        let endpoint: core::net::SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, key);
        peer.endpoints.push(endpoint).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        node.paths[0].direct_healthy = true;
        node.mark_direct_unhealthy(&key).unwrap();
        let id = node.tunnel.peer_by_public_key(key.as_bytes()).unwrap();

        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::DirectTransmit { endpoint: sent, .. } if sent == SocketAddr::V4(endpoint)
        ));
    }

    #[test]
    fn an_authenticated_inbound_derp_region_routes_before_home_derp_arrives() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let key = NodePrivate::from_bytes([77; 32]).public();
        let mut lease = Netmap::<2>::new();
        lease.peers.upsert(Peer::new(7, key)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        node.paths[0].direct = Some("192.0.2.10:41641".parse().unwrap());
        node.paths[0].direct_healthy = true;
        node.observe_relay(key, 9).unwrap();
        assert!(!node.paths[0].direct_healthy);
        node.netmap.home_derp = 22;
        node.connected_derp.push(9).unwrap();
        assert_eq!(node.required_derp_regions().as_slice(), &[22, 9]);
        let id = node.tunnel.peer_by_public_key(key.as_bytes()).unwrap();
        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::Derp(DerpCommand::Send { region: 9, .. })
        ));

        node.paths[0].home_derp = 22;
        node.paths[0].direct = Some("192.0.2.10:41641".parse().unwrap());
        node.paths[0].direct_healthy = true;
        node.observe_relay(key, 9).unwrap();
        assert!(!node.paths[0].direct_healthy);
        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::Derp(DerpCommand::Send { region: 9, .. })
        ));
        node.connected_derp.push(22).unwrap();
        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::Derp(DerpCommand::Send { region: 22, .. })
        ));
    }

    #[test]
    fn a_changed_advertised_endpoint_invalidates_the_old_direct_path() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let key = NodePrivate::from_bytes([77; 32]).public();
        let first: core::net::SocketAddrV4 = "192.0.2.10:41641".parse().unwrap();
        let learned: SocketAddr = "198.51.100.10:50123".parse().unwrap();
        let replacement: core::net::SocketAddrV4 = "192.0.2.11:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, key);
        peer.endpoints.push(first).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        let id = node.tunnel.peer_by_public_key(key.as_bytes()).unwrap();
        node.observe_direct(id, learned).unwrap();
        assert!(node.paths[0].direct_healthy);

        node.seed_staging(&mut lease);
        let peer = lease.peers.get_mut(7).unwrap();
        peer.endpoints.clear();
        peer.endpoints.push(replacement).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        assert_eq!(node.paths[0].advertised.as_slice(), &[replacement]);
        assert_eq!(node.paths[0].direct, Some(SocketAddr::V4(replacement)));
        assert!(!node.paths[0].direct_healthy);
    }

    /// On a map with many regions the first entry is a rendezvous of last
    /// resort, not a guess at where anyone is. Preferring it over a peer's
    /// advertised home meant the second slot always opened in the wrong place
    /// and had to be torn down as soon as that peer was actually addressed.
    #[test]
    fn a_peers_advertised_home_outranks_the_first_map_region() {
        fn region(id: u16) -> crate::netmap::DerpRegion {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(crate::netmap::DerpNode {
                    host_name: heapless::String::try_from("derp.example").unwrap(),
                    cert_name: None,
                    port: 443,
                    stun_port: 3478,
                })
                .unwrap();
            crate::netmap::DerpRegion {
                id,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            }
        }

        let mut node = Node::<16>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let mut map = Netmap::<16>::new();
        // Our own home is 9; the map's first region is 1; both peers live in 7.
        map.home_derp = 9;
        for region_id in [1, 7, 9] {
            map.derp.insert(region(region_id)).unwrap();
        }
        for index in 0..2u8 {
            let mut peer = Peer::new(
                u64::from(index) + 1,
                NodePrivate::from_bytes([index + 1; 32]).public(),
            );
            peer.home_derp = 7;
            map.peers.upsert(peer).unwrap();
        }
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut map,
            result: Ok(()),
        })
        .unwrap();

        assert_eq!(
            node.required_derp_regions().as_slice(),
            &[9, 7],
            "our home, then where the peers say they are — never region 1"
        );
    }

    #[test]
    fn insecure_derp_keeps_its_certificate_name() {
        let mut node = Node::<1>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let mut map = Netmap::<1>::new();
        map.home_derp = 9;
        let cert_name = map.derp.intern_cert_name("certificate.example").unwrap();
        let mut relay = crate::netmap::DerpNode {
            host_name: heapless::String::try_from("derp.example").unwrap(),
            cert_name: Some(cert_name),
            port: 443,
            stun_port: 3478,
        };
        relay.mark_insecure_for_tests();
        let mut nodes = heapless::Vec::new();
        nodes.push(relay).unwrap();
        map.derp
            .insert(crate::netmap::DerpRegion {
                id: 9,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            })
            .unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut map,
            result: Ok(()),
        })
        .unwrap();

        let Some(NodeAction::Derp(DerpCommand::Connect { endpoint, .. })) =
            node.poll_derp().unwrap()
        else {
            panic!("home DERP must connect");
        };
        assert_eq!(endpoint.host.as_str(), "derp.example");
        assert_eq!(
            endpoint.tls_name.as_ref().map(|name| name.as_str()),
            Some("certificate.example")
        );
        assert!(endpoint.insecure_for_tests);
    }

    #[test]
    fn only_home_and_active_peer_derp_are_kept_connected() {
        fn region(id: u16) -> crate::netmap::DerpRegion {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(crate::netmap::DerpNode {
                    host_name: heapless::String::try_from("derp.example").unwrap(),
                    cert_name: None,
                    port: 443,
                    stun_port: 3478,
                })
                .unwrap();
            crate::netmap::DerpRegion {
                id,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            }
        }

        let mut node = Node::<16>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let mut initial = Netmap::<16>::new();
        initial.home_derp = 1;
        for region_id in 1..=3 {
            let mut peer = Peer::new(
                u64::from(region_id),
                NodePrivate::from_bytes([region_id as u8; 32]).public(),
            );
            peer.home_derp = region_id;
            initial.peers.upsert(peer).unwrap();
            initial.derp.insert(region(region_id)).unwrap();
        }
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut initial,
            result: Ok(()),
        })
        .unwrap();
        for region_id in 1..=2 {
            node.handle_derp_event(
                DerpEvent::Connected { region: region_id },
                0,
                &mut Counter(1),
            )
            .unwrap();
        }
        assert_eq!(node.connected_derp.as_slice(), &[1, 2]);
        assert!(matches!(
            node.handle_derp_event(DerpEvent::Connected { region: 3 }, 0, &mut Counter(1)),
            Ok(Some(NodeAction::Derp(DerpCommand::Disconnect {
                region: 3
            })))
        ));
        node.handle_derp_event(DerpEvent::Disconnected { region: 3 }, 0, &mut Counter(1))
            .unwrap();

        let replacement_id = 4;
        let mut replacement = Netmap::<16>::new();
        replacement.home_derp = 3;
        let mut peer = Peer::new(4, NodePrivate::from_bytes([99; 32]).public());
        peer.home_derp = replacement_id;
        replacement.peers.upsert(peer).unwrap();
        replacement.derp.insert(region(3)).unwrap();
        replacement.derp.insert(region(replacement_id)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut replacement,
            result: Ok(()),
        })
        .unwrap();

        let mut disconnected = heapless::Vec::<u16, 2>::new();
        let mut action = node.poll_derp().unwrap().unwrap();
        for _ in 0..2 {
            let NodeAction::Derp(DerpCommand::Disconnect { region }) = action else {
                panic!("obsolete regions must disconnect before a replacement connects");
            };
            disconnected.push(region).unwrap();
            action = node
                .handle_derp_event(DerpEvent::Disconnected { region }, 0, &mut Counter(1))
                .unwrap()
                .unwrap();
        }
        assert!(disconnected.contains(&1));
        assert!(disconnected.contains(&2));

        assert!(matches!(
            action,
            NodeAction::Derp(DerpCommand::Connect {
                region,
                ..
            }) if region == 3
        ));
    }

    #[test]
    fn control_provided_ineligible_home_is_replaced_on_both_map_paths() {
        for stun_only in [false, true] {
            for reconnected in [false, true] {
                let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
                persisted(&mut node);
                let mut lease = Netmap::new();
                lease.home_derp = 1;
                let mut excluded = relay_region(1);
                if stun_only {
                    excluded.nodes[0].port = 0;
                } else {
                    excluded.no_measure_no_home = true;
                }
                lease.derp.insert(excluded).unwrap();
                lease.derp.insert(relay_region(9)).unwrap();
                if reconnected {
                    node.adopt_reconnected_map(&mut lease).unwrap();
                } else {
                    node.handle_control_event(ControlEvent::MapFinished {
                        lease: &mut lease,
                        result: Ok(()),
                    })
                    .unwrap();
                }
                assert_eq!(node.netmap().home_derp, 9);
                assert!(matches!(
                    node.poll_derp().unwrap(),
                    Some(NodeAction::Derp(DerpCommand::Connect { region: 9, .. }))
                ));
            }
        }
    }

    #[test]
    fn no_home_region_is_skipped_for_rendezvous_but_allowed_for_a_peer() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let mut lease = Netmap::new();
        lease.home_derp = 9;
        let mut peer_only = relay_region(1);
        peer_only.no_measure_no_home = true;
        lease.derp.insert(peer_only).unwrap();
        lease.derp.insert(relay_region(9)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert!(matches!(node.prefer_derp(1), Err(NodeError::InvalidState)));
        node.prefer_derp(9).unwrap();
        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 9, .. }))
        ));
        node.handle_derp_event(DerpEvent::Connected { region: 9 }, 0, &mut Counter(1))
            .unwrap();
        assert!(node.poll_derp().unwrap().is_none());
        let mut lease = node.netmap().clone();
        let mut peer = Peer::new(2, NodePrivate::from_bytes([2; 32]).public());
        peer.home_derp = 1;
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 1, .. }))
        ));
    }

    #[test]
    fn standalone_stun_region_cannot_block_relay_backup_after_a_dial_failure() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let mut lease = Netmap::new();
        lease.home_derp = 9;
        let mut stun = relay_region(1);
        stun.nodes[0].port = 0;
        lease.derp.insert(stun).unwrap();
        let mut relay = relay_region(9);
        let mut backup = relay.nodes[0].clone();
        backup.port = 8443;
        relay.nodes[0].port = 8444;
        relay.nodes.push(backup).unwrap();
        lease.derp.insert(relay).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert!(matches!(node.prefer_derp(1), Err(NodeError::InvalidState)));
        assert!(
            matches!(node.poll_derp().unwrap(), Some(NodeAction::Derp(DerpCommand::Connect { region: 9, endpoint })) if endpoint.port == 8444)
        );
        assert!(
            matches!(node.handle_derp_event(DerpEvent::Disconnected { region: 9 }, 0, &mut Counter(1)).unwrap(), Some(NodeAction::Derp(DerpCommand::Connect { region: 9, endpoint })) if endpoint.port == 8443)
        );
        assert!(node.poll_derp().unwrap().is_none());
    }

    #[test]
    fn failed_home_derp_does_not_block_the_peer_region() {
        fn region(id: u16) -> crate::netmap::DerpRegion {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(crate::netmap::DerpNode {
                    host_name: heapless::String::try_from("derp.example").unwrap(),
                    cert_name: None,
                    port: 443,
                    stun_port: 3478,
                })
                .unwrap();
            crate::netmap::DerpRegion {
                id,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            }
        }

        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let mut lease = Netmap::<2>::new();
        lease.home_derp = 1;
        let mut peer = Peer::new(2, NodePrivate::from_bytes([2; 32]).public());
        peer.home_derp = 2;
        lease.peers.upsert(peer).unwrap();
        lease.derp.insert(region(1)).unwrap();
        lease.derp.insert(region(2)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 1, .. }))
        ));
        assert!(matches!(
            node.handle_derp_event(DerpEvent::Disconnected { region: 1 }, 0, &mut Counter(1))
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 2, .. }))
        ));
        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 1, .. }))
        ));
        assert!(node.derp_connecting.contains(&1));
        assert!(node.derp_connecting.contains(&2));
    }

    #[test]
    fn removing_a_peer_clears_its_queued_derp_packet_when_the_region_stays() {
        fn region(id: u16) -> crate::netmap::DerpRegion {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(crate::netmap::DerpNode {
                    host_name: heapless::String::try_from("derp.example").unwrap(),
                    cert_name: None,
                    port: 443,
                    stun_port: 3478,
                })
                .unwrap();
            crate::netmap::DerpRegion {
                id,
                code: heapless::String::try_from("test").unwrap(),
                no_measure_no_home: false,
                nodes,
            }
        }

        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let removed_key = NodePrivate::from_bytes([2; 32]).public();
        let retained_key = NodePrivate::from_bytes([3; 32]).public();
        let mut lease = Netmap::<2>::new();
        for (id, key) in [(2, removed_key), (3, retained_key)] {
            let mut peer = Peer::new(id, key);
            peer.home_derp = 2;
            lease.peers.upsert(peer).unwrap();
        }
        lease.derp.insert(region(2)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        let removed_id = node
            .tunnel
            .peer_by_public_key(removed_key.as_bytes())
            .unwrap();
        assert!(matches!(
            node.route_packet(removed_id, &[4]).unwrap(),
            NodeAction::Derp(DerpCommand::Connect { region: 2, .. })
        ));
        assert_eq!(
            node.pending_derp.as_ref().map(|pending| pending.peer),
            Some(removed_key)
        );

        let mut replacement = Netmap::<2>::new();
        let mut retained = Peer::new(3, retained_key);
        retained.home_derp = 2;
        replacement.peers.upsert(retained).unwrap();
        replacement.derp.insert(region(2)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut replacement,
            result: Ok(()),
        })
        .unwrap();

        assert!(node.pending_derp.is_none());
        assert!(!matches!(
            node.handle_derp_event(DerpEvent::Connected { region: 2 }, 0, &mut Counter(1)),
            Ok(Some(NodeAction::Derp(DerpCommand::Send { .. })))
        ));
    }

    fn relay_region(id: u16) -> crate::netmap::DerpRegion {
        let mut nodes = heapless::Vec::new();
        nodes
            .push(crate::netmap::DerpNode {
                host_name: heapless::String::try_from("derp.example").unwrap(),
                cert_name: None,
                port: 443,
                stun_port: 3478,
            })
            .unwrap();
        crate::netmap::DerpRegion {
            id,
            code: heapless::String::try_from("test").unwrap(),
            no_measure_no_home: false,
            nodes,
        }
    }

    fn persisted<const PEERS: usize>(node: &mut Node<PEERS>) {
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();
    }

    #[test]
    fn outbound_call_me_maybe_uses_the_peer_relay_and_current_endpoints() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let key = NodePrivate::from_bytes([77; 32]).public();
        let disco = DiscoPrivate::from_bytes([88; 32]);
        let mut lease = Netmap::new();
        let mut peer = Peer::new(7, key);
        peer.disco_key = Some(disco.public());
        peer.home_derp = 9;
        lease.peers.upsert(peer).unwrap();
        lease.derp.insert(relay_region(9)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        // More publishable interfaces than the wire candidate bound must not
        // suppress the entire discovery message.
        let endpoints: [SocketAddr; 10] = core::array::from_fn(|index| {
            SocketAddr::from(([198, 51, 100, 20], 50123 + index as u16))
        });
        assert!(matches!(
            node.call_me_maybe(&key, &endpoints, &mut Counter(20))
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 9, .. }))
        ));
        let Some(NodeAction::Derp(DerpCommand::Send {
            region,
            peer,
            packet,
        })) = node
            .handle_derp_event(DerpEvent::Connected { region: 9 }, 0, &mut Counter(21))
            .unwrap()
        else {
            panic!("CallMeMaybe must use DERP");
        };
        assert_eq!(region, 9);
        assert_eq!(peer, key);
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let opened = crate::disco::open(
            &disco,
            &node.identity.disco.public(),
            packet.as_slice(),
            &mut plaintext,
        )
        .unwrap();
        let crate::disco::Message::CallMeMaybe(call) =
            crate::disco::Message::decode(&plaintext[..opened.len]).unwrap()
        else {
            panic!("wrong disco message");
        };
        assert_eq!(call.endpoints.as_slice(), &endpoints[..8]);
        node.set_direct_paths(false);
        assert!(
            node.call_me_maybe(&key, &endpoints, &mut Counter(21))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exhausted_direct_probes_restart_for_a_peer_seen_on_a_relay() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let key = NodePrivate::from_bytes([77; 32]).public();
        let mut peer = Peer::new(7, key);
        peer.disco_key = Some(DiscoPrivate::from_bytes([88; 32]).public());
        peer.home_derp = 9;
        peer.endpoints
            .push("198.51.100.20:50123".parse().unwrap())
            .unwrap();
        let mut lease = Netmap::new();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        for now in [0, 1000, 2000] {
            assert!(matches!(
                node.poll_disco(now, &mut Counter(20)).unwrap(),
                Some(NodeAction::DirectTransmit { .. })
            ));
        }
        assert!(node.poll_disco(3000, &mut Counter(21)).unwrap().is_none());
        // Inactive peers do not get an unbounded background probe loop.
        assert!(node.poll_disco(12_999, &mut Counter(21)).unwrap().is_none());
        node.observe_relay(key, 9).unwrap();
        assert!(node.poll_disco(12_999, &mut Counter(21)).unwrap().is_none());
        assert!(matches!(
            node.poll_disco(13_000, &mut Counter(22)).unwrap(),
            Some(NodeAction::DirectTransmit { .. })
        ));
    }

    #[test]
    fn a_relay_only_node_never_transmits_directly() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        node.set_direct_paths(false);
        assert!(!node.direct_paths());

        let peer_key = NodePrivate::from_bytes([77; 32]).public();
        let peer_disco = DiscoPrivate::from_bytes([88; 32]);
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, peer_key);
        peer.disco_key = Some(peer_disco.public());
        peer.home_derp = 9;
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        lease.derp.insert(relay_region(9)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        assert_eq!(node.paths[0].direct, None);

        // No disco probe for the advertised endpoint.
        assert!(node.poll_disco(0, &mut Counter(2)).unwrap().is_none());

        // Even the first handshake, which a direct-capable node probes
        // directly, is relayed.
        assert!(matches!(
            node.poll_tunnel(0, &[0; 12], &mut Counter(3)).unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect { region: 9, .. }))
        ));
        assert!(matches!(
            node.handle_derp_event(DerpEvent::Connected { region: 9 }, 0, &mut Counter(4))
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Send { region: 9, .. }))
        ));
        assert!(matches!(
            node.poll_tunnel(tunnel::timers::REKEY_TIMEOUT_MS, &[1; 12], &mut Counter(5))
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Send { region: 9, .. }))
        ));

        // A CallMeMaybe over DERP stages no direct candidate.
        let mut endpoints = heapless::Vec::new();
        endpoints
            .push("198.51.100.20:50123".parse().unwrap())
            .unwrap();
        let message = crate::disco::Message::CallMeMaybe(crate::disco::CallMeMaybe { endpoints });
        let mut plaintext = [0; crate::disco::MAX_PACKET];
        let plaintext_len = message.encode(&mut plaintext).unwrap();
        let mut datagram = [0; crate::disco::MAX_PACKET];
        let datagram_len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..plaintext_len],
            &mut Counter(20),
            &mut datagram,
        )
        .unwrap();
        assert!(
            node.handle_derp_event(
                DerpEvent::Packet {
                    region: 9,
                    peer: peer_key,
                    payload: &datagram[..datagram_len],
                },
                10,
                &mut Counter(30),
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(node.paths[0].direct, None);
        assert!(node.poll_disco(10, &mut Counter(31)).unwrap().is_none());

        // A disco ping over DERP is still answered over DERP.
        let ping = crate::disco::Message::Ping(crate::disco::Ping {
            tx_id: [0x5a; 12],
            node_key: Some(peer_key),
        });
        let ping_len = ping.encode(&mut plaintext).unwrap();
        let ping_datagram_len = crate::disco::seal(
            &peer_disco,
            &peer_disco.public(),
            &node.identity.disco.public(),
            &plaintext[..ping_len],
            &mut Counter(50),
            &mut datagram,
        )
        .unwrap();
        assert!(matches!(
            node.handle_derp_event(
                DerpEvent::Packet {
                    region: 9,
                    peer: peer_key,
                    payload: &datagram[..ping_datagram_len],
                },
                11,
                &mut Counter(60),
            )
            .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Send { region: 9, .. }))
        ));

        // The same ping arriving over UDP is ignored: no path is learned and
        // nothing is sent directly.
        assert!(
            node.handle_direct_from(
                &datagram[..ping_datagram_len],
                "198.51.100.20:50123".parse().unwrap(),
                12,
                &mut Counter(70),
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(node.paths[0].direct, None);
    }

    #[test]
    fn disabling_direct_paths_forgets_a_learned_one() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        let key = NodePrivate::from_bytes([77; 32]).public();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, key);
        peer.home_derp = 9;
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        lease.derp.insert(relay_region(9)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        let id = node.tunnel.peer_by_public_key(key.as_bytes()).unwrap();
        node.observe_direct(id, "198.51.100.10:50123".parse().unwrap())
            .unwrap();
        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::DirectTransmit { .. }
        ));

        node.set_direct_paths(false);
        assert!(matches!(
            node.route_packet(id, &[4]).unwrap(),
            NodeAction::Derp(DerpCommand::Connect { region: 9, .. })
        ));
    }

    #[test]
    fn a_relay_only_peer_without_a_region_has_no_path() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        node.set_direct_paths(false);
        let key = NodePrivate::from_bytes([77; 32]).public();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, key);
        peer.endpoints
            .push("192.0.2.10:41641".parse().unwrap())
            .unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();
        let id = node.tunnel.peer_by_public_key(key.as_bytes()).unwrap();
        assert_eq!(node.route_packet(id, &[4]).err(), Some(NodeError::NoPath));
    }

    #[test]
    fn on_demand_initiation_handshakes_only_with_addressed_peers() {
        let mut node = Node::<4>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        persisted(&mut node);
        node.set_direct_paths(false);
        node.set_initiate_on_demand(true);

        let wanted = NodePrivate::from_bytes([77; 32]).public();
        let idle = NodePrivate::from_bytes([78; 32]).public();
        let mut lease = Netmap::<4>::new();
        for (id, key) in [(7, wanted), (8, idle)] {
            let mut peer = Peer::new(id, key);
            peer.home_derp = 9;
            lease.peers.upsert(peer).unwrap();
        }
        lease.derp.insert(relay_region(9)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        // Nobody is addressed yet, so nobody is initiated to.
        assert!(
            node.poll_tunnel(0, &[0; 12], &mut Counter(2))
                .unwrap()
                .is_none()
        );

        // The first packet has no session; it arms the handshake instead.
        assert_eq!(
            node.encapsulate_ipv4(&wanted, &[0x45; 20], 0).err(),
            Some(NodeError::Tunnel(tunnel::Error::NoSession))
        );
        let Some(NodeAction::Derp(DerpCommand::Connect { region: 9, .. })) =
            node.poll_tunnel(0, &[1; 12], &mut Counter(3)).unwrap()
        else {
            panic!("the addressed peer is initiated to over its region");
        };
        let Some(NodeAction::Derp(DerpCommand::Send { peer, packet, .. })) = node
            .handle_derp_event(DerpEvent::Connected { region: 9 }, 0, &mut Counter(4))
            .unwrap()
        else {
            panic!("the queued initiation is sent once the region connects");
        };
        assert_eq!(peer, wanted);
        assert_eq!(
            packet.as_slice().first().copied(),
            Some(tunnel::messages::TYPE_INITIATION)
        );

        // Only the addressed peer is retried; the idle one stays a responder.
        let Some(NodeAction::Derp(DerpCommand::Send { peer, .. })) = node
            .poll_tunnel(tunnel::timers::REKEY_TIMEOUT_MS, &[2; 12], &mut Counter(5))
            .unwrap()
        else {
            panic!("the handshake is retried");
        };
        assert_eq!(peer, wanted);
        assert!(
            node.poll_tunnel(tunnel::timers::REKEY_TIMEOUT_MS, &[3; 12], &mut Counter(6))
                .unwrap()
                .is_none()
        );
    }
}
