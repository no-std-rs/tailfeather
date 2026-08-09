//! The transport-agnostic, cooperative node state machine.
//!
//! [`Node`] owns protocol state, while callers own sockets, streams, storage,
//! clocks, and executors. Each input produces at most one explicit action.

use core::net::SocketAddr;

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
}

impl Endpoint {
    pub fn new(host: &str, port: u16) -> Result<Self, NodeError> {
        Ok(Self {
            host: String::try_from(host).map_err(|_| NodeError::Capacity)?,
            port,
        })
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    Capacity,
    InvalidState,
    Persistence,
    StaleGeneration,
    Tunnel(tunnel::Error),
}

impl From<tunnel::Error> for NodeError {
    fn from(value: tunnel::Error) -> Self {
        Self::Tunnel(value)
    }
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Capacity => "a bounded node value is full",
            Self::InvalidState => "event is invalid in the current node state",
            Self::Persistence => "persisted state is corrupt or unknown",
            Self::StaleGeneration => "persistence acknowledgement is stale",
            Self::Tunnel(_) => "tunnel protocol error",
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
    blob: [u8; Self::BLOB_LEN],
}

impl PersistState {
    const MAGIC: [u8; 4] = *b"TFST";
    const VERSION: u8 = 1;
    const PAYLOAD_LEN: usize = 4 + 1 + 8 + 8 + 32 * 3;
    const CHECKSUM_LEN: usize = 16;
    pub const BLOB_LEN: usize = Self::PAYLOAD_LEN + Self::CHECKSUM_LEN;

    fn encode(identity: &Identity, generation: u64, trusted_time_floor: u64) -> Self {
        let mut blob = [0; Self::BLOB_LEN];
        blob[..4].copy_from_slice(&Self::MAGIC);
        blob[4] = Self::VERSION;
        blob[5..13].copy_from_slice(&generation.to_le_bytes());
        blob[13..21].copy_from_slice(&trusted_time_floor.to_le_bytes());
        blob[21..53].copy_from_slice(&identity.machine.to_bytes());
        blob[53..85].copy_from_slice(&identity.node.to_bytes());
        blob[85..117].copy_from_slice(&identity.disco.to_bytes());
        let checksum = tunnel::crypto::hash(&[&blob[..Self::PAYLOAD_LEN]]);
        blob[Self::PAYLOAD_LEN..].copy_from_slice(&checksum[..Self::CHECKSUM_LEN]);
        Self {
            generation,
            trusted_time_floor,
            blob,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeError> {
        if bytes.len() != Self::BLOB_LEN || bytes[..4] != Self::MAGIC || bytes[4] != Self::VERSION {
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
        if generation == 0 {
            return Err(NodeError::Persistence);
        }
        Ok(Self {
            generation,
            trusted_time_floor,
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

    fn identity(&self) -> Identity {
        let mut key = [0; 32];
        key.copy_from_slice(&self.blob[21..53]);
        let machine = MachinePrivate::from_bytes(key);
        key.copy_from_slice(&self.blob[53..85]);
        let node = NodePrivate::from_bytes(key);
        key.copy_from_slice(&self.blob[85..117]);
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

#[derive(Clone, Copy)]
struct PeerPath {
    key: NodePublic,
    /// Endpoint last advertised by the control plane. This is tracked
    /// separately from `direct`, which may have been learned from authenticated
    /// traffic after NAT translation.
    advertised: Option<SocketAddr>,
    direct: Option<SocketAddr>,
    direct_healthy: bool,
    /// Try a newly advertised endpoint once before falling back to DERP. A
    /// direct-only peer keeps using its only candidate for all traffic.
    direct_probe_pending: bool,
    home_derp: u16,
}

pub struct Node<const PEERS: usize = 32> {
    identity: Identity,
    netmap: Netmap<PEERS>,
    tunnel: Device<PEERS>,
    paths: Vec<PeerPath, PEERS>,
    registration: RegistrationState,
    generation: u64,
    trusted_time_floor: u64,
    persist_in_flight: bool,
    control_disconnect_pending: bool,
    control_endpoint: Option<Endpoint>,
    registration_body: Option<SecretBuffer<MAX_CONTROL_BODY>>,
    connected_derp: Vec<u16, { crate::netmap::MAX_DERP_REGIONS }>,
    derp_connecting: Option<u16>,
    derp_disconnecting: Vec<u16, { crate::netmap::MAX_DERP_REGIONS }>,
    reconnect_at_ms: u64,
    reconnect_backoff_s: u8,
}

impl<const PEERS: usize> Node<PEERS> {
    /// Create a replacement identity only for an explicit factory reset.
    pub fn factory_reset(identity: Identity, generation: u64) -> Self {
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
            persist_in_flight: false,
            control_disconnect_pending: false,
            control_endpoint: None,
            registration_body: None,
            connected_derp: Vec::new(),
            derp_connecting: None,
            derp_disconnecting: Vec::new(),
            reconnect_at_ms: 0,
            reconnect_backoff_s: 1,
        }
    }

    /// Restore an identity. Unknown or corrupt state fails closed.
    pub fn restore(state: &PersistState) -> Result<Self, NodeError> {
        let identity = state.identity();
        let mut node = Self::factory_reset(identity, state.generation);
        node.trusted_time_floor = state.trusted_time_floor;
        node.registration = RegistrationState::Disconnected;
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
            self.control_disconnect_pending = matches!(
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
                self.registration = RegistrationState::Registered;
                self.reconnect_backoff_s = 1;
                Ok(Some(NodeAction::Control(ControlCommand::RequestMap)))
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
                Ok(Some(NodeAction::StatusChanged(NodeStatus::MapChanged)))
            }
            ControlEvent::MapFinished { result: Err(_), .. } => Ok(None),
            _ => Err(NodeError::InvalidState),
        }
    }

    /// Seed the one caller-owned staging lease before a streaming update.
    pub fn seed_staging(&self, lease: &mut Netmap<PEERS>) {
        lease.clone_from(&self.netmap);
    }

    fn reconcile_peers(&mut self) -> Result<(), NodeError> {
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
                self.tunnel.set_initiating(id, true)?;
            }
            let mut path = Self::path(peer);
            if let Some(previous) = self.paths.iter().find(|previous| previous.key == path.key) {
                // Preserve an authenticated, possibly NAT-translated source only
                // while the control plane continues to advertise the same path.
                // A changed or removed endpoint invalidates the old health bit.
                if previous.advertised == path.advertised {
                    path.direct = previous.direct;
                    path.direct_healthy = previous.direct_healthy;
                    path.direct_probe_pending = previous.direct_probe_pending;
                }
            }
            next_paths.push(path).map_err(|_| NodeError::Capacity)?;
        }
        self.paths = next_paths;
        Ok(())
    }

    fn path(peer: &Peer) -> PeerPath {
        let advertised = peer.direct_endpoint().map(SocketAddr::V4);
        PeerPath {
            key: peer.node_key,
            advertised,
            direct: advertised,
            direct_healthy: false,
            direct_probe_pending: advertised.is_some(),
            home_derp: peer.home_derp,
        }
    }

    fn route_packet(&mut self, id: PeerId, packet: &[u8]) -> Result<NodeAction, NodeError> {
        let key = NodePublic::from_bytes(
            self.tunnel
                .peer_public_key(id)
                .ok_or(NodeError::InvalidState)?,
        );
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
            && path.direct.is_some()
            && (path.direct_probe_pending || path.home_derp == 0);
        if probe_direct {
            path.direct_probe_pending = false;
        }
        if let Some(endpoint) = path
            .direct
            .filter(|_| path.direct_healthy || probe_direct || path.home_derp == 0)
        {
            return Ok(NodeAction::DirectTransmit {
                peer: key,
                endpoint,
                packet: SecretBuffer::try_from_slice(packet)?,
            });
        }
        if path.home_derp == 0 {
            return Err(NodeError::InvalidState);
        }
        Ok(NodeAction::Derp(DerpCommand::Send {
            region: path.home_derp,
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
        path.direct = Some(source);
        path.direct_healthy = true;
        path.direct_probe_pending = false;
        Ok(())
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
        if let Some(region) = self
            .derp_connecting
            .filter(|region| !self.derp_region_required(*region))
        {
            self.derp_connecting = None;
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
        let Some(region) = self.paths.iter().map(|path| path.home_derp).find(|region| {
            *region != 0
                && !self.connected_derp.contains(region)
                && self.derp_connecting != Some(*region)
        }) else {
            return Ok(None);
        };
        let relay = self
            .netmap
            .derp
            .region(region)
            .and_then(|region| region.nodes.first())
            .ok_or(NodeError::InvalidState)?;
        let endpoint = Endpoint::new(relay.host_name.as_str(), relay.port)?;
        self.derp_connecting = Some(region);
        Ok(Some(NodeAction::Derp(DerpCommand::Connect {
            region,
            endpoint,
        })))
    }

    fn derp_region_required(&self, region: u16) -> bool {
        region != 0 && self.paths.iter().any(|path| path.home_derp == region)
    }

    pub fn handle_derp_event(
        &mut self,
        event: DerpEvent<'_>,
        now_ms: u64,
        rng: &mut impl tunnel::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
        match event {
            DerpEvent::Connected { region } => {
                if self.derp_connecting == Some(region) {
                    self.derp_connecting = None;
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
                Ok(None)
            }
            DerpEvent::Disconnected { region } => {
                if let Some(index) = self.connected_derp.iter().position(|item| *item == region) {
                    self.connected_derp.swap_remove(index);
                }
                if self.derp_connecting == Some(region) {
                    self.derp_connecting = None;
                }
                if let Some(index) = self
                    .derp_disconnecting
                    .iter()
                    .position(|item| *item == region)
                {
                    self.derp_disconnecting.swap_remove(index);
                }
                Ok(None)
            }
            DerpEvent::Packet {
                region,
                peer,
                payload,
            } => {
                let expected = self
                    .tunnel
                    .peer_by_public_key(peer.as_bytes())
                    .ok_or(NodeError::InvalidState)?;
                let mut out = [0; MAX_ACTION_PACKET];
                match self.tunnel.handle_udp_from_peer(
                    expected,
                    payload,
                    Instant(now_ms),
                    rng,
                    &mut out,
                )? {
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
        rng: &mut impl tunnel::Rng,
    ) -> Result<Option<NodeAction>, NodeError> {
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
        let state = PersistState::encode(&identity, 1, 0);
        let mut corrupt = [0; PersistState::BLOB_LEN];
        corrupt.copy_from_slice(state.as_bytes());
        corrupt[42] ^= 1;
        assert!(PersistState::from_bytes(&corrupt).is_err());
    }

    #[test]
    fn default_node_fits_device_budget() {
        assert!(core::mem::size_of::<Node<32>>() <= 64 * 1024);
        assert!(core::mem::size_of::<Netmap<32>>() <= 32 * 1024);
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
    fn a_new_direct_endpoint_is_probed_before_derp_fallback() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let endpoint: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        let mut lease = Netmap::<2>::new();
        let mut peer = Peer::new(7, NodePrivate::from_bytes([77; 32]).public());
        peer.home_derp = 9;
        peer.endpoints.push(endpoint).unwrap();
        lease.peers.upsert(peer).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut lease,
            result: Ok(()),
        })
        .unwrap();

        assert!(matches!(
            node.poll_tunnel(0, &[0; 12], &mut Counter(1)).unwrap(),
            Some(NodeAction::DirectTransmit { endpoint: sent, .. }) if sent == endpoint
        ));
        assert!(matches!(
            node.poll_tunnel(tunnel::timers::REKEY_TIMEOUT_MS, &[1; 12], &mut Counter(2),)
                .unwrap(),
            Some(NodeAction::Derp(DerpCommand::Send { region: 9, .. }))
        ));
    }

    #[test]
    fn a_direct_only_peer_keeps_retrying_its_advertised_endpoint() {
        let mut node = Node::<2>::factory_reset(Identity::generate(&mut Counter(1)), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => unreachable!(),
        };
        node.persistence_result(generation, true).unwrap();

        let endpoint: SocketAddr = "192.0.2.10:41641".parse().unwrap();
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
                Some(NodeAction::DirectTransmit { endpoint: sent, .. }) if sent == endpoint
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
        let endpoint: SocketAddr = "192.0.2.10:41641".parse().unwrap();
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
            NodeAction::DirectTransmit { endpoint: sent, .. } if sent == endpoint
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
        let first: SocketAddr = "192.0.2.10:41641".parse().unwrap();
        let learned: SocketAddr = "198.51.100.10:50123".parse().unwrap();
        let replacement: SocketAddr = "192.0.2.11:41641".parse().unwrap();
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

        assert_eq!(node.paths[0].advertised, Some(replacement));
        assert_eq!(node.paths[0].direct, Some(replacement));
        assert!(!node.paths[0].direct_healthy);
    }

    #[test]
    fn obsolete_derp_connections_are_closed_before_new_regions_connect() {
        fn region(id: u16) -> crate::netmap::DerpRegion {
            let mut nodes = heapless::Vec::new();
            nodes
                .push(crate::netmap::DerpNode {
                    host_name: heapless::String::try_from("derp.example").unwrap(),
                    port: 443,
                    stun_port: 3478,
                })
                .unwrap();
            crate::netmap::DerpRegion {
                id,
                code: heapless::String::try_from("test").unwrap(),
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
        for region_id in 1..=crate::netmap::MAX_DERP_REGIONS as u16 {
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
        for region_id in 1..=crate::netmap::MAX_DERP_REGIONS as u16 {
            node.handle_derp_event(
                DerpEvent::Connected { region: region_id },
                0,
                &mut Counter(1),
            )
            .unwrap();
        }
        assert_eq!(node.connected_derp.len(), crate::netmap::MAX_DERP_REGIONS);

        let replacement_id = 999;
        let mut replacement = Netmap::<16>::new();
        let mut peer = Peer::new(999, NodePrivate::from_bytes([99; 32]).public());
        peer.home_derp = replacement_id;
        replacement.peers.upsert(peer).unwrap();
        replacement.derp.insert(region(replacement_id)).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: &mut replacement,
            result: Ok(()),
        })
        .unwrap();

        let mut disconnected = heapless::Vec::<u16, { crate::netmap::MAX_DERP_REGIONS }>::new();
        for _ in 0..crate::netmap::MAX_DERP_REGIONS {
            let action = node.poll_derp().unwrap().unwrap();
            let NodeAction::Derp(DerpCommand::Disconnect { region }) = action else {
                panic!("obsolete regions must disconnect before a replacement connects");
            };
            disconnected.push(region).unwrap();
            node.handle_derp_event(DerpEvent::Disconnected { region }, 0, &mut Counter(1))
                .unwrap();
        }
        for region_id in 1..=crate::netmap::MAX_DERP_REGIONS as u16 {
            assert!(disconnected.contains(&region_id));
        }

        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(DerpCommand::Connect {
                region,
                ..
            })) if region == replacement_id
        ));
    }
}
