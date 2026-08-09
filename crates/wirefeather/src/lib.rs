//! A sans-io WireGuard core: `no_std`, allocation-free, and independent of any
//! particular socket API.
//!
//! # Sans-io
//!
//! [`Device`] never touches a socket, a clock, or a random number generator of
//! its own. Callers hand it received datagrams along with the current time and
//! a source of randomness, and it hands back [`Action`]s describing what should
//! be sent or delivered. That is what lets the identical code run inside an
//! Embassy task on an ESP32-C6 and under `cargo test` on a laptop.
//!
//! # Scope
//!
//! Both handshake roles are implemented. A peer is a pure responder until
//! [`Device::set_initiating`] is called for it, which is what a point-to-point
//! tunnel wants; a mesh node marks its peers as initiating and lets
//! [`Device::poll_handshakes`] drive rekeys.
//!
//! The cookie/`mac2` denial-of-service mechanism is not implemented; a
//! device-wide token bucket over handshake work stands in for it. Replay
//! protection *is* implemented in full.
//!
//! # Example
//!
//! ```
//! use wirefeather::{Device, Action, Instant, Rng};
//!
//! # struct Zeros;
//! # impl Rng for Zeros { fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(7) } }
//! # let mut rng = Zeros;
//! let mut device: Device<4> = Device::new([0x42; 32]);
//! let peer = device.add_peer([0x11; 32], None).unwrap();
//!
//! let mut out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
//! match device.poll_timers(Instant(0), &mut out) {
//!     Action::None => {}                       // nothing due yet
//!     Action::Send { peer, data } => { let _ = (peer, data); }
//!     Action::Receive { .. } => unreachable!(), // timers never deliver
//!     Action::Authenticated { .. } => unreachable!(), // nor receive input
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod budget;
pub mod crypto;
pub mod ip;
pub mod messages;
pub mod noise;
pub mod replay;
pub mod timers;
pub mod transport;

#[cfg(test)]
mod tests;

use x25519_dalek::{PublicKey, StaticSecret};

pub use budget::MAX_DATAGRAM_LEN;
pub use timers::Instant;

use crypto::{Key, TIMESTAMP_LEN};
use timers::HandshakeBudget;
use transport::Session;

/// A TAI64N timestamp, which every initiation carries.
///
/// The caller supplies it rather than the core reading a clock, for the same
/// reason `now` is injected. Unlike `now` this one must come from a *real-time*
/// clock and be comparable across reboots, because the responder rejects any
/// initiation whose timestamp is not strictly greater than the last it accepted
/// from us.
pub type Tai64n = [u8; TIMESTAMP_LEN];

/// A source of cryptographically secure random bytes.
///
/// Deliberately not `rand_core::RngCore`: this crate would then pin a
/// particular `rand_core` major version onto every consumer, and the ESP32's
/// hardware RNG and a host test's generator have nothing else in common. Only
/// ephemeral key generation and session index selection need it.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Identifies a peer previously registered with [`Device::add_peer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId(pub usize);

/// What the caller should do as a result of feeding input to a [`Device`].
#[derive(Debug)]
pub enum Action<'a> {
    /// Nothing to do.
    None,
    /// Send `data` to `peer`'s endpoint over UDP.
    Send { peer: PeerId, data: &'a [u8] },
    /// `packet` is a decrypted inner IP packet that arrived from `peer`.
    Receive { peer: PeerId, packet: &'a [u8] },
    /// An authenticated packet with no inner payload arrived from `peer`.
    ///
    /// WireGuard keepalives use this form. Surfacing the peer lets a transport
    /// adapter learn endpoint roaming from every authenticated datagram without
    /// manufacturing an empty IP packet for the application.
    Authenticated { peer: PeerId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong length, wrong type byte, or otherwise not a WireGuard message.
    Malformed,
    /// `mac1` did not match: the sender was not addressing this device.
    InvalidMac,
    /// A public key with no contributory Diffie-Hellman output.
    InvalidPublicKey,
    /// AEAD tag verification failed.
    Decryption,
    /// The initiator's static key matches no configured peer.
    UnknownPeer,
    /// No live session owns the receiver index in this packet.
    UnknownSession,
    /// The handshake timestamp was not newer than the last one seen, so this is
    /// a replayed initiation.
    StaleTimestamp,
    /// This transport counter has already been used, or is too old.
    Replay,
    /// The session is past its time or message limit.
    SessionExpired,
    /// No usable session exists for this peer yet.
    NoSession,
    /// The authenticated packet belongs to a different peer than its transport
    /// claimed. This is used when an outer relay already names the sender.
    PeerMismatch,
    /// The peer has not yet sent data over this session, so its keys are not
    /// confirmed and must not be used to send.
    Unconfirmed,
    /// Handshakes are arriving faster than the rate limit allows.
    RateLimited,
    /// The output buffer was shorter than the message to be written.
    BufferTooSmall,
    /// The device's peer table is full.
    TooManyPeers,
    /// A message type this implementation does not handle.
    Unsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed message",
            Self::InvalidMac => "invalid mac1",
            Self::InvalidPublicKey => "invalid public key",
            Self::Decryption => "decryption failed",
            Self::UnknownPeer => "unknown peer",
            Self::UnknownSession => "unknown session",
            Self::StaleTimestamp => "stale handshake timestamp",
            Self::Replay => "replayed counter",
            Self::SessionExpired => "session expired",
            Self::NoSession => "no session",
            Self::PeerMismatch => "packet authenticated as a different peer",
            Self::Unconfirmed => "session not confirmed",
            Self::RateLimited => "handshake rate limited",
            Self::BufferTooSmall => "output buffer too small",
            Self::TooManyPeers => "peer table full",
            Self::Unsupported => "unsupported message type",
        })
    }
}

impl core::error::Error for Error {}

struct Peer {
    public: PublicKey,
    preshared_key: Key,
    /// The newest TAI64N timestamp accepted from this peer. Initiations must
    /// carry strictly increasing timestamps.
    last_timestamp: Option<Tai64n>,
    current: Option<Session>,
    /// Kept briefly after a rekey so packets still in flight under the old keys
    /// are not dropped.
    previous: Option<Session>,
    /// When data last arrived with nothing sent back since, or `None` if we
    /// owe the peer nothing. See [`timers::keepalive_is_due`].
    keepalive_armed_since: Option<Instant>,
    /// Whether this device starts handshakes with this peer, rather than only
    /// answering the ones it starts.
    initiating: bool,
    /// The handshake we have in flight, if any, and when it began and was last
    /// retried.
    pending: Option<noise::Handshake>,
    pending_since: Option<Instant>,
    pending_last_sent: Option<Instant>,
}

impl Peer {
    /// Retire any session that has aged out, so expired keys are not held.
    fn expire_sessions(&mut self, now: Instant) {
        if self.current.as_ref().is_some_and(|s| !s.is_usable(now)) {
            self.current = None;
        }
        if self.previous.as_ref().is_some_and(|s| !s.is_usable(now)) {
            self.previous = None;
        }
    }

    /// Whether an initiation should be sent to this peer now.
    fn wants_handshake(&self, now: Instant) -> bool {
        if !self.initiating {
            return false;
        }
        let needs_session = match &self.current {
            None => true,
            // Rekeying starts while the old session is still carrying traffic,
            // so there is no window in which the peer is unreachable.
            Some(session) => {
                !session.is_usable(now) || timers::rekey_is_due(session.established(), now)
            }
        };
        needs_session && timers::handshake_retry_is_due(self.pending_last_sent, now)
    }

    /// Forget any in-flight handshake. Called once a session supersedes it, and
    /// on any state change that would make its ephemeral key useless.
    fn clear_pending(&mut self) {
        self.pending = None;
        self.pending_since = None;
        self.pending_last_sent = None;
    }
}

/// A WireGuard endpoint holding one static identity and up to `PEERS` peers.
///
/// `PEERS` is a const parameter rather than a fixed number because a
/// point-to-point tunnel needs one and a Tailscale mesh needs many, and neither
/// should pay for the other's table.
pub struct Device<const PEERS: usize> {
    static_private: StaticSecret,
    static_public: PublicKey,
    mac1_key: Key,
    peers: heapless::Vec<Peer, PEERS>,
    budget: HandshakeBudget,
}

impl<const PEERS: usize> Device<PEERS> {
    /// Create a device from a 32-byte X25519 private key.
    pub fn new(static_private: [u8; 32]) -> Self {
        let static_private = StaticSecret::from(static_private);
        let static_public = PublicKey::from(&static_private);
        Self {
            mac1_key: noise::mac1_key(&static_public),
            static_private,
            static_public,
            peers: heapless::Vec::new(),
            budget: HandshakeBudget::new(),
        }
    }

    /// This device's static public key, to be configured on the peer.
    pub fn public_key(&self) -> [u8; 32] {
        self.static_public.to_bytes()
    }

    /// Register a peer. `preshared_key` of `None` means plain IK, which is what
    /// WireGuard does when no PSK is configured.
    pub fn add_peer(
        &mut self,
        public: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> Result<PeerId, Error> {
        let id = PeerId(self.peers.len());
        self.peers
            .push(Peer {
                public: PublicKey::from(public),
                preshared_key: preshared_key.unwrap_or([0u8; 32]),
                last_timestamp: None,
                current: None,
                previous: None,
                keepalive_armed_since: None,
                initiating: false,
                pending: None,
                pending_since: None,
                pending_last_sent: None,
            })
            .map_err(|_| Error::TooManyPeers)?;
        Ok(id)
    }

    /// How many peers are registered.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Find a registered peer by its static public key.
    pub fn peer_by_public_key(&self, public: &[u8; 32]) -> Option<PeerId> {
        self.peers
            .iter()
            .position(|p| p.public.as_bytes() == public)
            .map(PeerId)
    }

    /// Return a peer's static public key.
    pub fn peer_public_key(&self, peer: PeerId) -> Option<[u8; 32]> {
        self.peers.get(peer.0).map(|p| p.public.to_bytes())
    }

    /// Remove peers not accepted by `keep`, preserving every accepted peer's
    /// live and previous sessions.
    ///
    /// Peer identifiers are dense indexes and may change after this call;
    /// callers should resolve them again by public key. This is intended for
    /// transactional configuration reconciliation, where keys are the stable
    /// identity and an index is only a short-lived handle.
    pub fn retain_peers(&mut self, mut keep: impl FnMut(&[u8; 32]) -> bool) {
        self.peers.retain(|peer| keep(peer.public.as_bytes()));
    }

    /// Choose whether this device starts handshakes with `peer`.
    ///
    /// Off by default, which is what a device that only ever answers wants. A
    /// node driven by a netmap turns it on: its peers are symmetric, and
    /// whichever side notices the missing session first should start.
    pub fn set_initiating(&mut self, peer: PeerId, initiating: bool) -> Result<(), Error> {
        let p = self.peers.get_mut(peer.0).ok_or(Error::UnknownPeer)?;
        p.initiating = initiating;
        if !initiating {
            p.clear_pending();
        }
        Ok(())
    }

    /// Whether a handshake with `peer` has been retrying long enough to treat
    /// the peer as unreachable.
    ///
    /// The device keeps retrying regardless — a peer that comes back should
    /// reconnect without being poked. This reports the condition so a caller can
    /// react to it, by falling back to a relayed path, for instance.
    pub fn handshake_is_stalled(&self, peer: PeerId, now: Instant) -> bool {
        self.peers
            .get(peer.0)
            .and_then(|p| p.pending_since)
            .is_some_and(|since| timers::handshake_has_expired(since, now))
    }

    /// Whether `peer` currently has a session usable for sending.
    pub fn is_connected(&self, peer: PeerId, now: Instant) -> bool {
        self.peers
            .get(peer.0)
            .and_then(|p| p.current.as_ref())
            .is_some_and(|s| s.is_usable(now) && s.is_confirmed())
    }

    /// Process one received UDP datagram.
    pub fn handle_udp<'o>(
        &mut self,
        datagram: &[u8],
        now: Instant,
        rng: &mut impl Rng,
        out: &'o mut [u8],
    ) -> Result<Action<'o>, Error> {
        self.handle_udp_inner(None, datagram, now, rng, out)
    }

    /// Process a datagram whose outer transport already authenticated its
    /// sender as `expected`.
    ///
    /// The binding is checked before peer session or replay state is changed,
    /// including for authenticated keepalives which yield
    /// [`Action::Authenticated`]. This is the entry point for DERP and similar
    /// relays.
    pub fn handle_udp_from_peer<'o>(
        &mut self,
        expected: PeerId,
        datagram: &[u8],
        now: Instant,
        rng: &mut impl Rng,
        out: &'o mut [u8],
    ) -> Result<Action<'o>, Error> {
        if self.peers.get(expected.0).is_none() {
            return Err(Error::UnknownPeer);
        }
        self.handle_udp_inner(Some(expected), datagram, now, rng, out)
    }

    fn handle_udp_inner<'o>(
        &mut self,
        expected: Option<PeerId>,
        datagram: &[u8],
        now: Instant,
        rng: &mut impl Rng,
        out: &'o mut [u8],
    ) -> Result<Action<'o>, Error> {
        match messages::message_type(datagram)? {
            messages::TYPE_INITIATION => {
                let (peer, len) = self.respond_to_initiation(expected, datagram, now, rng, out)?;
                let out: &'o [u8] = out;
                Ok(Action::Send {
                    peer,
                    data: &out[..len],
                })
            }
            messages::TYPE_DATA => {
                match self.open_data(expected, datagram, now, out)? {
                    Some((peer, len)) => {
                        let out: &'o [u8] = out;
                        Ok(Action::Receive {
                            peer,
                            packet: &out[..len],
                        })
                    }
                    // A keepalive: correctly authenticated, but carrying
                    // nothing to deliver. The peer still matters because the
                    // outer source may be a newly roamed endpoint.
                    None => Ok(Action::Authenticated {
                        peer: self.peer_for_data(datagram)?,
                    }),
                }
            }
            messages::TYPE_RESPONSE => {
                let peer = self.complete_handshake(expected, datagram, now)?;
                // The responder cannot send until it has seen a packet open
                // under the new keys, so the initiator owes it one immediately.
                // Without this the tunnel is one-way until the first packet the
                // *initiator* happens to send, which for an idle peer is never.
                let session = self.peers[peer.0]
                    .current
                    .as_mut()
                    .expect("the handshake just installed a session");
                let len = session.seal(&[], out)?;
                self.peers[peer.0].keepalive_armed_since = None;
                let out: &'o [u8] = out;
                Ok(Action::Send {
                    peer,
                    data: &out[..len],
                })
            }
            // We never issue cookies, so a cookie reply is meaningless to us.
            // Dropping it costs a handshake retry, which the timers already do.
            messages::TYPE_COOKIE_REPLY => Err(Error::Unsupported),
            _ => Err(Error::Malformed),
        }
    }

    /// Start a handshake with `peer`, writing an initiation into `out`.
    ///
    /// Any handshake already in flight for this peer is abandoned, and its
    /// ephemeral key with it. Existing sessions are left alone: they stay usable
    /// until the new handshake completes, so a rekey does not interrupt traffic.
    pub fn start_handshake(
        &mut self,
        peer: PeerId,
        now: Instant,
        timestamp: &Tai64n,
        rng: &mut impl Rng,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self.peers.get(peer.0).is_none() {
            return Err(Error::UnknownPeer);
        }
        if !self.budget.take(now) {
            return Err(Error::RateLimited);
        }

        let local_index = self.allocate_index(rng);
        let ephemeral = self.random_secret(rng);
        let static_private = self.static_private.clone();
        let static_public = self.static_public;

        let p = &mut self.peers[peer.0];
        let (len, handshake) = noise::create_initiation(
            &static_private,
            &static_public,
            &p.public,
            local_index,
            &ephemeral,
            timestamp,
            out,
        )?;

        // Keep the moment the *attempt* began across retries, so the stall
        // report measures how long the peer has been unreachable rather than
        // how long since the last packet.
        p.pending_since.get_or_insert(now);
        p.pending_last_sent = Some(now);
        p.pending = Some(handshake);
        Ok(len)
    }

    /// Emit at most one due handshake initiation.
    ///
    /// Call repeatedly until it returns [`Action::None`], the same contract as
    /// [`Device::poll_timers`]. Peers are visited in order and the token bucket
    /// bounds the total work, so a netmap naming more peers than the budget
    /// allows simply takes a few more ticks to converge.
    pub fn poll_handshakes<'o>(
        &mut self,
        now: Instant,
        timestamp: &Tai64n,
        rng: &mut impl Rng,
        out: &'o mut [u8],
    ) -> Action<'o> {
        for index in 0..self.peers.len() {
            self.peers[index].expire_sessions(now);
            if !self.peers[index].wants_handshake(now) {
                continue;
            }
            match self.start_handshake(PeerId(index), now, timestamp, rng, out) {
                Ok(len) => {
                    let out: &'o [u8] = out;
                    return Action::Send {
                        peer: PeerId(index),
                        data: &out[..len],
                    };
                }
                // Out of budget: every remaining peer would fail the same way,
                // so stop rather than walking the rest of the table.
                Err(Error::RateLimited) => break,
                Err(_) => continue,
            }
        }
        Action::None
    }

    /// Match a type-2 response to the handshake it answers and install the
    /// resulting session.
    fn complete_handshake(
        &mut self,
        expected: Option<PeerId>,
        datagram: &[u8],
        now: Instant,
    ) -> Result<PeerId, Error> {
        // Screen the message before any Diffie-Hellman work, and before
        // spending budget, exactly as the initiation path does.
        noise::verify_response_mac1(&self.mac1_key, datagram)?;

        let receiver = messages::get_u32(&datagram[messages::response::RECEIVER]);
        let id = self
            .peers
            .iter()
            .position(|p| {
                p.pending
                    .as_ref()
                    .is_some_and(|h| h.local_index == receiver)
            })
            .map(PeerId)
            .ok_or(Error::UnknownSession)?;
        Self::check_expected_peer(expected, id)?;

        if !self.budget.take(now) {
            return Err(Error::RateLimited);
        }

        let static_private = self.static_private.clone();
        let peer = &mut self.peers[id.0];
        let handshake = peer
            .pending
            .as_ref()
            .expect("located by its pending handshake");
        let (peer_index, keys) =
            noise::consume_response(handshake, &static_private, &peer.preshared_key, datagram)?;

        let local_index = handshake.local_index;
        peer.clear_pending();
        peer.previous = peer.current.take();
        let mut session = Session::new(keys, local_index, peer_index, now);
        // The responder proved it derived the same keys by producing a tag we
        // could verify, so unlike the responder we may send immediately.
        session.confirm();
        peer.current = Some(session);
        peer.keepalive_armed_since = None;
        Ok(id)
    }

    fn respond_to_initiation(
        &mut self,
        expected: Option<PeerId>,
        datagram: &[u8],
        now: Instant,
        rng: &mut impl Rng,
        out: &mut [u8],
    ) -> Result<(PeerId, usize), Error> {
        // Screen the message before rate limiting it, so that garbage and
        // forgeries are reported as what they are and cannot spend the rate
        // limit budget that protects the X25519 work below.
        noise::verify_initiation_mac1(&self.mac1_key, datagram)?;

        if !self.budget.take(now) {
            return Err(Error::RateLimited);
        }

        let initiation = noise::consume_initiation(
            &self.static_private,
            &self.static_public,
            &self.mac1_key,
            datagram,
        )?;

        let id = self
            .peers
            .iter()
            .position(|p| p.public.as_bytes() == initiation.peer_static.as_bytes())
            .map(PeerId)
            .ok_or(Error::UnknownPeer)?;
        Self::check_expected_peer(expected, id)?;

        // Reject replayed initiations before mutating any state.
        if let Some(last) = self.peers[id.0].last_timestamp
            && !noise::timestamp_is_newer(&initiation.timestamp, &last)
        {
            return Err(Error::StaleTimestamp);
        }

        let local_index = self.allocate_index(rng);
        let ephemeral = self.random_secret(rng);

        let peer = &mut self.peers[id.0];
        let (len, keys) = noise::create_response(
            &initiation,
            &peer.preshared_key,
            local_index,
            &ephemeral,
            out,
        )?;

        peer.last_timestamp = Some(initiation.timestamp);
        peer.previous = peer.current.take();
        peer.current = Some(Session::new(keys, local_index, initiation.peer_index, now));
        peer.keepalive_armed_since = None;
        // The peer got there first. Our own attempt, if we had one in flight,
        // is now redundant and its ephemeral key useless.
        peer.clear_pending();

        Ok((id, len))
    }

    fn open_data(
        &mut self,
        expected: Option<PeerId>,
        datagram: &[u8],
        now: Instant,
        out: &mut [u8],
    ) -> Result<Option<(PeerId, usize)>, Error> {
        if datagram.len() < messages::data::HEADER_LEN {
            return Err(Error::Malformed);
        }
        let receiver = messages::get_u32(&datagram[messages::data::RECEIVER]);

        let id = self
            .peers
            .iter()
            .position(|peer| {
                peer.current
                    .as_ref()
                    .is_some_and(|session| session.local_index == receiver)
                    || peer
                        .previous
                        .as_ref()
                        .is_some_and(|session| session.local_index == receiver)
            })
            .map(PeerId)
            .ok_or(Error::UnknownSession)?;
        Self::check_expected_peer(expected, id)?;

        let peer = &mut self.peers[id.0];
        peer.expire_sessions(now);
        // A rekey may still be settling, so the packet could belong to either
        // the current or the previous session.
        let (session, is_previous) = match (&mut peer.current, &mut peer.previous) {
            (Some(s), _) if s.local_index == receiver => (s, false),
            (_, Some(s)) if s.local_index == receiver => (s, true),
            _ => return Err(Error::UnknownSession),
        };

        let plaintext_len = session.open(datagram, out)?;
        session.confirm();
        if is_previous {
            // The peer is still using the old session, so it never saw our
            // newer handshake response. Discard the unused new session and
            // promote the one actually in use, otherwise nothing we send
            // would be readable by the peer.
            peer.current = peer.previous.take();
        }

        if plaintext_len == 0 {
            // A keepalive. It proves liveness but must not itself schedule
            // another keepalive, or two idle peers would ping forever.
            return Ok(None);
        }

        let len = ip::packet_len(&out[..plaintext_len]).ok_or(Error::Malformed)?;
        peer.keepalive_armed_since.get_or_insert(now);
        Ok(Some((id, len)))
    }

    fn peer_for_data(&self, datagram: &[u8]) -> Result<PeerId, Error> {
        let receiver = datagram
            .get(messages::data::RECEIVER)
            .map(messages::get_u32)
            .ok_or(Error::Malformed)?;
        self.peers
            .iter()
            .position(|peer| {
                peer.current
                    .as_ref()
                    .is_some_and(|session| session.local_index == receiver)
                    || peer
                        .previous
                        .as_ref()
                        .is_some_and(|session| session.local_index == receiver)
            })
            .map(PeerId)
            .ok_or(Error::UnknownSession)
    }

    fn check_expected_peer(expected: Option<PeerId>, actual: PeerId) -> Result<(), Error> {
        if expected.is_some_and(|expected| expected != actual) {
            return Err(Error::PeerMismatch);
        }
        Ok(())
    }

    /// Seal an inner IP packet for `peer`, writing a datagram into `out`.
    pub fn encapsulate<'o>(
        &mut self,
        peer: PeerId,
        packet: &[u8],
        now: Instant,
        out: &'o mut [u8],
    ) -> Result<Action<'o>, Error> {
        let p = self.peers.get_mut(peer.0).ok_or(Error::UnknownPeer)?;
        p.expire_sessions(now);
        let session = p.current.as_mut().ok_or(Error::NoSession)?;
        if !session.is_confirmed() {
            // WireGuard forbids the responder from sending data under keys the
            // peer has not yet demonstrated it derived identically.
            return Err(Error::Unconfirmed);
        }
        let len = session.seal(packet, out)?;
        p.keepalive_armed_since = None;
        let out: &'o [u8] = out;
        Ok(Action::Send {
            peer,
            data: &out[..len],
        })
    }

    /// Advance time. Retires expired sessions and emits at most one keepalive
    /// per call; call repeatedly until it returns [`Action::None`].
    pub fn poll_timers<'o>(&mut self, now: Instant, out: &'o mut [u8]) -> Action<'o> {
        for index in 0..self.peers.len() {
            self.peers[index].expire_sessions(now);
            let peer = &mut self.peers[index];
            if !timers::keepalive_is_due(peer.keepalive_armed_since, now) {
                continue;
            }
            let Some(session) = peer.current.as_mut() else {
                continue;
            };
            if !session.is_confirmed() {
                continue;
            }
            let Ok(len) = session.seal(&[], out) else {
                continue;
            };
            peer.keepalive_armed_since = None;
            let out: &'o [u8] = out;
            return Action::Send {
                peer: PeerId(index),
                data: &out[..len],
            };
        }
        Action::None
    }

    /// Pick a session index not currently in use.
    ///
    /// Indices are random rather than sequential so that an observer cannot
    /// count sessions or predict the next one.
    fn allocate_index(&mut self, rng: &mut impl Rng) -> u32 {
        loop {
            let mut bytes = [0u8; 4];
            rng.fill_bytes(&mut bytes);
            let candidate = u32::from_le_bytes(bytes);
            let taken = self.peers.iter().any(|p| {
                [&p.current, &p.previous]
                    .into_iter()
                    .flatten()
                    .any(|s| s.local_index == candidate)
            });
            if !taken {
                return candidate;
            }
        }
    }

    fn random_secret(&self, rng: &mut impl Rng) -> StaticSecret {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // `StaticSecret::from` clamps, so any 32 random bytes are a valid key.
        StaticSecret::from(bytes)
    }
}
