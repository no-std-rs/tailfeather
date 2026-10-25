//! Complete cooperative mesh client, independent of the executor and allocator.
//!
//! The application owns the node, TCP arena, link buffers, credentials, clock,
//! randomness and durable state. [`Network`] is the platform boundary: verified
//! TLS streams and one bound UDP socket. The same control/DERP/WireGuard actor
//! runs on Tokio or Embassy, using the core's transport-independent codecs.

use crate::{
    exec::{Clock, Either, Reactor, select},
    queue::Actions,
    tcp::{Packet, PacketQueue},
    tcp_async::{PacketIo, Tcp},
};
use core::{
    cell::{Cell, RefCell},
    net::{Ipv4Addr, SocketAddrV4},
};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex, channel::Channel, signal::Signal, watch::Watch,
};
use embedded_io_async::{Read, Write};
use heapless::{Deque, Vec};
use tailfeather::control::authority::Authority;
use tailfeather::keys::{Identity, Rng};
use tailfeather::{ControlCommand, ControlEvent, DerpCommand, Node, NodeAction, PersistState};

mod control;
mod derp;

pub type Error = &'static str;

/// Borrow independent directions after the TLS/protocol handshake. Relay reads
/// remain alive while outgoing packets and pongs progress, so adapters need not
/// make record reads cancellation-safe.
pub trait SplitStream: Read + Write {
    type Reader<'a>: Read
    where
        Self: 'a;
    type Writer<'a>: Write
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Reader<'_>, Self::Writer<'_>);
}

#[cfg(feature = "tls")]
impl<S, C> SplitStream for embedded_tls::TlsConnection<'_, S, C>
where
    S: SplitStream,
    C: embedded_tls::TlsCipherSuite + 'static,
{
    type Reader<'a>
        = embedded_tls::TlsReader<'a, S::Reader<'a>, C>
    where
        Self: 'a;
    type Writer<'a>
        = embedded_tls::TlsWriter<'a, S::Writer<'a>, C>
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Reader<'_>, Self::Writer<'_>) {
        self.split_with(|socket| socket.split())
    }
}

/// Local delivery of authenticated inner IPv4 packets. Implement this for a
/// kernel TUN interface, or use [`Tcp`] for the shared userspace TCP stack.
/// The driver must be cancellation-safe and must not bypass [`PacketIo`]'s
/// authenticated ingress. Address removal also invalidates local connections.
#[allow(async_fn_in_trait)]
pub trait Device {
    fn set_address(&self, address: Option<Ipv4Addr>, now_ms: u64, seed: u64) -> Result<(), Error>;
    fn visit_remote_addresses(&self, _visit: impl FnMut(Ipv4Addr)) {}
    async fn run<C: Clock, I: PacketIo<Error = Error>>(
        &self,
        reactor: &Reactor<C>,
        io: &I,
    ) -> Result<(), Error>;
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> Device for Tcp<'_, N, Q, B> {
    fn set_address(&self, address: Option<Ipv4Addr>, now_ms: u64, seed: u64) -> Result<(), Error> {
        if let Some(address) = address {
            Tcp::set_address(self, address, now_ms, seed);
        } else {
            self.clear_address();
        }
        Ok(())
    }
    fn visit_remote_addresses(&self, visit: impl FnMut(Ipv4Addr)) {
        self.remote_addresses().into_iter().for_each(visit);
    }
    async fn run<C: Clock, I: PacketIo<Error = Error>>(
        &self,
        reactor: &Reactor<C>,
        io: &I,
    ) -> Result<(), Error> {
        match Tcp::run(self, reactor, io).await {
            Ok(never) => match never {},
            Err(error) => Err(error),
        }
    }
}

/// Each returned RNG must draw fresh cryptographically secure randomness.
/// TCP/TLS must authenticate the requested DNS name against `ca` or trusted
/// public roots; an empty private CA must never disable certificate validation.
pub trait Network: Clock {
    type Stream<'a>: SplitStream
    where
        Self: 'a;
    type Rng: Rng
        + tailfeather::tunnel::Rng
        + tailfeather::disco::packet::Rng
        + tailfeather::derp::client::Rng;
    fn rng(&self) -> Self::Rng;
    fn unix_millis(&self) -> Result<u64, Error>;
    fn local_endpoint(&self) -> Result<SocketAddrV4, Error>;
    fn interface_address(&self) -> Option<Ipv4Addr>;
    fn validate_ca(&self, ca: &[u8]) -> Result<(), Error>;
    async fn resolve(&self, host: &str) -> Result<Vec<Ipv4Addr, 16>, Error>;
    async fn connect<'a>(
        &'a self,
        host: &str,
        port: u16,
        tls_name: &str,
        ca: &[u8],
        buffers: &'a mut LinkBuffers,
    ) -> Result<Self::Stream<'a>, Error>;
    async fn receive(&self, packet: &mut [u8]) -> Result<(usize, SocketAddrV4), Error>;
    async fn send(&self, packet: &[u8], to: SocketAddrV4) -> Result<(), Error>;
    /// Backend hook for bounded userspace TX bursts, preserving backpressure.
    async fn send_batch<'p>(
        &self,
        packets: impl Iterator<Item = (&'p [u8], SocketAddrV4)>,
    ) -> Result<(), Error> {
        for (packet, to) in packets {
            self.send(packet, to).await?;
        }
        Ok(())
    }
}

/// Implement atomic, durable replacement and exclusive ownership of identity.
/// A successful return must survive reset before network activity proceeds.
pub trait State {
    fn load(&self, output: &mut [u8]) -> Result<Option<usize>, Error>;
    fn save(&self, bytes: &[u8]) -> Result<(), Error>;
    fn load_timestamp(&self, output: &mut [u8; 12]) -> Result<bool, Error>;
    fn save_timestamp(&self, bytes: &[u8; 12]) -> Result<(), Error>;
}

pub struct Config<'a> {
    pub control_url: &'a str,
    pub hostname: &'a str,
    pub auth_key: &'a str,
    pub control_ca_der: &'a [u8],
    pub relay_only: bool,
    pub ephemeral: bool,
    pub os: &'a str,
}

/// Caller-owned transport and TLS buffers for one control or DERP connection.
pub struct LinkBuffers {
    pub rsa: tailfeather::control::tls::RsaWorkspace,
    pub tcp_rx: [u8; 4096],
    pub tcp_tx: [u8; 4096],
    pub tls_rx: [u8; tailfeather::control::tls::TLS_READ_BUFFER],
    pub tls_tx: [u8; tailfeather::control::tls::TLS_WRITE_BUFFER],
}
impl LinkBuffers {
    pub const fn new() -> Self {
        Self {
            rsa: tailfeather::control::tls::RsaWorkspace::new(),
            tcp_rx: [0; 4096],
            tcp_tx: [0; 4096],
            tls_rx: [0; tailfeather::control::tls::TLS_READ_BUFFER],
            tls_tx: [0; tailfeather::control::tls::TLS_WRITE_BUFFER],
        }
    }
}
impl Default for LinkBuffers {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Buffers<const PEERS: usize> {
    pub control: LinkBuffers,
    pub relays: [LinkBuffers; 2],
    pub staging: tailfeather::netmap::Netmap<PEERS>,
}
impl<const PEERS: usize> Buffers<PEERS> {
    pub fn new() -> Self {
        Self {
            control: LinkBuffers::new(),
            relays: [const { LinkBuffers::new() }; 2],
            staging: tailfeather::netmap::Netmap::new(),
        }
    }
}
impl<const PEERS: usize> Default for Buffers<PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Status {
    pub address: Option<Ipv4Addr>,
    pub error: Option<Error>,
}

struct Probe {
    transaction: [u8; 12],
    server: SocketAddrV4,
    received: Option<SocketAddrV4>,
}

pub struct Runtime<'a, P: Network, S: State, const PEERS: usize, const A: usize = 8> {
    config: Config<'a>,
    node: RefCell<&'a mut Node<PEERS>>,
    network: &'a P,
    state: &'a S,
    actions: RefCell<Actions<A>>,
    ready: Signal<NoopRawMutex, ()>,
    space: Watch<NoopRawMutex, u64, 4>,
    overflow: Cell<bool>,
    status: Watch<NoopRawMutex, Status, 16>,
    delivered: Channel<NoopRawMutex, Packet, A>,
    slots: [derp::Slot<A>; 2],
    candidates: RefCell<Vec<SocketAddrV4, 8>>,
    candidate_generation: Cell<u64>,
    probe: RefCell<Option<Probe>>,
    probed: Signal<NoopRawMutex, ()>,
    last_timestamp: Cell<[u8; 12]>,
    reserved_timestamp: Cell<[u8; 12]>,
    running: Cell<bool>,
}

/// Restore an authority-bound identity. Corrupt/mismatched state fails closed.
pub fn restore<P: Network, S: State, const PEERS: usize>(
    config: &Config<'_>,
    network: &P,
    state: &S,
) -> Result<Node<PEERS>, Error> {
    let authority = Authority::parse(config.control_url, false).map_err(|_| "HTTPS authority")?;
    let mut saved = zeroize::Zeroizing::new([0; PersistState::BLOB_LEN]);
    let result = match state.load(&mut saved[..])? {
        Some(len) => {
            let saved = saved.get(..len).ok_or("identity state length")?;
            let state = PersistState::from_bytes(saved).map_err(|_| "corrupt identity")?;
            Node::restore_for_authority(&state, authority.digest())
                .map_err(|_| "identity authority mismatch")
        }
        None => Ok(Node::factory_reset_for_authority(
            Identity::generate(&mut network.rng()),
            1,
            authority.digest(),
        )),
    };
    saved.fill(0);
    result
}

impl<'a, P: Network, S: State, const PEERS: usize, const A: usize> Runtime<'a, P, S, PEERS, A> {
    pub fn new(
        config: Config<'a>,
        node: &'a mut Node<PEERS>,
        network: &'a P,
        state: &'a S,
    ) -> Result<Self, Error> {
        if config.hostname.is_empty()
            || config.hostname.len() > 63
            || config.auth_key.len() > 1024
            || config.control_ca_der.len() > 4096
            || A == 0
        {
            return Err("invalid client configuration");
        }
        let authority =
            Authority::parse(config.control_url, false).map_err(|_| "HTTPS authority")?;
        if node.authority_hash() != authority.digest() {
            return Err("identity authority mismatch");
        }
        network.validate_ca(config.control_ca_der)?;
        network.unix_millis()?;
        node.set_control_endpoint(
            tailfeather::Endpoint::new(authority.host(), authority.port())
                .map_err(|_| "control endpoint")?,
        );
        node.set_initiate_on_demand(true);
        node.set_direct_paths(!config.relay_only);
        let mut floor = [0; 12];
        if state.load_timestamp(&mut floor)? {
            let seconds = u64::from_be_bytes(floor[..8].try_into().unwrap());
            let nanos = u32::from_be_bytes(floor[8..].try_into().unwrap());
            if !((1u64 << 62) + 10..=u64::MAX - 60).contains(&seconds) || nanos >= 1_000_000_000 {
                return Err("invalid timestamp state");
            }
        }
        let result = Self {
            config,
            node: RefCell::new(node),
            network,
            state,
            actions: RefCell::new(Actions::default()),
            ready: Signal::new(),
            space: Watch::new(),
            overflow: Cell::new(false),
            status: Watch::new(),
            delivered: Channel::new(),
            slots: [derp::Slot::new(), derp::Slot::new()],
            candidates: RefCell::new(Vec::new()),
            candidate_generation: Cell::new(0),
            probe: RefCell::new(None),
            probed: Signal::new(),
            last_timestamp: Cell::new(floor),
            reserved_timestamp: Cell::new(floor),
            running: Cell::new(false),
        };
        result.status.sender().send(Status::default());
        if let Some(address) = result
            .node
            .borrow()
            .netmap()
            .addresses
            .iter()
            .find_map(|cidr| match cidr.address {
                core::net::IpAddr::V4(address) => Some(address),
                _ => None,
            })
        {
            result.status.sender().send(Status {
                address: Some(address),
                error: None,
            });
        }
        result.space.sender().send(0);
        Ok(result)
    }

    pub fn status(&self) -> Status {
        self.status.anon_receiver().try_get().unwrap_or_default()
    }

    /// Observe completed map updates, including peer changes at the same local
    /// address, and terminal shutdown. Each subscriber holds one bounded slot.
    pub fn subscribe_status(
        &self,
    ) -> Result<embassy_sync::watch::Receiver<'_, NoopRawMutex, Status, 16>, Error> {
        self.status.receiver().ok_or("status waiter capacity")
    }

    /// Current peer IPv4 addresses from the last completely applied netmap.
    pub fn peer_addresses(&self) -> Vec<Ipv4Addr, PEERS> {
        self.node
            .borrow()
            .netmap()
            .peers
            .iter()
            .filter_map(|peer| peer.tailscale_ipv4())
            .collect()
    }

    pub async fn ready(&self) -> Result<Ipv4Addr, Error> {
        let mut receiver = self.status.receiver().ok_or("status waiter capacity")?;
        loop {
            let status = receiver.get().await;
            if let Some(error) = status.error {
                return Err(error);
            }
            if let Some(address) = status.address {
                return Ok(address);
            }
            receiver.changed().await;
        }
    }

    pub async fn connect<'r, 's, const N: usize, const Q: usize, B: PacketQueue<Q>>(
        &self,
        tcp: &'r Tcp<'s, N, Q, B>,
        address: Ipv4Addr,
        port: u16,
        local_port: u16,
    ) -> Result<crate::tcp_async::Stream<'r, 's, N, Q, B>, Error> {
        let own = self.ready().await?;
        let mut seed = [0; 8];
        Rng::fill_bytes(&mut self.network.rng(), &mut seed);
        tcp.set_address(own, self.network.now_millis(), u64::from_le_bytes(seed));
        tcp.connect(
            &Reactor::with_clock(self.network),
            address,
            port,
            local_port,
        )
        .await
        .map_err(|_| "tailnet TCP connection failed")
    }

    pub async fn listen<'r, 's, const N: usize, const Q: usize, B: PacketQueue<Q>>(
        &self,
        tcp: &'r Tcp<'s, N, Q, B>,
        port: u16,
    ) -> Result<crate::tcp_async::Listener<'r, 's, N, Q, B>, Error> {
        let own = self.ready().await?;
        let mut seed = [0; 8];
        Rng::fill_bytes(&mut self.network.rng(), &mut seed);
        tcp.set_address(own, self.network.now_millis(), u64::from_le_bytes(seed));
        tcp.listen(port)
            .map_err(|_| "tailnet TCP listener unavailable")
    }

    pub async fn run<const N: usize, const Q: usize, B: PacketQueue<Q>>(
        &self,
        tcp: &Tcp<'_, N, Q, B>,
        buffers: &mut Buffers<PEERS>,
    ) -> Result<(), Error> {
        self.run_device(tcp, buffers).await
    }

    /// Run the same control, relay, discovery and WireGuard actor with a local
    /// packet device. Dropping this future clears its assigned address.
    pub async fn run_device<D: Device>(
        &self,
        device: &D,
        buffers: &mut Buffers<PEERS>,
    ) -> Result<(), Error> {
        if self.status().error.is_some() {
            return Err("client stopped; restore before restarting");
        }
        if self.running.replace(true) {
            return Err("client already running");
        }
        struct Guard<'r, 'a, P: Network, S: State, D: Device, const PEERS: usize, const A: usize>(
            &'r Runtime<'a, P, S, PEERS, A>,
            &'r D,
        );
        impl<P: Network, S: State, D: Device, const PEERS: usize, const A: usize> Drop
            for Guard<'_, '_, P, S, D, PEERS, A>
        {
            fn drop(&mut self) {
                let _ = self.1.set_address(None, self.0.network.now_millis(), 0);
                if self.0.status().error.is_none() {
                    self.0.status.sender().send(Status {
                        address: None,
                        error: Some("client stopped"),
                    });
                }
                self.0.running.set(false);
            }
        }
        let _guard = Guard(self, device);
        let reactor = Reactor::with_clock(self.network);
        let [first, second] = &mut buffers.relays;
        use embassy_futures::select::{Either5, select5};
        let result = match select5(
            control::run(self, &reactor, &mut buffers.control, &mut buffers.staging),
            self.packets(device, &reactor),
            derp::worker(self, &reactor, &self.slots[0], first),
            derp::worker(self, &reactor, &self.slots[1], second),
            device.run(&reactor, self),
        )
        .await
        {
            Either5::First(result)
            | Either5::Second(result)
            | Either5::Third(result)
            | Either5::Fourth(result)
            | Either5::Fifth(result) => result,
        };
        self.status.sender().send(Status {
            address: None,
            error: Some(result.as_ref().err().copied().unwrap_or("client stopped")),
        });
        self.running.set(false);
        result
    }

    fn enqueue(&self, action: Option<NodeAction>) {
        if let Some(action) = action {
            if self.actions.borrow_mut().push(action).is_err() {
                self.overflow.set(true);
            }
            self.ready.signal(());
        }
    }
    fn pop(&self) -> Option<NodeAction> {
        let result = self.actions.borrow_mut().pop();
        self.space.sender().send(self.network.now_millis());
        result
    }
    async fn wait_for_space(&self) {
        let mut space = self
            .space
            .receiver()
            .expect("at most two relay readers wait");
        while self.actions.borrow().len() >= A.div_ceil(2) {
            space.changed().await;
        }
    }
    fn timestamp(&self) -> Result<[u8; 12], Error> {
        let mut last = self.last_timestamp.get();
        Ok(crate::routing::next_tai64n(
            &mut last,
            self.network.unix_millis()?,
        ))
    }
    fn commit_timestamp(&self, next: [u8; 12]) -> Result<(), Error> {
        if next > self.reserved_timestamp.get() {
            let mut reserved = next;
            let seconds = u64::from_be_bytes(next[..8].try_into().unwrap())
                .checked_add(60)
                .ok_or("timestamp exhausted")?;
            reserved[..8].copy_from_slice(&seconds.to_be_bytes());
            self.state.save_timestamp(&reserved)?;
            self.reserved_timestamp.set(reserved);
        }
        self.last_timestamp.set(next);
        Ok(())
    }
    fn candidates(&self, candidates: Vec<SocketAddrV4, 8>) {
        if *self.candidates.borrow() != candidates {
            *self.candidates.borrow_mut() = candidates;
            self.candidate_generation
                .set(self.candidate_generation.get().wrapping_add(1));
        }
    }
    async fn packets<D: Device>(&self, device: &D, reactor: &Reactor<&P>) -> Result<(), Error> {
        let mut datagram = [0; tailfeather::tunnel::MAX_DATAGRAM_LEN];
        let mut transmit: Vec<
            (
                tailfeather::node::SecretBuffer<{ tailfeather::node::MAX_ACTION_PACKET }>,
                SocketAddrV4,
            ),
            A,
        > = Vec::new();
        let mut punches: Vec<(tailfeather::keys::NodePublic, u64, u8), PEERS> = Vec::new();
        let mut generation = self.candidate_generation.get();
        let mut seed = [0; 8];
        self.network.rng().fill_bytes(&mut seed);
        let mut status = self.status.receiver().ok_or("status waiter capacity")?;
        let mut address = None;
        let mut next_maintenance = 0;
        let mut budget = 0;
        loop {
            if self.overflow.get() {
                return Err("node action capacity exceeded");
            }
            let current_address = status.try_get().unwrap_or_default().address;
            if current_address != address {
                device.set_address(
                    current_address,
                    reactor.clock_millis(),
                    u64::from_le_bytes(seed),
                )?;
                address = current_address;
            }
            for _ in 0..A {
                let Some(action) = self.pop() else {
                    break;
                };
                match action {
                    NodeAction::DirectTransmit {
                        endpoint: core::net::SocketAddr::V4(to),
                        packet,
                        ..
                    } => {
                        // At most A actions are consumed before flushing this burst.
                        let _ = transmit.push((packet, to));
                    }
                    NodeAction::DeliveredIpv4 { peer, packet } => {
                        let allowed =
                            {
                                let node = self.node.borrow();
                                let bytes = packet.as_slice();
                                (crate::routing::tcp_continuation(bytes)
                                    || node.netmap().packet_filter.allows_ipv4(bytes))
                                    && node.netmap().addresses.iter().any(|cidr| {
                                        match cidr.address {
                                            core::net::IpAddr::V4(own) => {
                                                crate::routing::inbound_allowed(
                                                    bytes,
                                                    &peer,
                                                    node.netmap().peers.iter(),
                                                    own,
                                                )
                                            }
                                            _ => false,
                                        }
                                    })
                            };
                        if allowed && let Ok(packet) = Packet::from_slice(packet.as_slice()) {
                            self.delivered.send(packet).await;
                        }
                    }
                    NodeAction::Derp(command) => {
                        if let Some(command) = derp::dispatch(self, command) {
                            let _ = self.actions.borrow_mut().push(NodeAction::Derp(command));
                        }
                    }
                    _ => {}
                }
            }
            if !transmit.is_empty() {
                let _ = self
                    .network
                    .send_batch(transmit.iter().map(|(packet, to)| (packet.as_slice(), *to)))
                    .await;
                transmit.clear();
            }
            let now = reactor.clock_millis();
            if now >= next_maintenance {
                next_maintenance = now.saturating_add(100);
                if !self.config.relay_only {
                    if generation != self.candidate_generation.get() {
                        punches.clear();
                        generation = self.candidate_generation.get();
                    }
                    let mut active: Vec<tailfeather::keys::NodePublic, PEERS> = Vec::new();
                    device.visit_remote_addresses(|address| {
                        if let Some(peer) = crate::routing::route_ipv4(
                            self.node.borrow().netmap().peers.iter(),
                            address,
                        ) && !active.contains(&peer)
                        {
                            let _ = active.push(peer);
                        }
                    });
                    punches.retain(|(peer, _, _)| active.contains(peer));
                    for peer in active {
                        if !punches.iter().any(|(key, _, _)| *key == peer) {
                            let _ = punches.push((peer, 0, 0));
                        }
                    }
                    let candidates: Vec<core::net::SocketAddr, 8> = self
                        .candidates
                        .borrow()
                        .iter()
                        .copied()
                        .map(Into::into)
                        .collect();
                    for (peer, next, attempts) in &mut punches {
                        if *attempts < 3
                            && now >= *next
                            && self.actions.borrow().len() < A.div_ceil(2)
                        {
                            self.enqueue(
                                self.node
                                    .borrow_mut()
                                    .call_me_maybe(peer, &candidates, &mut self.network.rng())
                                    .ok()
                                    .flatten(),
                            );
                            *attempts += 1;
                            *next = now.saturating_add(1000);
                        }
                    }
                }
                self.enqueue(
                    self.node
                        .borrow_mut()
                        .poll_disco(now, &mut self.network.rng())
                        .ok()
                        .flatten(),
                );
                self.enqueue(self.node.borrow_mut().poll_derp().ok().flatten());
                let timestamp = self.timestamp()?;
                let handshake = self
                    .node
                    .borrow_mut()
                    .poll_tunnel(now, &timestamp, &mut self.network.rng())
                    .ok()
                    .flatten();
                if handshake.is_some() {
                    self.commit_timestamp(timestamp)?;
                }
                self.enqueue(handshake);
                self.enqueue(
                    self.node
                        .borrow_mut()
                        .poll_tunnel_timers(now)
                        .ok()
                        .flatten(),
                );
            }
            budget += 1;
            if budget == 8 {
                budget = 0;
                crate::exec::yield_now().await;
            }
            let received = select(
                self.network.receive(&mut datagram),
                select(
                    status.changed(),
                    select(self.ready.wait(), reactor.sleep_until(next_maintenance)),
                ),
            )
            .await;
            if let Either::First(received) = received {
                let (len, from) = received?;
                let packet = datagram.get(..len).ok_or("UDP receive length")?;
                let stun = self.probe.borrow().as_ref().and_then(|probe| {
                    (probe.server == from)
                        .then(|| tailfeather::stun::response(packet, probe.transaction).ok())
                        .flatten()
                });
                if let Some((ip, port)) = stun {
                    if let Some(probe) = self.probe.borrow_mut().as_mut() {
                        probe.received = Some(SocketAddrV4::new(ip.into(), port));
                    }
                    self.probed.signal(());
                } else {
                    self.enqueue(
                        self.node
                            .borrow_mut()
                            .handle_direct_from(
                                packet,
                                from.into(),
                                reactor.clock_millis(),
                                &mut self.network.rng(),
                            )
                            .ok()
                            .flatten(),
                    );
                }
            }
        }
    }
}

impl<P: Network, S: State, const PEERS: usize, const A: usize> PacketIo
    for Runtime<'_, P, S, PEERS, A>
{
    type Error = Error;
    async fn receive(&self, output: &mut [u8]) -> Result<usize, Error> {
        let packet = self.delivered.receive().await;
        let dest = output
            .get_mut(..packet.len())
            .ok_or("inner receive buffer")?;
        dest.copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, packet: &[u8]) -> Result<(), Error> {
        self.wait_for_space().await;
        let peer = crate::routing::ipv4_addresses(packet).and_then(|(_, destination)| {
            crate::routing::route_ipv4(self.node.borrow().netmap().peers.iter(), destination)
        });
        if let Some(peer) = peer {
            let action = self
                .node
                .borrow_mut()
                .encapsulate_ipv4(&peer, packet, self.network.now_millis())
                .ok()
                .flatten();
            self.enqueue(action);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    struct PendingStream;
    impl embedded_io_async::ErrorType for PendingStream {
        type Error = core::convert::Infallible;
    }
    impl Read for PendingStream {
        async fn read(&mut self, _: &mut [u8]) -> Result<usize, Self::Error> {
            core::future::pending().await
        }
    }
    impl Write for PendingStream {
        async fn write(&mut self, _: &[u8]) -> Result<usize, Self::Error> {
            core::future::pending().await
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    impl SplitStream for PendingStream {
        type Reader<'a> = Self;
        type Writer<'a> = Self;
        fn split(&mut self) -> (Self, Self) {
            (Self, Self)
        }
    }
    struct Offline(Cell<u64>);
    impl Clock for Offline {
        fn now_millis(&self) -> u64 {
            self.0.get()
        }
        async fn sleep_until(&self, deadline: u64) {
            core::future::poll_fn(|_| {
                if self.0.get() >= deadline {
                    core::task::Poll::Ready(())
                } else {
                    core::task::Poll::Pending
                }
            })
            .await;
        }
    }
    impl Network for Offline {
        type Stream<'a> = PendingStream;
        type Rng = crate::native::OsRng;
        fn rng(&self) -> Self::Rng {
            crate::native::OsRng
        }
        fn unix_millis(&self) -> Result<u64, Error> {
            Ok(1_700_000_000_000 + self.now_millis())
        }
        fn local_endpoint(&self) -> Result<SocketAddrV4, Error> {
            Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51820))
        }
        fn interface_address(&self) -> Option<Ipv4Addr> {
            Some(Ipv4Addr::LOCALHOST)
        }
        fn validate_ca(&self, ca: &[u8]) -> Result<(), Error> {
            if ca.is_empty() {
                Ok(())
            } else {
                Err("invalid control CA")
            }
        }
        async fn resolve(&self, _: &str) -> Result<Vec<Ipv4Addr, 16>, Error> {
            Ok(Vec::new())
        }
        async fn connect<'a>(
            &'a self,
            _: &str,
            _: u16,
            _: &str,
            _: &[u8],
            _: &'a mut LinkBuffers,
        ) -> Result<PendingStream, Error> {
            core::future::pending().await
        }
        async fn receive(&self, _: &mut [u8]) -> Result<(usize, SocketAddrV4), Error> {
            core::future::pending().await
        }
        async fn send(&self, _: &[u8], _: SocketAddrV4) -> Result<(), Error> {
            Ok(())
        }
    }
    #[derive(Default)]
    struct MemoryState {
        identities: Cell<usize>,
        timestamps: Cell<usize>,
    }
    impl State for MemoryState {
        fn load(&self, _: &mut [u8]) -> Result<Option<usize>, Error> {
            Ok(None)
        }
        fn save(&self, _: &[u8]) -> Result<(), Error> {
            self.identities.set(self.identities.get() + 1);
            Ok(())
        }
        fn load_timestamp(&self, _: &mut [u8; 12]) -> Result<bool, Error> {
            Ok(false)
        }
        fn save_timestamp(&self, _: &[u8; 12]) -> Result<(), Error> {
            self.timestamps.set(self.timestamps.get() + 1);
            Ok(())
        }
    }
    fn config() -> Config<'static> {
        Config {
            control_url: "https://control.invalid",
            hostname: "fixture",
            auth_key: "fixture-only",
            control_ca_der: &[],
            relay_only: true,
            ephemeral: true,
            os: "fixture",
        }
    }

    #[test]
    fn idle_nodes_do_not_write_timestamp_reservations_and_cancellation_wakes_ready() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use core::future::Future;
                let network = Offline(Cell::new(0));
                let state = MemoryState::default();
                let config = config();
                let mut node = restore::<_, _, 1>(&config, &network, &state).unwrap();
                let runtime =
                    Runtime::<_, _, 1, 4>::new(config, &mut node, &network, &state).unwrap();
                let mut storage = crate::tcp::Storage::<4, 512>::new();
                let tcp = Tcp::new(crate::tcp::NetStack::<4, 2>::with_storage(1, &mut storage));
                let mut buffers = Buffers::new();
                let mut future = std::boxed::Box::pin(runtime.run(&tcp, &mut buffers));
                struct WakeCount(std::sync::atomic::AtomicUsize);
                impl std::task::Wake for WakeCount {
                    fn wake(self: std::sync::Arc<Self>) {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                let wake = std::sync::Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
                let waker = core::task::Waker::from(wake.clone());
                let mut cx = core::task::Context::from_waker(&waker);
                assert!(future.as_mut().poll(&mut cx).is_pending());
                assert!(future.as_mut().poll(&mut cx).is_pending());
                let initial_wakes = wake.0.load(std::sync::atomic::Ordering::Relaxed);
                assert!(future.as_mut().poll(&mut cx).is_pending());
                assert_eq!(
                    wake.0.load(std::sync::atomic::Ordering::Relaxed),
                    initial_wakes,
                    "idle reactor must not busy-wake itself"
                );
                network.0.set(120_000);
                assert!(future.as_mut().poll(&mut cx).is_pending());
                drop(future);
                assert_eq!(state.identities.get(), 1);
                assert_eq!(state.timestamps.get(), 0);
                let ready = runtime.ready();
                let mut ready = core::pin::pin!(ready);
                assert_eq!(
                    ready.as_mut().poll(&mut cx),
                    core::task::Poll::Ready(Err("client stopped"))
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    struct LocalDevice {
        addresses: RefCell<std::vec::Vec<Option<Ipv4Addr>>>,
        failure: Option<Error>,
    }
    impl Device for LocalDevice {
        fn set_address(&self, address: Option<Ipv4Addr>, _: u64, _: u64) -> Result<(), Error> {
            self.addresses.borrow_mut().push(address);
            Ok(())
        }
        async fn run<C: Clock, I: PacketIo<Error = Error>>(
            &self,
            _: &Reactor<C>,
            _: &I,
        ) -> Result<(), Error> {
            if let Some(error) = self.failure {
                Err(error)
            } else {
                core::future::pending().await
            }
        }
    }

    #[test]
    fn packet_device_address_lifecycle_and_failures_follow_runtime() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use core::future::Future;
                struct Wake;
                impl std::task::Wake for Wake {
                    fn wake(self: std::sync::Arc<Self>) {}
                }
                let waker = core::task::Waker::from(std::sync::Arc::new(Wake));
                let mut cx = core::task::Context::from_waker(&waker);
                for failure in [None, Some("TUN interface closed")] {
                    let network = Offline(Cell::new(0));
                    let state = MemoryState::default();
                    let config = config();
                    let mut node = restore::<_, _, 1>(&config, &network, &state).unwrap();
                    let runtime =
                        Runtime::<_, _, 1, 4>::new(config, &mut node, &network, &state).unwrap();
                    let address = Ipv4Addr::new(100, 64, 0, 1);
                    runtime.status.sender().send(Status {
                        address: Some(address),
                        error: None,
                    });
                    let device = LocalDevice {
                        addresses: RefCell::new(std::vec::Vec::new()),
                        failure,
                    };
                    let mut buffers = Buffers::new();
                    let mut future =
                        std::boxed::Box::pin(runtime.run_device(&device, &mut buffers));
                    let result = future.as_mut().poll(&mut cx);
                    if let Some(error) = failure {
                        assert_eq!(result, core::task::Poll::Ready(Err(error)));
                        assert_eq!(runtime.status().error, Some(error));
                    } else {
                        assert!(result.is_pending());
                        assert_eq!(device.addresses.borrow().as_slice(), &[Some(address)]);
                        runtime.status.sender().send(Status {
                            address: None,
                            error: None,
                        });
                        assert!(future.as_mut().poll(&mut cx).is_pending());
                        assert_eq!(device.addresses.borrow().last(), Some(&None));
                    }
                    drop(future);
                    assert_eq!(device.addresses.borrow().last(), Some(&None));
                    assert!(runtime.status().address.is_none());
                    assert!(!runtime.running.get());
                    let mut buffers = Buffers::new();
                    let restart = runtime.run_device(&device, &mut buffers);
                    let mut restart = core::pin::pin!(restart);
                    assert_eq!(
                        restart.as_mut().poll(&mut cx),
                        core::task::Poll::Ready(Err("client stopped; restore before restarting"))
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn identity_authority_and_custom_ca_are_checked_before_any_write() {
        let network = Offline(Default::default());
        let state = MemoryState::default();
        let mut node = restore::<_, _, 1>(&config(), &network, &state).unwrap();
        let mut other = config();
        other.control_url = "https://another.invalid";
        assert!(matches!(
            Runtime::<_, _, 1, 4>::new(other, &mut node, &network, &state),
            Err("identity authority mismatch")
        ));
        let mut bad_ca = config();
        bad_ca.control_ca_der = &[1, 2, 3];
        assert!(matches!(
            Runtime::<_, _, 1, 4>::new(bad_ca, &mut node, &network, &state),
            Err("invalid control CA")
        ));
        assert_eq!(state.identities.get(), 0);
        assert_eq!(state.timestamps.get(), 0);
    }
}
