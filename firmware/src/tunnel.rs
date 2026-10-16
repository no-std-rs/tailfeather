//! The mesh data path: a UDP socket on one side, [`tailfeather::Node`] on
//! the other, and source NAT out of the WiFi uplink for anything the tunnel
//! wants to forward.
//!
//! Everything runs in one task. The cryptography is the bottleneck by a wide
//! margin, so there is nothing to gain from processing packets concurrently,
//! and a single actor means [`tailfeather::Node`] needs no locking.

use core::net::{Ipv4Addr as CoreIpv4Addr, SocketAddr, SocketAddrV4};
use core::task::Poll;

use embassy_executor::Spawner;
use embassy_futures::poll_once;
use embassy_futures::select::{Either, Either6, select, select6};
use embassy_net::dns::DnsQueryType;
use embassy_net::raw::{IpProtocol, IpVersion, RawSocket};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpEndpoint, Ipv4Address, Stack, raw, udp};
use embassy_time::{Duration, Timer};
use log::{info, warn};
use static_cell::StaticCell;

use tailfeather::control::authority::Authority;
use tailfeather::keys::{Identity, NodePublic, Rng as KeyRng};
use tailfeather::state::TwoSlot;
use tailfeather::{DerpCommand, DerpEvent, Node, NodeAction};
use wirefeather::Rng;

use crate::nat;

/// The port we listen on, and the one the peer's `Endpoint` must point at.
pub(crate) const LISTEN_PORT: u16 = 51820;

/// How long to idle before giving the timers a turn. Keepalives are due on a
/// ten-second scale, so a quarter second is ample resolution.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The hardware keeps three live peer sessions: the active client, one spare,
/// and an independently enrolled exit-node client. Larger tailnets are parsed
/// without aborting: the bounded map retains the first three non-self peers and
/// marks the snapshot as truncated. Portable parsing and policy tests still
/// exercise the public `Node<32>` ceiling.
pub(crate) const PEERS: usize = 3;

/// Two full-size datagrams absorb a packet arriving immediately behind an ACK
/// or DNS message. Keep the RX payload arena aligned with its metadata slots:
/// undersizing it silently discards otherwise valid input.
const WG_DATAGRAM_LEN: usize = wirefeather::MAX_DATAGRAM_LEN;
const WG_RX_PACKETS: usize = 2;
const WG_TX_PACKETS: usize = 1;
const WG_RX_BUFFER_LEN: usize = WG_RX_PACKETS * WG_DATAGRAM_LEN;
const WG_TX_BUFFER_LEN: usize = WG_TX_PACKETS * WG_DATAGRAM_LEN;

static WG_RX_META: StaticCell<[PacketMetadata; WG_RX_PACKETS]> = StaticCell::new();
static WG_TX_META: StaticCell<[PacketMetadata; WG_TX_PACKETS]> = StaticCell::new();
static WG_RX_BUFFER: StaticCell<[u8; WG_RX_BUFFER_LEN]> = StaticCell::new();
static WG_TX_BUFFER: StaticCell<[u8; WG_TX_BUFFER_LEN]> = StaticCell::new();

/// The shared raw socket carrying every translated TCP flow. Twenty-four
/// metadata entries absorb a simultaneous SYN/SYN-ACK burst, while the RX
/// payload arena retains the four full packets permitted by the advertised
/// client receive window. TX remains a single-packet, backpressured queue.
const TCP_RAW_RX_ARENA_PACKETS: usize = 4;
const TCP_CLIENT_WINDOW_PACKETS: u16 = 4;
const TCP_RAW_RX_BUFFER_LEN: usize = TCP_RAW_RX_ARENA_PACKETS * wirefeather::budget::INNER_MTU;
const TCP_RAW_TX_BUFFER_LEN: usize = 2_048;
const TCP_RAW_PACKETS: usize = 24;
const CLIENT_TCP_RECEIVE_WINDOW: u16 = TCP_CLIENT_WINDOW_PACKETS * nat::MAX_MSS;
const SERVER_TCP_RECEIVE_WINDOW: u16 = nat::MAX_MSS;

const _: () = assert!(CLIENT_TCP_RECEIVE_WINDOW as usize <= TCP_RAW_RX_BUFFER_LEN);
const _: () = assert!(SERVER_TCP_RECEIVE_WINDOW as usize <= WG_DATAGRAM_LEN);

static RAW_RX_META: StaticCell<[raw::PacketMetadata; TCP_RAW_PACKETS]> = StaticCell::new();
static RAW_TX_META: StaticCell<[raw::PacketMetadata; TCP_RAW_PACKETS]> = StaticCell::new();
static RAW_RX_BUFFER: StaticCell<[u8; TCP_RAW_RX_BUFFER_LEN]> = StaticCell::new();
static RAW_TX_BUFFER: StaticCell<[u8; TCP_RAW_TX_BUFFER_LEN]> = StaticCell::new();

/// All 32 UDP mappings share this raw socket. This replaces four independently
/// buffered datagram sockets and funds the peer API's bounded connection state.
const UDP_RAW_BUFFER_LEN: usize = wirefeather::budget::INNER_MTU;
const UDP_RAW_PACKETS: usize = 4;
static UDP_RAW_RX_META: StaticCell<[raw::PacketMetadata; UDP_RAW_PACKETS]> = StaticCell::new();
static UDP_RAW_TX_META: StaticCell<[raw::PacketMetadata; UDP_RAW_PACKETS]> = StaticCell::new();
static UDP_RAW_RX_BUFFER: StaticCell<[u8; UDP_RAW_BUFFER_LEN]> = StaticCell::new();
// This arena used to live in RTC-fast, which had "exactly enough" room for it.
// Exactly enough is not a budget: the next static to grow overflowed the bank,
// and the one that grew was the staged netmap, which is the one occupant RTC
// exists for. A transient TX arena retains nothing across a reset and has no
// business competing for retained memory, so it sits in .bss and the 1,280
// bytes of stack headroom it costs are bought back from the radio heap the way
// the rest of this trade is — see the memory.x patch and `heap_allocator!`.
static UDP_RAW_TX_BUFFER: StaticCell<[u8; UDP_RAW_BUFFER_LEN]> = StaticCell::new();

/// Echo diagnostics need only small packets; bounding these arenas leaves
/// main-stack headroom for the control TLS handshake.
const ICMP_RAW_BUFFER_LEN: usize = 128;
const ICMP_RAW_PACKETS: usize = 4;
static ICMP_RX_META: StaticCell<[raw::PacketMetadata; ICMP_RAW_PACKETS]> = StaticCell::new();
static ICMP_TX_META: StaticCell<[raw::PacketMetadata; ICMP_RAW_PACKETS]> = StaticCell::new();
static ICMP_RX_BUFFER: StaticCell<[u8; ICMP_RAW_BUFFER_LEN]> = StaticCell::new();
static ICMP_TX_BUFFER: StaticCell<[u8; ICMP_RAW_BUFFER_LEN]> = StaticCell::new();

/// Fixed source port for raw upstream peer-API DNS. It is outside both NAT
/// ranges, so replies are unambiguous before their DNS tuple is checked.
const PEER_API_DNS_UPLINK_PORT: u16 = 53_053;

const NTP_PACKETS: usize = 2;
const NTP_BUFFER_LEN: usize = NTP_PACKETS * 64;
// NTP is used only before control starts. The persistent staged netmap has
// priority for the limited RTC-fast bank.
static NTP_RX_META: StaticCell<[PacketMetadata; NTP_PACKETS]> = StaticCell::new();
static NTP_TX_META: StaticCell<[PacketMetadata; NTP_PACKETS]> = StaticCell::new();
static NTP_RX_BUFFER: StaticCell<[u8; NTP_BUFFER_LEN]> = StaticCell::new();
static NTP_TX_BUFFER: StaticCell<[u8; NTP_BUFFER_LEN]> = StaticCell::new();

static NODE: StaticCell<Node<PEERS>> = StaticCell::new();
static SCRATCH: StaticCell<Scratch> = StaticCell::new();
static PEER_API: StaticCell<tailfeather_gateway::peerapi::Server> = StaticCell::new();

/// The working buffers stay out of the task's future. They use main SRAM so
/// RTC-fast can hold the complete bounded staged map for the live tailnet.
struct Scratch {
    /// A received outer datagram, or a received NAT reply payload.
    datagram: [u8; wirefeather::MAX_DATAGRAM_LEN],
    /// An inner packet we have built and are about to encapsulate.
    inner: [u8; wirefeather::budget::INNER_MTU],
}

#[derive(Default)]
struct Diagnostics {
    ipv6_rejected: u64,
    udp_capacity_drops: u64,
    udp_queue_drops: u64,
    tcp_capacity_drops: u64,
    icmp_oversize_drops: u64,
    icmp_queue_drops: u64,
    peerapi_capacity_drops: u64,
    peerapi_dns_queries: u64,
    peerapi_dns_success: u64,
    peerapi_dns_failure: u64,
    peerapi_dns_reply_rejected: u64,
    lan_policy_rejections: u64,
    derp_packet_errors: u64,
    derp_peer_gone: u64,
}

/// Regions whose DERP connect a busy worker queue refused.
///
/// One actor iteration can dispatch a connect for each required region — a
/// replacement for a `Disconnected` notice and another from the trailing
/// `poll_derp` — and the same full queue can refuse both. Keeping only one
/// would leave the other recorded in the node's `derp_connecting` forever,
/// since nothing else retries it.
struct RefusedRegions {
    regions: [u16; Self::CAPACITY],
    len: usize,
}

impl RefusedRegions {
    /// Two DERP worker slots, so at most two regions can be connecting at once;
    /// the spare entries absorb a refusal carried over from a previous
    /// iteration.
    const CAPACITY: usize = 4;

    const fn new() -> Self {
        Self {
            regions: [0; Self::CAPACITY],
            len: 0,
        }
    }

    fn push(&mut self, region: Option<u16>) {
        let Some(region) = region else {
            return;
        };
        if self.regions[..self.len].contains(&region) {
            return;
        }
        if self.len == Self::CAPACITY {
            warn!("derp refusal queue full, dropping region={region}");
            return;
        }
        self.regions[self.len] = region;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let region = self.regions[0];
        self.regions.copy_within(1..self.len, 0);
        self.len -= 1;
        Some(region)
    }
}

fn rate_limited(counter: &mut u64, metric: &str) {
    *counter = counter.saturating_add(1);
    if counter.is_power_of_two() {
        info!("metric={metric} count={counter}");
    }
}

/// The hardware RNG, which yields true random numbers here because the radio is
/// running and mixes physical noise into it. `Trng` would additionally occupy
/// the ADC, which buys nothing while WiFi is up.
pub(crate) struct HwRng(pub(crate) esp_hal::rng::Rng);

impl Rng for HwRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

impl KeyRng for HwRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

impl tailfeather::disco::packet::Rng for HwRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

impl tailfeather::derp::client::Rng for HwRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

pub(crate) fn now_ms() -> u64 {
    embassy_time::Instant::now().as_millis()
}

#[embassy_executor::task]
pub async fn tunnel(
    stack: Stack<'static>,
    flash: esp_hal::peripherals::FLASH<'static>,
    spawner: Spawner,
) -> ! {
    let authority = Authority::parse(
        crate::TS_CONTROL_URL,
        cfg!(feature = "test-insecure-control"),
    )
    .expect("TS_CONTROL_URL was validated before flashing");
    let mut rng = HwRng(esp_hal::rng::Rng::new());
    let mut state_store = TwoSlot::new(crate::flash::FlashSlots::new(flash));
    let loaded = state_store
        .load_with_metadata()
        .expect("persistent state slots are readable and not both corrupt");
    let needs_repair = loaded.needs_repair();
    let replacement_generation = loaded
        .replacement_generation()
        .expect("persistent state generation is not exhausted");
    let node = match loaded.into_state() {
        Some(state) => match Node::restore_for_authority(&state, authority.digest()) {
            Ok(node) => {
                if needs_repair && !node.requires_persistence() {
                    state_store
                        .save(&state)
                        .expect("repair the missing persistent state copy before networking");
                }
                info!("state=identity-restored");
                node
            }
            Err(_) => {
                info!("state=identity-created reason=authority-changed");
                Node::factory_reset_for_authority(
                    Identity::generate(&mut rng),
                    replacement_generation,
                    authority.digest(),
                )
            }
        },
        None => {
            info!("state=identity-created reason=first-boot");
            Node::factory_reset_for_authority(
                Identity::generate(&mut rng),
                replacement_generation,
                authority.digest(),
            )
        }
    };
    let node = NODE.init(node);
    if node.requires_persistence() {
        let state = match node.poll(0) {
            Ok(Some(NodeAction::PersistState(state))) => state,
            _ => panic!("a fresh or migrated node must request persistence"),
        };
        let generation = state.generation();
        let saved = state_store.save(&state).is_ok()
            && (state_store
                .load_with_metadata()
                .is_ok_and(|loaded| loaded.is_redundant_at(generation))
                || (state_store.save(&state).is_ok()
                    && state_store
                        .load_with_metadata()
                        .is_ok_and(|loaded| loaded.is_redundant_at(generation))));
        node.persistence_result(generation, saved)
            .expect("the initial identity generation matches");
        if !saved {
            panic!("could not verify both identity state slots");
        }
    }
    let clock_floor = node.trusted_time_floor().max(crate::BUILD_TIME_FLOOR);
    let provisional_time = if authority.is_secure() {
        let Some(provisional_time) = bootstrap_time(stack, &mut rng, clock_floor).await else {
            warn!("time-bootstrap failed; retrying after reboot");
            Timer::after(Duration::from_secs(5)).await;
            esp_hal::system::software_reset();
        };
        provisional_time
    } else {
        clock_floor
    };
    spawner.spawn(
        crate::control::run(stack, node, authority, state_store, provisional_time)
            .expect("the control task is spawned once"),
    );
    let crate::control::BootstrapNotice::Ready(node) = crate::control::next_bootstrap().await;
    let published_uplink = stack
        .config_v4()
        .expect("control bootstrap requires an IPv4 lease")
        .address
        .address();
    let endpoint_refresh_at = embassy_time::Instant::now() + Duration::from_secs(30 * 60);
    let scratch = SCRATCH.init(Scratch {
        datagram: [0; wirefeather::MAX_DATAGRAM_LEN],
        inner: [0; wirefeather::budget::INNER_MTU],
    });
    crate::derp::start(spawner, stack);
    let mut derp_regions = [None; crate::derp::SLOTS];
    let mut preferred_derp = node.netmap().home_derp;

    let mut wg_socket = UdpSocket::new(
        stack,
        WG_RX_META.init([PacketMetadata::EMPTY; WG_RX_PACKETS]),
        WG_RX_BUFFER.init([0; WG_RX_BUFFER_LEN]),
        WG_TX_META.init([PacketMetadata::EMPTY; WG_TX_PACKETS]),
        WG_TX_BUFFER.init([0; WG_TX_BUFFER_LEN]),
    );
    wg_socket.bind(LISTEN_PORT).expect("port 51820 is free");

    let udp_raw_socket = RawSocket::new(
        stack,
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Udp),
        UDP_RAW_RX_META.init([raw::PacketMetadata::EMPTY; UDP_RAW_PACKETS]),
        UDP_RAW_RX_BUFFER.init([0; UDP_RAW_BUFFER_LEN]),
        UDP_RAW_TX_META.init([raw::PacketMetadata::EMPTY; UDP_RAW_PACKETS]),
        UDP_RAW_TX_BUFFER.init([0; UDP_RAW_BUFFER_LEN]),
    );
    let mut table = nat::Table::new();

    // One raw socket handles all TCP. Unlike UDP, a forwarded connection
    // cannot use a `TcpSocket`, because that would terminate the connection
    // here rather than pass it through.
    let raw_socket = RawSocket::new(
        stack,
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Tcp),
        RAW_RX_META.init([raw::PacketMetadata::EMPTY; TCP_RAW_PACKETS]),
        RAW_RX_BUFFER.init([0; TCP_RAW_RX_BUFFER_LEN]),
        RAW_TX_META.init([raw::PacketMetadata::EMPTY; TCP_RAW_PACKETS]),
        RAW_TX_BUFFER.init([0; TCP_RAW_TX_BUFFER_LEN]),
    );
    let mut tcp_table = nat::TcpTable::new();
    let icmp_socket = RawSocket::new(
        stack,
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Icmp),
        ICMP_RX_META.init([raw::PacketMetadata::EMPTY; ICMP_RAW_PACKETS]),
        ICMP_RX_BUFFER.init([0; ICMP_RAW_BUFFER_LEN]),
        ICMP_TX_META.init([raw::PacketMetadata::EMPTY; ICMP_RAW_PACKETS]),
        ICMP_TX_BUFFER.init([0; ICMP_RAW_BUFFER_LEN]),
    );
    let mut icmp_table = nat::IcmpTable::new();

    // Translated packets must carry this device's own address as their source.
    let uplink = stack
        .config_v4()
        .expect("the tunnel task starts only after DHCP has completed");
    let mut resolvers = [None; 3];
    let mut resolver_count = 0usize;
    for resolver in uplink.dns_servers.iter().take(resolvers.len()) {
        resolvers[resolver_count] = Some(resolver.octets());
        resolver_count += 1;
    }
    let mut diagnostics = Diagnostics::default();
    let peer_api = PEER_API.init(tailfeather_gateway::peerapi::Server::new(rng.0.random()));
    let mut reverse_priority = false;
    // Regions whose DERP connect could not be handed to a worker; drained by
    // replaying one as a disconnect at the end of an iteration. The replay can
    // itself be refused while the worker queue is still full, so this outlives
    // one iteration: dropping a refusal would strand the region in
    // `derp_connecting` with no further retry. See `dispatch_derp`.
    let mut refused_derp = RefusedRegions::new();
    info!(
        "wireguard listening on :{LISTEN_PORT}, udp-nat={} tcp-nat={} peerapi=:{} resolvers={resolver_count}",
        nat::SLOTS,
        nat::TCP_SLOTS,
        tailfeather_gateway::peerapi::PORT,
    );

    loop {
        // `wait_recv_ready` borrows immutably, so all the sockets can be waited
        // on together and only the one that fired is then borrowed mutably.
        let ready = if reverse_priority {
            match select6(
                select(crate::control::next_notice(), crate::derp::next_notice()),
                icmp_socket.wait_recv_ready(),
                raw_socket.wait_recv_ready(),
                udp_raw_socket.wait_recv_ready(),
                wg_socket.wait_recv_ready(),
                Timer::after(POLL_INTERVAL),
            )
            .await
            {
                Either6::First(Either::First(notice)) => Ready::Control(notice),
                Either6::First(Either::Second(notice)) => Ready::Derp(notice),
                Either6::Second(()) => Ready::Icmp,
                Either6::Third(()) => Ready::Raw,
                Either6::Fourth(()) => Ready::Udp,
                Either6::Fifth(()) => Ready::Tunnel,
                Either6::Sixth(()) => Ready::Timers,
            }
        } else {
            match select6(
                wg_socket.wait_recv_ready(),
                udp_raw_socket.wait_recv_ready(),
                raw_socket.wait_recv_ready(),
                icmp_socket.wait_recv_ready(),
                select(crate::control::next_notice(), crate::derp::next_notice()),
                Timer::after(POLL_INTERVAL),
            )
            .await
            {
                Either6::First(()) => Ready::Tunnel,
                Either6::Second(()) => Ready::Udp,
                Either6::Third(()) => Ready::Raw,
                Either6::Fourth(()) => Ready::Icmp,
                Either6::Fifth(Either::First(notice)) => Ready::Control(notice),
                Either6::Fifth(Either::Second(notice)) => Ready::Derp(notice),
                Either6::Sixth(()) => Ready::Timers,
            }
        };
        reverse_priority = !reverse_priority;

        // DHCP may replace the address while this long-lived task and its
        // sockets remain active. Every translation must use the current lease.
        let Some(uplink) = stack.config_v4() else {
            stack.wait_config_up().await;
            continue;
        };
        let our_ip = uplink.address.address().octets();
        let uplink_prefix = uplink.address.prefix_len();
        if uplink.address.address() != published_uplink
            || embassy_time::Instant::now() >= endpoint_refresh_at
        {
            warn!("endpoint-publication stale; restarting control bootstrap");
            esp_hal::system::software_reset();
        }
        resolvers.fill(None);
        resolver_count = 0;
        for (slot, resolver) in uplink.dns_servers.iter().take(resolvers.len()).enumerate() {
            resolvers[slot] = Some(resolver.octets());
            resolver_count += 1;
        }

        match ready {
            Ready::Tunnel => {
                if let Ok((len, from)) = wg_socket.recv_from(&mut scratch.datagram).await {
                    handle_tunnel_datagram(
                        node,
                        &mut rng,
                        scratch,
                        len,
                        from,
                        &wg_socket,
                        &udp_raw_socket,
                        &mut table,
                        &raw_socket,
                        &mut tcp_table,
                        &icmp_socket,
                        &mut icmp_table,
                        our_ip,
                        uplink_prefix,
                        peer_api,
                        &resolvers,
                        resolver_count,
                        &mut diagnostics,
                        &mut derp_regions,
                    )
                    .await;
                }
            }
            Ready::Udp => {
                handle_udp_reply(
                    node,
                    scratch,
                    &udp_raw_socket,
                    &mut table,
                    peer_api,
                    &resolvers,
                    &wg_socket,
                    our_ip,
                    &mut diagnostics,
                    &mut derp_regions,
                )
                .await;
            }
            Ready::Raw => {
                // A receive-window burst is already ordered and bounded. Drain
                // everything currently queued before timer bookkeeping so the
                // raw ring reaches its wraparound slack promptly. Recheck with
                // a one-poll future to avoid waiting for another packet here.
                for _ in 0..TCP_RAW_PACKETS {
                    handle_raw_reply(
                        node,
                        scratch,
                        &raw_socket,
                        &mut tcp_table,
                        &wg_socket,
                        our_ip,
                        &mut derp_regions,
                    )
                    .await;
                    if poll_once(raw_socket.wait_recv_ready()).is_pending() {
                        break;
                    }
                }
            }
            Ready::Icmp => {
                handle_icmp_reply(
                    node,
                    scratch,
                    &icmp_socket,
                    &mut icmp_table,
                    &wg_socket,
                    our_ip,
                    &mut derp_regions,
                )
                .await;
            }
            Ready::Control(crate::control::Notice::Map(lease)) => {
                let status = node
                    .handle_control_event(tailfeather::ControlEvent::MapFinished {
                        lease: &mut *lease,
                        result: Ok(()),
                    })
                    .ok()
                    .flatten();
                crate::control::emit_action(status.as_ref());
                info!(
                    "netmap peers={} truncated={}",
                    node.netmap().peers.len(),
                    node.netmap().peers_truncated
                );
                if node.exit_control_ready() {
                    info!("state=exit-ready");
                }
                node.seed_staging(&mut *lease);
                crate::control::return_lease(lease);
            }
            Ready::Control(crate::control::Notice::NodeKeyExpired) => {
                crate::control::rotate_expired_node_key(node, &mut rng).await;
            }
            Ready::Derp(crate::derp::Notice::Connected { slot, region }) => {
                // The worker is the authority on what its own slot holds, so
                // its report is adopted rather than checked against the local
                // map. Dropping a mismatched notice left the worker connected
                // with nobody tracking it: the node never learned the region
                // existed, so it never asked for a disconnect, and the slot was
                // occupied for good — half the relay capacity gone until
                // reboot.
                if slot < derp_regions.len() {
                    derp_regions[slot] = Some(region);
                }
                let action = node
                    .handle_derp_event(DerpEvent::Connected { region }, now_ms(), &mut rng)
                    .ok()
                    .flatten();
                crate::control::emit_action(action.as_ref());
                if let Some(action) = action {
                    refused_derp.push(
                        dispatch_node_action(node, &wg_socket, &mut derp_regions, action).await,
                    );
                }
                if node.exit_control_ready() {
                    info!("state=exit-ready");
                }
            }
            Ready::Derp(crate::derp::Notice::PeerGone { region, peer, .. }) => {
                // Relaying through a region the server says has no such peer
                // only burns MTU-sized writes. Clearing it lets the node pick
                // the peer's home region or a direct path on the next send.
                node.forget_relay(&peer, region);
                rate_limited(&mut diagnostics.derp_peer_gone, "derp-peer-gone");
            }
            Ready::Derp(crate::derp::Notice::Disconnected { slot, region }) => {
                if derp_regions.get(slot) == Some(&Some(region)) {
                    derp_regions[slot] = None;
                }
                if let Ok(Some(action)) =
                    node.handle_derp_event(DerpEvent::Disconnected { region }, now_ms(), &mut rng)
                {
                    refused_derp.push(
                        dispatch_node_action(node, &wg_socket, &mut derp_regions, action).await,
                    );
                }
            }
            Ready::Derp(crate::derp::Notice::Packet { slot, region, peer }) => {
                let action = crate::derp::with_packet(slot, |packet| {
                    node.handle_derp_event(
                        DerpEvent::Packet {
                            region,
                            peer,
                            payload: packet,
                        },
                        now_ms(),
                        &mut rng,
                    )
                });
                match action {
                    Some(Ok(Some(NodeAction::DeliveredIpv4 { peer, packet }))) => {
                        handle_delivered_ipv4(
                            node,
                            &peer,
                            packet.as_slice(),
                            scratch,
                            &wg_socket,
                            &udp_raw_socket,
                            &mut table,
                            &raw_socket,
                            &mut tcp_table,
                            &icmp_socket,
                            &mut icmp_table,
                            our_ip,
                            uplink_prefix,
                            peer_api,
                            &resolvers,
                            resolver_count,
                            &mut diagnostics,
                            &mut derp_regions,
                        )
                        .await;
                    }
                    Some(Ok(Some(NodeAction::Derp(command)))) => {
                        refused_derp.push(dispatch_derp(node, &mut derp_regions, command).await);
                    }
                    Some(Err(error)) => {
                        diagnostics.derp_packet_errors =
                            diagnostics.derp_packet_errors.saturating_add(1);
                        if diagnostics.derp_packet_errors.is_power_of_two() {
                            warn!(
                                "metric=derp-packet-error count={} error={error}",
                                diagnostics.derp_packet_errors
                            );
                        }
                    }
                    _ => {}
                }
            }
            Ready::Timers => {}
        }

        // Peer-API failover, timeout, close, and retransmission deadlines must
        // advance even while another socket is continuously ready.
        let tunnel_ip = assigned_ipv4(node).unwrap_or([0; 4]);
        drive_peerapi_timers(
            node,
            scratch,
            peer_api,
            &udp_raw_socket,
            &resolvers,
            resolver_count,
            &wg_socket,
            our_ip,
            tunnel_ip,
            &mut diagnostics,
            &mut derp_regions,
        )
        .await;

        while let Ok(Some(action)) = node.poll_tunnel_timers(now_ms()) {
            dispatch_transmit(&wg_socket, &mut derp_regions, action).await;
        }
        if let Ok(Some(NodeAction::DirectTransmit {
            endpoint, packet, ..
        })) = node.poll_disco(now_ms(), &mut rng)
        {
            send_direct(&wg_socket, packet.as_slice(), endpoint).await;
        }
        refresh_derp_preferences(node, &derp_regions, &mut preferred_derp);
        if let Ok(Some(NodeAction::Derp(command))) = node.poll_derp() {
            refused_derp.push(dispatch_derp(node, &mut derp_regions, command).await);
        }
        // A refused connect leaves the node believing that region is still
        // connecting, which it never retries. Replaying it as a disconnect
        // clears that, marks the region as last-failed and rotates the relay
        // node list, so the next `poll_derp` issues a fresh connect. Handled
        // once per iteration so a repeated refusal cannot recurse; a refusal of
        // the replay itself is carried into the next iteration instead.
        if let Some(region) = refused_derp.pop()
            && let Ok(Some(action)) =
                node.handle_derp_event(DerpEvent::Disconnected { region }, now_ms(), &mut rng)
        {
            // The replayed connect can be refused again while the worker queue
            // is still full. Carrying that refusal into the next iteration,
            // rather than discarding it, keeps the region from being stranded
            // in `derp_connecting` with no further retry.
            refused_derp
                .push(dispatch_node_action(node, &wg_socket, &mut derp_regions, action).await);
        }
    }
}

async fn bootstrap_time(stack: Stack<'static>, rng: &mut HwRng, floor: u64) -> Option<u64> {
    let addresses = match stack.dns_query("pool.ntp.org", DnsQueryType::A).await {
        Ok(addresses) => addresses,
        Err(error) => {
            warn!("time-bootstrap dns={error:?}");
            return None;
        }
    };
    let mut socket = UdpSocket::new(
        stack,
        NTP_RX_META.init([PacketMetadata::EMPTY; NTP_PACKETS]),
        NTP_RX_BUFFER.init([0; NTP_BUFFER_LEN]),
        NTP_TX_META.init([PacketMetadata::EMPTY; NTP_PACKETS]),
        NTP_TX_BUFFER.init([0; NTP_BUFFER_LEN]),
    );
    if socket.bind(0).is_err() {
        return None;
    }

    let resolved = addresses.len();
    let mut sent = 0usize;
    let mut received_count = 0usize;
    let mut valid = 0usize;
    let mut source_mismatches = 0usize;
    let mut last_error = None;
    let mut consensus = tailfeather::time::Consensus::new();
    let mut response = [0; 512];
    'servers: for address in addresses {
        let embassy_net::IpAddress::Ipv4(address) = address;
        let server = address.octets();
        let mut nonce = [0; 8];
        rng.0.read(&mut nonce);
        let request = tailfeather::time::request(nonce);
        let endpoint = IpEndpoint::new(address.into(), 123);
        if socket.send_to(&request, endpoint).await.is_err() {
            continue;
        }
        sent += 1;
        let deadline = embassy_time::Instant::now() + Duration::from_millis(1_500);
        let (len, _source) = loop {
            match select(socket.recv_from(&mut response), Timer::at(deadline)).await {
                Either::First(Ok((len, source))) if source.endpoint == endpoint => {
                    break (len, source);
                }
                Either::First(Ok(_)) => {
                    received_count += 1;
                    source_mismatches += 1;
                }
                Either::First(Err(_)) | Either::Second(()) => continue 'servers,
            }
        };
        received_count += 1;
        let seconds = match tailfeather::time::response(&response[..len], nonce, floor) {
            Ok(seconds) => seconds,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        valid += 1;
        if consensus.push(server, seconds).is_err() {
            continue;
        }
        if let Some(seconds) = consensus.provisional() {
            info!("state=time-ready");
            return Some(seconds);
        }
    }
    warn!(
        "time-bootstrap insufficient-consensus resolved={resolved} sent={sent} received={received_count} valid={valid} source-mismatches={source_mismatches} last-error={last_error:?}"
    );
    None
}

#[allow(
    clippy::large_enum_variant,
    reason = "the actor moves one bounded packet without heap indirection"
)]
enum Ready {
    Tunnel,
    Udp,
    Raw,
    Icmp,
    Control(crate::control::Notice),
    Derp(crate::derp::Notice),
    Timers,
}

/// Decrypt one outer datagram and act on whatever was inside it.
#[allow(clippy::too_many_arguments)]
async fn handle_tunnel_datagram(
    node: &mut Node<PEERS>,
    rng: &mut HwRng,
    scratch: &mut Scratch,
    len: usize,
    from: udp::UdpMetadata,
    wg_socket: &UdpSocket<'_>,
    udp_raw_socket: &RawSocket<'_>,
    table: &mut nat::Table,
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    icmp_socket: &RawSocket<'_>,
    icmp_table: &mut nat::IcmpTable,
    our_ip: [u8; 4],
    uplink_prefix: u8,
    peer_api: &mut tailfeather_gateway::peerapi::Server,
    resolvers: &[Option<[u8; 4]>; 3],
    resolver_count: usize,
    diagnostics: &mut Diagnostics,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Scratch { datagram, .. } = scratch;

    let source = match from.endpoint.addr {
        embassy_net::IpAddress::Ipv4(address) => SocketAddr::V4(SocketAddrV4::new(
            CoreIpv4Addr::from(address.octets()),
            from.endpoint.port,
        )),
    };
    match node.handle_direct_from(&datagram[..len], source, now_ms(), rng) {
        Ok(Some(NodeAction::DirectTransmit {
            endpoint, packet, ..
        })) => send_direct(wg_socket, packet.as_slice(), endpoint).await,
        Ok(Some(NodeAction::DeliveredIpv4 { peer, packet })) => {
            handle_delivered_ipv4(
                node,
                &peer,
                packet.as_slice(),
                scratch,
                wg_socket,
                udp_raw_socket,
                table,
                raw_socket,
                tcp_table,
                icmp_socket,
                icmp_table,
                our_ip,
                uplink_prefix,
                peer_api,
                resolvers,
                resolver_count,
                diagnostics,
                derp_regions,
            )
            .await;
        }
        Ok(_) => {}
        Err(e) => warn!("rx: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_delivered_ipv4(
    node: &mut Node<PEERS>,
    peer: &NodePublic,
    packet: &[u8],
    scratch: &mut Scratch,
    wg_socket: &UdpSocket<'_>,
    udp_raw_socket: &RawSocket<'_>,
    table: &mut nat::Table,
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    icmp_socket: &RawSocket<'_>,
    icmp_table: &mut nat::IcmpTable,
    our_ip: [u8; 4],
    uplink_prefix: u8,
    peer_api: &mut tailfeather_gateway::peerapi::Server,
    resolvers: &[Option<[u8; 4]>; 3],
    resolver_count: usize,
    diagnostics: &mut Diagnostics,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Some(peer_ip) = node
        .netmap()
        .peers
        .by_node_key(peer)
        .and_then(|peer| peer.tailscale_ipv4())
        .map(|address| address.octets())
    else {
        return;
    };
    if let Some(info) = nat::parse_tcp4(packet)
        && info.src_ip == peer_ip
        && info.dst_port == tailfeather_gateway::peerapi::PORT
        && assigned_ipv4(node).is_some_and(|address| address == info.dst_ip)
    {
        handle_peerapi_segment(
            node,
            peer,
            &info,
            true,
            scratch,
            peer_api,
            udp_raw_socket,
            resolvers,
            resolver_count,
            wg_socket,
            our_ip,
            diagnostics,
            derp_regions,
        )
        .await;
        return;
    }
    match tailfeather_gateway::policy::classify(packet, peer_ip, our_ip, uplink_prefix) {
        tailfeather_gateway::policy::Decision::ForwardIpv4 => {}
        tailfeather_gateway::policy::Decision::RejectIpv6 => {
            rate_limited(&mut diagnostics.ipv6_rejected, "ipv6-rejected");
            return;
        }
        tailfeather_gateway::policy::Decision::IsolatedDestination => {
            rate_limited(
                &mut diagnostics.lan_policy_rejections,
                "lan-policy-rejection",
            );
            return;
        }
        reason => {
            warn!("exit-policy drop={reason:?}");
            return;
        }
    }
    if !node.netmap().packet_filter.allows_ipv4(packet) {
        warn!("exit-policy drop=control-filter");
        return;
    }
    let inner = &mut scratch.inner;
    if let Some(reply_len) = assigned_ipv4(node)
        .and_then(|our_tunnel_ip| crate::inner::icmp_echo_reply(packet, our_tunnel_ip, inner))
    {
        encapsulate_and_send(node, peer, &inner[..reply_len], wg_socket, derp_regions).await;
    } else if !node.netmap().default_routes_approved() {
        warn!("exit-policy drop=routes-not-approved");
    } else if !nat::ipv4_ttl_is_forwardable(packet) {
        warn!("exit-policy drop=expired-ttl");
    } else if let Some(flow) = nat::parse_udp4(packet) {
        forward_udp_out(
            udp_raw_socket,
            table,
            inner,
            &flow,
            our_ip,
            packet[8] - 1,
            diagnostics,
        )
        .await;
    } else if let Some(info) = nat::parse_tcp4(packet) {
        forward_tcp_out(
            raw_socket,
            tcp_table,
            inner,
            packet,
            &info,
            our_ip,
            diagnostics,
        )
        .await;
    } else if let Some(info) = nat::parse_icmp4(packet) {
        forward_icmp_out(
            icmp_socket,
            icmp_table,
            inner,
            packet,
            &info,
            our_ip,
            diagnostics,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_peerapi_segment(
    node: &mut Node<PEERS>,
    peer: &NodePublic,
    info: &nat::TcpInfo<'_>,
    authorized: bool,
    scratch: &mut Scratch,
    server: &mut tailfeather_gateway::peerapi::Server,
    udp_raw_socket: &RawSocket<'_>,
    resolvers: &[Option<[u8; 4]>; 3],
    resolver_count: usize,
    wg_socket: &UdpSocket<'_>,
    uplink_ip: [u8; 4],
    diagnostics: &mut Diagnostics,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    if !authorized {
        rate_limited(
            &mut diagnostics.peerapi_dns_failure,
            "peerapi-dns-failure-acl",
        );
    }
    let received = server.receive(info, authorized, now_ms());
    if received.send_reset
        && let Some(len) =
            tailfeather_gateway::peerapi::build_reset(info, info.dst_ip, &mut scratch.inner)
    {
        encapsulate_and_send(node, peer, &scratch.inner[..len], wg_socket, derp_regions).await;
    }
    if received.capacity_drop {
        rate_limited(
            &mut diagnostics.peerapi_capacity_drops,
            "peerapi-capacity-drop",
        );
    }
    let Some(slot) = received.slot else { return };
    if received.send_ack
        && let Some(len) = server.build_ack(slot, info.dst_ip, &mut scratch.inner)
    {
        encapsulate_and_send(node, peer, &scratch.inner[..len], wg_socket, derp_regions).await;
    }
    let mut dns_failed = false;
    if received.dns_query
        && (resolver_count == 0
            || !send_peerapi_dns_query(
                node,
                server,
                slot,
                0,
                udp_raw_socket,
                resolvers,
                uplink_ip,
                scratch,
                diagnostics,
            ))
    {
        server.fail_dns(slot);
        dns_failed = true;
        rate_limited(
            &mut diagnostics.peerapi_dns_failure,
            "peerapi-dns-failure-no-authorized-resolver",
        );
    }
    if received.send_response || dns_failed {
        send_peerapi_response(
            node,
            scratch,
            server,
            slot,
            wg_socket,
            info.dst_ip,
            derp_regions,
        )
        .await;
    }
    if received.close_after_ack {
        server.release(slot);
    }
}

/// Whether this node may proxy DNS for `client_ip` at all.
///
/// The exit-node grant itself is decided by
/// [`tailfeather_gateway::peerapi::client_may_resolve`], which the bare harness
/// calls too — the conformance topology exercises the shipped decision rather
/// than a copy of it. What is added here is the local precondition: a node with
/// no approved default routes is not an exit node yet, so there is nothing to
/// resolve *through*.
fn client_may_resolve(node: &Node<PEERS>, client_ip: [u8; 4]) -> bool {
    node.netmap().default_routes_approved()
        && tailfeather_gateway::peerapi::client_may_resolve(client_ip, |client| {
            node.netmap()
                .packet_filter
                .allows_dns_from(CoreIpv4Addr::from(client))
        })
}

#[allow(clippy::too_many_arguments)]
fn send_peerapi_dns_query(
    node: &Node<PEERS>,
    server: &mut tailfeather_gateway::peerapi::Server,
    slot: usize,
    resolver: usize,
    socket: &RawSocket<'_>,
    resolvers: &[Option<[u8; 4]>; 3],
    uplink_ip: [u8; 4],
    scratch: &mut Scratch,
    diagnostics: &mut Diagnostics,
) -> bool {
    let Some(client_ip) = server.client_ip(slot) else {
        return false;
    };
    if !client_may_resolve(node, client_ip) {
        return false;
    }
    let Some((resolver, address)) = resolvers
        .iter()
        .copied()
        .enumerate()
        .skip(resolver)
        .filter_map(|(index, address)| address.map(|address| (index, address)))
        .next()
    else {
        return false;
    };
    let Some(query) = server.query(slot) else {
        return false;
    };
    let Some(len) = nat::build_udp4(
        uplink_ip,
        PEER_API_DNS_UPLINK_PORT,
        address,
        53,
        query,
        &mut scratch.inner,
    ) else {
        return false;
    };
    match poll_once(socket.send(&scratch.inner[..len])) {
        Poll::Ready(()) => {
            server.note_dns_sent(slot, resolver, now_ms());
            rate_limited(
                &mut diagnostics.peerapi_dns_queries,
                "peerapi-dns-query-sent",
            );
            true
        }
        Poll::Pending => {
            server.note_dns_unsent(slot);
            rate_limited(&mut diagnostics.udp_queue_drops, "peerapi-dns-queue-drop");
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_peerapi_timers(
    node: &mut Node<PEERS>,
    scratch: &mut Scratch,
    server: &mut tailfeather_gateway::peerapi::Server,
    udp_raw_socket: &RawSocket<'_>,
    resolvers: &[Option<[u8; 4]>; 3],
    resolver_count: usize,
    wg_socket: &UdpSocket<'_>,
    uplink_ip: [u8; 4],
    local_ip: [u8; 4],
    diagnostics: &mut Diagnostics,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    match server.poll_dns(now_ms(), resolver_count) {
        Some(tailfeather_gateway::peerapi::DnsTimer::Send { slot, resolver })
            if !send_peerapi_dns_query(
                node,
                server,
                slot,
                resolver,
                udp_raw_socket,
                resolvers,
                uplink_ip,
                scratch,
                diagnostics,
            ) =>
        {
            rate_limited(
                &mut diagnostics.peerapi_dns_failure,
                "peerapi-dns-failover-unavailable",
            );
        }
        Some(tailfeather_gateway::peerapi::DnsTimer::Send { .. }) => {}
        Some(tailfeather_gateway::peerapi::DnsTimer::Failed { slot }) => {
            rate_limited(
                &mut diagnostics.peerapi_dns_failure,
                "peerapi-dns-failure-timeout",
            );
            send_peerapi_response(
                node,
                scratch,
                server,
                slot,
                wg_socket,
                local_ip,
                derp_regions,
            )
            .await;
        }
        None => {}
    }
    if let Some(slot) = server.retransmit_due(now_ms()) {
        send_peerapi_response(
            node,
            scratch,
            server,
            slot,
            wg_socket,
            local_ip,
            derp_regions,
        )
        .await;
    }
}

async fn send_peerapi_response(
    node: &mut Node<PEERS>,
    scratch: &mut Scratch,
    server: &mut tailfeather_gateway::peerapi::Server,
    slot: usize,
    wg_socket: &UdpSocket<'_>,
    local_ip: [u8; 4],
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Some(len) = server.build_response(
        slot,
        local_ip,
        &mut scratch.datagram[..wirefeather::budget::INNER_MTU - 40],
        &mut scratch.inner,
        now_ms(),
    ) else {
        return;
    };
    let Some(client_ip) = nat::parse_tcp4(&scratch.inner[..len]).map(|packet| packet.dst_ip) else {
        return;
    };
    let Some(peer) = peer_for_ip(node, client_ip) else {
        return;
    };
    encapsulate_and_send(node, &peer, &scratch.inner[..len], wg_socket, derp_regions).await;
}

async fn forward_icmp_out(
    socket: &RawSocket<'_>,
    table: &mut nat::IcmpTable,
    scratch: &mut [u8],
    packet: &[u8],
    info: &nat::Icmp4,
    our_ip: [u8; 4],
    diagnostics: &mut Diagnostics,
) {
    if packet.len() > ICMP_RAW_BUFFER_LEN {
        rate_limited(&mut diagnostics.icmp_oversize_drops, "icmp-oversize-drop");
        return;
    }
    let now = now_ms();
    let Some(slot) = table.slot_for_packet(info, now) else {
        return;
    };
    let Some(out) = scratch.get_mut(..packet.len()) else {
        return;
    };
    out.copy_from_slice(packet);
    if !nat::decrement_ipv4_ttl(out) || !nat::rewrite_icmp_outbound(out, our_ip, slot) {
        return;
    }
    match poll_once(socket.send(out)) {
        Poll::Ready(()) => table.observe_outbound(slot, info, now),
        Poll::Pending => rate_limited(&mut diagnostics.icmp_queue_drops, "icmp-queue-drop"),
    }
}

async fn handle_icmp_reply(
    node: &mut Node<PEERS>,
    scratch: &mut Scratch,
    socket: &RawSocket<'_>,
    table: &mut nat::IcmpTable,
    wg_socket: &UdpSocket<'_>,
    our_ip: [u8; 4],
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Ok(len) = socket.recv(&mut scratch.inner).await else {
        return;
    };
    let Some(info) = nat::parse_icmp4(&scratch.inner[..len]) else {
        return;
    };
    let Some(flow) = table.reverse(&info, our_ip, now_ms()) else {
        return;
    };
    if !nat::rewrite_icmp_inbound(&mut scratch.inner[..len], flow)
        || !nat::decrement_ipv4_ttl(&mut scratch.inner[..len])
    {
        return;
    }
    let Some(peer) = peer_for_ip(node, flow.client_ip) else {
        return;
    };
    encapsulate_and_send(node, &peer, &scratch.inner[..len], wg_socket, derp_regions).await;
}

/// Translate a tunnelled UDP datagram through the shared raw uplink socket.
async fn forward_udp_out(
    socket: &RawSocket<'_>,
    table: &mut nat::Table,
    scratch: &mut [u8],
    flow: &nat::Udp4<'_>,
    our_ip: [u8; 4],
    hop_limit: u8,
    diagnostics: &mut Diagnostics,
) {
    if flow.payload.len() > nat::MAX_PAYLOAD {
        return;
    }
    let now = embassy_time::Instant::now().as_millis();
    let Some(slot) =
        table.slot_for_packet(flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, now)
    else {
        rate_limited(&mut diagnostics.udp_capacity_drops, "udp-nat-capacity-drop");
        return;
    };
    let Some(len) = nat::build_udp4(
        our_ip,
        nat::EXT_PORT_BASE + slot as u16,
        flow.dst_ip,
        flow.dst_port,
        flow.payload,
        scratch,
    ) else {
        return;
    };
    scratch[8] = hop_limit;
    scratch[10..12].fill(0);
    let checksum = tailfeather_gateway::checksum(&scratch[..20]);
    scratch[10..12].copy_from_slice(&checksum.to_be_bytes());
    match poll_once(socket.send(&scratch[..len])) {
        Poll::Ready(()) => table.observe_outbound(
            slot,
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            now,
        ),
        Poll::Pending => rate_limited(&mut diagnostics.udp_queue_drops, "udp-queue-drop"),
    }
}

/// Translate a TCP segment from the tunnel and put it on the uplink.
///
/// Unlike UDP, nothing here terminates the connection: the segment keeps its
/// sequence numbers, flags and payload, and only its source address and port
/// are rewritten. The connection is between the tunnel client and the server,
/// with this device in the middle.
async fn forward_tcp_out(
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    scratch: &mut [u8],
    packet: &[u8],
    info: &nat::TcpInfo<'_>,
    our_ip: [u8; 4],
    diagnostics: &mut Diagnostics,
) {
    if !nat::ipv4_ttl_is_forwardable(packet) {
        return;
    }
    let now_ms = embassy_time::Instant::now().as_millis();
    let Some(slot) = tcp_table.slot_for_packet(info, now_ms) else {
        rate_limited(&mut diagnostics.tcp_capacity_drops, "tcp-nat-capacity-drop");
        return;
    };
    let Some(external_port) = tcp_table.external_port_for_packet(slot, info, now_ms) else {
        return;
    };
    let Some(buffer) = scratch.get_mut(..packet.len()) else {
        return;
    };
    buffer.copy_from_slice(packet);

    // Clamp before translating: the option is covered by the checksum, and
    // both adjustments are incremental from whatever it currently is.
    nat::clamp_mss(buffer);
    nat::clamp_tcp_receive_window_scaled(
        buffer,
        CLIENT_TCP_RECEIVE_WINDOW,
        tcp_table.window_scale(slot, true),
    );
    if !nat::rewrite_tcp_outbound(buffer, our_ip, external_port) {
        return;
    }
    if !nat::decrement_ipv4_ttl(buffer) {
        return;
    }

    raw_socket.send(buffer).await;
    tcp_table.observe_outbound(slot, info, now_ms);
}

/// Translate a TCP segment arriving from the uplink back into the tunnel.
async fn handle_raw_reply(
    node: &mut Node<PEERS>,
    scratch: &mut Scratch,
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    wg_socket: &UdpSocket<'_>,
    our_ip: [u8; 4],
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Scratch { inner, .. } = scratch;

    let Ok(len) = raw_socket.recv(inner).await else {
        return;
    };
    let packet = &inner[..len];
    if !nat::ipv4_ttl_is_forwardable(packet) {
        return;
    }
    let Some(info) = nat::parse_tcp4(packet) else {
        return;
    };

    // Raw sockets see unrelated host traffic too. A translated port alone is
    // not sufficient authority to inject a segment into the tunnel: every
    // address and port must match the allocated flow.
    let translated_port = info.dst_port;
    let now = embassy_time::Instant::now().as_millis();
    let Some(flow) = tcp_table.reverse_tcp(&info, our_ip) else {
        return;
    };
    let Some(slot) = tcp_table.slot_for_external_port(translated_port) else {
        return;
    };
    let window_scale = tcp_table.window_scale(slot, false);
    // Observe the authenticated, tuple-validated segment exactly once before
    // its in-place rewrite. This also records the server's original Window
    // Scale from a SYN-ACK for normalizing later window fields.
    tcp_table.observe_inbound(slot, &info, now);

    let inner_packet = &mut inner[..len];
    nat::clamp_mss(inner_packet);
    nat::clamp_tcp_receive_window_scaled(inner_packet, SERVER_TCP_RECEIVE_WINDOW, window_scale);
    if !nat::rewrite_tcp_inbound(inner_packet, flow.client_ip, flow.client_port) {
        return;
    }
    if !nat::decrement_ipv4_ttl(inner_packet) {
        return;
    }
    let Some(peer) = peer_for_ip(node, flow.client_ip) else {
        return;
    };
    let action = match node.encapsulate_ipv4(&peer, &inner[..len], now_ms()) {
        Ok(action) => action,
        Err(e) => {
            warn!("encapsulate: {e}");
            return;
        }
    };
    if let Some(action) = action {
        dispatch_transmit(wg_socket, derp_regions, action).await;
    }
}

/// Take a raw UDP reply and put it back into the tunnel after complete tuple
/// validation.
#[allow(clippy::too_many_arguments)]
async fn handle_udp_reply(
    node: &mut Node<PEERS>,
    scratch: &mut Scratch,
    socket: &RawSocket<'_>,
    table: &mut nat::Table,
    peer_api: &mut tailfeather_gateway::peerapi::Server,
    resolvers: &[Option<[u8; 4]>; 3],
    wg_socket: &UdpSocket<'_>,
    our_ip: [u8; 4],
    diagnostics: &mut Diagnostics,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    let Scratch { datagram, inner } = scratch;

    let Ok(len) = socket.recv(datagram).await else {
        return;
    };
    let Some(packet) = nat::parse_udp4(&datagram[..len]) else {
        return;
    };
    if packet.dst_ip == our_ip && packet.dst_port == PEER_API_DNS_UPLINK_PORT {
        let Some(resolver) = (packet.src_port == 53)
            .then(|| {
                resolvers
                    .iter()
                    .position(|candidate| candidate == &Some(packet.src_ip))
            })
            .flatten()
        else {
            rate_limited(
                &mut diagnostics.peerapi_dns_reply_rejected,
                "peerapi-dns-reply-rejected-tuple",
            );
            return;
        };
        let Some(slot) = peer_api.complete_dns(resolver, packet.payload, now_ms()) else {
            rate_limited(
                &mut diagnostics.peerapi_dns_reply_rejected,
                "peerapi-dns-reply-rejected-message",
            );
            return;
        };
        rate_limited(&mut diagnostics.peerapi_dns_success, "peerapi-dns-success");
        let tunnel_ip = assigned_ipv4(node).unwrap_or([0; 4]);
        send_peerapi_response(
            node,
            scratch,
            peer_api,
            slot,
            wg_socket,
            tunnel_ip,
            derp_regions,
        )
        .await;
        return;
    }
    let Some(flow) = table.reverse_udp(&packet, our_ip, now_ms()) else {
        return;
    };

    // The client addressed the server, so the reply must appear to come from
    // the server, not from this gateway. That is what makes the translation
    // invisible to the client.
    let Some(inner_len) = nat::build_udp4(
        flow.server_ip,
        flow.server_port,
        flow.client_ip,
        flow.client_port,
        packet.payload,
        inner,
    ) else {
        return;
    };

    let Some(peer) = peer_for_ip(node, flow.client_ip) else {
        return;
    };
    encapsulate_and_send(node, &peer, &inner[..inner_len], wg_socket, derp_regions).await;
}

fn assigned_ipv4(node: &Node<PEERS>) -> Option<[u8; 4]> {
    node.netmap()
        .addresses
        .iter()
        .find_map(|cidr| match cidr.address {
            core::net::IpAddr::V4(address) => Some(address.octets()),
            core::net::IpAddr::V6(_) => None,
        })
}

fn peer_for_ip(node: &Node<PEERS>, address: [u8; 4]) -> Option<NodePublic> {
    node.netmap()
        .peers
        .iter()
        .find_map(|peer| (peer.tailscale_ipv4()?.octets() == address).then_some(peer.node_key))
}

async fn encapsulate_and_send(
    node: &mut Node<PEERS>,
    peer: &NodePublic,
    packet: &[u8],
    socket: &UdpSocket<'_>,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
) {
    match node.encapsulate_ipv4(peer, packet, now_ms()) {
        Ok(Some(action)) => dispatch_transmit(socket, derp_regions, action).await,
        Ok(None) => {}
        Err(e) => warn!("encapsulate: {e}"),
    }
}

async fn dispatch_transmit(
    socket: &UdpSocket<'_>,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
    action: NodeAction,
) {
    match action {
        NodeAction::DirectTransmit {
            endpoint, packet, ..
        } => send_direct(socket, packet.as_slice(), endpoint).await,
        NodeAction::Derp(DerpCommand::Send {
            region,
            peer,
            packet,
        }) => {
            relay_or_drop(derp_regions, region, peer, packet.as_slice());
        }
        _ => {}
    }
}

/// Hand a packet to the worker owning `region`, or drop it.
///
/// Never waits. The actor is the only task that drains worker notices, and a
/// worker blocks after each delivered packet until the actor acknowledges it —
/// so an actor parked in a relay send is an actor that cannot release the
/// worker that is keeping it parked. That livelock used to unwind only on the
/// five-second write timeout, stalling every other peer, socket, and timer
/// behind it.
///
/// Dropping is the right answer: this carries WireGuard, which retransmits.
fn relay_or_drop(
    derp_regions: &[Option<u16>; crate::derp::SLOTS],
    region: u16,
    peer: NodePublic,
    packet: &[u8],
) -> bool {
    let Some(slot) = derp_regions
        .iter()
        .position(|connected| *connected == Some(region))
    else {
        return false;
    };
    crate::derp::try_send_packet(slot, region, peer, packet)
}

async fn dispatch_node_action(
    node: &Node<PEERS>,
    socket: &UdpSocket<'_>,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
    action: NodeAction,
) -> Option<u16> {
    match action {
        NodeAction::Derp(command) => dispatch_derp(node, derp_regions, command).await,
        action => {
            dispatch_transmit(socket, derp_regions, action).await;
            None
        }
    }
}

/// Returns the region of a `Connect` that could not be handed to a worker.
///
/// The node has already recorded that region as connecting, and only a
/// `Connected`/`Disconnected` event clears it. Dropping the command silently
/// therefore stranded the region forever: `poll_derp` skips regions it believes
/// are connecting, so it never retried, and because the home region is always
/// required the entry was never evicted. With `pending_derp` still set, every
/// subsequent relay send also failed with `Capacity`. The caller feeds the
/// returned region back as a `Disconnected` event to undo that.
async fn dispatch_derp(
    node: &Node<PEERS>,
    derp_regions: &mut [Option<u16>; crate::derp::SLOTS],
    command: DerpCommand,
) -> Option<u16> {
    match command {
        DerpCommand::Connect { region, endpoint } => {
            if derp_regions.contains(&Some(region)) {
                return None;
            }
            let Some(slot) = derp_regions.iter().position(Option::is_none) else {
                warn!("derp connect refused: both bounded slots are occupied region={region}");
                return Some(region);
            };
            // The slot's command channel holds one entry and also carries
            // `Send`, so a packet queued just before the previous session ended
            // can still occupy it here. The worker drains it moments later,
            // which is why this is reported for retry rather than treated as
            // fatal.
            if crate::derp::try_command(
                slot,
                crate::derp::Command::Connect {
                    region,
                    endpoint,
                    identity: node.identity().node.clone(),
                    preferred: node.netmap().home_derp == region,
                },
            ) {
                derp_regions[slot] = Some(region);
            } else {
                warn!("derp connect refused: slot={slot} command queue busy region={region}");
                return Some(region);
            }
        }
        DerpCommand::Send {
            region,
            peer,
            packet,
        } => {
            if !relay_or_drop(derp_regions, region, peer, packet.as_slice()) {
                warn!("derp send dropped: region={region}");
            }
        }
        DerpCommand::Disconnect { region } => {
            if let Some(slot) = derp_regions
                .iter()
                .position(|connected| *connected == Some(region))
            {
                crate::derp::request_disconnect(slot, region);
            }
        }
    }
    None
}

fn refresh_derp_preferences(
    node: &Node<PEERS>,
    derp_regions: &[Option<u16>; crate::derp::SLOTS],
    previous: &mut u16,
) {
    let preferred = node.netmap().home_derp;
    if preferred == *previous {
        return;
    }
    *previous = preferred;
    for (slot, region) in derp_regions.iter().copied().enumerate() {
        if let Some(region) = region {
            crate::derp::set_preferred(slot, region, preferred == region);
        }
    }
}

async fn send_direct(socket: &UdpSocket<'_>, data: &[u8], endpoint: SocketAddr) {
    let SocketAddr::V4(endpoint) = endpoint else {
        warn!("IPv6 direct endpoints are not supported by this firmware");
        return;
    };
    let endpoint = IpEndpoint::new(
        Ipv4Address::from(endpoint.ip().octets()).into(),
        endpoint.port(),
    );
    send(socket, data, endpoint.into()).await;
}

async fn send(socket: &UdpSocket<'_>, data: &[u8], to: udp::UdpMetadata) {
    if let Err(e) = socket.send_to(data, to).await {
        warn!("send: {e:?}");
    }
}
