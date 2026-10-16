//! Allocation-free WireGuard exit-node routing for the namespace topology.
//!
//! With `--resolver`, this also terminates the exit node's peer API — the same
//! [`tailfeather_gateway::peerapi::Server`] the firmware runs, driven the same
//! way — so an RFC 8484 DoH request can be answered through a real WireGuard
//! tunnel rather than in a unit test. The authorization decision is
//! [`tailfeather_gateway::peerapi::client_may_resolve`], asked of a packet
//! filter supplied on the command line, so the shipped decision is what a
//! conformance run exercises.

use core::net::{Ipv4Addr, SocketAddrV4};

use tailfeather::netmap::PacketPolicy;
use tailfeather_gateway::{nat, peerapi};
use wirefeather::{Action, Device, PeerId};

use crate::exec::{Either4, Reactor, block_on, select4};
use crate::net::{NetError, RawIpv4Socket, RawProtocol, UdpSocket};
use crate::time::Clock;
use crate::{OsRng, wg};

const TICK_MS: u64 = 250;

/// The uplink source port the peer API's own DNS queries carry, mirroring the
/// firmware. Replies on any other port belong to a translated client flow.
const PEER_API_DNS_UPLINK_PORT: u16 = 53_053;

/// What the peer API's DNS proxy needs: somewhere to ask, and a policy saying
/// who may ask.
pub struct Dns {
    pub resolver: Ipv4Addr,
    pub policy: PacketPolicy,
}

enum Event {
    Tunnel(Result<(usize, SocketAddrV4), NetError>),
    Udp(Result<usize, NetError>),
    Tcp(Result<usize, NetError>),
    Timers,
}

/// Run one WireGuard responder and route its decrypted IPv4 traffic through
/// raw uplink sockets. This process is intentionally long-lived: UDP and TCP
/// flows share one authenticated peer, endpoint, and timer loop.
pub fn run(config: wg::Config, uplink: Ipv4Addr, dns: Option<Dns>) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    let mut device: Device<1> = Device::new(config.private_key);
    let peer = device
        .add_peer(config.peer_key, None)
        .expect("the gateway has room for its one peer");

    let tunnel = UdpSocket::bind(&reactor, config.bind, config.port).expect("bind WireGuard");
    let raw_udp =
        RawIpv4Socket::bind(&reactor, uplink, RawProtocol::Udp).expect("bind raw UDP uplink");
    let raw_tcp =
        RawIpv4Socket::bind(&reactor, uplink, RawProtocol::Tcp).expect("bind raw TCP uplink");
    let mut udp_table = nat::Table::new();
    let mut tcp_table = nat::TcpTable::new();
    let mut endpoint: Option<SocketAddrV4> = None;
    let mut isn_seed = [0u8; 4];
    crate::rt::getrandom(&mut isn_seed);
    let mut peer_api = peerapi::Server::new(u32::from_le_bytes(isn_seed));

    println!("our public key: {}", crate::HexBytes(&device.public_key()));
    println!(
        "gateway listening on {}:{}, tunnel {}, uplink {}",
        config.bind,
        config.port,
        Ipv4Addr::from(config.tunnel_ip),
        uplink
    );
    match &dns {
        Some(dns) => println!(
            "peer API on {}:{}, resolver {}, {} filter rule(s)",
            Ipv4Addr::from(config.tunnel_ip),
            peerapi::PORT,
            dns.resolver,
            dns.policy.rule_count()
        ),
        None => println!("peer API disabled; no resolver was configured"),
    }
    evt!("{{\"event\":\"ready\",\"gateway\":\"router\"}}");

    let mut wg_datagram = [0u8; 2048];
    let mut udp_packet = [0u8; wirefeather::budget::INNER_MTU];
    let mut tcp_packet = [0u8; wirefeather::budget::INNER_MTU];
    let mut inner = [0u8; wirefeather::budget::INNER_MTU];
    let mut api_segment = [0u8; wirefeather::budget::INNER_MTU];
    let mut api_payload = [0u8; wirefeather::budget::INNER_MTU];
    let mut wg_out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut sealed = [0u8; wirefeather::MAX_DATAGRAM_LEN];

    block_on(&reactor, async {
        let mut first = 0;
        loop {
            let event = match select4(
                first,
                tunnel.recv_from(&mut wg_datagram),
                raw_udp.recv(&mut udp_packet),
                raw_tcp.recv(&mut tcp_packet),
                reactor.sleep(TICK_MS),
            )
            .await
            {
                Either4::First(result) => Event::Tunnel(result),
                Either4::Second(result) => Event::Udp(result),
                Either4::Third(result) => Event::Tcp(result),
                Either4::Fourth(()) => Event::Timers,
            };
            first = (first + 1) % 4;

            // A segment for the peer API is copied out of the decrypted packet
            // and answered below, once the borrow on the WireGuard receive
            // buffer has ended and the device is free to encapsulate a reply.
            let mut peerapi_segment = None;

            match event {
                Event::Tunnel(Ok((len, from))) => {
                    match device.handle_udp(
                        &wg_datagram[..len],
                        clock.now(),
                        &mut OsRng,
                        &mut wg_out,
                    ) {
                        Ok(Action::Send { data, .. }) => {
                            let len = data.len();
                            let _ = tunnel.send_to(&wg_out[..len], &from).await;
                        }
                        Ok(Action::Receive {
                            peer: authenticated,
                            packet,
                        }) if authenticated == peer => {
                            endpoint = Some(from);
                            if let Some(reply_len) = tailfeather_gateway::icmp_echo_reply(
                                packet,
                                config.tunnel_ip,
                                &mut inner,
                            ) {
                                encapsulate(
                                    &mut device,
                                    peer,
                                    &inner[..reply_len],
                                    endpoint,
                                    &tunnel,
                                    &mut sealed,
                                    clock.now(),
                                )
                                .await;
                            } else if let Some(len) = capture_peerapi(
                                dns.as_ref(),
                                packet,
                                config.tunnel_ip,
                                &mut api_segment,
                            ) {
                                peerapi_segment = Some(len);
                            } else {
                                route_outbound(
                                    packet,
                                    uplink.octets(),
                                    &raw_udp,
                                    &raw_tcp,
                                    &mut udp_table,
                                    &mut tcp_table,
                                    &mut inner,
                                    clock.millis(),
                                )
                                .await;
                            }
                        }
                        Ok(Action::Authenticated {
                            peer: authenticated,
                        }) if authenticated == peer => endpoint = Some(from),
                        Ok(
                            Action::None | Action::Receive { .. } | Action::Authenticated { .. },
                        ) => {}
                        Err(error) => println!("!! WireGuard receive: {error}"),
                    }
                }
                Event::Tunnel(Err(error)) => println!("!! WireGuard socket: {error}"),
                Event::Udp(Ok(len)) => {
                    match peerapi_dns_reply(
                        dns.as_ref(),
                        &udp_packet[..len],
                        uplink.octets(),
                        &mut peer_api,
                        clock.millis(),
                    ) {
                        DnsReply::Completed(slot) => {
                            send_peerapi_response(
                                &mut peer_api,
                                slot,
                                config.tunnel_ip,
                                &mut device,
                                peer,
                                endpoint,
                                &tunnel,
                                &mut api_payload[..wirefeather::budget::INNER_MTU - 40],
                                &mut inner,
                                &mut sealed,
                                clock.millis(),
                                clock.now(),
                            )
                            .await;
                            continue;
                        }
                        // Addressed to the proxy's own uplink port but from the
                        // wrong tuple, or an answer nothing was waiting for.
                        // Translating it as a client flow would be worse than
                        // dropping it.
                        DnsReply::Rejected => {
                            println!("!! peer-API DNS reply rejected");
                            continue;
                        }
                        DnsReply::NotOurs => {}
                    }
                    handle_udp_reply(
                        &udp_packet[..len],
                        uplink.octets(),
                        &mut udp_table,
                        &mut device,
                        peer,
                        endpoint,
                        &tunnel,
                        &mut inner,
                        &mut sealed,
                        clock.millis(),
                        clock.now(),
                    )
                    .await;
                }
                Event::Udp(Err(error)) => println!("!! raw UDP receive: {error}"),
                Event::Tcp(Ok(len)) => {
                    handle_tcp_reply(
                        &mut tcp_packet[..len],
                        uplink.octets(),
                        &mut tcp_table,
                        &mut device,
                        peer,
                        endpoint,
                        &tunnel,
                        &mut sealed,
                        clock.millis(),
                        clock.now(),
                    )
                    .await;
                }
                Event::Tcp(Err(error)) => println!("!! raw TCP receive: {error}"),
                Event::Timers => {}
            }

            if let Some(dns) = dns.as_ref() {
                if let Some(len) = peerapi_segment {
                    handle_peerapi_segment(
                        dns,
                        &api_segment[..len],
                        &mut peer_api,
                        &raw_udp,
                        uplink.octets(),
                        config.tunnel_ip,
                        &mut device,
                        peer,
                        endpoint,
                        &tunnel,
                        &mut api_payload[..wirefeather::budget::INNER_MTU - 40],
                        &mut inner,
                        &mut sealed,
                        clock.millis(),
                        clock.now(),
                    )
                    .await;
                }
                drive_peerapi_timers(
                    dns,
                    &mut peer_api,
                    &raw_udp,
                    uplink.octets(),
                    config.tunnel_ip,
                    &mut device,
                    peer,
                    endpoint,
                    &tunnel,
                    &mut api_payload[..wirefeather::budget::INNER_MTU - 40],
                    &mut inner,
                    &mut sealed,
                    clock.millis(),
                    clock.now(),
                )
                .await;
            }

            let Some(to) = endpoint else { continue };
            loop {
                let action = device.poll_timers(clock.now(), &mut wg_out);
                let Action::Send { data, .. } = action else {
                    break;
                };
                let len = data.len();
                let _ = tunnel.send_to(&wg_out[..len], &to).await;
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn route_outbound(
    packet: &[u8],
    uplink: [u8; 4],
    raw_udp: &RawIpv4Socket<'_>,
    raw_tcp: &RawIpv4Socket<'_>,
    udp_table: &mut nat::Table,
    tcp_table: &mut nat::TcpTable,
    scratch: &mut [u8],
    now_ms: u64,
) {
    if !nat::ipv4_ttl_is_forwardable(packet) {
        return;
    }
    if let Some(udp) = nat::parse_udp4(packet) {
        let Some(slot) =
            udp_table.slot_for(udp.src_ip, udp.src_port, udp.dst_ip, udp.dst_port, now_ms)
        else {
            return;
        };
        let Some(len) = nat::build_udp4(
            uplink,
            nat::EXT_PORT_BASE + slot as u16,
            udp.dst_ip,
            udp.dst_port,
            udp.payload,
            scratch,
        ) else {
            return;
        };
        scratch[8] = packet[8];
        if !nat::decrement_ipv4_ttl(&mut scratch[..len]) {
            return;
        }
        let _ = raw_udp
            .send(&scratch[..len], Ipv4Addr::from(udp.dst_ip))
            .await;
        return;
    }

    let Some(info) = nat::parse_tcp4(packet) else {
        return;
    };
    let Some(slot) = tcp_table.slot_for_packet(&info, now_ms) else {
        return;
    };
    let Some(out) = scratch.get_mut(..packet.len()) else {
        return;
    };
    out.copy_from_slice(packet);
    nat::clamp_mss(out);
    // Reusing a closed slot rotates its external port, so ask the table which
    // port this packet actually maps to rather than deriving it from the slot.
    let Some(external_port) = tcp_table.external_port_for_packet(slot, &info, now_ms) else {
        return;
    };
    if !nat::rewrite_tcp_outbound(out, uplink, external_port) {
        return;
    }
    if !nat::decrement_ipv4_ttl(out) {
        return;
    }
    if raw_tcp.send(out, Ipv4Addr::from(info.dst_ip)).await.is_ok() {
        tcp_table.observe_outbound(slot, &info, now_ms);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_udp_reply(
    packet: &[u8],
    uplink: [u8; 4],
    table: &mut nat::Table,
    device: &mut Device<1>,
    peer: PeerId,
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    inner: &mut [u8],
    sealed: &mut [u8],
    now_ms: u64,
    now: wirefeather::Instant,
) {
    if !nat::ipv4_ttl_is_forwardable(packet) {
        return;
    }
    let Some(udp) = nat::parse_udp4(packet) else {
        return;
    };
    let Some(flow) = table.reverse_udp(&udp, uplink, now_ms) else {
        return;
    };
    let Some(len) = nat::build_udp4(
        flow.server_ip,
        flow.server_port,
        flow.client_ip,
        flow.client_port,
        udp.payload,
        inner,
    ) else {
        return;
    };
    inner[8] = packet[8];
    if !nat::decrement_ipv4_ttl(&mut inner[..len]) {
        return;
    }
    encapsulate(device, peer, &inner[..len], endpoint, tunnel, sealed, now).await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_reply(
    packet: &mut [u8],
    uplink: [u8; 4],
    table: &mut nat::TcpTable,
    device: &mut Device<1>,
    peer: PeerId,
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    sealed: &mut [u8],
    now_ms: u64,
    now: wirefeather::Instant,
) {
    if !nat::ipv4_ttl_is_forwardable(packet) {
        return;
    }
    let Some(info) = nat::parse_tcp4(packet) else {
        return;
    };
    let translated_port = info.dst_port;
    let Some(flow) = table.reverse_tcp(&info, uplink) else {
        return;
    };
    let Some(slot) = table.slot_for_external_port(translated_port) else {
        return;
    };
    table.observe_inbound(slot, &info, now_ms);
    nat::clamp_mss(packet);
    if !nat::rewrite_tcp_inbound(packet, flow.client_ip, flow.client_port) {
        return;
    }
    if !nat::decrement_ipv4_ttl(packet) {
        return;
    }
    encapsulate(device, peer, packet, endpoint, tunnel, sealed, now).await;
    let Some(observed) = nat::parse_tcp4(packet) else {
        return;
    };
    table.observe_inbound(slot, &observed, now_ms);
}

async fn encapsulate(
    device: &mut Device<1>,
    peer: PeerId,
    packet: &[u8],
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    sealed: &mut [u8],
    now: wirefeather::Instant,
) {
    let Some(endpoint) = endpoint else { return };
    match device.encapsulate(peer, packet, now, sealed) {
        Ok(Action::Send { data, .. }) => {
            let len = data.len();
            let _ = tunnel.send_to(&sealed[..len], &endpoint).await;
        }
        Ok(_) => {}
        Err(error) => println!("!! WireGuard encapsulate: {error}"),
    }
}

/// What a raw UDP datagram turned out to be, from the peer API's point of view.
enum DnsReply {
    /// Not addressed to the proxy's uplink port; a translated client flow.
    NotOurs,
    /// Addressed to the proxy but unusable: wrong tuple, or an answer no
    /// connection was waiting for.
    Rejected,
    Completed(usize),
}

/// Copy a segment addressed to the peer API out of the decrypted packet.
///
/// The copy is the point. The decrypted packet borrows the WireGuard receive
/// buffer, and answering the segment needs the device again to encapsulate a
/// reply, so the borrow has to end first.
fn capture_peerapi(
    dns: Option<&Dns>,
    packet: &[u8],
    tunnel_ip: [u8; 4],
    out: &mut [u8],
) -> Option<usize> {
    dns?;
    let info = nat::parse_tcp4(packet)?;
    if info.dst_ip != tunnel_ip || info.dst_port != peerapi::PORT {
        return None;
    }
    out.get_mut(..packet.len())?.copy_from_slice(packet);
    Some(packet.len())
}

/// Feed one peer-API segment through the shared server, mirroring the firmware.
#[allow(clippy::too_many_arguments)]
async fn handle_peerapi_segment(
    dns: &Dns,
    segment: &[u8],
    server: &mut peerapi::Server,
    raw_udp: &RawIpv4Socket<'_>,
    uplink: [u8; 4],
    tunnel_ip: [u8; 4],
    device: &mut Device<1>,
    peer: PeerId,
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    payload_out: &mut [u8],
    packet_out: &mut [u8],
    sealed: &mut [u8],
    now_ms: u64,
    now: wirefeather::Instant,
) {
    let Some(info) = nat::parse_tcp4(segment) else {
        return;
    };
    // The segment arrived inside an authenticated WireGuard session with this
    // gateway's one configured peer, which is the condition the firmware
    // applies too. Whether the client may *resolve* is a separate question,
    // asked of the packet filter below.
    let received = server.receive(&info, true, now_ms);
    if received.send_reset
        && let Some(len) = peerapi::build_reset(&info, tunnel_ip, packet_out)
    {
        encapsulate(
            device,
            peer,
            &packet_out[..len],
            endpoint,
            tunnel,
            sealed,
            now,
        )
        .await;
    }
    if received.capacity_drop {
        println!("!! peer-API capacity drop");
    }
    let Some(slot) = received.slot else { return };
    if received.send_ack
        && let Some(len) = server.build_ack(slot, tunnel_ip, packet_out)
    {
        encapsulate(
            device,
            peer,
            &packet_out[..len],
            endpoint,
            tunnel,
            sealed,
            now,
        )
        .await;
    }
    let mut dns_failed = false;
    if received.dns_query
        && !send_dns_query(dns, server, slot, raw_udp, uplink, packet_out, now_ms).await
    {
        server.fail_dns(slot);
        dns_failed = true;
    }
    if received.send_response || dns_failed {
        send_peerapi_response(
            server,
            slot,
            tunnel_ip,
            device,
            peer,
            endpoint,
            tunnel,
            payload_out,
            packet_out,
            sealed,
            now_ms,
            now,
        )
        .await;
    }
    if received.close_after_ack {
        server.release(slot);
    }
}

/// Ask the upstream resolver, if the tailnet policy lets this client ask.
async fn send_dns_query(
    dns: &Dns,
    server: &mut peerapi::Server,
    slot: usize,
    raw_udp: &RawIpv4Socket<'_>,
    uplink: [u8; 4],
    out: &mut [u8],
    now_ms: u64,
) -> bool {
    let Some(client_ip) = server.client_ip(slot) else {
        return false;
    };
    // The shipped decision, not a copy of it. What it must *not* consult is the
    // resolver's own address: it is reached from this uplink, as ourselves, and
    // an RFC1918 resolver under an `autogroup:internet` grant is exactly the
    // configuration that used to answer every query with a 500.
    if !peerapi::client_may_resolve(client_ip, |client| {
        dns.policy.allows_dns_from(Ipv4Addr::from(client))
    }) {
        println!(
            "!! peer-API DNS refused for {}: the policy grants no DNS",
            Ipv4Addr::from(client_ip)
        );
        return false;
    }
    let Some(query) = server.query(slot) else {
        return false;
    };
    let Some(len) = nat::build_udp4(
        uplink,
        PEER_API_DNS_UPLINK_PORT,
        dns.resolver.octets(),
        53,
        query,
        out,
    ) else {
        return false;
    };
    if raw_udp.send(&out[..len], dns.resolver).await.is_err() {
        return false;
    }
    server.note_dns_sent(slot, 0, now_ms);
    true
}

/// Match a raw UDP datagram against the proxy's own outstanding query.
fn peerapi_dns_reply(
    dns: Option<&Dns>,
    packet: &[u8],
    uplink: [u8; 4],
    server: &mut peerapi::Server,
    now_ms: u64,
) -> DnsReply {
    let Some(dns) = dns else {
        return DnsReply::NotOurs;
    };
    let Some(udp) = nat::parse_udp4(packet) else {
        return DnsReply::NotOurs;
    };
    if udp.dst_ip != uplink || udp.dst_port != PEER_API_DNS_UPLINK_PORT {
        return DnsReply::NotOurs;
    }
    if udp.src_port != 53 || udp.src_ip != dns.resolver.octets() {
        return DnsReply::Rejected;
    }
    match server.complete_dns(0, udp.payload, now_ms) {
        Some(slot) => DnsReply::Completed(slot),
        None => DnsReply::Rejected,
    }
}

/// The failover and retransmit timers the peer API needs turned.
#[allow(clippy::too_many_arguments)]
async fn drive_peerapi_timers(
    dns: &Dns,
    server: &mut peerapi::Server,
    raw_udp: &RawIpv4Socket<'_>,
    uplink: [u8; 4],
    tunnel_ip: [u8; 4],
    device: &mut Device<1>,
    peer: PeerId,
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    payload_out: &mut [u8],
    packet_out: &mut [u8],
    sealed: &mut [u8],
    now_ms: u64,
    now: wirefeather::Instant,
) {
    // One resolver here, so a `Send` timer is always a retry of the same one
    // rather than a failover to the next.
    let timer = server.poll_dns(now_ms, 1);
    let mut respond_for = match timer {
        Some(peerapi::DnsTimer::Failed { slot }) => Some(slot),
        _ => None,
    };
    if let Some(peerapi::DnsTimer::Send { slot, .. }) = timer
        && !send_dns_query(dns, server, slot, raw_udp, uplink, packet_out, now_ms).await
    {
        server.fail_dns(slot);
        respond_for = Some(slot);
    }
    if respond_for.is_none() {
        respond_for = server.retransmit_due(now_ms);
    }
    let Some(slot) = respond_for else { return };
    send_peerapi_response(
        server,
        slot,
        tunnel_ip,
        device,
        peer,
        endpoint,
        tunnel,
        payload_out,
        packet_out,
        sealed,
        now_ms,
        now,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn send_peerapi_response(
    server: &mut peerapi::Server,
    slot: usize,
    tunnel_ip: [u8; 4],
    device: &mut Device<1>,
    peer: PeerId,
    endpoint: Option<SocketAddrV4>,
    tunnel: &UdpSocket<'_>,
    payload_out: &mut [u8],
    packet_out: &mut [u8],
    sealed: &mut [u8],
    now_ms: u64,
    now: wirefeather::Instant,
) {
    let Some(len) = server.build_response(slot, tunnel_ip, payload_out, packet_out, now_ms) else {
        return;
    };
    encapsulate(
        device,
        peer,
        &packet_out[..len],
        endpoint,
        tunnel,
        sealed,
        now,
    )
    .await;
}

/// The packet filter the topology installs, named on the command line.
///
/// Both are allow-lists, as tailcfg policies are: a destination that appears in
/// no rule is denied by not being mentioned.
pub fn policy(name: &str) -> Option<PacketPolicy> {
    use tailfeather::netmap::policy::{Destination, FilterRule, Network};

    // Everything the client can send, so the DoH round trip is measured without
    // a policy question in the way.
    const OPEN: &[&str] = &["0.0.0.0/0"];
    // `autogroup:internet`, abridged: public blocks only, and no RFC1918
    // anywhere. Both of the probes the grant is tested with — 8.8.8.8 and
    // 1.1.1.1 — are inside it, and the topology's own 10.211.0.2 resolver is
    // not, which is the whole point of running the check against it.
    const INTERNET: &[&str] = &[
        "1.0.0.0/8",
        "4.0.0.0/6",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "13.0.0.0/8",
        "208.0.0.0/4",
    ];

    let destinations = match name {
        "open" => OPEN,
        "internet" => INTERNET,
        _ => return None,
    };

    let mut policy = PacketPolicy::new();
    policy.replace_set("base").ok()?;
    let mut rule = FilterRule::new();
    // The tunnel's CGNAT range: whoever is on the other side of WireGuard.
    rule.sources
        .push(Network::parse("100.64.0.0/10").ok()?)
        .ok()?;
    rule.protocols.push(17).ok()?;
    for destination in destinations {
        rule.destinations
            .push(Destination {
                network: Network::parse(destination).ok()?,
                first_port: 53,
                last_port: 53,
            })
            .ok()?;
    }
    policy.push_rule("base", rule).ok()?;
    Some(policy)
}
