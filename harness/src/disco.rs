//! Disco against a real Tailscale client.
//!
//! The netmap says where a peer claims to be and what disco key it uses; this
//! sends a probe to each candidate and listens for the answer. A pong from a
//! real `tailscaled` is the only thing that proves the packet format and the
//! NaCl box are right — the message is unforgeable by construction, so it either
//! opens on the other side or the exchange is silent.
//!
//! Pings that arrive are answered, which is the other half: the reference client
//! probes back once it knows where we are, and its willingness to keep doing so
//! is what turns a path into a chosen one.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tailfeather::disco::{Message, Ping, Pong};
use tailfeather::keys::{DiscoPublic, NodePublic};

use crate::OsRng;
use crate::control::ControlError;
use crate::exec::{Either, Reactor, block_on, select};
use crate::net::UdpSocket;
use crate::time::Clock;

impl tailfeather::disco::packet::Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::rt::getrandom(dest);
    }
}

/// How long to wait for answers before giving up, when the caller does not say.
const DEFAULT_LISTEN_MS: u64 = 12_000;

/// How often to repeat the probes while waiting.
const PROBE_INTERVAL_MS: u64 = 1_000;

pub fn run(
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    hostname: &str,
    seconds: Option<u64>,
) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    let listen_ms = seconds.map(|s| s * 1_000).unwrap_or(DEFAULT_LISTEN_MS);
    match block_on(
        &reactor,
        exchange(
            &reactor, state_dir, address, port, hostname, clock, listen_ms,
        ),
    ) {
        Ok(()) => crate::rt::exit(0),
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"disco\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

/// One candidate path to one peer.
struct Candidate {
    endpoint: SocketAddrV4,
    node: NodePublic,
    disco: DiscoPublic,
    tx_id: [u8; 12],
}

/// Attribute an authenticated ping to one candidate.
///
/// A disco key can be shared by more than one node. Use the node key carried by
/// modern pings; only fall back to the disco key for legacy pings that omit it,
/// and only when the disco key names exactly one candidate.
fn candidate_for_ping(
    candidates: &[Candidate],
    disco: DiscoPublic,
    node: Option<NodePublic>,
) -> Option<usize> {
    if let Some(node) = node {
        return candidates
            .iter()
            .position(|candidate| candidate.disco == disco && candidate.node == node);
    }

    let mut matches = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.disco == disco)
        .map(|(index, _)| index);
    let index = matches.next()?;
    matches.next().is_none().then_some(index)
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    reactor: &Reactor,
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    hostname: &str,
    clock: Clock,
    listen_ms: u64,
) -> Result<(), ControlError> {
    let store =
        crate::store::FileStore::new(state_dir, "identity.bin").map_err(ControlError::Store)?;
    let (identity, _) =
        tailfeather::keys::store::load_or_create(&store, &mut OsRng).map_err(|e| match e {
            tailfeather::keys::store::IdentityError::Store(e) => ControlError::Store(e),
            tailfeather::keys::store::IdentityError::Format(e) => ControlError::Identity(e),
        })?;

    // Bound before the map request, because the port has to be in it. Peers
    // learn where to probe us from what the server was told, so a node that
    // registers its endpoints after asking for the map waits a whole poll
    // interval before anyone tries.
    let socket = UdpSocket::bind(reactor, Ipv4Addr::UNSPECIFIED, 0).map_err(ControlError::Net)?;
    let bound = socket.local_address().map_err(ControlError::Net)?;
    let local_ip = UdpSocket::advertisable_address(&SocketAddrV4::new(address, port))
        .map_err(ControlError::Net)?;
    let endpoint = SocketAddrV4::new(local_ip, bound.port());

    let mut endpoint_text = heapless::String::<32>::new();
    let _ = core::fmt::Write::write_fmt(&mut endpoint_text, format_args!("{endpoint}"));
    println!("advertising endpoint {endpoint_text}");
    evt!("{{\"event\":\"endpoint\",\"advertised\":\"{endpoint_text}\"}}");

    let mut netmap = crate::control::load_netmap(
        reactor,
        state_dir,
        address,
        port,
        hostname,
        &[&endpoint_text],
    )
    .await?;
    let our_disco = identity.disco.public();
    println!("our disco key: {our_disco}");

    // The address a peer would send tunnelled traffic to, which is what the
    // conformance suite needs in order to ask the reference client to reach us.
    if let Some(ours) = netmap
        .addresses
        .iter()
        .find(|cidr| cidr.is_ipv4())
        .map(|cidr| cidr.address)
    {
        println!("our tailnet address: {ours}");
        evt!("{{\"event\":\"self\",\"address\":\"{ours}\",\"disco\":\"{our_disco}\"}}");
    }

    // Every peer that published both a disco key and an address we can reach.
    let mut candidates: heapless::Vec<Candidate, { tailfeather::netmap::MAX_PEERS }> =
        heapless::Vec::new();
    for peer in netmap.peers.iter() {
        let (Some(disco), Some(endpoint)) = (peer.disco_key, peer.direct_endpoint()) else {
            continue;
        };
        let mut tx_id = [0u8; 12];
        crate::rt::getrandom(&mut tx_id);
        let _ = candidates.push(Candidate {
            endpoint,
            node: peer.node_key,
            disco,
            tx_id,
        });
    }

    // The same socket the tunnel would use. A probe answered on a different
    // port proves a path WireGuard cannot take, because a NAT maps ports
    // independently.
    println!("probing from {bound}");

    let mut pongs = 0usize;
    let mut pings = 0usize;
    let mut packet = [0u8; tailfeather::disco::MAX_PACKET];
    let mut plaintext = [0u8; tailfeather::disco::MAX_PACKET];
    let mut incoming = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let started = clock.millis();
    let deadline = started.saturating_add(listen_ms);
    // Discovery is useful, but peer probes are the primary purpose of this
    // exchange. Bound the entire DERP scan to one third of the caller's budget
    // so unreachable DNS or STUN servers cannot consume the listen phase.
    let stun_deadline = started.saturating_add(listen_ms / 3);

    let mut next_probe = 0u64;
    let mut stun_region = 0usize;
    let mut stun_best = None;
    while clock.millis() < deadline
        && !probe_stun(
            reactor,
            &socket,
            &netmap,
            clock,
            stun_deadline,
            &mut stun_region,
            &mut stun_best,
        )
        .await
    {
        // STUN left the peer datagram queued after peeking at it. Service it,
        // then resume discovery from the same DERP region.
        let Ok(received) = socket.recv_from(&mut incoming).await else {
            continue;
        };
        handle_incoming(
            &socket,
            &identity,
            &our_disco,
            candidates.as_mut_slice(),
            &incoming,
            received,
            &mut packet,
            &mut plaintext,
            &mut pongs,
            &mut pings,
            &mut next_probe,
        )
        .await?;
    }
    if let Some((_, region, reflexive)) = stun_best
        && apply_preferred_derp(&identity, &mut netmap, region)
    {
        let mut reflexive_text = heapless::String::<32>::new();
        let _ = core::fmt::Write::write_fmt(&mut reflexive_text, format_args!("{reflexive}"));
        let endpoints = [endpoint_text.as_str(), reflexive_text.as_str()];
        let endpoint_count = if endpoints[0] == endpoints[1] { 1 } else { 2 };
        crate::control::publish_endpoint_update(
            reactor,
            state_dir,
            address,
            port,
            hostname,
            region,
            &endpoints[..endpoint_count],
        )
        .await?;
        println!("STUN selected DERP region {region}, reflexive endpoint {reflexive}");
        evt!("{{\"event\":\"stun\",\"region\":{region},\"endpoint\":\"{reflexive}\"}}");
    }

    if candidates.is_empty() {
        println!("!! no peer published both a disco key and a reachable endpoint");
        evt!("{{\"event\":\"disco\",\"result\":\"no-candidates\"}}");
        return Ok(());
    }
    println!("{} candidate path(s)", candidates.len());

    while clock.millis() < deadline {
        if clock.millis() >= next_probe {
            next_probe = clock.millis() + PROBE_INTERVAL_MS;
            for candidate in candidates.iter() {
                let ping = Message::Ping(Ping {
                    tx_id: candidate.tx_id,
                    node_key: Some(identity.node.public()),
                });
                let len = ping.encode(&mut plaintext).map_err(ControlError::Disco)?;
                let total = tailfeather::disco::seal(
                    &identity.disco,
                    &our_disco,
                    &candidate.disco,
                    &plaintext[..len],
                    &mut OsRng,
                    &mut packet,
                )
                .map_err(ControlError::Disco)?;
                let _ = socket.send_to(&packet[..total], &candidate.endpoint).await;
                println!("-> ping {} bytes to {}", total, candidate.endpoint);
            }
        }

        let received = match select(
            socket.recv_from(&mut incoming),
            reactor.sleep(PROBE_INTERVAL_MS),
        )
        .await
        {
            Either::First(Ok(received)) => received,
            Either::First(Err(_)) | Either::Second(()) => continue,
        };
        handle_incoming(
            &socket,
            &identity,
            &our_disco,
            candidates.as_mut_slice(),
            &incoming,
            received,
            &mut packet,
            &mut plaintext,
            &mut pongs,
            &mut pings,
            &mut next_probe,
        )
        .await?;
    }

    println!("{pongs} pong(s) received, {pings} ping(s) answered");
    evt!(
        "{{\"event\":\"disco\",\"result\":\"ok\",\"pongs\":{pongs},\"pings\":{pings},\"candidates\":{}}}",
        candidates.len()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming(
    socket: &UdpSocket<'_>,
    identity: &tailfeather::keys::Identity,
    our_disco: &DiscoPublic,
    candidates: &mut [Candidate],
    incoming: &[u8],
    received: (usize, SocketAddrV4),
    packet: &mut [u8],
    plaintext: &mut [u8],
    pongs: &mut usize,
    pings: &mut usize,
    next_probe: &mut u64,
) -> Result<(), ControlError> {
    let (len, from) = received;
    if !tailfeather::disco::is_disco(&incoming[..len]) {
        println!("<- {len} bytes from {from}, not disco");
        return Ok(());
    }

    let claimed = match tailfeather::disco::packet::sender_key(&incoming[..len]) {
        Ok(key) => key,
        Err(e) => {
            println!("!! malformed disco packet: {e}");
            return Ok(());
        }
    };
    if !candidates
        .iter()
        .any(|candidate| candidate.disco == claimed)
    {
        println!("<- disco from an unknown key {claimed}");
        return Ok(());
    }

    let opened =
        match tailfeather::disco::open(&identity.disco, &claimed, &incoming[..len], plaintext) {
            Ok(opened) => opened,
            Err(e) => {
                println!("!! disco box from {from}: {e}");
                return Ok(());
            }
        };

    match Message::decode(&plaintext[..opened.len]) {
        Ok(Message::Pong(pong)) => {
            let expected = candidates
                .iter()
                .any(|candidate| candidate.disco == claimed && candidate.tx_id == pong.tx_id);
            *pongs += 1;
            println!(
                "<- pong from {from}: it sees us at {} (txid {})",
                pong.src,
                if expected { "matches" } else { "UNEXPECTED" }
            );
            evt!(
                "{{\"event\":\"pong\",\"from\":\"{from}\",\"observed\":\"{}\",\"txid_matches\":{expected}}}",
                pong.src
            );
        }
        Ok(Message::Ping(ping)) => {
            *pings += 1;
            println!("<- ping from {from}, answering");
            if let Some(index) = candidate_for_ping(candidates, claimed, ping.node_key)
                && candidates[index].endpoint != from
            {
                println!(
                    "   authenticated path for {} moved {} -> {from}",
                    candidates[index].node, candidates[index].endpoint
                );
                candidates[index].endpoint = from;
                *next_probe = 0;
            }

            let pong = Message::Pong(Pong {
                tx_id: ping.tx_id,
                src: SocketAddr::V4(from),
            });
            let plen = pong.encode(plaintext).map_err(ControlError::Disco)?;
            let total = tailfeather::disco::seal(
                &identity.disco,
                our_disco,
                &claimed,
                &plaintext[..plen],
                &mut OsRng,
                packet,
            )
            .map_err(ControlError::Disco)?;
            let _ = socket.send_to(&packet[..total], &from).await;
            evt!("{{\"event\":\"ping\",\"from\":\"{from}\"}}");
        }
        Ok(Message::CallMeMaybe(call)) => {
            println!("<- call-me-maybe with {} endpoint(s)", call.endpoints.len());
        }
        Err(e) => println!("!! disco message from {from}: {e}"),
    }
    Ok(())
}

async fn probe_stun(
    reactor: &Reactor,
    socket: &UdpSocket<'_>,
    netmap: &tailfeather::netmap::Netmap<{ tailfeather::netmap::MAX_PEERS }>,
    clock: Clock,
    scan_deadline: u64,
    next_region: &mut usize,
    best: &mut Option<(u64, u16, SocketAddrV4)>,
) -> bool {
    const TIMEOUT_MS: u64 = 400;
    let mut response = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    while let Some(region) = netmap.derp.iter().nth(*next_region) {
        if !region.can_be_home() {
            *next_region += 1;
            continue;
        }
        let remaining = scan_deadline.saturating_sub(clock.millis());
        if remaining == 0 {
            return true;
        }
        let Some(relay) = region.nodes.iter().find(|node| node.stun_port != 0) else {
            *next_region += 1;
            continue;
        };
        let Some(address) =
            crate::dns::resolve_v4(reactor, relay.host_name.as_str(), remaining).await
        else {
            *next_region += 1;
            continue;
        };
        let server = SocketAddrV4::new(address, relay.stun_port);
        let mut transaction = [0; tailfeather::stun::TRANSACTION_ID_LEN];
        crate::rt::getrandom(&mut transaction);
        let request = tailfeather::stun::request(transaction);
        let started = clock.millis();
        if socket.send_to(&request, &server).await.is_err() {
            *next_region += 1;
            continue;
        }
        let deadline = started.saturating_add(TIMEOUT_MS).min(scan_deadline);
        let reflexive = loop {
            let remaining = deadline.saturating_sub(clock.millis());
            if remaining == 0 {
                break None;
            }
            // Do not steal peer traffic from the exchange loop. Peeking lets
            // this phase consume only the active STUN server's packets; any
            // disco or WireGuard datagram stays queued and preempts the rest
            // of discovery so the peer can be serviced immediately.
            match select(socket.peek_from(&mut response), reactor.sleep(remaining)).await {
                Either::First(Ok((len, source))) if source == server => {
                    let parsed = tailfeather::stun::response(&response[..len], transaction);
                    // No other task reads this socket, so the datagram just
                    // inspected is still at the head of the queue.
                    if socket.recv_from(&mut response).await.is_err() {
                        break None;
                    }
                    match parsed {
                        Ok((address, port)) => {
                            break Some(SocketAddrV4::new(Ipv4Addr::from(address), port));
                        }
                        Err(_) => continue,
                    }
                }
                Either::First(Ok(_)) => return false,
                Either::First(Err(_)) | Either::Second(()) => break None,
            }
        };
        if let Some(reflexive) = reflexive {
            let elapsed = clock.millis().saturating_sub(started);
            if best.is_none_or(|current| elapsed < current.0) {
                *best = Some((elapsed, region.id, reflexive));
            }
        }
        *next_region += 1;
    }
    true
}

fn apply_preferred_derp(
    identity: &tailfeather::keys::Identity,
    netmap: &mut tailfeather::netmap::Netmap<{ tailfeather::netmap::MAX_PEERS }>,
    region: u16,
) -> bool {
    let mut node =
        tailfeather::Node::<{ tailfeather::netmap::MAX_PEERS }>::factory_reset(identity.clone(), 1);
    let generation = match node.poll(0) {
        Ok(Some(tailfeather::NodeAction::PersistState(state))) => state.generation(),
        _ => return false,
    };
    if node.persistence_result(generation, true).is_err() {
        return false;
    }
    let mut staging = netmap.clone();
    if node
        .handle_control_event(tailfeather::ControlEvent::MapFinished {
            lease: &mut staging,
            result: Ok(()),
        })
        .is_err()
        || node.prefer_derp(region).is_err()
    {
        return false;
    }
    netmap.home_derp = node.netmap().home_derp;
    true
}
