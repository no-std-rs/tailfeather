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

use ts_disco::{Message, Ping, Pong};
use ts_keys::DiscoPublic;

use crate::control::ControlError;
use crate::exec::{Either, Reactor, block_on, select};
use crate::net::UdpSocket;
use crate::time::Clock;
use crate::OsRng;

impl ts_disco::packet::Rng for OsRng {
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
        exchange(&reactor, state_dir, address, port, hostname, clock, listen_ms),
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
    disco: DiscoPublic,
    tx_id: [u8; 12],
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
    let store = crate::store::FileStore::new(state_dir, "identity.bin")
        .map_err(ControlError::Store)?;
    let (identity, _) =
        ts_keys::store::load_or_create(&store, &mut OsRng).map_err(|e| match e {
            ts_keys::store::IdentityError::Store(e) => ControlError::Store(e),
            ts_keys::store::IdentityError::Format(e) => ControlError::Identity(e),
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

    let netmap =
        crate::control::load_netmap(reactor, state_dir, address, port, hostname, &[&endpoint_text])
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
    let mut candidates: heapless::Vec<Candidate, { ts_netmap::MAX_PEERS }> =
        heapless::Vec::new();
    for peer in netmap.peers.iter() {
        let (Some(disco), Some(endpoint)) = (peer.disco_key, peer.direct_endpoint()) else {
            continue;
        };
        let mut tx_id = [0u8; 12];
        crate::rt::getrandom(&mut tx_id);
        let _ = candidates.push(Candidate {
            endpoint,
            disco,
            tx_id,
        });
    }

    if candidates.is_empty() {
        println!("!! no peer published both a disco key and a reachable endpoint");
        evt!("{{\"event\":\"disco\",\"result\":\"no-candidates\"}}");
        return Ok(());
    }
    println!("{} candidate path(s)", candidates.len());

    // The same socket the tunnel would use. A probe answered on a different
    // port proves a path WireGuard cannot take, because a NAT maps ports
    // independently.
    println!("probing from {bound}");

    let mut pongs = 0usize;
    let mut pings = 0usize;
    let mut packet = [0u8; ts_disco::MAX_PACKET];
    let mut plaintext = [0u8; ts_disco::MAX_PACKET];
    let deadline = clock.millis() + listen_ms;

    let mut next_probe = 0u64;
    while clock.millis() < deadline {
        if clock.millis() >= next_probe {
            next_probe = clock.millis() + PROBE_INTERVAL_MS;
            for candidate in candidates.iter() {
                let ping = Message::Ping(Ping {
                    tx_id: candidate.tx_id,
                    node_key: Some(identity.node.public()),
                });
                let len = ping.encode(&mut plaintext).map_err(ControlError::Disco)?;
                let total = ts_disco::seal(
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

        let mut incoming = [0u8; ts_disco::MAX_PACKET];
        let received = match select(
            socket.recv_from(&mut incoming),
            reactor.sleep(PROBE_INTERVAL_MS),
        )
        .await
        {
            Either::First(Ok(received)) => received,
            Either::First(Err(_)) | Either::Second(()) => continue,
        };
        let (len, from) = received;

        if !ts_disco::is_disco(&incoming[..len]) {
            // WireGuard traffic on the shared socket. Nothing here handles it;
            // reporting it is how a demultiplexing mistake would show up.
            println!("<- {len} bytes from {from}, not disco");
            continue;
        }

        // The sender's key names which peer to expect. It is not proof of
        // anything until the box opens under it.
        let claimed = match ts_disco::packet::sender_key(&incoming[..len]) {
            Ok(key) => key,
            Err(e) => {
                println!("!! malformed disco packet: {e}");
                continue;
            }
        };
        let Some(candidate) = candidates.iter().find(|c| c.disco == claimed) else {
            println!("<- disco from an unknown key {claimed}");
            continue;
        };

        let opened = match ts_disco::open(
            &identity.disco,
            &candidate.disco,
            &incoming[..len],
            &mut plaintext,
        ) {
            Ok(opened) => opened,
            Err(e) => {
                println!("!! disco box from {from}: {e}");
                continue;
            }
        };

        match Message::decode(&plaintext[..opened.len]) {
            Ok(Message::Pong(pong)) => {
                // The transaction id ties the answer to the probe, and so to
                // the path it was sent on.
                let expected = pong.tx_id == candidate.tx_id;
                pongs += 1;
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
                pings += 1;
                println!("<- ping from {from}, answering");
                // The answer carries the address the ping arrived from, which
                // is the only way the sender can learn its own public address.
                let pong = Message::Pong(Pong {
                    tx_id: ping.tx_id,
                    src: SocketAddr::V4(from),
                });
                let plen = pong.encode(&mut plaintext).map_err(ControlError::Disco)?;
                let total = ts_disco::seal(
                    &identity.disco,
                    &our_disco,
                    &claimed,
                    &plaintext[..plen],
                    &mut OsRng,
                    &mut packet,
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
    }

    println!("{pongs} pong(s) received, {pings} ping(s) answered");
    evt!(
        "{{\"event\":\"disco\",\"result\":\"ok\",\"pongs\":{pongs},\"pings\":{pings},\"candidates\":{}}}",
        candidates.len()
    );
    Ok(())
}
