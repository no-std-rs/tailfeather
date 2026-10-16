//! The two WireGuard roles, driven against a real peer.
//!
//! [`run_responder`] is milestone M2's loop: `scripts/interop-wireguard.sh` has
//! been pointing kernel WireGuard at it since then, and its control flow is
//! unchanged so that it keeps working as a regression canary while everything
//! around it is rebuilt.
//!
//! [`run_initiator`] is the new half, and is written on the async runtime
//! instead. That is deliberate: it means the reactor, the non-blocking sockets
//! and the timer path are all exercised by an interop test against the Linux
//! kernel rather than only by a self-test talking to itself.

use core::net::{Ipv4Addr, SocketAddrV4};

use wirefeather::{Action, Device};

use crate::exec::{Either, Reactor, block_on, select};
use crate::net::UdpSocket;
use crate::time::{Clock, tai64n};
use crate::{OsRng, inner};

/// How often a node wakes with nothing to read, to run its timers.
const TICK_MS: u64 = 250;

pub struct Config {
    pub bind: Ipv4Addr,
    pub port: u16,
    pub private_key: [u8; 32],
    pub peer_key: [u8; 32],
    pub tunnel_ip: [u8; 4],
}

/// Wait for a peer to start a handshake, then serve it.
pub fn run_responder(config: Config) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    let mut device: Device<1> = Device::new(config.private_key);
    let peer = device
        .add_peer(config.peer_key, None)
        .expect("the peer table has room for one peer");

    println!("our public key: {}", crate::HexBytes(&device.public_key()));

    let socket = UdpSocket::bind(&reactor, config.bind, config.port).expect("bind");
    println!("listening on {}:{}", config.bind, config.port);
    evt!("{{\"event\":\"ready\",\"role\":\"responder\"}}");

    let mut datagram = [0u8; 2048];
    let mut out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut reply = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut endpoint: Option<SocketAddrV4> = None;

    block_on(&reactor, async {
        loop {
            let received =
                match select(socket.recv_from(&mut datagram), reactor.sleep(TICK_MS)).await {
                    Either::First(Ok(received)) => Some(received),
                    Either::First(Err(e)) => {
                        println!("!! recv: {e}");
                        None
                    }
                    Either::Second(()) => None,
                };

            if let Some((len, from)) = received {
                endpoint = Some(from);
                match device.handle_udp(&datagram[..len], clock.now(), &mut OsRng, &mut out) {
                    Ok(Action::Send { data, .. }) => {
                        let n = data.len();
                        println!("-> handshake response, {n} bytes");
                        let _ = socket.send_to(&out[..n], &from).await;
                    }
                    Ok(Action::Receive { packet, .. }) => {
                        println!("<- tunnelled packet, {} bytes", packet.len());
                        let echo = inner::icmp_echo_reply(packet, config.tunnel_ip, &mut reply);
                        if let Some(n) = echo {
                            let mut sealed = [0u8; wirefeather::MAX_DATAGRAM_LEN];
                            match device.encapsulate(peer, &reply[..n], clock.now(), &mut sealed) {
                                Ok(Action::Send { data, .. }) => {
                                    let n = data.len();
                                    println!("-> echo reply, {n} bytes");
                                    let _ = socket.send_to(&sealed[..n], &from).await;
                                }
                                Ok(_) => {}
                                Err(e) => println!("!! encapsulate: {e}"),
                            }
                        }
                    }
                    Ok(Action::None | Action::Authenticated { .. }) => {}
                    Err(e) => println!("!! {e}"),
                }
            }

            let Some(to) = endpoint else { continue };
            loop {
                let action = device.poll_timers(clock.now(), &mut out);
                let Action::Send { data, .. } = action else {
                    break;
                };
                let n = data.len();
                println!("-> keepalive, {n} bytes");
                let _ = socket.send_to(&out[..n], &to).await;
            }
        }
    })
}

/// Start the handshake ourselves, and keep the session up.
pub fn run_initiator(config: Config, peer_endpoint: SocketAddrV4, accelerated_rekey: bool) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    let mut device: Device<4> = Device::new(config.private_key);
    let peer = device
        .add_peer(config.peer_key, None)
        .expect("the peer table has room for one peer");
    device
        .set_initiating(peer, true)
        .expect("the peer was just added");

    println!("our public key: {}", crate::HexBytes(&device.public_key()));

    let socket = UdpSocket::bind(&reactor, config.bind, config.port).expect("bind");
    let bound = socket.local_address().expect("getsockname");
    println!("initiating from {bound} to {peer_endpoint}");
    evt!("{{\"event\":\"ready\",\"role\":\"initiator\"}}");

    let mut datagram = [0u8; 2048];
    let mut out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut reply = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut handshake_count = 0u8;
    let mut virtual_offset_ms = 0u64;
    let mut scheduled_virtual_offset: Option<(u64, u64)> = None;

    block_on(&reactor, async {
        loop {
            let real_now = clock.now();
            if let Some((deadline, offset)) = scheduled_virtual_offset
                && real_now.0 >= deadline
            {
                virtual_offset_ms = offset;
                scheduled_virtual_offset = None;
            }
            let now = wirefeather::Instant(real_now.0.saturating_add(virtual_offset_ms));

            // Handshakes first: until one completes there is nothing else this
            // node can usefully do.
            loop {
                let timestamp = tai64n();
                let action = device.poll_handshakes(now, &timestamp, &mut OsRng, &mut out);
                let Action::Send { data, .. } = action else {
                    break;
                };
                let n = data.len();
                println!("-> handshake initiation, {n} bytes");
                let _ = socket.send_to(&out[..n], &peer_endpoint).await;
            }

            loop {
                let action = device.poll_timers(now, &mut out);
                let Action::Send { data, .. } = action else {
                    break;
                };
                let n = data.len();
                println!("-> keepalive, {n} bytes");
                let _ = socket.send_to(&out[..n], &peer_endpoint).await;
            }

            let received =
                match select(socket.recv_from(&mut datagram), reactor.sleep(TICK_MS)).await {
                    Either::First(Ok(received)) => Some(received),
                    Either::First(Err(e)) => {
                        println!("!! recv: {e}");
                        None
                    }
                    Either::Second(()) => None,
                };

            let Some((len, from)) = received else {
                continue;
            };

            let handshake_response = datagram[..len].get(..4) == Some(&2u32.to_le_bytes());
            let handled = device.handle_udp(&datagram[..len], now, &mut OsRng, &mut out);
            let accepted_handshake_response = handshake_response && handled.is_ok();
            match handled {
                Ok(Action::Send { data, .. }) => {
                    let n = data.len();
                    println!("-> {n} bytes");
                    let _ = socket.send_to(&out[..n], &from).await;
                }
                Ok(Action::Receive { packet, .. }) => {
                    println!("<- tunnelled packet, {} bytes", packet.len());
                    let echo = inner::icmp_echo_reply(packet, config.tunnel_ip, &mut reply);
                    if let Some(n) = echo {
                        let mut sealed = [0u8; wirefeather::MAX_DATAGRAM_LEN];
                        match device.encapsulate(peer, &reply[..n], now, &mut sealed) {
                            Ok(Action::Send { data, .. }) => {
                                let n = data.len();
                                println!("-> echo reply, {n} bytes");
                                let _ = socket.send_to(&sealed[..n], &from).await;
                            }
                            Ok(_) => {}
                            Err(e) => println!("!! encapsulate: {e}"),
                        }
                    }
                }
                Ok(Action::None | Action::Authenticated { .. }) => {}
                Err(e) => println!("!! {e}"),
            }

            if accepted_handshake_response && device.is_connected(peer, now) {
                handshake_count = handshake_count.saturating_add(1);
                if handshake_count == 1 {
                    println!("handshake complete");
                    evt!("{{\"event\":\"handshake\",\"role\":\"initiator\"}}");
                } else {
                    println!("rekey {} complete", handshake_count - 1);
                    evt!("{{\"event\":\"rekey\",\"number\":{}}}", handshake_count - 1);
                }
                if accelerated_rekey && handshake_count < 3 {
                    // The production threshold remains unchanged. Advancing the
                    // injected monotonic clock makes the live kernel test take
                    // seconds instead of waiting four minutes for two rekeys.
                    scheduled_virtual_offset = Some((
                        real_now.0.saturating_add(1_000),
                        virtual_offset_ms.saturating_add(wirefeather::timers::REKEY_AFTER_TIME_MS),
                    ));
                }
            }
        }
    })
}
