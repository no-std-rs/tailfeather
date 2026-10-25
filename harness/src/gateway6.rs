//! IPv6 counterpart of the allocation-free namespace gateway.

use crate::exec::{Either4, Reactor, block_on, select4};
use crate::net::{RawIpv6Socket, UdpSocket};
use crate::time::Clock;
use crate::{OsRng, wg};
use core::net::Ipv6Addr;
use tailfeather_gateway::ipv6;
use wirefeather::{Action, Device};

pub fn run(config: wg::Config, uplink: Ipv6Addr, client: Ipv6Addr, tunnel_ip: Ipv6Addr) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    let mut device: Device<1> = Device::new(config.private_key);
    let peer = device
        .add_peer(config.peer_key, None)
        .expect("one authenticated peer");
    let tunnel = UdpSocket::bind(&reactor, config.bind, config.port).expect("WireGuard bind");
    let raw = RawIpv6Socket::bind(&reactor, uplink).expect("IPv6 raw uplink");
    let mut gateway = ipv6::Gateway::new();
    let mut datagram = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut received = [0u8; 2048];
    let mut inner = [0u8; ipv6::MTU];
    let mut output = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut endpoint = None;
    evt!("{{\"event\":\"ready\",\"gateway\":\"ipv6-router\"}}");
    block_on(&reactor, async {
        let mut first = 0;
        loop {
            let event = select4(
                first,
                tunnel.recv_from(&mut datagram),
                raw.recv(&mut received),
                reactor.sleep(250),
                core::future::pending::<()>(),
            )
            .await;
            first = (first + 1) % 3;
            let mut reply_len = None;
            match event {
                Either4::First(Ok((len, from))) => {
                    match device.handle_udp(&datagram[..len], clock.now(), &mut OsRng, &mut output)
                    {
                        Ok(Action::Send { data, .. }) => {
                            let _ = tunnel.send_to(data, &from).await;
                        }
                        Ok(Action::Authenticated {
                            peer: authenticated,
                        }) if authenticated == peer => endpoint = Some(from),
                        Ok(Action::Receive {
                            peer: authenticated,
                            packet,
                        }) if authenticated == peer => {
                            endpoint = Some(from);
                            if packet.len() <= inner.len() {
                                inner[..packet.len()].copy_from_slice(packet);
                                match gateway.outbound(
                                    &mut inner[..packet.len()],
                                    client,
                                    uplink,
                                    clock.millis(),
                                ) {
                                    Ok(destination) => {
                                        let _ = raw.send(&inner[..packet.len()], destination).await;
                                    }
                                    Err(error) => {
                                        reply_len = gateway.error_response(
                                            packet,
                                            tunnel_ip,
                                            error,
                                            clock.millis(),
                                            &mut inner,
                                        )
                                    }
                                }
                            } else if ipv6::Packet::parse(packet).is_ok_and(|p| p.source == client)
                            {
                                reply_len = gateway.error_response(
                                    packet,
                                    tunnel_ip,
                                    ipv6::Error::PacketTooBig,
                                    clock.millis(),
                                    &mut inner,
                                );
                            }
                        }
                        _ => {}
                    }
                }
                Either4::Second(Ok(len)) => {
                    match gateway.inbound(&mut received[..len], uplink, clock.millis()) {
                        Ok(destination) if destination == client => {
                            inner[..len].copy_from_slice(&received[..len]);
                            reply_len = Some(len);
                        }
                        Err(error) => {
                            if let Some(size) = gateway.error_response(
                                &received[..len],
                                uplink,
                                error,
                                clock.millis(),
                                &mut inner,
                            ) && let Ok(reply) = ipv6::Packet::parse(&inner[..size])
                            {
                                let _ = raw.send(&inner[..size], reply.destination).await;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            if let Some(len) = reply_len
                && let Some(to) = endpoint
                && let Ok(Action::Send { data, .. }) =
                    device.encapsulate(peer, &inner[..len], clock.now(), &mut output)
            {
                let _ = tunnel.send_to(data, &to).await;
            }
            while let Action::Send { data, .. } = device.poll_timers(clock.now(), &mut output) {
                if let Some(to) = endpoint {
                    let _ = tunnel.send_to(data, &to).await;
                }
            }
        }
    })
}
