//! A std WireGuard responder, for interoperability testing against the real
//! thing.
//!
//! This is the M2 milestone proved on a laptop instead of on the chip: it wires
//! [`wirefeather::Device`] to a plain `std::net::UdpSocket` and answers ICMP echo
//! requests that arrive inside the tunnel, which is exactly what the firmware's
//! `tunnel.rs` and `inner.rs` will do over embassy-net. Debugging the protocol
//! here is far cheaper than debugging it over a serial cable.
//!
//! Driven by `scripts/interop-wireguard.sh`; see that script for how the peer
//! is set up.
//!
//! ```text
//! responder <listen addr> <our private key, hex> <peer public key, hex> <our tunnel IPv4>
//! ```

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use wirefeather::{Action, Device, Instant, PeerId, Rng};

/// Reads from the operating system's entropy pool.
struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        std::fs::File::open("/dev/urandom")
            .expect("/dev/urandom is present on Linux")
            .read_exact(dest)
            .expect("/dev/urandom never short reads");
    }
}

fn parse_key(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str.trim()).expect("key must be valid hex");
    bytes.try_into().expect("key must be 32 bytes")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, listen, private_hex, peer_hex, tunnel_ip] = args.as_slice() else {
        eprintln!(
            "usage: responder <listen addr> <private key hex> <peer public key hex> <tunnel ipv4>"
        );
        std::process::exit(2);
    };

    let mut device: Device<1> = Device::new(parse_key(private_hex));
    device
        .add_peer(parse_key(peer_hex), None)
        .expect("the peer table has room for one peer");
    let our_ip: std::net::Ipv4Addr = tunnel_ip.parse().expect("tunnel ip must be IPv4");

    let socket = UdpSocket::bind(listen.as_str()).expect("bind failed");
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("read timeouts are supported on UDP sockets");
    println!("listening on {listen}");
    println!("our public key: {}", hex::encode(device.public_key()));

    let started = StdInstant::now();
    let now = || Instant(started.elapsed().as_millis() as u64);

    let mut endpoint: Option<SocketAddr> = None;
    let mut datagram = [0u8; 2048];
    let mut out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    let mut reply = [0u8; wirefeather::MAX_DATAGRAM_LEN];

    loop {
        match socket.recv_from(&mut datagram) {
            Ok((len, from)) => {
                endpoint = Some(from);
                if std::env::var_os("WG_DUMP").is_some() {
                    println!("DUMP {}", hex::encode(&datagram[..len]));
                }
                match device.handle_udp(&datagram[..len], now(), &mut OsRng, &mut out) {
                    Ok(Action::Send { data, .. }) => {
                        println!("-> handshake response, {} bytes", data.len());
                        let _ = socket.send_to(data, from);
                    }
                    Ok(Action::Receive { peer, packet }) => {
                        println!("<- tunnelled packet, {} bytes", packet.len());
                        if let Some(len) = icmp_echo_reply(packet, our_ip, &mut reply) {
                            send_encapsulated(
                                &mut device,
                                peer,
                                &reply[..len],
                                now(),
                                &socket,
                                from,
                            );
                        }
                    }
                    Ok(Action::None | Action::Authenticated { .. }) => {}
                    Err(e) => println!("!! {e}"),
                }
            }
            // A timeout is the normal idle path, and the point at which timers
            // get a chance to run.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("recv failed: {e}");
                break;
            }
        }

        while let Action::Send { data, .. } = device.poll_timers(now(), &mut out) {
            let Some(to) = endpoint else { break };
            println!("-> keepalive, {} bytes", data.len());
            let _ = socket.send_to(data, to);
        }
    }
}

fn send_encapsulated(
    device: &mut Device<1>,
    peer: PeerId,
    packet: &[u8],
    now: Instant,
    socket: &UdpSocket,
    to: SocketAddr,
) {
    let mut out = [0u8; wirefeather::MAX_DATAGRAM_LEN];
    match device.encapsulate(peer, packet, now, &mut out) {
        Ok(Action::Send { data, .. }) => {
            println!("-> echo reply, {} bytes", data.len());
            let _ = socket.send_to(data, to);
        }
        Ok(_) => {}
        Err(e) => println!("!! encapsulate: {e}"),
    }
}

/// The internet checksum of RFC 1071: the one's complement of the one's
/// complement sum of 16-bit words.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Turn an ICMP echo request addressed to `our_ip` into an echo reply.
///
/// Returns the reply length, or `None` if `packet` was not an echo request for
/// us. This is the logic the firmware's `inner.rs` needs, prototyped here where
/// it can be tested against a real `ping`.
fn icmp_echo_reply(packet: &[u8], our_ip: std::net::Ipv4Addr, out: &mut [u8]) -> Option<usize> {
    const PROTO_ICMP: u8 = 1;
    const ECHO_REQUEST: u8 = 8;
    const ECHO_REPLY: u8 = 0;

    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if packet[9] != PROTO_ICMP || packet.len() < header_len + 8 {
        return None;
    }
    if packet[16..20] != our_ip.octets() || packet[header_len] != ECHO_REQUEST {
        return None;
    }

    let out = out.get_mut(..packet.len())?;
    out.copy_from_slice(packet);

    // Swap source and destination so the reply goes back where it came from.
    out.copy_within(12..16, 16);
    out[12..16].copy_from_slice(&packet[16..20]);
    out[8] = 64; // fresh TTL
    out[10..12].fill(0);
    let ip_checksum = checksum(&out[..header_len]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // An echo reply differs from a request only in the type byte, so the ICMP
    // payload and identifier are carried over untouched.
    out[header_len] = ECHO_REPLY;
    out[header_len + 2..header_len + 4].fill(0);
    let icmp_checksum = checksum(&out[header_len..]);
    out[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    Some(out.len())
}
