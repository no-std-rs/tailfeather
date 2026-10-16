//! The two ends of a DNS-over-HTTPS round trip through the exit node.
//!
//! `dns-server` is a fixed-answer UDP resolver, and `doh-client` is an RFC 8484
//! client. Between them sits the real thing: a kernel WireGuard tunnel, the
//! `harness gateway` NAT, and `tailfeather_gateway::peerapi::Server`. Nothing
//! here understands DNS beyond what that round trip needs — the point is not to
//! be a resolver but to be a *reference* one, so that what the proxy sends
//! upstream can be observed rather than assumed.
//!
//! The observation that matters is the advertised EDNS0 payload size. The
//! client asks for 4096, which is more than the proxy can buffer; the resolver
//! reports what actually arrived, and the topology asserts it was lowered.

use core::net::Ipv4Addr;

use crate::exec::{Reactor, block_on};
use crate::net::{TcpStream, UdpSocket};
use crate::time::Clock;

/// What every query is answered with. TEST-NET-3, so a leaked answer cannot be
/// mistaken for a real address.
pub const ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

/// What a DoH client asks an upstream resolver for, before the proxy clamps it.
const CLIENT_PAYLOAD_SIZE: u16 = 4096;

const HTTP_BUFFER: usize = 2048;

/// A fixed-answer resolver that reports what it was asked for.
///
/// `delay_ms` holds each answer back before sending it. A resolver that replies
/// instantly lets the proxy finish one request before the next arrives, so its
/// four connection slots are never under simultaneous pressure and a capacity
/// bug cannot show. Real upstream resolvers take milliseconds to tens of
/// milliseconds, and on hardware that was enough to exhaust the slots.
pub fn dns_server(bind: Ipv4Addr, port: u16, delay_ms: u64) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    let socket = UdpSocket::bind(&reactor, bind, port).expect("bind fixed-answer DNS server");
    evt!("{{\"event\":\"ready\",\"probe\":\"dns-server\",\"delay_ms\":{delay_ms}}}");

    block_on(&reactor, async {
        let mut query = [0u8; crate::dns::MAX_MESSAGE];
        let mut response = [0u8; crate::dns::MAX_MESSAGE];
        loop {
            let (len, from) = socket
                .recv_from(&mut query)
                .await
                .expect("receive a DNS query");
            let query = &query[..len];
            // A query with no OPT record means the classic 512-byte limit, so
            // the two cases are reported apart rather than collapsed.
            let advertised = crate::dns::advertised_payload_size(query).unwrap_or(512);
            let Some(response_len) = answer(query, &mut response) else {
                println!("!! unanswerable query, {len} bytes");
                continue;
            };
            if delay_ms != 0 {
                reactor.sleep(delay_ms).await;
            }
            let _ = socket.send_to(&response[..response_len], &from).await;
            println!("<- query from {from}, advertised {advertised}, answered {ANSWER}");
            evt!("{{\"event\":\"resolved\",\"advertised\":{advertised},\"answer\":\"{ANSWER}\"}}");
        }
    })
}

/// Echo the question and append one A record for it.
fn answer(query: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = crate::dns::question_end(query)?;
    out.get_mut(..end)?.copy_from_slice(&query[..end]);
    // QR=1 and RD copied from the request; RA=1, RCODE=0.
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80;
    out[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // A compression pointer back to the question's name, TYPE A, CLASS IN.
    let record = [
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
    ];
    out.get_mut(end..end + record.len())?
        .copy_from_slice(&record);
    let cursor = end + record.len();
    out.get_mut(cursor..cursor + 4)?
        .copy_from_slice(&ANSWER.octets());
    Some(cursor + 4)
}

/// One RFC 8484 request against the exit node's peer API.
pub fn doh_client(gateway: Ipv4Addr, port: u16, method: &str, name: &str, expected: Ipv4Addr) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    let mut transaction = [0u8; 2];
    crate::rt::getrandom(&mut transaction);
    let mut query = [0u8; crate::dns::MAX_MESSAGE];
    let query_len = crate::dns::write_query(name, transaction, &mut query)
        .expect("build a DNS query for the requested name");
    // Ask for more than the proxy can hold, so its clamp has something to do.
    let query_len = crate::dns::append_opt(&mut query, query_len, CLIENT_PAYLOAD_SIZE)
        .expect("append an EDNS0 OPT record");
    let query = &query[..query_len];

    block_on(&reactor, async {
        let stream = TcpStream::connect(&reactor, gateway, port)
            .await
            .expect("connect to the peer API");

        let mut request = [0u8; HTTP_BUFFER];
        let request_len = match method {
            "get" => write_get(query, gateway, &mut request),
            "post" => write_post(query, gateway, &mut request),
            _ => panic!("DoH method must be get or post"),
        }
        .expect("build the DoH request");
        stream
            .write_all(&request[..request_len])
            .await
            .expect("send the DoH request");

        // The peer API answers `Connection: close`, so end of stream is the end
        // of the response and no chunk framing is involved.
        let mut response = [0u8; HTTP_BUFFER];
        let mut filled = 0;
        loop {
            match stream.read(&mut response[filled..]).await {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(_) => break,
            }
        }
        let response = &response[..filled];

        let status = response
            .split(|byte| *byte == b'\r')
            .next()
            .unwrap_or_default();
        assert!(
            status.starts_with(b"HTTP/1.1 200"),
            "the peer API refused the query"
        );
        let body_at = find(response, b"\r\n\r\n").expect("a complete HTTP response") + 4;
        let body = &response[body_at..];

        let resolved =
            crate::dns::parse_response(body, transaction).expect("an A record in the answer");
        assert_eq!(resolved, expected, "the resolved address");
        println!("{method} /dns-query resolved {name} to {resolved}");
        evt!("{{\"event\":\"verified\",\"method\":\"{method}\",\"address\":\"{resolved}\"}}");
        crate::rt::exit(0)
    })
}

fn write_get(query: &[u8], host: Ipv4Addr, out: &mut [u8]) -> Option<usize> {
    let mut len = 0;
    push(out, &mut len, b"GET /dns-query?dns=")?;
    len += base64url(query, out.get_mut(len..)?)?;
    push(out, &mut len, b" HTTP/1.1\r\nHost: ")?;
    len += write_host(host, out.get_mut(len..)?)?;
    push(
        out,
        &mut len,
        b"\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n",
    )?;
    Some(len)
}

fn write_post(query: &[u8], host: Ipv4Addr, out: &mut [u8]) -> Option<usize> {
    let mut len = 0;
    push(out, &mut len, b"POST /dns-query HTTP/1.1\r\nHost: ")?;
    len += write_host(host, out.get_mut(len..)?)?;
    push(
        out,
        &mut len,
        b"\r\nContent-Type: application/dns-message\r\nContent-Length: ",
    )?;
    let mut digits = [0u8; 20];
    push(out, &mut len, decimal(query.len(), &mut digits))?;
    push(out, &mut len, b"\r\nConnection: close\r\n\r\n")?;
    push(out, &mut len, query)?;
    Some(len)
}

/// Base64url without padding, which is what RFC 8484 specifies for the `dns`
/// parameter and the only alphabet the peer API's decoder accepts.
fn base64url(input: &[u8], out: &mut [u8]) -> Option<usize> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut written = 0;
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in input {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            *out.get_mut(written)? = ALPHABET[((accumulator >> bits) & 0x3f) as usize];
            written += 1;
        }
    }
    if bits > 0 {
        *out.get_mut(written)? = ALPHABET[((accumulator << (6 - bits)) & 0x3f) as usize];
        written += 1;
    }
    Some(written)
}

fn write_host(host: Ipv4Addr, out: &mut [u8]) -> Option<usize> {
    let mut len = 0;
    let mut digits = [0u8; 20];
    for (index, octet) in host.octets().iter().enumerate() {
        if index != 0 {
            push(out, &mut len, b".")?;
        }
        push(out, &mut len, decimal(usize::from(*octet), &mut digits))?;
    }
    Some(len)
}

fn push(out: &mut [u8], len: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = len.checked_add(bytes.len())?;
    out.get_mut(*len..end)?.copy_from_slice(bytes);
    *len = end;
    Some(())
}

fn decimal(mut value: usize, out: &mut [u8; 20]) -> &[u8] {
    let mut start = out.len();
    loop {
        start -= 1;
        out[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &out[start..];
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
