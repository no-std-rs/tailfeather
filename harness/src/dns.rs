//! Minimal allocation-free DNS A lookup for DERP/STUN adapter hostnames.

use core::net::{Ipv4Addr, SocketAddrV4};

use crate::exec::{Either, Reactor, select};
use crate::net::UdpSocket;

const DNS_PORT: u16 = 53;
const TIMEOUT_MS: u64 = 1_000;
pub(crate) const MAX_MESSAGE: usize = 512;

pub async fn resolve_v4(reactor: &Reactor, host: &str, timeout_ms: u64) -> Option<Ipv4Addr> {
    if let Ok(address) = host.parse() {
        return Some(address);
    }
    let server = nameserver()?;
    let socket = UdpSocket::bind(reactor, Ipv4Addr::UNSPECIFIED, 0).ok()?;
    let mut transaction = [0u8; 2];
    crate::rt::getrandom(&mut transaction);
    let mut request = [0u8; MAX_MESSAGE];
    let request_len = write_query(host, transaction, &mut request)?;
    let server = SocketAddrV4::new(server, DNS_PORT);
    socket
        .send_to(&request[..request_len], &server)
        .await
        .ok()?;

    let mut response = [0u8; MAX_MESSAGE];
    let timeout_ms = timeout_ms.min(TIMEOUT_MS);
    if timeout_ms == 0 {
        return None;
    }
    match select(socket.recv_from(&mut response), reactor.sleep(timeout_ms)).await {
        Either::First(Ok((len, source))) if source == server => {
            parse_response(&response[..len], transaction)
        }
        Either::First(Ok(_) | Err(_)) | Either::Second(()) => None,
    }
}

fn nameserver() -> Option<Ipv4Addr> {
    let mut contents = [0u8; 1024];
    let len = crate::store::read_file("/etc/resolv.conf", &mut contents).ok()?;
    let text = core::str::from_utf8(&contents[..len]).ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver")
            && let Some(address) = fields.next()
            && let Ok(address) = address.parse()
        {
            return Some(address);
        }
    }
    None
}

pub(crate) fn write_query(host: &str, transaction: [u8; 2], out: &mut [u8]) -> Option<usize> {
    let header = out.get_mut(..12)?;
    header.fill(0);
    header[..2].copy_from_slice(&transaction);
    header[2] = 0x01; // recursion desired
    header[5] = 0x01; // one question

    let mut cursor = 12;
    let mut labels = 0;
    for label in host.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        *out.get_mut(cursor)? = bytes.len() as u8;
        cursor += 1;
        out.get_mut(cursor..cursor + bytes.len())?
            .copy_from_slice(bytes);
        cursor += bytes.len();
        labels += 1;
    }
    if labels == 0 {
        return None;
    }
    *out.get_mut(cursor)? = 0;
    cursor += 1;
    out.get_mut(cursor..cursor + 4)?
        .copy_from_slice(&[0, 1, 0, 1]); // A, IN
    Some(cursor + 4)
}

pub(crate) fn parse_response(packet: &[u8], transaction: [u8; 2]) -> Option<Ipv4Addr> {
    let header = packet.get(..12)?;
    if header[..2] != transaction
        || header[2] & 0x80 == 0
        || header[2] & 0x02 != 0
        || header[3] & 0x0f != 0
    {
        return None;
    }
    let questions = u16::from_be_bytes([header[4], header[5]]) as usize;
    let answers = u16::from_be_bytes([header[6], header[7]]) as usize;
    let mut cursor = 12;
    for _ in 0..questions {
        cursor = skip_name(packet, cursor)?;
        cursor = cursor.checked_add(4)?;
        packet.get(..cursor)?;
    }
    for _ in 0..answers {
        cursor = skip_name(packet, cursor)?;
        let fields = packet.get(cursor..cursor + 10)?;
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        let class = u16::from_be_bytes([fields[2], fields[3]]);
        let length = u16::from_be_bytes([fields[8], fields[9]]) as usize;
        cursor += 10;
        let data = packet.get(cursor..cursor + length)?;
        if record_type == 1 && class == 1 && data.len() == 4 {
            return Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        cursor += length;
    }
    None
}

pub(crate) fn skip_name(packet: &[u8], mut cursor: usize) -> Option<usize> {
    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            packet.get(cursor..cursor + 2)?;
            return Some(cursor + 2);
        }
        cursor += 1;
        if length == 0 {
            return Some(cursor);
        }
        if length > 63 {
            return None;
        }
        cursor = cursor.checked_add(usize::from(length))?;
        packet.get(..cursor)?;
    }
}

/// Append an EDNS0 OPT record advertising `payload_size` bytes.
///
/// The record's CLASS field is not a class: in an OPT record it is the sender's
/// advertised UDP payload size, which is the whole reason this exists. A DoH
/// client routinely asks for 4096, far past what the peer API can buffer, and
/// the proxy is supposed to lower it before the query leaves the uplink.
pub(crate) fn append_opt(message: &mut [u8], len: usize, payload_size: u16) -> Option<usize> {
    let [high, low] = payload_size.to_be_bytes();
    // root name, TYPE=41 (OPT), CLASS=payload size, TTL=0, RDLENGTH=0
    let record = [0u8, 0, 41, high, low, 0, 0, 0, 0, 0, 0];
    message
        .get_mut(len..len + record.len())?
        .copy_from_slice(&record);
    // ARCOUNT
    message
        .get_mut(10..12)?
        .copy_from_slice(&1u16.to_be_bytes());
    Some(len + record.len())
}

/// The advertised EDNS0 payload size in a query, if it carries an OPT record.
///
/// A query with no OPT record implies the classic 512-byte limit, reported as
/// `None` rather than guessed at.
pub(crate) fn advertised_payload_size(message: &[u8]) -> Option<u16> {
    let header = message.get(..12)?;
    let questions = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let records = usize::from(u16::from_be_bytes([header[6], header[7]]))
        + usize::from(u16::from_be_bytes([header[8], header[9]]))
        + usize::from(u16::from_be_bytes([header[10], header[11]]));
    let mut cursor = 12;
    for _ in 0..questions {
        cursor = skip_name(message, cursor)?;
        cursor = cursor.checked_add(4)?;
    }
    for _ in 0..records {
        cursor = skip_name(message, cursor)?;
        let fields = message.get(cursor..cursor + 10)?;
        let kind = u16::from_be_bytes([fields[0], fields[1]]);
        if kind == 41 {
            return Some(u16::from_be_bytes([fields[2], fields[3]]));
        }
        cursor += 10 + usize::from(u16::from_be_bytes([fields[8], fields[9]]));
    }
    None
}

/// Where the question section ends, so a reply can echo it byte for byte.
pub(crate) fn question_end(message: &[u8]) -> Option<usize> {
    let header = message.get(..12)?;
    let questions = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if questions == 0 {
        return None;
    }
    let mut cursor = 12;
    for _ in 0..questions {
        cursor = skip_name(message, cursor)?;
        cursor = cursor.checked_add(4)?;
        message.get(..cursor)?;
    }
    Some(cursor)
}
