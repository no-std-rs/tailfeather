//! The HTTP/1.1 exchange that turns a TCP connection into a ts2021 one.
//!
//! Two requests, both trivial, neither worth a general HTTP client:
//!
//! ```text
//! GET /key?v=131            -> {"publicKey":"mkey:…"}
//! POST /ts2021              -> 101 Switching Protocols
//!   Upgrade: tailscale-control-protocol
//!   X-Tailscale-Handshake: <base64 of the 101-byte initiation>
//! ```
//!
//! After the `101` the connection is no longer HTTP: the Noise response follows
//! immediately, then records. Every byte after the blank line belongs to
//! [`crate::record`], which is why [`ResponseParser`] reports exactly where the
//! headers ended rather than consuming what it happens to have been given.
//!
//! The request lines below are copied from the captured session, header for
//! header. `Content-Length: 0` in particular is not optional — Headscale reads
//! the request body before switching protocols, and a request without it is
//! read as chunked and hangs.

use crate::{CAPABILITY_VERSION, Error};

/// The token both sides name the protocol with.
pub const UPGRADE_TOKEN: &str = "tailscale-control-protocol";

/// Base64 of a 101-byte initiation: `ceil(101/3)*4`.
pub const HANDSHAKE_HEADER_LEN: usize = 136;

/// Enough for the whole `POST /ts2021` request, including a long host.
pub const MAX_REQUEST: usize = 512;

/// Write `GET /key?v=<capver>` into `out`.
///
/// The capability version is a query parameter rather than a header, and
/// omitting it is refused outright — the lab's Headscale answers "capability
/// version must be set", which the conformance suite asserts.
pub fn write_key_request<'o>(host: &str, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let mut w = Writer::new(out);
    w.str("GET /key?v=")?;
    w.u16(CAPABILITY_VERSION)?;
    w.str(" HTTP/1.1\r\nHost: ")?;
    w.str(host)?;
    w.str("\r\nConnection: close\r\n\r\n")?;
    Ok(w.finish())
}

/// Write the `POST /ts2021` upgrade request, carrying `initiation`.
pub fn write_upgrade_request<'o>(
    host: &str,
    initiation: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let mut w = Writer::new(out);
    w.str("POST /ts2021 HTTP/1.1\r\nHost: ")?;
    w.str(host)?;
    w.str("\r\nUser-Agent: ts-noise\r\nContent-Length: 0\r\nConnection: upgrade\r\nUpgrade: ")?;
    w.str(UPGRADE_TOKEN)?;
    w.str("\r\nX-Tailscale-Handshake: ")?;
    w.base64(initiation)?;
    w.str("\r\n\r\n")?;
    Ok(w.finish())
}

/// Where an HTTP response's headers ended, and what it said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Bytes from the start of the response to just past the blank line. On a
    /// `101` everything after this is already the Noise response.
    pub header_len: usize,
}

/// Parse a response far enough to find the status and the end of the headers.
///
/// Returns [`Error::Incomplete`] until the blank line has arrived. Headers are
/// not indexed: the only one that matters is `Upgrade`, and a `101` that named a
/// different protocol would be a server bug rather than a case to handle.
pub fn parse_response(bytes: &[u8]) -> Result<Response, Error> {
    if bytes.len() < 12 {
        return Err(Error::Incomplete);
    }
    if !bytes.starts_with(b"HTTP/1.1 ") && !bytes.starts_with(b"HTTP/1.0 ") {
        return Err(Error::Malformed);
    }
    let status = ascii_u16(&bytes[9..12]).ok_or(Error::Malformed)?;

    let header_len = find_blank_line(bytes).ok_or(Error::Incomplete)?;
    Ok(Response { status, header_len })
}

/// Check that a response is the upgrade we asked for.
pub fn is_upgrade(bytes: &[u8], response: Response) -> bool {
    response.status == 101 && contains_ignoring_case(&bytes[..response.header_len], UPGRADE_TOKEN)
}

fn find_blank_line(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn ascii_u16(digits: &[u8]) -> Option<u16> {
    let mut value = 0u16;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((c - b'0') as u16)?;
    }
    Some(value)
}

fn contains_ignoring_case(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Appends to a fixed buffer, refusing to overflow it.
struct Writer<'o> {
    out: &'o mut [u8],
    len: usize,
}

impl<'o> Writer<'o> {
    fn new(out: &'o mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.len + bytes.len();
        if end > self.out.len() {
            return Err(Error::BufferTooSmall);
        }
        self.out[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn str(&mut self, text: &str) -> Result<(), Error> {
        self.bytes(text.as_bytes())
    }

    fn u16(&mut self, mut value: u16) -> Result<(), Error> {
        let mut digits = [0u8; 5];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for i in 0..count {
            self.bytes(&[digits[count - 1 - i]])?;
        }
        Ok(())
    }

    /// Standard base64 with padding, which is what the captured header uses.
    fn base64(&mut self, input: &[u8]) -> Result<(), Error> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            let mut group = [
                ALPHABET[(n >> 18) as usize & 63],
                ALPHABET[(n >> 12) as usize & 63],
                ALPHABET[(n >> 6) as usize & 63],
                ALPHABET[n as usize & 63],
            ];
            // Pad rather than truncate: the captured header ends in '=', and Go's
            // StdEncoding refuses unpadded input.
            if chunk.len() < 3 {
                group[3] = b'=';
            }
            if chunk.len() < 2 {
                group[2] = b'=';
            }
            self.bytes(&group)?;
        }
        Ok(())
    }

    fn finish(self) -> &'o [u8] {
        &self.out[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_request_matches_the_captured_one() {
        // The capture shows: GET /key?v=131 HTTP/1.1
        let mut out = [0u8; MAX_REQUEST];
        let request = write_key_request("127.0.0.1:8080", &mut out).unwrap();
        let text = core::str::from_utf8(request).unwrap();
        assert!(text.starts_with("GET /key?v=131 HTTP/1.1\r\n"));
        assert!(text.contains("Host: 127.0.0.1:8080\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_upgrade_request_carries_every_header_the_capture_shows() {
        let mut out = [0u8; MAX_REQUEST];
        let request = write_upgrade_request("127.0.0.1:8080", &[0x41; 101], &mut out).unwrap();
        let text = core::str::from_utf8(request).unwrap();

        assert!(text.starts_with("POST /ts2021 HTTP/1.1\r\n"));
        // Headscale reads the body before switching protocols; without this it
        // treats the request as chunked and waits forever.
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.contains("Connection: upgrade\r\n"));
        assert!(text.contains("Upgrade: tailscale-control-protocol\r\n"));
        assert!(text.contains("X-Tailscale-Handshake: "));
        assert!(text.ends_with("\r\n\r\n"));
    }

    /// Base64 against RFC 4648's own test vectors.
    ///
    /// This used to be a copy of the `X-Tailscale-Handshake` header from
    /// `tests/vectors/ts2021-session.pcap`, transcribed by hand. That anchor now
    /// lives where it can never go stale — `ts-conformance`'s `pcap_replay`
    /// test reads the header out of the capture and re-encodes it — so what is
    /// left here is the part that needs no capture: the encoding itself,
    /// checked against the vectors in the standard that defines it.
    ///
    /// Every padding case appears: `len % 3` of 0, 1 and 2.
    #[test]
    fn base64_matches_rfc_4648s_vectors_including_padding() {
        const VECTORS: &[(&str, &str)] = &[
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in VECTORS {
            let mut out = [0u8; MAX_REQUEST];
            let mut w = Writer::new(&mut out);
            w.base64(input.as_bytes()).unwrap();
            assert_eq!(
                core::str::from_utf8(w.finish()).unwrap(),
                *expected,
                "base64({input:?})"
            );
        }

        // The `+` and `/` of the standard alphabet, which the URL-safe variant
        // spells differently. Headscale refuses the URL-safe form.
        let mut out = [0u8; MAX_REQUEST];
        let mut w = Writer::new(&mut out);
        w.base64(&[0xfb, 0xff, 0xbf]).unwrap();
        assert_eq!(core::str::from_utf8(w.finish()).unwrap(), "+/+/");
    }

    /// A 101-byte input is what the handshake header actually carries, and its
    /// encoded length is a constant other code sizes buffers against.
    #[test]
    fn an_initiation_sized_input_encodes_to_the_declared_header_length() {
        let mut out = [0u8; MAX_REQUEST];
        let mut w = Writer::new(&mut out);
        w.base64(&[0x41; 101]).unwrap();
        let encoded = w.finish();
        assert_eq!(encoded.len(), HANDSHAKE_HEADER_LEN);
        // 101 % 3 == 2, so exactly one '=' of padding.
        assert!(encoded.ends_with(b"="));
        assert!(!encoded.ends_with(b"=="));
    }

    #[test]
    fn a_101_naming_our_protocol_is_recognised_and_the_body_offset_is_exact() {
        // Copied from the capture, headers and all. The offset matters: the very
        // next byte is the start of the Noise response, and being one out means
        // the response fails to parse.
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nX-Content-Type-Options: nosniff\r\n\r\n\x02\x000W";
        let parsed = parse_response(response).unwrap();
        assert_eq!(parsed.status, 101);
        assert!(is_upgrade(response, parsed));
        assert_eq!(&response[parsed.header_len..], b"\x02\x000W");
    }

    #[test]
    fn an_incomplete_response_asks_for_more_rather_than_guessing() {
        assert_eq!(parse_response(b"HTTP/1.1"), Err(Error::Incomplete));
        assert_eq!(
            parse_response(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n"),
            Err(Error::Incomplete)
        );
        assert_eq!(parse_response(b"not http at all"), Err(Error::Malformed));
    }

    #[test]
    fn anything_but_a_101_upgrade_is_not_an_upgrade() {
        let refused = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n";
        let parsed = parse_response(refused).unwrap();
        assert_eq!(parsed.status, 400);
        assert!(!is_upgrade(refused, parsed));

        // A 101 for some other protocol is not ours either.
        let other = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        let parsed = parse_response(other).unwrap();
        assert!(!is_upgrade(other, parsed));
    }

    #[test]
    fn a_buffer_too_small_for_the_request_is_an_error_not_a_truncation() {
        let mut tiny = [0u8; 32];
        assert_eq!(
            write_upgrade_request("127.0.0.1:8080", &[0x41; 101], &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }
}
