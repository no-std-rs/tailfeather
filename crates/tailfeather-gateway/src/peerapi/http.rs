//! Sans-I/O HTTP/1.1 framing for stream-based peer API endpoints.
//!
//! Tailscale's peer API is plain HTTP/1.1 carried inside the WireGuard
//! tunnel: the tunnel already authenticates the remote node, so there is no
//! TLS layer. This module owns no stream and performs no allocation. It
//! locates and parses message heads in caller-supplied buffers, decodes
//! `Content-Length` and `chunked` bodies incrementally, and formats the small
//! heads the endpoints send. The blocking and async drivers in
//! [`super::taildrop`] are thin loops over these pieces, so both share one
//! protocol implementation.
//!
//! The parser is deliberately strict, because a lenient one is how request
//! smuggling starts: lines end in CRLF, obsolete line folding is rejected, a
//! message may not carry both `Content-Length` and `Transfer-Encoding`, and
//! `chunked` is the only transfer coding accepted.

use core::fmt::{self, Write as _};

/// HTTP request methods the peer API distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Other,
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body (a request without `Content-Length` or `Transfer-Encoding`).
    None,
    /// Exactly this many bytes follow the head.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

impl Framing {
    /// The declared size, when the message states one up front.
    pub fn declared_len(self) -> Option<u64> {
        match self {
            Self::None => Some(0),
            Self::Length(len) => Some(len),
            Self::Chunked => None,
        }
    }
}

/// A parsed request head. Borrows the buffer the head was read into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub method: Method,
    /// The raw request target, including any query string.
    pub target: &'a str,
    pub framing: Framing,
    /// The client sent `Expect: 100-continue` and waits before the body.
    pub expect_continue: bool,
}

impl<'a> Request<'a> {
    /// The target's path, without the query string.
    pub fn path(&self) -> &'a str {
        self.target
            .split_once('?')
            .map_or(self.target, |(path, _)| path)
    }
}

/// A parsed response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub framing: Framing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The head did not fit in the caller's buffer.
    HeadTooLarge,
    /// The stream ended before a complete message.
    UnexpectedEof,
    /// The head is not well-formed HTTP/1.1.
    Malformed,
    /// Not HTTP/1.0 or HTTP/1.1.
    UnsupportedVersion,
    /// A transfer coding other than `chunked`.
    UnsupportedTransferEncoding,
    /// Both `Content-Length` and `Transfer-Encoding`, or disagreeing lengths.
    AmbiguousLength,
    /// A chunked body violated its framing.
    BadChunk,
    /// The output buffer cannot hold the formatted head.
    OutputTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeadTooLarge => "HTTP head exceeds the buffer",
            Self::UnexpectedEof => "stream ended inside an HTTP message",
            Self::Malformed => "malformed HTTP head",
            Self::UnsupportedVersion => "unsupported HTTP version",
            Self::UnsupportedTransferEncoding => "unsupported transfer encoding",
            Self::AmbiguousLength => "ambiguous HTTP message length",
            Self::BadChunk => "malformed chunked body",
            Self::OutputTooSmall => "output buffer too small for HTTP head",
        })
    }
}

impl core::error::Error for Error {}

/// The length of the head at the start of `buf`, including the blank line
/// that ends it, or `None` while it is still incomplete.
pub fn head_len(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Parse a request head as delimited by [`head_len`].
pub fn parse_request(head: &[u8]) -> Result<Request<'_>, Error> {
    let (start, headers) = split_head(head)?;
    let mut parts = start.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed);
    };
    check_version(version)?;
    if !is_token(method) || target.is_empty() || !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Malformed);
    }
    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        _ => Method::Other,
    };
    let fields = scan_headers(headers)?;
    Ok(Request {
        method,
        target,
        framing: fields.framing.unwrap_or(Framing::None),
        expect_continue: fields.expect_continue,
    })
}

/// Parse a response head as delimited by [`head_len`].
///
/// A response without `Content-Length` or `Transfer-Encoding` reads to the
/// end of the stream; callers that only need the status may ignore the body.
pub fn parse_response(head: &[u8]) -> Result<Response, Error> {
    let (start, headers) = split_head(head)?;
    let mut parts = start.splitn(3, ' ');
    let (Some(version), Some(status)) = (parts.next(), parts.next()) else {
        return Err(Error::Malformed);
    };
    check_version(version)?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    let status = status.parse().map_err(|_| Error::Malformed)?;
    let fields = scan_headers(headers)?;
    Ok(Response {
        status,
        framing: fields.framing.unwrap_or(Framing::None),
    })
}

fn split_head(head: &[u8]) -> Result<(&str, &str), Error> {
    let head = head.strip_suffix(b"\r\n\r\n").ok_or(Error::Malformed)?;
    let head = core::str::from_utf8(head).map_err(|_| Error::Malformed)?;
    Ok(head.split_once("\r\n").unwrap_or((head, "")))
}

fn check_version(version: &str) -> Result<(), Error> {
    match version {
        "HTTP/1.1" | "HTTP/1.0" => Ok(()),
        _ if version.starts_with("HTTP/") => Err(Error::UnsupportedVersion),
        _ => Err(Error::Malformed),
    }
}

struct Fields {
    framing: Option<Framing>,
    expect_continue: bool,
}

fn scan_headers(headers: &str) -> Result<Fields, Error> {
    let mut length = None;
    let mut chunked = false;
    let mut expect_continue = false;
    for line in headers.split("\r\n").filter(|line| !line.is_empty()) {
        // A leading space or tab is obsolete line folding (RFC 9112 §5.2).
        let (name, value) = line.split_once(':').ok_or(Error::Malformed)?;
        if !is_token(name) || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return Err(Error::Malformed);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Malformed);
            }
            let parsed: u64 = value.parse().map_err(|_| Error::Malformed)?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(Error::AmbiguousLength);
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(Error::UnsupportedTransferEncoding);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("expect") {
            expect_continue = value.eq_ignore_ascii_case("100-continue");
        }
    }
    let framing = match (length, chunked) {
        (Some(_), true) => return Err(Error::AmbiguousLength),
        (Some(len), false) => Some(Framing::Length(len)),
        (None, true) => Some(Framing::Chunked),
        (None, false) => None,
    };
    Ok(Fields {
        framing,
        expect_continue,
    })
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// One step of [`BodyDecoder::decode`].
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// Input bytes this step used, framing included.
    pub consumed: usize,
    /// Body bytes found within them. Empty steps only advance framing.
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Reading hex digits; the flag records that at least one was seen.
    Size(u64, bool),
    /// Skipping a chunk extension up to the line end.
    Extension(u64),
    SizeLf(u64),
    Data(u64),
    DataCr,
    DataLf,
    /// At the start of a trailer line; a bare CRLF ends the body.
    TrailerStart,
    TrailerLine,
    TrailerLf,
    FinalLf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyState {
    Length(u64),
    Chunked(Chunk),
    Done,
}

/// Incremental decoder for one message body.
///
/// Feed it whatever bytes arrive; it never needs more than it is given and
/// keeps only a few words of state, so chunk boundaries may fall anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyDecoder {
    state: BodyState,
}

impl BodyDecoder {
    pub fn new(framing: Framing) -> Self {
        let state = match framing {
            Framing::None | Framing::Length(0) => BodyState::Done,
            Framing::Length(len) => BodyState::Length(len),
            Framing::Chunked => BodyState::Chunked(Chunk::Size(0, false)),
        };
        Self { state }
    }

    /// The body has been read completely; any further input belongs to the
    /// next message.
    pub fn is_done(&self) -> bool {
        self.state == BodyState::Done
    }

    /// Decode from the front of `input`. Call repeatedly until the input is
    /// consumed or [`Self::is_done`]; each call yields at most one contiguous
    /// run of body bytes.
    pub fn decode<'a>(&mut self, input: &'a [u8]) -> Result<Decoded<'a>, Error> {
        match self.state {
            BodyState::Done => Ok(Decoded {
                consumed: 0,
                data: &[],
            }),
            BodyState::Length(remaining) => {
                let take = clamp(remaining, input.len());
                let left = remaining - take as u64;
                self.state = if left == 0 {
                    BodyState::Done
                } else {
                    BodyState::Length(left)
                };
                Ok(Decoded {
                    consumed: take,
                    data: &input[..take],
                })
            }
            BodyState::Chunked(Chunk::Data(remaining)) => {
                let take = clamp(remaining, input.len());
                let left = remaining - take as u64;
                self.state = BodyState::Chunked(if left == 0 {
                    Chunk::DataCr
                } else {
                    Chunk::Data(left)
                });
                Ok(Decoded {
                    consumed: take,
                    data: &input[..take],
                })
            }
            BodyState::Chunked(mut chunk) => {
                let mut consumed = 0;
                let mut done = false;
                for &byte in input {
                    consumed += 1;
                    if chunk == Chunk::FinalLf {
                        if byte != b'\n' {
                            return Err(Error::BadChunk);
                        }
                        done = true;
                        break;
                    }
                    chunk = step_chunk(chunk, byte)?;
                    if matches!(chunk, Chunk::Data(_)) {
                        break;
                    }
                }
                self.state = if done {
                    BodyState::Done
                } else {
                    BodyState::Chunked(chunk)
                };
                Ok(Decoded {
                    consumed,
                    data: &[],
                })
            }
        }
    }
}

fn clamp(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |remaining| remaining.min(available))
}

fn step_chunk(chunk: Chunk, byte: u8) -> Result<Chunk, Error> {
    Ok(match (chunk, byte) {
        (Chunk::Size(size, _), b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') => {
            let digit = (byte as char).to_digit(16).unwrap_or(0) as u64;
            let size = size
                .checked_mul(16)
                .and_then(|size| size.checked_add(digit))
                .ok_or(Error::BadChunk)?;
            Chunk::Size(size, true)
        }
        (Chunk::Size(size, true), b';' | b' ' | b'\t') => Chunk::Extension(size),
        (Chunk::Size(size, true), b'\r') | (Chunk::Extension(size), b'\r') => Chunk::SizeLf(size),
        (Chunk::Extension(size), b) if b != b'\n' => Chunk::Extension(size),
        (Chunk::SizeLf(0), b'\n') => Chunk::TrailerStart,
        (Chunk::SizeLf(size), b'\n') => Chunk::Data(size),
        (Chunk::DataCr, b'\r') => Chunk::DataLf,
        (Chunk::DataLf, b'\n') => Chunk::Size(0, false),
        (Chunk::TrailerStart, b'\r') => Chunk::FinalLf,
        (Chunk::TrailerStart, b) if b != b'\n' => Chunk::TrailerLine,
        (Chunk::TrailerLine, b'\r') => Chunk::TrailerLf,
        (Chunk::TrailerLine, b) if b != b'\n' => Chunk::TrailerLine,
        (Chunk::TrailerLf, b'\n') => Chunk::TrailerStart,
        _ => return Err(Error::BadChunk),
    })
}

/// A `core::fmt::Write` cursor over a byte buffer, used to format heads.
pub struct Cursor<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(Error::OutputTooSmall)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::OutputTooSmall)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    pub fn args(&mut self, args: fmt::Arguments<'_>) -> Result<(), Error> {
        self.write_fmt(args).map_err(|_| Error::OutputTooSmall)
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// The interim response sent to a client waiting on `Expect: 100-continue`.
pub const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// Format a complete, connection-closing response with a short body.
/// `extra_headers` is inserted verbatim; each line must end in CRLF.
pub fn write_response(
    out: &mut [u8],
    status: u16,
    content_type: &str,
    extra_headers: &str,
    body: &[u8],
) -> Result<usize, Error> {
    let mut cursor = Cursor::new(out);
    cursor.args(format_args!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
        reason(status),
        body.len(),
    ))?;
    cursor.bytes(body)?;
    Ok(cursor.len())
}

/// The standard reason phrase for the statuses the peer API sends.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// Characters a path segment carries verbatim; everything else is escaped.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode `segment` as one URL path segment.
pub fn escape_segment(segment: &str, out: &mut Cursor<'_>) -> Result<(), Error> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in segment.as_bytes() {
        if is_unreserved(byte) {
            out.bytes(&[byte])?;
        } else {
            out.bytes(&[
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ])?;
        }
    }
    Ok(())
}

/// Decode one percent-encoded path segment into `out`. Fails on truncated or
/// non-hex escapes, a decoded result that is not UTF-8, or a full buffer.
pub fn unescape_segment<'o>(segment: &str, out: &'o mut [u8]) -> Option<&'o str> {
    let bytes = segment.as_bytes();
    let mut read = 0;
    let mut written = 0;
    while read < bytes.len() {
        let byte = if bytes[read] == b'%' {
            let hex = bytes.get(read + 1..read + 3)?;
            let hex = core::str::from_utf8(hex).ok()?;
            read += 3;
            u8::from_str_radix(hex, 16).ok()?
        } else {
            read += 1;
            bytes[read - 1]
        };
        *out.get_mut(written)? = byte;
        written += 1;
    }
    core::str::from_utf8(&out[..written]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_go_style_put() {
        let head = b"PUT /v0/put/a%20b.txt HTTP/1.1\r\nHost: 100.64.0.2:5254\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 12\r\nAccept-Encoding: gzip\r\n\r\n";
        assert_eq!(head_len(head), Some(head.len()));
        let request = parse_request(head).unwrap();
        assert_eq!(request.method, Method::Put);
        assert_eq!(request.path(), "/v0/put/a%20b.txt");
        assert_eq!(request.framing, Framing::Length(12));
        assert!(!request.expect_continue);
    }

    #[test]
    fn head_len_waits_for_the_blank_line() {
        assert_eq!(head_len(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(head_len(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
    }

    #[test]
    fn rejects_smuggling_shapes() {
        let both = b"PUT / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(parse_request(both), Err(Error::AmbiguousLength));
        let twice = b"PUT / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(parse_request(twice), Err(Error::AmbiguousLength));
        let folded = b"PUT / HTTP/1.1\r\nX: a\r\n b\r\n\r\n";
        assert_eq!(parse_request(folded), Err(Error::Malformed));
        let gzip = b"PUT / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert_eq!(parse_request(gzip), Err(Error::UnsupportedTransferEncoding));
        let signed = b"PUT / HTTP/1.1\r\nContent-Length: +1\r\n\r\n";
        assert_eq!(parse_request(signed), Err(Error::Malformed));
        let spaced_name = b"PUT / HTTP/1.1\r\nContent-Length : 1\r\n\r\n";
        assert_eq!(parse_request(spaced_name), Err(Error::Malformed));
        assert_eq!(
            parse_request(b"PUT / HTTP/2.0\r\n\r\n"),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(
            parse_request(b"PUT  / HTTP/1.1\r\n\r\n"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn parses_chunked_and_expect() {
        let head = b"PUT /x HTTP/1.1\r\nTransfer-Encoding: Chunked\r\nExpect: 100-continue\r\n\r\n";
        let request = parse_request(head).unwrap();
        assert_eq!(request.framing, Framing::Chunked);
        assert!(request.expect_continue);
    }

    #[test]
    fn parses_responses() {
        let response = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.framing, Framing::Length(3));
        let response = parse_response(b"HTTP/1.1 403 \r\n\r\n").unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(
            parse_response(b"HTTP/1.1 20 OK\r\n\r\n"),
            Err(Error::Malformed)
        );
    }

    fn decode_all(
        framing: Framing,
        input: &[u8],
        step: usize,
    ) -> Result<([u8; 64], usize, usize), Error> {
        let mut decoder = BodyDecoder::new(framing);
        let mut out = [0u8; 64];
        let mut len = 0;
        let mut offset = 0;
        while offset < input.len() && !decoder.is_done() {
            let end = (offset + step).min(input.len());
            let mut piece = &input[offset..end];
            while !piece.is_empty() && !decoder.is_done() {
                let decoded = decoder.decode(piece)?;
                out[len..len + decoded.data.len()].copy_from_slice(decoded.data);
                len += decoded.data.len();
                offset += decoded.consumed;
                piece = &piece[decoded.consumed..];
            }
        }
        if !decoder.is_done() {
            return Err(Error::UnexpectedEof);
        }
        Ok((out, len, offset))
    }

    #[test]
    fn decodes_chunked_bodies_at_every_split() {
        let body = b"5;name=value\r\nhello\r\n7\r\n, world\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
        for step in 1..=body.len() {
            let (out, len, consumed) = decode_all(Framing::Chunked, body, step).unwrap();
            assert_eq!(&out[..len], b"hello, world", "step {step}");
            assert_eq!(&body[consumed..], b"NEXT", "step {step}");
        }
    }

    #[test]
    fn decodes_length_bodies() {
        let (out, len, consumed) = decode_all(Framing::Length(5), b"helloNEXT", 2).unwrap();
        assert_eq!(&out[..len], b"hello");
        assert_eq!(consumed, 5);
        assert!(BodyDecoder::new(Framing::None).is_done());
    }

    #[test]
    fn rejects_bad_chunks() {
        for body in [
            &b"\r\n"[..],
            b"g\r\n",
            b"5\r\nhelloXX",
            b"5\nhello",
            b"ffffffffffffffffff\r\n",
            b"0\r\n\n",
        ] {
            assert_eq!(
                decode_all(Framing::Chunked, body, body.len()).map(|_| ()),
                Err(Error::BadChunk),
                "{body:?}"
            );
        }
    }

    #[test]
    fn round_trips_path_segments() {
        let mut buf = [0u8; 96];
        let mut cursor = Cursor::new(&mut buf);
        escape_segment("résumé v2/final?.pdf", &mut cursor).unwrap();
        let len = cursor.len();
        let escaped = core::str::from_utf8(&buf[..len]).unwrap();
        assert_eq!(escaped, "r%C3%A9sum%C3%A9%20v2%2Ffinal%3F.pdf");
        let mut out = [0u8; 64];
        assert_eq!(
            unescape_segment(escaped, &mut out),
            Some("résumé v2/final?.pdf")
        );
        assert_eq!(unescape_segment("%4", &mut out), None);
        assert_eq!(unescape_segment("%zz", &mut out), None);
        assert_eq!(unescape_segment("%ff", &mut out), None);
        assert_eq!(unescape_segment("abc", &mut [0u8; 2]), None);
    }

    #[test]
    fn formats_responses() {
        let mut out = [0u8; 128];
        let len = write_response(&mut out, 200, "application/json", "", b"{}\n").unwrap();
        assert_eq!(
            &out[..len],
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}\n"
        );
        assert_eq!(
            write_response(&mut [0u8; 8], 200, "text/plain", "", b""),
            Err(Error::OutputTooSmall)
        );
    }
}
