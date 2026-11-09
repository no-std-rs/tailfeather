//! Taildrop file transfer over the peer API: receive, send and resume.
//!
//! A sender `PUT`s the file to `/v0/put/<escaped name>` on the receiver's
//! advertised peer API port (Hostinfo `Services`, `peerapi4`/`peerapi6`),
//! inside the tunnel. This is the protocol Tailscale's `tailscale file cp`
//! speaks, so a Tailfeather node can both receive from and send to stock
//! clients, including [`resume`] of interrupted transfers.
//!
//! # Authorization
//!
//! WireGuard authenticates the remote node; whether that node may drop files
//! here is the caller's decision, passed as [`Peer::may_send_files`] and
//! checked before any body byte is read (`403` otherwise). Stock Tailscale
//! decides it from the netmap: this node must hold the
//! `https://tailscale.com/cap/file-sharing` node capability, the sender must
//! not be an unsigned (`UnsignedPeerAPIOnly`) node, and either both nodes are
//! untagged and owned by the same user, or packet-filter grants give the
//! sender `https://tailscale.com/cap/file-send` toward this node.
//! `tailfeather::netmap::Netmap::taildrop_allows_from` (with its
//! `peer-api` feature) implements exactly that decision.
//!
//! # Drivers
//!
//! [`serve`], [`send`] and [`resume_offset`] use blocking [`embedded_io`]
//! streams; [`serve_async`], [`send_async`] and [`resume_offset_async`] use
//! [`embedded_io_async`]. None needs an executor or allocator, and all share
//! the sans-I/O [`route`] and [`super::http`] framing. Each call handles one
//! connection-closing exchange.
//!
//! The async drivers are runtime-agnostic: wrap a Tokio or `futures` stream
//! with the `embedded-io-adapters` crate (`FromTokio`, `FromFutures`) or a
//! small adapter of your own. With concrete stream and sink types the
//! returned futures are `Send` whenever those types are, so they can be
//! given to `tokio::spawn`.
//!
//! # Resume
//!
//! A sink that keeps the partial file of an aborted upload can implement
//! [`FileSink::read_partial`]; the receiver then answers a sender's probe
//! with block checksums and accepts `Range: bytes=<offset>-` uploads that
//! continue it. A sender with a seekable source calls [`resume_offset`] on
//! one connection and then [`send`] with [`Upload::offset`] on the next.

use core::net::{IpAddr, SocketAddr};

use super::http::{self, BodyDecoder, Framing, Method, Request};

mod blocking;
mod nonblocking;
pub mod resume;

pub use blocking::{resume_offset, send, serve};
pub use nonblocking::{resume_offset_async, send_async, serve_async};

#[cfg(feature = "alloc")]
mod memory;
#[cfg(feature = "alloc")]
pub use memory::{MemoryError, MemorySink, ReceivedFile};

/// Request path prefix of the file upload endpoint.
pub const PUT_PREFIX: &str = "/v0/put/";
/// Longest accepted file name in bytes, matching common filesystem limits.
pub const MAX_NAME: usize = 255;
/// Smallest connection buffer the client drivers accept: it fits any request
/// head they write (a fully percent-escaped [`MAX_NAME`] plus headers), and
/// [`resume_offset`] splits it between the response and source reads.
pub const MIN_CLIENT_BUFFER: usize = 1024;
const REPLY_BUFFER: usize = 256;

/// The authenticated remote node on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// The node's tailnet address, as validated by WireGuard.
    pub addr: IpAddr,
    /// The caller's policy decision; see the module documentation.
    pub may_send_files: bool,
}

/// Receive-side limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Larger files are refused with `413`, up front when the length is
    /// declared and as soon as a chunked body exceeds it otherwise. A resumed
    /// upload counts from the start of the file.
    pub max_file_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: u64::MAX,
        }
    }
}

/// Why a file name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidName;

impl core::fmt::Display for InvalidName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid Taildrop file name")
    }
}

impl core::error::Error for InvalidName {}

/// Accept only a plain base name that is safe to create in a flat inbox.
///
/// Mirrors Tailscale's rules: non-empty, at most [`MAX_NAME`] bytes, no path
/// separators, not `.` or `..`, no surrounding whitespace, no control
/// characters, and none of the suffixes Tailscale uses for its own
/// in-progress files. Sinks on restrictive filesystems (FAT, for example)
/// may still need to refuse further characters.
pub fn validate_name(name: &str) -> Result<(), InvalidName> {
    let bad = name.is_empty()
        || name.len() > MAX_NAME
        || name == "."
        || name == ".."
        || name.trim() != name
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
        || name.ends_with(".partial")
        || name.ends_with(".deleted");
    if bad { Err(InvalidName) } else { Ok(()) }
}

/// A file announced by a sender, handed to the sink before its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming<'a> {
    pub from: IpAddr,
    /// Validated with [`validate_name`].
    pub name: &'a str,
    /// Where this upload starts in the file. Nonzero only when the sender
    /// resumes a partial file the sink kept for it; the sink then keeps
    /// exactly the first `offset` bytes of that partial and appends to them.
    pub offset: u64,
    /// The bytes this upload declares (excluding `offset`); `None` when
    /// chunked.
    pub size: Option<u64>,
}

/// A sink's refusal to begin a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal<E> {
    /// A finished file of this name already exists (`409 Conflict`).
    Exists,
    /// Anything else (`500`).
    Failed(E),
}

impl<E> From<E> for Refusal<E> {
    fn from(error: E) -> Self {
        Self::Failed(error)
    }
}

/// Blocking destination for received files, one file at a time.
///
/// The driver calls [`begin`](Self::begin), any number of
/// [`write`](Self::write)s, then exactly one of [`finish`](Self::finish) or
/// [`abort`](Self::abort). A failed `finish` is followed by `abort`. After
/// `abort` the sink may keep what it received as that sender's partial file,
/// for a later resumed upload, or discard it.
pub trait FileSink {
    type Error: core::fmt::Debug;
    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<Self::Error>>;
    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn abort(&mut self);

    /// Copy bytes of the partial file kept for `from` under `name`, starting
    /// at `offset`, into `out`; `Ok(0)` at its end or when nothing is kept.
    /// The default keeps nothing, which makes every sender start over.
    fn read_partial(
        &mut self,
        from: IpAddr,
        name: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (from, name, offset, out);
        Ok(0)
    }

    /// Report the names of the partial files kept for `from`.
    fn partial_names(
        &mut self,
        from: IpAddr,
        each: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), Self::Error> {
        let _ = (from, each);
        Ok(())
    }
}

/// Async counterpart of [`FileSink`], with the same call contract.
#[allow(async_fn_in_trait)]
pub trait AsyncFileSink {
    type Error: core::fmt::Debug;
    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<Self::Error>>;
    async fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn finish(&mut self) -> Result<(), Self::Error>;
    async fn abort(&mut self);

    /// See [`FileSink::read_partial`].
    async fn read_partial(
        &mut self,
        from: IpAddr,
        name: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (from, name, offset, out);
        Ok(0)
    }

    /// See [`FileSink::partial_names`].
    async fn partial_names(
        &mut self,
        from: IpAddr,
        each: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), Self::Error> {
        let _ = (from, each);
        Ok(())
    }
}

/// A canned response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The file was stored.
    Stored,
    BadRequest,
    InvalidName,
    InvalidRange,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    /// A finished file of this name exists.
    Exists,
    TooLarge,
    HeadTooLarge,
    StorageFailed,
    NotImplemented,
    UnsupportedVersion,
}

impl Reply {
    pub fn status(self) -> u16 {
        match self {
            Self::Stored => 200,
            Self::BadRequest | Self::InvalidName | Self::InvalidRange => 400,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::Exists => 409,
            Self::TooLarge => 413,
            Self::HeadTooLarge => 431,
            Self::StorageFailed => 500,
            Self::NotImplemented => 501,
            Self::UnsupportedVersion => 505,
        }
    }

    fn body(self) -> &'static [u8] {
        match self {
            Self::Stored => b"{}\n",
            Self::BadRequest => b"bad request\n",
            Self::InvalidName => b"invalid filename\n",
            Self::InvalidRange => b"invalid Range header\n",
            Self::Forbidden => b"Taildrop disabled; no storage directory\n",
            Self::NotFound => b"not found\n",
            Self::MethodNotAllowed => b"expected method GET or PUT\n",
            Self::Exists => b"file already exists\n",
            Self::TooLarge => b"file too large\n",
            Self::HeadTooLarge => b"request head too large\n",
            Self::StorageFailed => b"failed to store file\n",
            Self::NotImplemented => b"transfer coding not implemented\n",
            Self::UnsupportedVersion => b"HTTP version not supported\n",
        }
    }

    fn for_error(error: http::Error) -> Self {
        match error {
            http::Error::HeadTooLarge => Self::HeadTooLarge,
            http::Error::UnsupportedVersion => Self::UnsupportedVersion,
            http::Error::UnsupportedTransferEncoding => Self::NotImplemented,
            _ => Self::BadRequest,
        }
    }

    /// Format the complete response into `out`.
    pub fn write(self, out: &mut [u8]) -> Result<usize, http::Error> {
        let (content_type, extra) = match self {
            Self::Stored => ("application/json", ""),
            Self::MethodNotAllowed => ("text/plain; charset=utf-8", "Allow: GET, PUT\r\n"),
            _ => ("text/plain; charset=utf-8", ""),
        };
        http::write_response(out, self.status(), content_type, extra, self.body())
    }
}

/// What to do with one parsed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'n> {
    /// Stream the body into the sink under this decoded, validated name.
    Receive {
        name: &'n str,
        framing: Framing,
        expect_continue: bool,
        offset: u64,
    },
    /// Stream block checksums of the partial file kept under this name.
    Checksums {
        name: &'n str,
    },
    /// List the partial files kept for the sender.
    ListPartials,
    Respond(Reply),
}

/// The sans-I/O routing decision for one request. The decoded file name is
/// written to `name`, so it outlives the connection buffer.
pub fn route<'n>(
    request: &Request<'_>,
    peer: &Peer,
    config: &Config,
    name: &'n mut [u8; MAX_NAME],
) -> Action<'n> {
    let Some(segment) = request.path().strip_prefix(PUT_PREFIX) else {
        return Action::Respond(Reply::NotFound);
    };
    if !peer.may_send_files {
        return Action::Respond(Reply::Forbidden);
    }
    match request.method {
        Method::Get if segment.is_empty() => return Action::ListPartials,
        Method::Get | Method::Put => {}
        _ => return Action::Respond(Reply::MethodNotAllowed),
    }
    let decoded = match http::unescape_segment(segment, name) {
        Some(decoded) if validate_name(decoded).is_ok() => decoded,
        _ => return Action::Respond(Reply::InvalidName),
    };
    if request.method == Method::Get {
        return Action::Checksums { name: decoded };
    }
    let offset = match request.header("range") {
        None => 0,
        Some(value) => match resume::parse_range(value) {
            Some(offset) => offset,
            None => return Action::Respond(Reply::InvalidRange),
        },
    };
    let too_large = match request.framing.declared_len() {
        Some(len) => offset
            .checked_add(len)
            .is_none_or(|end| end > config.max_file_size),
        None => offset > config.max_file_size,
    };
    if too_large {
        return Action::Respond(Reply::TooLarge);
    }
    Action::Receive {
        name: decoded,
        framing: request.framing,
        expect_continue: request.expect_continue,
        offset,
    }
}

/// How a served connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The peer closed without sending a request.
    Closed,
    /// A request other than an upload was answered with this status.
    Replied(u16),
    /// An upload of `bytes` starting at `offset` completed the file.
    Received { bytes: u64, offset: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError<E, S> {
    /// The stream failed; no response could be relied upon.
    Io(E),
    /// The request was malformed; an error response was attempted.
    Http(http::Error),
    /// The sink failed; `500` was attempted unless a response had started.
    Sink(S),
    /// A finished file of this name exists; `409` was attempted.
    Exists,
    /// A chunked body exceeded [`Config::max_file_size`]; `413` was attempted.
    TooLarge,
}

impl<E: core::fmt::Debug, S: core::fmt::Debug> core::fmt::Display for ServeError<E, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "peer API stream failed: {error:?}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Sink(error) => write!(f, "Taildrop sink failed: {error:?}"),
            Self::Exists => f.write_str("Taildrop file already exists"),
            Self::TooLarge => f.write_str("Taildrop upload exceeded the size limit"),
        }
    }
}

impl<E: core::fmt::Debug, S: core::fmt::Debug> core::error::Error for ServeError<E, S> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<E, R> {
    /// The connection failed.
    Io(E),
    /// Reading or seeking the file source failed.
    Source(R),
    /// The source ended before the announced size.
    SourceEnded,
    InvalidName,
    /// [`Upload::offset`] is past [`Upload::size`].
    InvalidOffset,
    /// The buffer is smaller than [`MIN_CLIENT_BUFFER`] demands for this name,
    /// or the response was malformed.
    Http(http::Error),
    /// The receiver answered with this non-success status.
    Rejected(u16),
}

impl<E: core::fmt::Debug, R: core::fmt::Debug> core::fmt::Display for SendError<E, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "peer API connection failed: {error:?}"),
            Self::Source(error) => write!(f, "reading the file failed: {error:?}"),
            Self::SourceEnded => f.write_str("file ended before its announced size"),
            Self::InvalidName => f.write_str("invalid Taildrop file name"),
            Self::InvalidOffset => f.write_str("resume offset past the end of the file"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Rejected(status) => write!(f, "receiver rejected the file with HTTP {status}"),
        }
    }
}

impl<E: core::fmt::Debug, R: core::fmt::Debug> core::error::Error for SendError<E, R> {}

/// A file to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upload<'a> {
    /// The receiver's tailnet address and advertised peer API port.
    pub peer_api: SocketAddr,
    pub name: &'a str,
    /// The whole file's size.
    pub size: u64,
    /// Resume here (from [`resume_offset`]); the source must be positioned at
    /// this byte and provide `size - offset` more. Zero sends everything.
    pub offset: u64,
}

/// Format the upload request head. With a body to send it asks for
/// `100 Continue`, so a refusal (`403`, `409`, `413`, ...) arrives before any
/// file byte is sent.
pub fn write_upload_head(upload: &Upload<'_>, out: &mut [u8]) -> Result<usize, http::Error> {
    let remaining = upload
        .size
        .checked_sub(upload.offset)
        .ok_or(http::Error::Malformed)?;
    let mut cursor = http::Cursor::new(out);
    cursor.bytes(b"PUT ")?;
    cursor.bytes(PUT_PREFIX.as_bytes())?;
    http::escape_segment(upload.name, &mut cursor)?;
    cursor.args(format_args!(
        " HTTP/1.1\r\nHost: {}\r\nUser-Agent: tailfeather\r\nContent-Length: {remaining}\r\n",
        upload.peer_api,
    ))?;
    if upload.offset != 0 {
        cursor.args(format_args!("Range: bytes={}-\r\n", upload.offset))?;
    }
    if remaining != 0 {
        cursor.bytes(b"Expect: 100-continue\r\n")?;
    }
    cursor.bytes(b"Connection: close\r\n\r\n")?;
    Ok(cursor.len())
}

/// Format the resume probe for `name`: a `GET` of its block checksums.
pub fn write_probe_head(
    peer_api: SocketAddr,
    name: &str,
    out: &mut [u8],
) -> Result<usize, http::Error> {
    let mut cursor = http::Cursor::new(out);
    cursor.bytes(b"GET ")?;
    cursor.bytes(PUT_PREFIX.as_bytes())?;
    http::escape_segment(name, &mut cursor)?;
    cursor.args(format_args!(
        " HTTP/1.1\r\nHost: {peer_api}\r\nUser-Agent: tailfeather\r\nConnection: close\r\n\r\n",
    ))?;
    Ok(cursor.len())
}

/// Head of a checksum stream; the body runs until the connection closes.
const CHECKSUMS_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";

/// Builds the partial-file listing, a JSON array of names, in a buffer.
struct PartialList<'a> {
    cursor: http::Cursor<'a>,
    first: bool,
    result: Result<(), http::Error>,
}

impl<'a> PartialList<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        let mut cursor = http::Cursor::new(out);
        let result = cursor.bytes(b"[");
        Self {
            cursor,
            first: true,
            result,
        }
    }

    fn push(&mut self, name: &str) {
        let open: &[u8] = if self.first { b"\"" } else { b",\"" };
        self.first = false;
        let cursor = &mut self.cursor;
        let mut result = core::mem::replace(&mut self.result, Ok(()));
        result = result.and_then(|()| cursor.bytes(open));
        // JSON needs escapes only for quotes here: `validate_name` already
        // excludes backslashes and control characters.
        for byte in name.bytes() {
            let escaped: &[u8] = if byte == b'"' { b"\\\"" } else { &[byte] };
            result = result.and_then(|()| cursor.bytes(escaped));
        }
        self.result = result.and_then(|()| cursor.bytes(b"\""));
    }

    /// The listing's length in the buffer.
    fn finish(mut self) -> Result<usize, http::Error> {
        self.result?;
        self.cursor.bytes(b"]\n")?;
        Ok(self.cursor.len())
    }
}

enum HeadError<E> {
    Io(E),
    Http(http::Error),
}

/// Shared tail of the drivers' head reads: `Ok(None)` while more input is
/// needed, the head length once complete.
fn head_progress(buf: &[u8], filled: usize) -> Result<Option<usize>, http::Error> {
    if let Some(len) = http::head_len(&buf[..filled]) {
        return Ok(Some(len));
    }
    if filled == buf.len() {
        return Err(http::Error::HeadTooLarge);
    }
    Ok(None)
}

/// Limit-checked body step shared by both server drivers.
fn body_step<'a>(
    decoder: &mut BodyDecoder,
    input: &'a [u8],
    received: &mut u64,
    limit: u64,
) -> Result<http::Decoded<'a>, Reply> {
    let step = decoder.decode(input).map_err(|_| Reply::BadRequest)?;
    *received += step.data.len() as u64;
    if *received > limit {
        return Err(Reply::TooLarge);
    }
    Ok(step)
}

/// A response body: framed, or running to the end of the stream, which is
/// how a `Connection: close` reply without length framing ends.
struct ResponseBody {
    decoder: BodyDecoder,
    until_close: bool,
}

impl ResponseBody {
    fn new(framing: Framing) -> Self {
        Self {
            decoder: BodyDecoder::new(framing),
            until_close: framing == Framing::None,
        }
    }

    fn is_done(&self) -> bool {
        !self.until_close && self.decoder.is_done()
    }

    fn decode<'a>(&mut self, input: &'a [u8]) -> Result<http::Decoded<'a>, http::Error> {
        if self.until_close {
            return Ok(http::Decoded {
                consumed: input.len(),
                data: input,
            });
        }
        self.decoder.decode(input)
    }

    fn at_eof(&self) -> Result<(), http::Error> {
        if self.until_close {
            Ok(())
        } else {
            Err(http::Error::UnexpectedEof)
        }
    }
}

fn clamp(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |remaining| remaining.min(available))
}

#[cfg(test)]
mod tests;
