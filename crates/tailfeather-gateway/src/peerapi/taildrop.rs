//! Taildrop file transfer over the peer API, receive and send.
//!
//! A sender `PUT`s the file to `/v0/put/<escaped name>` on the receiver's
//! advertised peer API port (Hostinfo `Services`, `peerapi4`/`peerapi6`),
//! inside the tunnel. This is the protocol Tailscale's `tailscale file cp`
//! speaks, so a Tailfeather node can both receive from and send to stock
//! clients.
//!
//! # Authorization
//!
//! WireGuard authenticates the remote node; whether that node may drop files
//! here is the caller's decision, passed as [`Peer::may_send_files`]. Stock
//! Tailscale allows it when the sender belongs to the same user as this node
//! (or a grant gives it the file-sharing capability) and this node has
//! Taildrop enabled. Unauthorized peers are answered `403` before any body
//! byte is read.
//!
//! # Drivers
//!
//! [`serve`] and [`send`] use blocking [`embedded_io`] streams;
//! [`serve_async`] and [`send_async`] use [`embedded_io_async`]. Neither needs
//! an executor or allocator, and both share the sans-I/O [`route`] and
//! [`super::http`] framing. Each call handles one connection-closing
//! exchange.
//!
//! The async drivers are runtime-agnostic: wrap a Tokio or `futures` stream
//! with the `embedded-io-adapters` crate (`FromTokio`, `FromFutures`) or a
//! small adapter of your own. With concrete stream and sink types the
//! returned futures are `Send` whenever those types are, so they can be
//! given to `tokio::spawn`.
//!
//! Resuming partial transfers is not supported: a resume probe (`GET` on the
//! same path) is answered with no partial data, so senders restart from zero.

use core::net::{IpAddr, SocketAddr};

use super::http::{self, BodyDecoder, Framing, Method, Request};

/// Request path prefix of the file upload endpoint.
pub const PUT_PREFIX: &str = "/v0/put/";
/// Longest accepted file name in bytes, matching common filesystem limits.
pub const MAX_NAME: usize = 255;
/// Smallest connection buffer that fits any upload head this module writes
/// (a fully percent-escaped [`MAX_NAME`] plus fixed headers).
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
    /// Larger uploads are refused with `413`, up front when the length is
    /// declared and as soon as a chunked body exceeds it otherwise.
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
    /// The declared size; `None` for a chunked upload.
    pub size: Option<u64>,
}

/// Blocking destination for received files, one file at a time.
///
/// The driver calls [`begin`](Self::begin), any number of
/// [`write`](Self::write)s, then exactly one of [`finish`](Self::finish) or
/// [`abort`](Self::abort). A failed `finish` is followed by `abort`, so a sink
/// only keeps files it finished successfully.
pub trait FileSink {
    type Error: core::fmt::Debug;
    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Self::Error>;
    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn abort(&mut self);
}

/// Async counterpart of [`FileSink`], with the same call contract.
#[allow(async_fn_in_trait)]
pub trait AsyncFileSink {
    type Error: core::fmt::Debug;
    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Self::Error>;
    async fn write(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    async fn finish(&mut self) -> Result<(), Self::Error>;
    async fn abort(&mut self);
}

/// A canned response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The file was stored.
    Stored,
    /// Answer to a resume probe: nothing partial is kept here.
    NoPartialFile,
    BadRequest,
    InvalidName,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    TooLarge,
    HeadTooLarge,
    StorageFailed,
    NotImplemented,
    UnsupportedVersion,
}

impl Reply {
    pub fn status(self) -> u16 {
        match self {
            Self::Stored | Self::NoPartialFile => 200,
            Self::BadRequest | Self::InvalidName => 400,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
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
            Self::NoPartialFile => b"",
            Self::BadRequest => b"bad request\n",
            Self::InvalidName => b"invalid filename\n",
            Self::Forbidden => b"Taildrop access denied\n",
            Self::NotFound => b"not found\n",
            Self::MethodNotAllowed => b"expected method PUT\n",
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
            Self::Stored | Self::NoPartialFile => ("application/json", ""),
            Self::MethodNotAllowed => ("text/plain; charset=utf-8", "Allow: PUT, GET\r\n"),
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
    },
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
        Method::Put => {}
        Method::Get => return Action::Respond(Reply::NoPartialFile),
        _ => return Action::Respond(Reply::MethodNotAllowed),
    }
    let decoded = match http::unescape_segment(segment, name) {
        Some(decoded) if validate_name(decoded).is_ok() => decoded,
        _ => return Action::Respond(Reply::InvalidName),
    };
    if request
        .framing
        .declared_len()
        .is_some_and(|len| len > config.max_file_size)
    {
        return Action::Respond(Reply::TooLarge);
    }
    Action::Receive {
        name: decoded,
        framing: request.framing,
        expect_continue: request.expect_continue,
    }
}

/// How a served connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The peer closed without sending a request.
    Closed,
    /// A non-upload request was answered with this status.
    Replied(u16),
    /// A file of this many bytes was stored and acknowledged.
    Received { bytes: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError<E, S> {
    /// The stream failed; no response could be relied upon.
    Io(E),
    /// The request was malformed; an error response was attempted.
    Http(http::Error),
    /// The sink refused or failed; `500` was attempted.
    Sink(S),
    /// A chunked body exceeded [`Config::max_file_size`]; `413` was attempted.
    TooLarge,
}

impl<E: core::fmt::Debug, S: core::fmt::Debug> core::fmt::Display for ServeError<E, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "peer API stream failed: {error:?}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Sink(error) => write!(f, "Taildrop sink failed: {error:?}"),
            Self::TooLarge => f.write_str("Taildrop upload exceeded the size limit"),
        }
    }
}

impl<E: core::fmt::Debug, S: core::fmt::Debug> core::error::Error for ServeError<E, S> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<E, R> {
    /// The connection failed.
    Io(E),
    /// Reading the file body failed.
    Source(R),
    /// The body source ended before the announced size.
    SourceEnded,
    InvalidName,
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
    /// Exact number of body bytes the source will provide.
    pub size: u64,
}

/// Format the upload request head. It asks for `100 Continue`, so a refusal
/// (`403`, `413`, ...) arrives before any file byte is sent.
pub fn write_upload_head(upload: &Upload<'_>, out: &mut [u8]) -> Result<usize, http::Error> {
    let mut cursor = http::Cursor::new(out);
    cursor.bytes(b"PUT ")?;
    cursor.bytes(PUT_PREFIX.as_bytes())?;
    http::escape_segment(upload.name, &mut cursor)?;
    cursor.args(format_args!(
        " HTTP/1.1\r\nHost: {}\r\nUser-Agent: tailfeather\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        upload.peer_api, upload.size,
    ))?;
    Ok(cursor.len())
}

enum HeadError<E> {
    Io(E),
    Http(http::Error),
}

/// Shared tail of both drivers' head reads: `Ok(None)` while more input is
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
    config: &Config,
) -> Result<http::Decoded<'a>, Reply> {
    let step = decoder.decode(input).map_err(|_| Reply::BadRequest)?;
    *received += step.data.len() as u64;
    if *received > config.max_file_size {
        return Err(Reply::TooLarge);
    }
    Ok(step)
}

mod blocking {
    use embedded_io::{Read, Write};

    use super::*;

    fn read_head<IO: Read>(
        io: &mut IO,
        buf: &mut [u8],
    ) -> Result<Option<(usize, usize)>, HeadError<IO::Error>> {
        let mut filled = 0;
        loop {
            if let Some(head) = head_progress(buf, filled).map_err(HeadError::Http)? {
                return Ok(Some((head, filled)));
            }
            let read = io.read(&mut buf[filled..]).map_err(HeadError::Io)?;
            if read == 0 {
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err(HeadError::Http(http::Error::UnexpectedEof))
                };
            }
            filled += read;
        }
    }

    fn reply<IO: Write>(io: &mut IO, reply: Reply) -> Result<(), IO::Error> {
        let mut out = [0u8; REPLY_BUFFER];
        // Every canned reply fits the fixed buffer; covered by a unit test.
        let len = reply.write(&mut out).unwrap_or(0);
        io.write_all(&out[..len])?;
        io.flush()
    }

    /// Serve one Taildrop request on a blocking stream.
    ///
    /// `buf` holds the request head and then body reads; 1–2 KiB is plenty,
    /// and heads larger than it are refused with `431`.
    pub fn serve<IO, S>(
        io: &mut IO,
        peer: &Peer,
        config: &Config,
        sink: &mut S,
        buf: &mut [u8],
    ) -> Result<Served, ServeError<IO::Error, S::Error>>
    where
        IO: Read + Write,
        S: FileSink,
    {
        let (head, filled) = match read_head(io, buf) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(Served::Closed),
            Err(HeadError::Io(error)) => return Err(ServeError::Io(error)),
            Err(HeadError::Http(error)) => {
                let _ = reply(io, Reply::for_error(error));
                return Err(ServeError::Http(error));
            }
        };
        let mut name = [0u8; MAX_NAME];
        let action = match http::parse_request(&buf[..head]) {
            Ok(request) => route(&request, peer, config, &mut name),
            Err(error) => {
                let _ = reply(io, Reply::for_error(error));
                return Err(ServeError::Http(error));
            }
        };
        let (name, framing, expect_continue) = match action {
            Action::Respond(answer) => {
                reply(io, answer).map_err(ServeError::Io)?;
                return Ok(Served::Replied(answer.status()));
            }
            Action::Receive {
                name,
                framing,
                expect_continue,
            } => (name, framing, expect_continue),
        };
        let incoming = Incoming {
            from: peer.addr,
            name,
            size: framing.declared_len(),
        };
        if let Err(error) = sink.begin(&incoming) {
            let _ = reply(io, Reply::StorageFailed);
            return Err(ServeError::Sink(error));
        }
        if expect_continue
            && let Err(error) = io.write_all(http::CONTINUE).and_then(|()| io.flush())
        {
            sink.abort();
            return Err(ServeError::Io(error));
        }

        let mut decoder = BodyDecoder::new(framing);
        let mut received = 0;
        let (mut start, mut end) = (head, filled);
        while !decoder.is_done() {
            if start == end {
                match io.read(buf) {
                    Ok(0) => {
                        sink.abort();
                        return Err(ServeError::Http(http::Error::UnexpectedEof));
                    }
                    Ok(read) => (start, end) = (0, read),
                    Err(error) => {
                        sink.abort();
                        return Err(ServeError::Io(error));
                    }
                }
            }
            let step = match body_step(&mut decoder, &buf[start..end], &mut received, config) {
                Ok(step) => step,
                Err(answer) => {
                    sink.abort();
                    let _ = reply(io, answer);
                    return Err(if answer == Reply::TooLarge {
                        ServeError::TooLarge
                    } else {
                        ServeError::Http(http::Error::BadChunk)
                    });
                }
            };
            start += step.consumed;
            if !step.data.is_empty()
                && let Err(error) = sink.write(step.data)
            {
                sink.abort();
                let _ = reply(io, Reply::StorageFailed);
                return Err(ServeError::Sink(error));
            }
        }
        if let Err(error) = sink.finish() {
            sink.abort();
            let _ = reply(io, Reply::StorageFailed);
            return Err(ServeError::Sink(error));
        }
        reply(io, Reply::Stored).map_err(ServeError::Io)?;
        Ok(Served::Received { bytes: received })
    }

    /// Send one file to a peer over a connected blocking stream.
    ///
    /// `buf` must hold the request head (see [`MIN_CLIENT_BUFFER`]) and is
    /// reused to copy the body. The receiver must honour
    /// `Expect: 100-continue`, as Go's `net/http` (stock Tailscale) and
    /// [`serve`] do.
    pub fn send<IO, R>(
        io: &mut IO,
        upload: &Upload<'_>,
        body: &mut R,
        buf: &mut [u8],
    ) -> Result<(), SendError<IO::Error, R::Error>>
    where
        IO: Read + Write,
        R: Read,
    {
        validate_name(upload.name).map_err(|_| SendError::InvalidName)?;
        let len = write_upload_head(upload, buf).map_err(SendError::Http)?;
        io.write_all(&buf[..len]).map_err(SendError::Io)?;
        io.flush().map_err(SendError::Io)?;
        let status = response_status(io, buf)?;
        if status != 100 {
            return Err(SendError::Rejected(status));
        }

        let mut remaining = upload.size;
        while remaining > 0 {
            let want = super::http_clamp(remaining, buf.len());
            let read = body.read(&mut buf[..want]).map_err(SendError::Source)?;
            if read == 0 {
                return Err(SendError::SourceEnded);
            }
            io.write_all(&buf[..read]).map_err(SendError::Io)?;
            remaining -= read as u64;
        }
        io.flush().map_err(SendError::Io)?;
        match response_status(io, buf)? {
            200 => Ok(()),
            status => Err(SendError::Rejected(status)),
        }
    }

    /// Read one response head. A final (non-1xx) response's body is drained,
    /// so the receiver can finish writing before the caller closes.
    fn response_status<IO: Read + Write, R>(
        io: &mut IO,
        buf: &mut [u8],
    ) -> Result<u16, SendError<IO::Error, R>> {
        let (head, filled) = match read_head(io, buf) {
            Ok(Some(head)) => head,
            Ok(None) => return Err(SendError::Http(http::Error::UnexpectedEof)),
            Err(HeadError::Io(error)) => return Err(SendError::Io(error)),
            Err(HeadError::Http(error)) => return Err(SendError::Http(error)),
        };
        let response = http::parse_response(&buf[..head]).map_err(SendError::Http)?;
        if response.status < 200 {
            return Ok(response.status);
        }
        let mut drain = Drain::new(response.framing);
        let mut pending = head..filled;
        loop {
            drain.feed(&buf[pending]).map_err(SendError::Http)?;
            if drain.is_done() {
                return Ok(response.status);
            }
            let read = io.read(buf).map_err(SendError::Io)?;
            if read == 0 {
                return drain
                    .at_eof()
                    .map(|()| response.status)
                    .map_err(SendError::Http);
            }
            pending = 0..read;
        }
    }
}

mod nonblocking {
    use embedded_io_async::{Read, Write};

    use super::*;

    async fn read_head<IO: Read>(
        io: &mut IO,
        buf: &mut [u8],
    ) -> Result<Option<(usize, usize)>, HeadError<IO::Error>> {
        let mut filled = 0;
        loop {
            if let Some(head) = head_progress(buf, filled).map_err(HeadError::Http)? {
                return Ok(Some((head, filled)));
            }
            let read = io.read(&mut buf[filled..]).await.map_err(HeadError::Io)?;
            if read == 0 {
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err(HeadError::Http(http::Error::UnexpectedEof))
                };
            }
            filled += read;
        }
    }

    async fn reply<IO: Write>(io: &mut IO, reply: Reply) -> Result<(), IO::Error> {
        let mut out = [0u8; REPLY_BUFFER];
        let len = reply.write(&mut out).unwrap_or(0);
        io.write_all(&out[..len]).await?;
        io.flush().await
    }

    /// Async [`serve`](super::serve): serve one Taildrop request.
    pub async fn serve_async<IO, S>(
        io: &mut IO,
        peer: &Peer,
        config: &Config,
        sink: &mut S,
        buf: &mut [u8],
    ) -> Result<Served, ServeError<IO::Error, S::Error>>
    where
        IO: Read + Write,
        S: AsyncFileSink,
    {
        let (head, filled) = match read_head(io, buf).await {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(Served::Closed),
            Err(HeadError::Io(error)) => return Err(ServeError::Io(error)),
            Err(HeadError::Http(error)) => {
                let _ = reply(io, Reply::for_error(error)).await;
                return Err(ServeError::Http(error));
            }
        };
        let mut name = [0u8; MAX_NAME];
        let action = match http::parse_request(&buf[..head]) {
            Ok(request) => route(&request, peer, config, &mut name),
            Err(error) => {
                let _ = reply(io, Reply::for_error(error)).await;
                return Err(ServeError::Http(error));
            }
        };
        let (name, framing, expect_continue) = match action {
            Action::Respond(answer) => {
                reply(io, answer).await.map_err(ServeError::Io)?;
                return Ok(Served::Replied(answer.status()));
            }
            Action::Receive {
                name,
                framing,
                expect_continue,
            } => (name, framing, expect_continue),
        };
        let incoming = Incoming {
            from: peer.addr,
            name,
            size: framing.declared_len(),
        };
        if let Err(error) = sink.begin(&incoming).await {
            let _ = reply(io, Reply::StorageFailed).await;
            return Err(ServeError::Sink(error));
        }
        if expect_continue {
            let sent = match io.write_all(http::CONTINUE).await {
                Ok(()) => io.flush().await,
                Err(error) => Err(error),
            };
            if let Err(error) = sent {
                sink.abort().await;
                return Err(ServeError::Io(error));
            }
        }

        let mut decoder = BodyDecoder::new(framing);
        let mut received = 0;
        let (mut start, mut end) = (head, filled);
        while !decoder.is_done() {
            if start == end {
                match io.read(buf).await {
                    Ok(0) => {
                        sink.abort().await;
                        return Err(ServeError::Http(http::Error::UnexpectedEof));
                    }
                    Ok(read) => (start, end) = (0, read),
                    Err(error) => {
                        sink.abort().await;
                        return Err(ServeError::Io(error));
                    }
                }
            }
            let step = match body_step(&mut decoder, &buf[start..end], &mut received, config) {
                Ok(step) => step,
                Err(answer) => {
                    sink.abort().await;
                    let _ = reply(io, answer).await;
                    return Err(if answer == Reply::TooLarge {
                        ServeError::TooLarge
                    } else {
                        ServeError::Http(http::Error::BadChunk)
                    });
                }
            };
            start += step.consumed;
            if !step.data.is_empty()
                && let Err(error) = sink.write(step.data).await
            {
                sink.abort().await;
                let _ = reply(io, Reply::StorageFailed).await;
                return Err(ServeError::Sink(error));
            }
        }
        if let Err(error) = sink.finish().await {
            sink.abort().await;
            let _ = reply(io, Reply::StorageFailed).await;
            return Err(ServeError::Sink(error));
        }
        reply(io, Reply::Stored).await.map_err(ServeError::Io)?;
        Ok(Served::Received { bytes: received })
    }

    /// Async [`send`](super::send): send one file to a peer.
    pub async fn send_async<IO, R>(
        io: &mut IO,
        upload: &Upload<'_>,
        body: &mut R,
        buf: &mut [u8],
    ) -> Result<(), SendError<IO::Error, R::Error>>
    where
        IO: Read + Write,
        R: Read,
    {
        validate_name(upload.name).map_err(|_| SendError::InvalidName)?;
        let len = write_upload_head(upload, buf).map_err(SendError::Http)?;
        io.write_all(&buf[..len]).await.map_err(SendError::Io)?;
        io.flush().await.map_err(SendError::Io)?;
        let status = response_status(io, buf).await?;
        if status != 100 {
            return Err(SendError::Rejected(status));
        }

        let mut remaining = upload.size;
        while remaining > 0 {
            let want = super::http_clamp(remaining, buf.len());
            let read = body
                .read(&mut buf[..want])
                .await
                .map_err(SendError::Source)?;
            if read == 0 {
                return Err(SendError::SourceEnded);
            }
            io.write_all(&buf[..read]).await.map_err(SendError::Io)?;
            remaining -= read as u64;
        }
        io.flush().await.map_err(SendError::Io)?;
        match response_status(io, buf).await? {
            200 => Ok(()),
            status => Err(SendError::Rejected(status)),
        }
    }

    async fn response_status<IO: Read + Write, R>(
        io: &mut IO,
        buf: &mut [u8],
    ) -> Result<u16, SendError<IO::Error, R>> {
        let (head, filled) = match read_head(io, buf).await {
            Ok(Some(head)) => head,
            Ok(None) => return Err(SendError::Http(http::Error::UnexpectedEof)),
            Err(HeadError::Io(error)) => return Err(SendError::Io(error)),
            Err(HeadError::Http(error)) => return Err(SendError::Http(error)),
        };
        let response = http::parse_response(&buf[..head]).map_err(SendError::Http)?;
        if response.status < 200 {
            return Ok(response.status);
        }
        let mut drain = Drain::new(response.framing);
        let mut pending = head..filled;
        loop {
            drain.feed(&buf[pending]).map_err(SendError::Http)?;
            if drain.is_done() {
                return Ok(response.status);
            }
            let read = io.read(buf).await.map_err(SendError::Io)?;
            if read == 0 {
                return drain
                    .at_eof()
                    .map(|()| response.status)
                    .map_err(SendError::Http);
            }
            pending = 0..read;
        }
    }
}

/// Discards a response body. A response without length framing runs to the
/// end of the stream, which is how a `Connection: close` reply may end.
struct Drain {
    decoder: BodyDecoder,
    until_close: bool,
}

impl Drain {
    fn new(framing: Framing) -> Self {
        Self {
            decoder: BodyDecoder::new(framing),
            until_close: framing == Framing::None,
        }
    }

    fn is_done(&self) -> bool {
        !self.until_close && self.decoder.is_done()
    }

    /// Discard the body bytes in `input`; anything after the body is ignored
    /// because the exchange closes the connection.
    fn feed(&mut self, mut input: &[u8]) -> Result<(), http::Error> {
        while !self.until_close && !input.is_empty() && !self.decoder.is_done() {
            let step = self.decoder.decode(input)?;
            input = &input[step.consumed..];
        }
        Ok(())
    }

    fn at_eof(&self) -> Result<(), http::Error> {
        if self.until_close {
            Ok(())
        } else {
            Err(http::Error::UnexpectedEof)
        }
    }
}

fn http_clamp(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |remaining| remaining.min(available))
}

pub use blocking::{send, serve};
pub use nonblocking::{send_async, serve_async};

#[cfg(feature = "alloc")]
mod memory;
#[cfg(feature = "alloc")]
pub use memory::{MemoryError, MemorySink, ReceivedFile};

#[cfg(test)]
mod tests;
