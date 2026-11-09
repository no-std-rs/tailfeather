extern crate std;

use core::convert::Infallible;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::vec::Vec;

use super::*;

const PEER: Peer = Peer {
    addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)),
    may_send_files: true,
};

/// A blocking stream whose reads return the scripted segments one at a time
/// and whose writes are captured.
struct Script<'a> {
    segments: &'a [&'a [u8]],
    offset: usize,
    written: Vec<u8>,
}

impl<'a> Script<'a> {
    fn new(segments: &'a [&'a [u8]]) -> Self {
        Self {
            segments,
            offset: 0,
            written: Vec::new(),
        }
    }
}

impl embedded_io::ErrorType for Script<'_> {
    type Error = Infallible;
}

impl embedded_io::Read for Script<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        let Some((segment, rest)) = self.segments.split_first() else {
            return Ok(0);
        };
        let take = (segment.len() - self.offset).min(buf.len());
        buf[..take].copy_from_slice(&segment[self.offset..self.offset + take]);
        self.offset += take;
        if self.offset == segment.len() {
            self.segments = rest;
            self.offset = 0;
        }
        Ok(take)
    }
}

impl embedded_io::Write for Script<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

/// An allocation-free sink that records one file, optionally failing writes.
struct ArraySink {
    name: [u8; MAX_NAME],
    name_len: usize,
    size: Option<u64>,
    data: [u8; 256],
    len: usize,
    begun: usize,
    finished: usize,
    aborted: usize,
    fail_writes: bool,
}

impl ArraySink {
    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap()
    }

    fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Default for ArraySink {
    fn default() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            size: None,
            data: [0; 256],
            len: 0,
            begun: 0,
            finished: 0,
            aborted: 0,
            fail_writes: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Full;

impl FileSink for ArraySink {
    type Error = Full;

    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<Full>> {
        self.begun += 1;
        self.name[..file.name.len()].copy_from_slice(file.name.as_bytes());
        self.name_len = file.name.len();
        self.size = file.size;
        self.len = 0;
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Full> {
        let end = self.len + data.len();
        if self.fail_writes || end > self.data.len() {
            return Err(Full);
        }
        self.data[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Full> {
        self.finished += 1;
        Ok(())
    }

    fn abort(&mut self) {
        self.aborted += 1;
    }
}

impl AsyncFileSink for ArraySink {
    type Error = Full;

    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<Full>> {
        FileSink::begin(self, file)
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), Full> {
        FileSink::write(self, data)
    }

    async fn finish(&mut self) -> Result<(), Full> {
        FileSink::finish(self)
    }

    async fn abort(&mut self) {
        FileSink::abort(self)
    }
}

fn status_of(written: &[u8]) -> u16 {
    let head = http::head_len(written).unwrap();
    http::parse_response(&written[..head]).unwrap().status
}

fn body_of(written: &[u8]) -> &[u8] {
    &written[http::head_len(written).unwrap()..]
}

#[test]
fn every_canned_reply_fits_the_reply_buffer() {
    for reply in [
        Reply::Stored,
        Reply::BadRequest,
        Reply::InvalidName,
        Reply::InvalidRange,
        Reply::Exists,
        Reply::Forbidden,
        Reply::NotFound,
        Reply::MethodNotAllowed,
        Reply::TooLarge,
        Reply::HeadTooLarge,
        Reply::StorageFailed,
        Reply::NotImplemented,
        Reply::UnsupportedVersion,
    ] {
        let mut out = [0u8; REPLY_BUFFER];
        let len = reply.write(&mut out).unwrap();
        assert_eq!(status_of(&out[..len]), reply.status());
    }
}

#[test]
fn validates_names_like_tailscale() {
    for good in ["a.txt", "résumé.pdf", "IMG 0001.HEIC", ".hidden", "a..b"] {
        assert_eq!(validate_name(good), Ok(()), "{good}");
    }
    let long = "x".repeat(MAX_NAME + 1);
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        " lead",
        "trail ",
        "nl\n",
        "x.partial",
        "x.deleted",
        &long,
    ] {
        assert_eq!(validate_name(bad), Err(InvalidName), "{bad:?}");
    }
}

fn route_of(head: &[u8], peer: &Peer, config: &Config) -> Option<Reply> {
    let request = http::parse_request(head).unwrap();
    match route(&request, peer, config, &mut [0; MAX_NAME]) {
        Action::Respond(reply) => Some(reply),
        Action::Receive { .. } | Action::Checksums { .. } | Action::ListPartials => None,
    }
}

#[test]
fn routes_before_reading_any_body() {
    let config = Config { max_file_size: 10 };
    let put = b"PUT /v0/put/a.txt HTTP/1.1\r\nContent-Length: 3\r\n\r\n";
    assert_eq!(route_of(put, &PEER, &config), None);
    let denied = Peer {
        may_send_files: false,
        ..PEER
    };
    assert_eq!(route_of(put, &denied, &config), Some(Reply::Forbidden));
    assert_eq!(
        route_of(b"PUT /v0/other HTTP/1.1\r\n\r\n", &PEER, &config),
        Some(Reply::NotFound)
    );
    // Resume probes and listings are routed to their streaming handlers.
    let request = http::parse_request(b"GET /v0/put/a%20b HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(
        route(&request, &PEER, &config, &mut [0; MAX_NAME]),
        Action::Checksums { name: "a b" }
    );
    let request = http::parse_request(b"GET /v0/put/ HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(
        route(&request, &PEER, &config, &mut [0; MAX_NAME]),
        Action::ListPartials
    );
    assert_eq!(
        route_of(
            b"PUT /v0/put/a.txt HTTP/1.1\r\nRange: bytes=1-2\r\n\r\n",
            &PEER,
            &config
        ),
        Some(Reply::InvalidRange)
    );
    let resumed = b"PUT /v0/put/a.txt HTTP/1.1\r\nRange: bytes=8-\r\nContent-Length: 3\r\n\r\n";
    assert_eq!(route_of(resumed, &PEER, &config), Some(Reply::TooLarge));
    let request = http::parse_request(
        b"PUT /v0/put/a.txt HTTP/1.1\r\nRange: bytes=4-\r\nContent-Length: 3\r\n\r\n",
    )
    .unwrap();
    assert_eq!(
        route(&request, &PEER, &config, &mut [0; MAX_NAME]),
        Action::Receive {
            name: "a.txt",
            framing: Framing::Length(3),
            expect_continue: false,
            offset: 4,
        }
    );
    assert_eq!(
        route_of(b"DELETE /v0/put/a.txt HTTP/1.1\r\n\r\n", &PEER, &config),
        Some(Reply::MethodNotAllowed)
    );
    for name in ["..", "a%2Fb", "%2E%2E", "bad%zz", "x.partial", ""] {
        let head = std::format!("PUT /v0/put/{name} HTTP/1.1\r\nContent-Length: 1\r\n\r\n");
        assert_eq!(
            route_of(head.as_bytes(), &PEER, &config),
            Some(Reply::InvalidName),
            "{name}"
        );
    }
    let big = b"PUT /v0/put/a.txt HTTP/1.1\r\nContent-Length: 11\r\n\r\n";
    assert_eq!(route_of(big, &PEER, &config), Some(Reply::TooLarge));
}

#[test]
fn receives_a_go_style_upload_split_across_reads() {
    let segments: &[&[u8]] = &[
        b"PUT /v0/put/hello%20world.txt HTTP/1.1\r\nHost: 100.64.0.1:5254\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 11\r\n\r\nhel",
        b"lo w",
        b"orld",
    ];
    let mut io = Script::new(segments);
    let mut sink = ArraySink::default();
    let mut buf = [0u8; 512];
    let served = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut buf).unwrap();
    assert_eq!(
        served,
        Served::Received {
            bytes: 11,
            offset: 0
        }
    );
    assert_eq!(sink.name(), "hello world.txt");
    assert_eq!(sink.size, Some(11));
    assert_eq!(sink.data(), b"hello world");
    assert_eq!((sink.finished, sink.aborted), (1, 0));
    assert_eq!(status_of(&io.written), 200);
    assert_eq!(body_of(&io.written), b"{}\n");
}

#[test]
fn receives_chunked_uploads_after_100_continue() {
    let segments: &[&[u8]] = &[
        b"PUT /v0/put/stdin.bin HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
        b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n",
    ];
    let mut io = Script::new(segments);
    let mut sink = ArraySink::default();
    let mut buf = [0u8; 256];
    let served = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut buf).unwrap();
    assert_eq!(
        served,
        Served::Received {
            bytes: 6,
            offset: 0
        }
    );
    assert_eq!(sink.size, None);
    assert_eq!(sink.data(), b"abcdef");
    assert!(io.written.starts_with(http::CONTINUE));
    assert_eq!(status_of(&io.written[http::CONTINUE.len()..]), 200);
}

#[test]
fn refuses_unauthorized_peers_without_touching_the_sink() {
    let segments: &[&[u8]] = &[b"PUT /v0/put/a HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"];
    let mut io = Script::new(segments);
    let mut sink = ArraySink::default();
    let denied = Peer {
        may_send_files: false,
        ..PEER
    };
    let served = serve(
        &mut io,
        &denied,
        &Config::default(),
        &mut sink,
        &mut [0; 256],
    )
    .unwrap();
    assert_eq!(served, Served::Replied(403));
    assert_eq!(sink.begun, 0);
    assert_eq!(status_of(&io.written), 403);
}

#[test]
fn enforces_the_limit_on_chunked_bodies() {
    let segments: &[&[u8]] = &[
        b"PUT /v0/put/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"8\r\n12345678\r\n0\r\n\r\n",
    ];
    let mut io = Script::new(segments);
    let mut sink = ArraySink::default();
    let config = Config { max_file_size: 4 };
    let error = serve(&mut io, &PEER, &config, &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::TooLarge);
    assert_eq!((sink.finished, sink.aborted), (0, 1));
    assert_eq!(status_of(&io.written), 413);
}

#[test]
fn reports_sink_failures_as_500() {
    let segments: &[&[u8]] = &[b"PUT /v0/put/a HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"];
    let mut io = Script::new(segments);
    let mut sink = ArraySink {
        fail_writes: true,
        ..ArraySink::default()
    };
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Sink(Full));
    assert_eq!(sink.aborted, 1);
    assert_eq!(status_of(&io.written), 500);
}

#[test]
fn aborts_truncated_uploads() {
    let segments: &[&[u8]] = &[b"PUT /v0/put/a HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"];
    let mut io = Script::new(segments);
    let mut sink = ArraySink::default();
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Http(http::Error::UnexpectedEof));
    assert_eq!((sink.finished, sink.aborted), (0, 1));
    assert!(io.written.is_empty());
}

#[test]
fn answers_oversized_and_malformed_heads() {
    let segments: &[&[u8]] =
        &[b"PUT /v0/put/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n"];
    let mut io = Script::new(segments);
    let error = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut ArraySink::default(),
        &mut [0; 32],
    )
    .unwrap_err();
    assert_eq!(error, ServeError::Http(http::Error::HeadTooLarge));
    assert_eq!(status_of(&io.written), 431);

    let segments: &[&[u8]] =
        &[b"PUT /v0/put/a HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"];
    let mut io = Script::new(segments);
    let error = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut ArraySink::default(),
        &mut [0; 256],
    )
    .unwrap_err();
    assert_eq!(error, ServeError::Http(http::Error::AmbiguousLength));
    assert_eq!(status_of(&io.written), 400);

    let mut io = Script::new(&[]);
    let served = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut ArraySink::default(),
        &mut [0; 256],
    );
    assert_eq!(served, Ok(Served::Closed));
}

const RECEIVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)), 5254);

#[test]
fn sends_an_upload_and_reads_the_acknowledgement() {
    let segments: &[&[u8]] = &[
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}\n",
    ];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a b.txt",
        size: 5,
        offset: 0,
    };
    let mut body: &[u8] = b"hello";
    send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap();
    let expected = b"PUT /v0/put/a%20b.txt HTTP/1.1\r\nHost: 100.64.0.9:5254\r\nUser-Agent: tailfeather\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nhello";
    assert_eq!(io.written, expected);
}

#[test]
fn stops_before_the_body_when_refused() {
    let segments: &[&[u8]] = &[b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a",
        size: 5,
        offset: 0,
    };
    let mut body: &[u8] = b"hello";
    let error = send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap_err();
    assert_eq!(error, SendError::Rejected(403));
    assert!(!io.written.ends_with(b"hello"));
}

#[test]
fn rejects_short_sources_and_bad_names() {
    let segments: &[&[u8]] = &[b"HTTP/1.1 100 Continue\r\n\r\n"];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a",
        size: 9,
        offset: 0,
    };
    let mut body: &[u8] = b"short";
    let error = send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap_err();
    assert_eq!(error, SendError::SourceEnded);

    let upload = Upload {
        name: "../etc/passwd",
        ..upload
    };
    let error = send(
        &mut Script::new(&[]),
        &upload,
        &mut body,
        &mut [0; MIN_CLIENT_BUFFER],
    )
    .unwrap_err();
    assert_eq!(error, SendError::InvalidName);
}

#[test]
fn the_longest_escaped_name_fits_the_minimum_client_buffer() {
    let name = "é".repeat(MAX_NAME / 2);
    let upload = Upload {
        peer_api: SocketAddr::new(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST), 65535),
        name: &name,
        size: u64::MAX,
        offset: 0,
    };
    write_upload_head(&upload, &mut [0; MIN_CLIENT_BUFFER]).unwrap();
}

/// Adapts a Tokio stream to `embedded-io-async`, the way the
/// `embedded-io-adapters` crate's `FromTokio` does.
mod tokio_adapter {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub struct FromTokio<T>(pub T);

    impl<T> embedded_io_async::ErrorType for FromTokio<T> {
        type Error = embedded_io::ErrorKind;
    }

    impl<T: AsyncRead + Unpin> embedded_io_async::Read for FromTokio<T> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.0
                .read(buf)
                .await
                .map_err(|_| embedded_io::ErrorKind::Other)
        }
    }

    impl<T: AsyncWrite + Unpin> embedded_io_async::Write for FromTokio<T> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.0
                .write(buf)
                .await
                .map_err(|_| embedded_io::ErrorKind::Other)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.0
                .flush()
                .await
                .map_err(|_| embedded_io::ErrorKind::Other)
        }
    }
}

#[test]
fn async_drivers_round_trip_on_a_multithreaded_tokio_runtime() {
    use tokio_adapter::FromTokio;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    runtime.block_on(async {
        // A tiny duplex window forces many partial reads and writes.
        let (client, server) = tokio::io::duplex(7);

        // `tokio::spawn` requires `Send` futures: this compiles only because
        // the drivers hold nothing that is not `Send`.
        let server = tokio::spawn(async move {
            let mut io = FromTokio(server);
            let mut sink = ArraySink::default();
            let mut buf = [0u8; 512];
            let served = serve_async(&mut io, &PEER, &Config::default(), &mut sink, &mut buf)
                .await
                .unwrap();
            (served, sink)
        });
        let client = tokio::spawn(async move {
            let mut io = FromTokio(client);
            let upload = Upload {
                peer_api: RECEIVER,
                name: "photo #1.jpg",
                size: 26,
                offset: 0,
            };
            let mut body: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
            send_async(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).await
        });

        client.await.unwrap().unwrap();
        let (served, sink) = server.await.unwrap();
        assert_eq!(
            served,
            Served::Received {
                bytes: 26,
                offset: 0
            }
        );
        assert_eq!(sink.name(), "photo #1.jpg");
        assert_eq!(sink.data(), b"abcdefghijklmnopqrstuvwxyz");
    });
}

#[test]
fn async_server_refuses_like_the_blocking_one() {
    use tokio_adapter::FromTokio;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (client, server) = tokio::io::duplex(64);
        let denied = Peer {
            may_send_files: false,
            ..PEER
        };
        let server = async move {
            let mut io = FromTokio(server);
            let mut sink = ArraySink::default();
            let served = serve_async(
                &mut io,
                &denied,
                &Config::default(),
                &mut sink,
                &mut [0; 256],
            )
            .await
            .unwrap();
            (served, sink.begun)
        };
        let client = async move {
            let mut io = FromTokio(client);
            let upload = Upload {
                peer_api: RECEIVER,
                name: "a",
                size: 3,
                offset: 0,
            };
            let mut body: &[u8] = b"abc";
            send_async(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).await
        };
        let ((served, begun), sent) = tokio::join!(server, client);
        assert_eq!(served, Served::Replied(403));
        assert_eq!(begun, 0);
        assert_eq!(sent, Err(SendError::Rejected(403)));
    });
}

#[cfg(feature = "alloc")]
#[test]
fn memory_sink_keeps_finished_files_within_budget() {
    let upload = |name: &str| {
        std::format!("PUT /v0/put/{name} HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc").into_bytes()
    };
    // The budget charges records and names too: each file here costs its
    // record plus 5 + 3 bytes, so one fits and a second does not.
    let record = core::mem::size_of::<ReceivedFile>();
    let mut sink = MemorySink::new(2 * record + 13);
    let first = upload("a.txt");
    let segments: &[&[u8]] = &[&first];
    let mut io = Script::new(segments);
    serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
    assert_eq!(sink.files().len(), 1);
    assert_eq!(sink.files()[0].name, "a.txt");
    assert_eq!(sink.files()[0].data, b"abc");

    // A second file of the same name conflicts, as in stock Tailscale.
    let segments: &[&[u8]] = &[&first];
    let mut io = Script::new(segments);
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Exists);
    assert_eq!(status_of(&io.written), 409);

    // Only a record and five bytes of budget remain.
    let second = upload("b.txt");
    let segments: &[&[u8]] = &[&second];
    let mut io = Script::new(segments);
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Sink(MemoryError::OverBudget));
    assert_eq!(status_of(&io.written), 500);

    assert_eq!(sink.take().len(), 1);
    let segments: &[&[u8]] = &[&second];
    let mut io = Script::new(segments);
    serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
}

/// Deterministic file content for the resume tests.
#[cfg(feature = "alloc")]
fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// A seekable source that fails reads at `fail_at`, like a dropped link.
struct Source<'a> {
    data: &'a [u8],
    pos: usize,
    fail_at: Option<usize>,
}

impl<'a> Source<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            fail_at: None,
        }
    }

    fn step(&mut self, buf: &mut [u8]) -> Result<usize, embedded_io::ErrorKind> {
        let end = self.fail_at.unwrap_or(self.data.len()).min(self.data.len());
        if self.pos >= end && self.fail_at.is_some() {
            return Err(embedded_io::ErrorKind::BrokenPipe);
        }
        let len = buf.len().min(end - self.pos);
        buf[..len].copy_from_slice(&self.data[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }

    fn reposition(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, embedded_io::ErrorKind> {
        let embedded_io::SeekFrom::Start(pos) = pos else {
            return Err(embedded_io::ErrorKind::Unsupported);
        };
        self.pos = pos as usize;
        Ok(pos)
    }
}

impl embedded_io::ErrorType for Source<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for Source<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.step(buf)
    }
}

impl embedded_io::Seek for Source<'_> {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        self.reposition(pos)
    }
}

impl embedded_io_async::Read for Source<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.step(buf)
    }
}

impl embedded_io_async::Seek for Source<'_> {
    async fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        self.reposition(pos)
    }
}

/// A sink holding a 70,000-byte partial of `photo.jpg` from [`PEER`],
/// left by an upload of 100,000 bytes that broke off.
#[cfg(feature = "alloc")]
fn sink_with_partial(data: &[u8]) -> MemorySink {
    let mut sink = MemorySink::new(1 << 20);
    let head = b"PUT /v0/put/photo.jpg HTTP/1.1\r\nContent-Length: 100000\r\n\r\n";
    let segments: &[&[u8]] = &[head, &data[..70_000]];
    let mut io = Script::new(segments);
    let error = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 4096],
    )
    .unwrap_err();
    assert_eq!(error, ServeError::Http(http::Error::UnexpectedEof));
    assert_eq!(sink.partials()[0].data.len(), 70_000);
    sink
}

#[cfg(feature = "alloc")]
#[test]
fn streams_block_checksums_of_a_kept_partial() {
    use sha2::{Digest, Sha256};

    let data = content(100_000);
    let mut sink = sink_with_partial(&data);
    let mut io = Script::new(&[b"GET /v0/put/photo.jpg HTTP/1.1\r\n\r\n"]);
    let served = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 1500],
    )
    .unwrap();
    assert_eq!(served, Served::Replied(200));
    let body = core::str::from_utf8(body_of(&io.written)).unwrap();
    let hex = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| std::format!("{byte:02x}"))
            .collect::<std::string::String>()
    };
    // Go's json.Encoder output for the two blocks of the 70,000-byte partial.
    let expected = std::format!(
        "{{\"checksum\":\"{}\",\"algo\":\"sha256\",\"size\":65536}}\n{{\"checksum\":\"{}\",\"algo\":\"sha256\",\"size\":4464}}\n",
        hex(&data[..65_536]),
        hex(&data[65_536..70_000]),
    );
    assert_eq!(body, expected);

    // Another sender sees no partial file: an empty stream.
    let stranger = Peer {
        addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 99)),
        ..PEER
    };
    let mut io = Script::new(&[b"GET /v0/put/photo.jpg HTTP/1.1\r\n\r\n"]);
    serve(
        &mut io,
        &stranger,
        &Config::default(),
        &mut sink,
        &mut [0; 1500],
    )
    .unwrap();
    assert!(body_of(&io.written).is_empty());

    let mut io = Script::new(&[b"GET /v0/put/ HTTP/1.1\r\n\r\n"]);
    serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 1500],
    )
    .unwrap();
    assert_eq!(body_of(&io.written), b"[\"photo.jpg\"]\n");
}

#[cfg(feature = "alloc")]
#[test]
fn ranged_upload_completes_the_kept_partial() {
    let data = content(100_000);
    let mut sink = sink_with_partial(&data);
    let head =
        b"PUT /v0/put/photo.jpg HTTP/1.1\r\nRange: bytes=70000-\r\nContent-Length: 30000\r\n\r\n";
    let segments: &[&[u8]] = &[head, &data[70_000..]];
    let mut io = Script::new(segments);
    let served = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 4096],
    )
    .unwrap();
    assert_eq!(
        served,
        Served::Received {
            bytes: 30_000,
            offset: 70_000
        }
    );
    assert_eq!(sink.files()[0].data, data);
    assert!(sink.partials().is_empty());

    // Resuming past what was kept is refused, and the partial survives.
    let mut sink = sink_with_partial(&data);
    let head =
        b"PUT /v0/put/photo.jpg HTTP/1.1\r\nRange: bytes=80000-\r\nContent-Length: 20000\r\n\r\n";
    let segments: &[&[u8]] = &[head, &data[80_000..]];
    let mut io = Script::new(segments);
    let error = serve(
        &mut io,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 4096],
    )
    .unwrap_err();
    assert_eq!(error, ServeError::Sink(MemoryError::BadOffset));
    assert_eq!(sink.partials()[0].data.len(), 70_000);
}

#[cfg(feature = "alloc")]
#[test]
fn resume_offset_matches_the_receivers_blocks() {
    let data = content(100_000);
    let mut sink = sink_with_partial(&data);
    // Capture the receiver's real checksum stream, then replay it to the client.
    let mut probe = Script::new(&[b"GET /v0/put/photo.jpg HTTP/1.1\r\n\r\n"]);
    serve(
        &mut probe,
        &PEER,
        &Config::default(),
        &mut sink,
        &mut [0; 1500],
    )
    .unwrap();
    let response = probe.written;
    for split in [1, 7, 100, response.len()] {
        let segments: Vec<&[u8]> = response.chunks(split).collect();
        let mut io = Script::new(&segments);
        // Left mid-file by an earlier attempt: the probe must rewind it.
        let mut source = Source {
            pos: 12_345,
            ..Source::new(&data)
        };
        let offset = resume_offset(
            &mut io,
            RECEIVER,
            "photo.jpg",
            &mut source,
            &mut [0; MIN_CLIENT_BUFFER],
        )
        .unwrap();
        assert_eq!(offset, 70_000, "split {split}");
        assert_eq!(source.pos, 70_000);
        assert!(
            io.written
                .starts_with(b"GET /v0/put/photo.jpg HTTP/1.1\r\n")
        );
    }

    // A changed second block resumes after the first.
    let mut edited = data.clone();
    edited[65_600] ^= 1;
    let segments: &[&[u8]] = &[&response];
    let mut source = Source::new(&edited);
    let offset = resume_offset(
        &mut Script::new(segments),
        RECEIVER,
        "photo.jpg",
        &mut source,
        &mut [0; MIN_CLIENT_BUFFER],
    )
    .unwrap();
    assert_eq!(offset, 65_536);

    // A receiver without resume support yields zero, with the source there.
    let segments: &[&[u8]] = &[b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"];
    let mut source = Source {
        pos: 999,
        ..Source::new(&data)
    };
    let offset = resume_offset(
        &mut Script::new(segments),
        RECEIVER,
        "photo.jpg",
        &mut source,
        &mut [0; MIN_CLIENT_BUFFER],
    )
    .unwrap();
    assert_eq!((offset, source.pos), (0, 0));
}

#[test]
fn resumed_uploads_announce_their_range() {
    let segments: &[&[u8]] = &[
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}\n",
    ];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a",
        size: 10,
        offset: 6,
    };
    let mut body: &[u8] = b"WXYZ";
    send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap();
    let text = core::str::from_utf8(&io.written).unwrap();
    assert!(
        text.contains("\r\nContent-Length: 4\r\nRange: bytes=6-\r\n"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\nWXYZ"));
    let upload = Upload {
        offset: 11,
        ..upload
    };
    let error = send(
        &mut Script::new(&[]),
        &upload,
        &mut body,
        &mut [0; MIN_CLIENT_BUFFER],
    )
    .unwrap_err();
    assert_eq!(error, SendError::InvalidOffset);
}

#[cfg(feature = "alloc")]
#[test]
fn async_upload_resumes_after_a_broken_transfer() {
    use tokio_adapter::FromTokio;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    runtime.block_on(async {
        let data: &'static [u8] = std::vec::Vec::leak(content(200_000));
        let sink = std::sync::Arc::new(tokio::sync::Mutex::new(MemorySink::new(1 << 20)));
        let connection = |sink: std::sync::Arc<tokio::sync::Mutex<MemorySink>>| {
            let (client, server) = tokio::io::duplex(4096);
            let served = tokio::spawn(async move {
                let mut io = FromTokio(server);
                let mut sink = sink.lock().await;
                let mut buf = [0u8; 4096];
                serve_async(&mut io, &PEER, &Config::default(), &mut *sink, &mut buf).await
            });
            (FromTokio(client), served)
        };
        let upload = Upload {
            peer_api: RECEIVER,
            name: "big.bin",
            size: data.len() as u64,
            offset: 0,
        };

        // The first attempt breaks off 70,000 bytes in.
        let (mut io, served) = connection(sink.clone());
        let mut source = Source {
            fail_at: Some(70_000),
            ..Source::new(data)
        };
        let sent = send_async(&mut io, &upload, &mut source, &mut [0; 4096]).await;
        assert!(matches!(sent, Err(SendError::Source(_))), "{sent:?}");
        drop(io);
        assert!(served.await.unwrap().is_err());

        // The probe finds the kept prefix, and the rest completes the file.
        // The interrupted attempt's own source is reused, as a retrying
        // sender would: the probe rewinds it before comparing.
        source.fail_at = None;
        let (mut io, served) = connection(sink.clone());
        let offset = resume_offset_async(
            &mut io,
            RECEIVER,
            "big.bin",
            &mut source,
            &mut [0; MIN_CLIENT_BUFFER],
        )
        .await
        .unwrap();
        assert_eq!(offset, 70_000);
        assert_eq!(served.await.unwrap(), Ok(Served::Replied(200)));

        let (mut io, served) = connection(sink.clone());
        let resumed = Upload { offset, ..upload };
        send_async(&mut io, &resumed, &mut source, &mut [0; 4096])
            .await
            .unwrap();
        assert_eq!(
            served.await.unwrap(),
            Ok(Served::Received {
                bytes: 130_000,
                offset: 70_000
            })
        );
        let sink = sink.lock().await;
        assert_eq!(sink.files()[0].data, data);
        assert!(sink.partials().is_empty());
    });
}

#[test]
fn uploads_with_nothing_left_do_not_wait_for_100_continue() {
    // Resuming at the end of the file: no body, so no `Expect`, and the final
    // response is the only one.
    let segments: &[&[u8]] = &[b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}\n"];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a",
        size: 10,
        offset: 10,
    };
    let mut body: &[u8] = b"";
    send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap();
    let text = core::str::from_utf8(&io.written).unwrap();
    assert!(!text.contains("Expect:"), "{text}");
    assert!(
        text.contains("\r\nContent-Length: 0\r\nRange: bytes=10-\r\n"),
        "{text}"
    );

    // Our own receiver answers it directly too.
    let mut sink = ArraySink::default();
    let mut io = Script::new(&[b"PUT /v0/put/a HTTP/1.1\r\nContent-Length: 0\r\n\r\n"]);
    let served = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
    assert_eq!(
        served,
        Served::Received {
            bytes: 0,
            offset: 0
        }
    );
    assert_eq!(status_of(&io.written), 200);
}

#[test]
fn a_final_response_behind_100_continue_is_read_not_awaited() {
    // Both heads in one read: the refusal must not be lost (and then waited
    // for), and no body byte may follow it.
    let segments: &[&[u8]] =
        &[b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"];
    let mut io = Script::new(segments);
    let upload = Upload {
        peer_api: RECEIVER,
        name: "a",
        size: 5,
        offset: 0,
    };
    let mut body: &[u8] = b"hello";
    let error = send(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).unwrap_err();
    assert_eq!(error, SendError::Rejected(403));
    assert!(!io.written.ends_with(b"hello"));
}

#[cfg(feature = "alloc")]
#[test]
fn interrupted_uploads_keep_only_what_arrived() {
    // An authorized sender announcing near-budget files, sending a byte and
    // hanging up must not make the sink hold the reservations.
    const BUDGET: usize = 1 << 20;
    let mut sink = MemorySink::new(BUDGET);
    for index in 0..10 {
        let head = std::format!(
            "PUT /v0/put/file{index} HTTP/1.1\r\nContent-Length: {}\r\n\r\nx",
            BUDGET - 4096
        );
        let segments: &[&[u8]] = &[head.as_bytes()];
        let mut io = Script::new(segments);
        let error =
            serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
        assert_eq!(error, ServeError::Http(http::Error::UnexpectedEof));
    }
    assert_eq!(sink.partials().len(), 10);
    let held: usize = sink
        .partials()
        .iter()
        .map(|file| file.data.capacity())
        .sum();
    assert_eq!(
        held, 10,
        "partials hold {held} bytes of buffer for 10 bytes of data"
    );

    // The budget charges reservations: one in-flight announcement of the
    // whole budget leaves no room for a second.
    let mut big = MemorySink::new(BUDGET + 4 * core::mem::size_of::<ReceivedFile>());
    let begin = |sink: &mut MemorySink, name: &str| {
        FileSink::begin(
            sink,
            &Incoming {
                from: PEER.addr,
                name,
                offset: 0,
                size: Some((BUDGET - 4096) as u64),
            },
        )
    };
    begin(&mut big, "first").unwrap();
    FileSink::write(&mut big, b"y").unwrap();
    FileSink::finish(&mut big).unwrap();
    assert_eq!(begin(&mut big, "second"), Ok(()));
    FileSink::abort(&mut big);
    assert_eq!(begin(&mut big, "third"), Ok(()));
}

#[cfg(feature = "alloc")]
#[test]
fn chunked_uploads_stay_within_the_budget() {
    let record = core::mem::size_of::<ReceivedFile>();
    let mut sink = MemorySink::new(record + 100);
    let head: &[u8] = b"PUT /v0/put/a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let body: &[u8] = b"20\r\n0123456789abcdef0123456789abcdef\r\n20\r\n0123456789abcdef0123456789abcdef\r\n0\r\n\r\n";
    let segments: &[&[u8]] = &[head, body];
    let mut io = Script::new(segments);
    serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
    let file = &sink.files()[0];
    assert_eq!(file.data.len(), 64);
    assert!(file.data.capacity() + file.name.capacity() <= 100);

    // A second 64-byte file does not fit what is left of the 100 bytes.
    let renamed: &[u8] = b"PUT /v0/put/b HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let segments: &[&[u8]] = &[renamed, body];
    let mut io = Script::new(segments);
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Sink(MemoryError::OverBudget));
}

#[cfg(feature = "alloc")]
#[test]
fn growth_reserves_before_writing_and_respects_the_budget() {
    // Codex's case: a 12-byte budget beyond the record, a one-byte name, and
    // chunked writes of 5, 1 and 5 bytes. Every byte fits, but never more.
    let record = core::mem::size_of::<ReceivedFile>();
    let mut sink = MemorySink::new(record + 12);
    let incoming = Incoming {
        from: PEER.addr,
        name: "a",
        offset: 0,
        size: None,
    };
    FileSink::begin(&mut sink, &incoming).unwrap();
    for chunk in [&b"12345"[..], b"6", b"789ab"] {
        FileSink::write(&mut sink, chunk).unwrap();
    }
    assert_eq!(
        FileSink::write(&mut sink, b"c"),
        Err(MemoryError::OverBudget)
    );
    FileSink::finish(&mut sink).unwrap();
    let file = &sink.files()[0];
    assert_eq!(file.data, b"123456789ab");
    assert!(record + file.name.capacity() + file.data.capacity() <= record + 12);
}

#[cfg(feature = "alloc")]
#[test]
fn empty_files_still_count_against_the_budget() {
    fn empty(name: &str) -> Incoming<'_> {
        Incoming {
            from: PEER.addr,
            name,
            offset: 0,
            size: Some(0),
        }
    }
    let mut zero = MemorySink::new(0);
    assert_eq!(
        FileSink::begin(&mut zero, &empty("x")),
        Err(Refusal::Failed(MemoryError::OverBudget))
    );

    // A budget for three records takes three empty files and refuses more.
    let record = core::mem::size_of::<ReceivedFile>();
    let mut small = MemorySink::new(3 * (record + 2));
    let mut accepted = 0;
    for index in 0..100 {
        let name = std::format!("{index:02}");
        if FileSink::begin(&mut small, &empty(&name)).is_ok() {
            FileSink::finish(&mut small).unwrap();
            accepted += 1;
        }
    }
    assert_eq!(accepted, 3);
}
