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

    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Full> {
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

    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Full> {
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
        Reply::NoPartialFile,
        Reply::BadRequest,
        Reply::InvalidName,
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
        Action::Receive { .. } => None,
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
    assert_eq!(
        route_of(
            b"GET /v0/put/a.txt?offset=0 HTTP/1.1\r\n\r\n",
            &PEER,
            &config
        ),
        Some(Reply::NoPartialFile)
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
    assert_eq!(served, Served::Received { bytes: 11 });
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
    assert_eq!(served, Served::Received { bytes: 6 });
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
            };
            let mut body: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
            send_async(&mut io, &upload, &mut body, &mut [0; MIN_CLIENT_BUFFER]).await
        });

        client.await.unwrap().unwrap();
        let (served, sink) = server.await.unwrap();
        assert_eq!(served, Served::Received { bytes: 26 });
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
    let segments: &[&[u8]] = &[b"PUT /v0/put/a.txt HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"];
    let mut sink = MemorySink::new(5);
    let mut io = Script::new(segments);
    serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
    assert_eq!(sink.files().len(), 1);
    assert_eq!(sink.files()[0].name, "a.txt");
    assert_eq!(sink.files()[0].data, b"abc");

    // Only two bytes of budget remain.
    let mut io = Script::new(segments);
    let error = serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap_err();
    assert_eq!(error, ServeError::Sink(MemoryError::OverBudget));
    assert_eq!(status_of(&io.written), 500);

    let files = sink.take();
    assert_eq!(files.len(), 1);
    let mut io = Script::new(segments);
    serve(&mut io, &PEER, &Config::default(), &mut sink, &mut [0; 256]).unwrap();
}
