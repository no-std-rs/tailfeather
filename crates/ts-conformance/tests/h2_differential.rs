//! `micro-h2` against `h2`, the HTTP/2 implementation behind most Rust servers.
//!
//! Until now every HTTP/2 test in this tree fed our encoder's output to our
//! decoder. That cannot detect a shared misreading of the specification, and
//! HTTP/2 has one failure mode where a shared misreading is invisible right up
//! until it deadlocks: **flow control**.
//!
//! # The payoff test
//!
//! Both windows start at 65535 bytes. A receiver that never sends
//! `WINDOW_UPDATE` gets exactly 65535 bytes and then the connection stops —
//! no error, no reset, just silence. `conn.rs` documents this and raises the
//! window in three places to avoid it, and nothing tested any of them, because
//! our own test server had no window accounting to stall against.
//!
//! `h2` does. [`a_four_megabyte_response_is_not_stalled_by_flow_control`] asks
//! for 4 MB, which is 64 times the default window. Every test here runs under a
//! timeout so that a flow-control bug fails as a failure rather than hanging CI.
//!
//! # Why not through ts2021
//!
//! `micro-h2` is sans-io, so it is driven straight over a `tokio::io::duplex`
//! pipe. Layering it through the Noise record layer first would mean a failure
//! here could be a record-framing bug, and the ts2021 stack is anchored
//! separately by `pcap_replay` and `noise_vs_snow`.
//!
//! # What this file does *not* anchor
//!
//! **`DATA` and `HEADERS` padding.** `h2` never emits padded frames, and neither
//! does Go's HTTP/2 server, so no reference implementation here will produce
//! one. `conn.rs` handles padding and `micro-h2`'s own tests cover it with
//! hand-written frames — which is to say that path remains checked only against
//! our own reading of RFC 7540 section 6.1. It is listed here rather than
//! quietly counted as covered.

use std::time::Duration;

use bytes::Bytes;
use micro_h2::{Connection, Event, FrameHeader, frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Generous enough that a slow machine does not trip it, short enough that a
/// stalled connection fails within a test run rather than at the CI job limit.
const TIMEOUT: Duration = Duration::from_secs(30);

/// h2's default `max_frame_size` is 16 KiB; this holds a whole one with room.
const FRAME_BUFFER: usize = 64 * 1024;

/// Enough for our replies: window updates, settings and ping acknowledgements.
const OUT_BUFFER: usize = 4096;

/// Drives `micro_h2::Connection` over one side of a duplex pipe.
struct Client {
    conn: Connection,
    io: DuplexStream,
    /// Bytes read from the socket but not yet consumed as whole frames.
    pending: Vec<u8>,
}

impl Client {
    async fn start(mut io: DuplexStream) -> Self {
        let mut conn = Connection::new();
        let mut out = [0u8; OUT_BUFFER];
        let n = conn.start(&mut out).expect("preface");
        io.write_all(&out[..n]).await.expect("write preface");
        Self {
            conn,
            io,
            pending: Vec::new(),
        }
    }

    async fn request(&mut self, method: &str, path: &str, body: &[u8]) -> u32 {
        let mut out = vec![0u8; FRAME_BUFFER + body.len()];
        let (stream, n) = self
            .conn
            .request(method, path, "example.test", "http", &[], body, &mut out)
            .expect("request");
        self.io.write_all(&out[..n]).await.expect("write request");
        stream
    }

    /// Read exactly one frame and hand it to `Connection::recv`, flushing
    /// whatever that owes the peer.
    ///
    /// Returns `None` at end of stream. The caller passes a closure rather than
    /// getting an `Event` back because `Event::Data` borrows the frame buffer.
    async fn next_frame<T>(
        &mut self,
        mut handle: impl FnMut(&Event<'_>, &FrameHeader) -> Option<T>,
    ) -> Option<T> {
        loop {
            while self.pending.len() < frame::HEADER_LEN {
                if !self.fill().await {
                    return None;
                }
            }
            let header = FrameHeader::parse(&self.pending).expect("frame header");
            let total = frame::HEADER_LEN + header.length;
            assert!(
                total <= FRAME_BUFFER,
                "h2 sent a {total}-byte frame, larger than our buffer"
            );
            while self.pending.len() < total {
                if !self.fill().await {
                    panic!("the connection ended inside a frame");
                }
            }

            let frame_bytes: Vec<u8> = self.pending.drain(..total).collect();
            let mut out = [0u8; OUT_BUFFER];
            let (event, written) = self
                .conn
                .recv(&frame_bytes, |_, _| {}, &mut out)
                .expect("our connection accepts h2's frame");

            let result = handle(&event, &header);
            if written > 0 {
                // A failed write here is not necessarily a fault: after a GOAWAY
                // the peer is entitled to have closed already, and our reply is
                // then simply undeliverable. Failing the test on it would make
                // the shutdown tests racy.
                let _ = self.io.write_all(&out[..written]).await;
            }
            if let Some(value) = result {
                return Some(value);
            }
        }
    }

    async fn fill(&mut self) -> bool {
        let mut buffer = [0u8; FRAME_BUFFER];
        match self.io.read(&mut buffer).await {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.pending.extend_from_slice(&buffer[..n]);
                true
            }
        }
    }

    /// Read until the given stream ends, returning the body and the headers.
    async fn collect_body(&mut self, stream: u32) -> (Vec<u8>, Vec<(String, String)>) {
        let mut body = Vec::new();
        let mut headers = Vec::new();
        loop {
            let done = self
                .next_frame(|event, _| match event {
                    Event::Data {
                        stream: s,
                        data,
                        end_stream,
                    } if *s == stream => {
                        body.extend_from_slice(data);
                        end_stream.then_some(())
                    }
                    Event::Headers {
                        stream: s,
                        end_stream,
                    } if *s == stream => {
                        headers.push((String::new(), String::new()));
                        end_stream.then_some(())
                    }
                    Event::Reset { stream: s, code } if *s == stream => {
                        panic!("stream {s} was reset with code {code}")
                    }
                    Event::GoAway { code } => panic!("the server went away with code {code}"),
                    _ => None,
                })
                .await;
            if done.is_some() {
                return (body, headers);
            }
        }
    }
}

/// Run an `h2` server on the other end of the pipe.
///
/// `respond` is given the request and returns the response body.
fn serve(
    io: DuplexStream,
    respond: impl Fn(http::Request<h2::RecvStream>) -> (http::Response<()>, Vec<Bytes>)
    + Send
    + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut connection = h2::server::handshake(io)
            .await
            .expect("h2 server handshake");

        while let Some(request) = connection.accept().await {
            let (request, mut sender) = request.expect("accept a stream");
            let (response, chunks) = respond(request);

            // Each response is sent from its own task. `h2::server::Connection`
            // only performs I/O while it is being polled, and `accept()` is what
            // polls it — so blocking here on `poll_capacity` would stop the
            // connection from ever writing the bytes that would grant the
            // capacity being waited for. That deadlock looks exactly like a
            // flow-control bug in the client, which is the failure this file is
            // supposed to be able to distinguish.
            tokio::spawn(async move {
                let mut body = sender.send_response(response, false).expect("send headers");
                for chunk in chunks {
                    let mut remaining = chunk;
                    while !remaining.is_empty() {
                        // The real choke point: capacity only grows when the
                        // peer sends WINDOW_UPDATE, so a client that does not
                        // will park here forever.
                        body.reserve_capacity(remaining.len());
                        let available = std::future::poll_fn(|cx| body.poll_capacity(cx))
                            .await
                            .expect("the peer never granted more capacity")
                            .expect("capacity");
                        let take = available.min(remaining.len());
                        let piece = remaining.split_to(take);
                        body.send_data(piece, false).expect("send data");
                    }
                }
                body.send_data(Bytes::new(), true).expect("end stream");
            });
        }
    })
}

fn ok_response() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(())
        .unwrap()
}

async fn with_timeout<T>(what: &str, future: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(TIMEOUT, future).await {
        Ok(value) => value,
        Err(_) => panic!("{what} did not finish within {TIMEOUT:?} — most likely a stalled window"),
    }
}

// ---------------------------------------------------------------------------

/// A request and a short response, exchanged with a real HTTP/2 server.
///
/// The floor: our preface, SETTINGS, HPACK header block and DATA framing are all
/// acceptable to an implementation that did not write them.
#[tokio::test]
async fn h2_accepts_our_preface_and_answers_our_request() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = serve(server_io, |request| {
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/machine/register");
        (ok_response(), vec![Bytes::from_static(b"{\"MachineAuthorized\":true}")])
    });

    let mut client = Client::start(client_io).await;
    let stream = client.request("POST", "/machine/register", b"{}").await;
    let (body, _) = with_timeout("the register exchange", client.collect_body(stream)).await;

    assert_eq!(body, b"{\"MachineAuthorized\":true}");
    drop(client);
    let _ = server.await;
}

/// The reason this file exists.
///
/// 4 MB is 64 times the 65535-byte default window. Without `WINDOW_UPDATE` at
/// both the connection and stream level, `h2` blocks in `poll_capacity` and this
/// test hits its timeout instead of completing.
#[tokio::test]
async fn a_four_megabyte_response_is_not_stalled_by_flow_control() {
    const SIZE: usize = 4 * 1024 * 1024;
    const _: () = assert!(SIZE > 64 * 65535, "smaller than this and the window never binds");

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = serve(server_io, |_| {
        // A recognisable pattern, so a truncated or misordered body is caught
        // rather than just a wrong length.
        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        (ok_response(), vec![Bytes::from(payload)])
    });

    let mut client = Client::start(client_io).await;
    let stream = client.request("POST", "/machine/map", b"{}").await;
    let (body, _) = with_timeout(
        "the 4 MB transfer",
        client.collect_body(stream),
    )
    .await;

    assert_eq!(body.len(), SIZE, "the transfer stopped short");
    assert!(
        body.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8),
        "the body arrived corrupted or out of order"
    );

    drop(client);
    let _ = server.await;
}

/// The window must be replenished continuously, not once.
///
/// A single large `WINDOW_UPDATE` after the preface would carry the previous
/// test but stall here, because the connection window is consumed across every
/// stream in turn.
#[tokio::test]
async fn several_sequential_streams_each_exceed_the_default_window() {
    const SIZE: usize = 200 * 1024;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = serve(server_io, |_| {
        (ok_response(), vec![Bytes::from(vec![0x5a; SIZE])])
    });

    let mut client = Client::start(client_io).await;
    for round in 0..4 {
        let stream = client.request("POST", "/machine/map", b"{}").await;
        let (body, _) =
            with_timeout(&format!("round {round}"), client.collect_body(stream)).await;
        assert_eq!(body.len(), SIZE, "round {round} stopped short");
        assert!(body.iter().all(|&b| b == 0x5a));
    }

    drop(client);
    let _ = server.await;
}

/// `RST_STREAM` from a real server, with a real error code.
#[tokio::test]
async fn a_reset_from_h2_is_surfaced_with_its_code() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        if let Some(request) = connection.accept().await {
            let (_, mut sender) = request.expect("accept");
            sender.send_reset(h2::Reason::REFUSED_STREAM);
        }
        // The connection only writes while it is polled, so the RST_STREAM would
        // never leave the buffer if this task simply slept here.
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| connection.poll_closed(cx)),
        )
        .await;
    });

    let mut client = Client::start(client_io).await;
    let stream = client.request("POST", "/machine/map", b"{}").await;

    let code = with_timeout("the reset", async {
        client
            .next_frame(|event, _| match event {
                Event::Reset { stream: s, code } if *s == stream => Some(*code),
                _ => None,
            })
            .await
    })
    .await
    .expect("a reset arrived");

    // REFUSED_STREAM is 0x7 in RFC 7540's error code registry.
    assert_eq!(code, u32::from(h2::Reason::REFUSED_STREAM), "the code we read");
    assert_eq!(code, 0x7, "REFUSED_STREAM is 7 on the wire");

    drop(client);
    let _ = server.await;
}

/// `GOAWAY` from a real server.
#[tokio::test]
async fn a_goaway_from_h2_is_surfaced_with_its_code() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.expect("handshake");
        connection.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
        let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
    });

    let mut client = Client::start(client_io).await;
    let _ = client.request("POST", "/machine/map", b"{}").await;

    let code = with_timeout("the goaway", async {
        client
            .next_frame(|event, _| match event {
                Event::GoAway { code } => Some(*code),
                _ => None,
            })
            .await
    })
    .await
    .expect("a goaway arrived");

    assert_eq!(code, u32::from(h2::Reason::ENHANCE_YOUR_CALM));
    assert_eq!(code, 0xb, "ENHANCE_YOUR_CALM is 11 on the wire");

    drop(client);
    let _ = server.await;
}

/// Response headers from `h2`'s HPACK encoder, which indexes freely.
///
/// This is the same dynamic-table path `hpack_differential` covers, reached here
/// through a real server rather than a bare encoder.
#[tokio::test]
async fn response_headers_from_h2s_encoder_decode_correctly() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = serve(server_io, |_| {
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("x-conformance", "a-value-that-is-not-in-the-static-table")
            .header("cache-control", "no-store")
            .body(())
            .unwrap();
        (response, vec![Bytes::from_static(b"{}")])
    });

    let mut client = Client::start(client_io).await;
    let stream = client.request("POST", "/machine/map", b"{}").await;

    let mut seen: Vec<(String, String)> = Vec::new();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        assert!(tokio::time::Instant::now() < deadline, "timed out reading headers");

        // `next_frame` swallows the header callback, so drive one frame here
        // with a callback that records.
        let mut out = [0u8; OUT_BUFFER];
        while client.pending.len() < frame::HEADER_LEN {
            assert!(client.fill().await, "connection closed before headers");
        }
        let header = FrameHeader::parse(&client.pending).unwrap();
        let total = frame::HEADER_LEN + header.length;
        while client.pending.len() < total {
            assert!(client.fill().await, "connection closed mid-frame");
        }
        let bytes: Vec<u8> = client.pending.drain(..total).collect();
        let (event, written) = client
            .conn
            .recv(
                &bytes,
                |name, value| seen.push((name.to_string(), value.to_string())),
                &mut out,
            )
            .expect("recv");
        if written > 0 {
            client.io.write_all(&out[..written]).await.unwrap();
        }
        if matches!(event, Event::Headers { stream: s, .. } if s == stream) {
            break;
        }
    }

    let lookup = |name: &str| {
        seen.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(lookup(":status").as_deref(), Some("200"));
    assert_eq!(lookup("content-type").as_deref(), Some("application/json"));
    assert_eq!(
        lookup("x-conformance").as_deref(),
        Some("a-value-that-is-not-in-the-static-table")
    );
    assert_eq!(lookup("cache-control").as_deref(), Some("no-store"));

    drop(client);
    let _ = server.await;
}
