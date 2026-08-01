//! Replay `tests/vectors/ts2021-session.pcap` through the code that has to
//! interoperate with it.
//!
//! The capture holds a real tailscaled 1.94.2 registering with a real Headscale
//! v0.29.3. Before this file existed the pcap was never opened by anything: its
//! contents had been read once by a human and copied into doc comments. Those
//! comments were right, but a comment cannot fail, so nothing stopped the code
//! and the capture from drifting apart.
//!
//! Every assertion here is answered by bytes a Go implementation put on a wire.
//! Where an assertion is answered by our own code instead, it says so.

use ts_conformance::pcap::Capture;
use ts_keys::MachinePublic;
use ts_noise::ik::{TYPE_INITIATION, TYPE_RESPONSE};
use ts_noise::record::TYPE_RECORD;
use ts_noise::{HEADER_LEN, INITIATION_LEN, MAX_MESSAGE, RESPONSE_LEN, Session, upgrade};

/// The `/key` exchange, on its own short-lived connection.
const KEY_REQUEST: (u16, u16) = (47610, 8080);
const KEY_RESPONSE: (u16, u16) = (8080, 47610);

/// The ts2021 connection: upgrade, handshake, then records both ways.
const SESSION_CLIENT: (u16, u16) = (47622, 8080);
const SESSION_SERVER: (u16, u16) = (8080, 47622);

/// A second, later ts2021 connection. Only the server direction carries records
/// in any volume.
const SECOND_SERVER: (u16, u16) = (8080, 53868);

fn capture() -> Capture {
    Capture::ts2021_session().expect("tests/vectors/ts2021-session.pcap")
}

fn stream(capture: &Capture, (src, dst): (u16, u16)) -> &[u8] {
    let stream = capture
        .stream(src, dst)
        .unwrap_or_else(|| panic!("no stream {src}->{dst} in the capture"));
    assert_eq!(
        stream.gaps(),
        &[],
        "stream {src}->{dst} was reassembled with holes; every assertion \
         downstream of this would be against spliced bytes"
    );
    stream.bytes()
}

// ---------------------------------------------------------------------------
// /key
// ---------------------------------------------------------------------------

#[test]
fn headscales_key_response_parses_and_the_body_offset_is_exact() {
    let capture = capture();
    let response = stream(&capture, KEY_RESPONSE);

    let parsed = upgrade::parse_response(response).expect("parse the /key response");
    assert_eq!(parsed.status, 200);

    // `header_len` must land exactly on the `{`. One byte out and the JSON scan
    // starts on a newline or eats the brace.
    assert_eq!(
        response[parsed.header_len], b'{',
        "header_len did not land on the start of the body"
    );

    let body = &response[parsed.header_len..];
    // Headscale advertises the length; it must agree with what parse_response left.
    let declared: usize = std::str::from_utf8(response)
        .unwrap()
        .split("Content-Length: ")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .and_then(|n| n.parse().ok())
        .expect("Content-Length");
    assert_eq!(body.len(), declared, "body length disagrees with Content-Length");
    assert_eq!(declared, 176, "Headscale v0.29.3 sends a 176-byte /key body");

    // The trailing newline is Go's json.Encoder, not an accident, and a parser
    // that assumes the body ends at `}` would be reading a different length than
    // Content-Length promised.
    assert_eq!(*body.last().unwrap(), b'\n');
}

#[test]
fn the_published_machine_key_parses_with_ts_keys() {
    let capture = capture();
    let response = stream(&capture, KEY_RESPONSE);
    let parsed = upgrade::parse_response(response).unwrap();
    let body = std::str::from_utf8(&response[parsed.header_len..]).unwrap();

    let value: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
    let published = value["publicKey"].as_str().expect("publicKey");
    let key = MachinePublic::parse(published).expect("ts-keys parses Headscale's mkey:");

    // Round-tripping proves our encoder agrees with the server's, not merely
    // that our decoder accepted something.
    let mut out = [0u8; 128];
    assert_eq!(key.encode(&mut out).unwrap(), published);
}

/// The ordering hazard in Headscale's real body, and how narrowly it is missed.
///
/// `legacyPublicKey` is emitted *first* and ends in the letters `PublicKey`. A
/// case-sensitive search for `publicKey` misses it — but only because Go
/// capitalised the `P`. A case-insensitive scan, or a server that ever renames
/// the field to `legacypublickey`, finds the legacy key instead: all zeroes in
/// this capture, so the handshake would run against a key that is not merely
/// wrong but invalid.
///
/// The safe needle is `"publicKey"` including the opening quote, which is
/// anchored to a field boundary rather than to a capitalisation accident.
#[test]
fn the_legacy_key_is_emitted_first_and_the_needle_must_be_quote_anchored() {
    let capture = capture();
    let response = stream(&capture, KEY_RESPONSE);
    let parsed = upgrade::parse_response(response).unwrap();
    let body = std::str::from_utf8(&response[parsed.header_len..]).unwrap();

    let legacy = body.find("legacyPublicKey").expect("legacyPublicKey is present");
    let quoted = body.find("\"publicKey\"").expect("\"publicKey\" is present");
    assert!(legacy < quoted, "the legacy key comes first in the real body");

    // Case-sensitively, the bare needle is safe here: its first hit is the same
    // field, one byte past the opening quote.
    assert_eq!(body.find("publicKey"), Some(quoted + 1));
    // Case-insensitively it is not — this is the near miss.
    let lowered = body.to_ascii_lowercase();
    assert!(
        lowered.find("publickey").unwrap() < lowered.find("\"publickey\"").unwrap(),
        "a case-insensitive scan would land inside legacyPublicKey"
    );

    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        value["legacyPublicKey"].as_str().unwrap(),
        "mkey:0000000000000000000000000000000000000000000000000000000000000000",
        "the legacy key is all zeroes, so mistaking it for the real one \
         produces an invalid public key rather than a wrong-but-usable one"
    );
}

#[test]
fn our_key_request_matches_the_one_the_go_client_sent() {
    let capture = capture();
    let sent = stream(&capture, KEY_REQUEST);
    let sent = std::str::from_utf8(sent).unwrap();

    let mut out = [0u8; upgrade::MAX_REQUEST];
    let ours = upgrade::write_key_request("127.0.0.1:8080", &mut out).unwrap();
    let ours = std::str::from_utf8(ours).unwrap();

    // The request line is the part that has to match; User-Agent is ours to pick.
    assert_eq!(
        sent.lines().next().unwrap(),
        ours.lines().next().unwrap(),
        "our request line differs from tailscaled's"
    );
    assert!(sent.contains("Host: 127.0.0.1:8080\r\n"));
    assert!(ours.contains("Host: 127.0.0.1:8080\r\n"));
}

// ---------------------------------------------------------------------------
// The initiation
// ---------------------------------------------------------------------------

/// The initiation travels base64 in the `X-Tailscale-Handshake` request header,
/// not in the TCP body. The body immediately after the blank line is already the
/// client's first *record*.
fn captured_initiation(capture: &Capture) -> Vec<u8> {
    let request = stream(capture, SESSION_CLIENT);
    let head_end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .expect("the request headers end somewhere");

    let text = std::str::from_utf8(&request[..head_end]).unwrap();
    let encoded = text
        .split("X-Tailscale-Handshake: ")
        .nth(1)
        .and_then(|rest| rest.split("\r\n").next())
        .expect("the capture carries the handshake in a header");
    decode_base64(encoded)
}

#[test]
fn the_initiation_is_carried_in_a_header_and_the_body_starts_with_a_record() {
    let capture = capture();
    let request = stream(&capture, SESSION_CLIENT);
    let head_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    // The doc comment in ik.rs used to imply the initiation was in the body.
    // It is not: the first body byte is a record header.
    assert_eq!(
        request[head_end], TYPE_RECORD,
        "the byte after the blank line is the client's first record, \
         not the initiation"
    );
}

#[test]
fn the_captured_initiation_agrees_with_our_constants() {
    let capture = capture();
    let initiation = captured_initiation(&capture);

    assert_eq!(initiation.len(), 101);
    assert_eq!(initiation.len(), INITIATION_LEN);
    assert_eq!(u16::from_be_bytes([initiation[0], initiation[1]]), 131);
    assert_eq!(initiation[2], TYPE_INITIATION);

    // The wire's own length field, agreeing with our constant independently of
    // it: the message declares 96 bytes of body and is 101 bytes long.
    let declared = u16::from_be_bytes([initiation[3], initiation[4]]) as usize;
    assert_eq!(declared, 96);
    assert_eq!(5 + declared, initiation.len());
    assert_eq!(5 + declared, INITIATION_LEN);
}

/// Re-encoding the captured initiation must reproduce the captured header byte
/// for byte.
///
/// This replaces a hand-transcribed base64 literal that used to live in
/// `upgrade.rs`. Reading it from the pcap means a re-capture cannot leave a
/// stale anchor behind.
#[test]
fn our_upgrade_request_reproduces_the_captured_handshake_header() {
    let capture = capture();
    let request = stream(&capture, SESSION_CLIENT);
    let head_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let text = std::str::from_utf8(&request[..head_end]).unwrap();
    let captured_header = text
        .split("\r\n")
        .find(|line| line.starts_with("X-Tailscale-Handshake: "))
        .unwrap();

    let initiation = captured_initiation(&capture);
    let mut out = [0u8; upgrade::MAX_REQUEST];
    let ours = upgrade::write_upgrade_request("127.0.0.1:8080", &initiation, &mut out).unwrap();
    let ours = std::str::from_utf8(ours).unwrap();

    assert!(
        ours.contains(captured_header),
        "our base64 of the captured initiation does not reproduce the \
         captured header:\n  captured: {captured_header}\n  ours:     {}",
        ours.split("\r\n")
            .find(|l| l.starts_with("X-Tailscale-Handshake: "))
            .unwrap()
    );
    // Padding specifically: Go's StdEncoding pads, and Headscale refuses unpadded.
    assert!(captured_header.ends_with('='));

    // The header is exactly as long as our constant says a base64'd initiation is.
    let encoded_len = captured_header.len() - "X-Tailscale-Handshake: ".len();
    assert_eq!(encoded_len, upgrade::HANDSHAKE_HEADER_LEN);
}

#[test]
fn the_upgrade_response_is_recognised_and_the_noise_response_follows_it() {
    let capture = capture();
    let response = stream(&capture, SESSION_SERVER);

    let parsed = upgrade::parse_response(response).unwrap();
    assert_eq!(parsed.status, 101);
    assert!(upgrade::is_upgrade(response, parsed));

    // The very next byte begins the Noise response: type 2, 48-byte body.
    let body = &response[parsed.header_len..];
    assert_eq!(body[0], TYPE_RESPONSE);
    assert_eq!(u16::from_be_bytes([body[1], body[2]]), 48);
    assert_eq!(3 + 48, RESPONSE_LEN);
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

/// Segment a byte stream into `(type, body_len)` using the framing rules under
/// test, returning what is left over.
///
/// Only the length arithmetic is test-local; the decision about whether a header
/// is acceptable, and how long its body is, comes from
/// [`Session::ciphertext_len`].
fn frame(mut bytes: &[u8]) -> (Vec<(u8, usize)>, usize) {
    let mut records = Vec::new();
    loop {
        if bytes.len() < HEADER_LEN {
            return (records, bytes.len());
        }
        let Ok(len) = Session::ciphertext_len(&bytes[..HEADER_LEN]) else {
            return (records, bytes.len());
        };
        if bytes.len() < HEADER_LEN + len {
            return (records, bytes.len());
        }
        records.push((bytes[0], len));
        bytes = &bytes[HEADER_LEN + len..];
    }
}

#[test]
fn the_client_stream_is_fifteen_records_and_nothing_left_over() {
    let capture = capture();
    let request = stream(&capture, SESSION_CLIENT);
    let head_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    let (records, trailing) = frame(&request[head_end..]);
    assert_eq!(records.len(), 15);
    assert_eq!(
        trailing, 0,
        "the framer must consume the client stream exactly; leftover bytes \
         mean a length was misread somewhere earlier"
    );
    assert!(records.iter().all(|&(t, _)| t == TYPE_RECORD));

    let longest = records.iter().map(|&(_, l)| l).max().unwrap();
    assert_eq!(longest, 1281);
    assert!(HEADER_LEN + longest < MAX_MESSAGE);
}

#[test]
fn the_server_stream_is_a_handshake_response_then_twenty_records() {
    let capture = capture();
    let response = stream(&capture, SESSION_SERVER);
    let parsed = upgrade::parse_response(response).unwrap();
    let body = &response[parsed.header_len..];

    // The Noise response is type 2 and is not a record; skip it by its own
    // constant, then everything after must frame as records.
    assert_eq!(body[0], TYPE_RESPONSE);
    let (records, trailing) = frame(&body[RESPONSE_LEN..]);

    assert_eq!(records.len(), 20);
    assert_eq!(trailing, 0);
    assert!(records.iter().all(|&(t, _)| t == TYPE_RECORD));

    // MAX_MESSAGE = 4096 has headroom over what a real server sent, rather than
    // being a number picked to fit.
    let longest = records.iter().map(|&(_, l)| l).max().unwrap();
    assert_eq!(longest, 1705);
    assert!(
        HEADER_LEN + longest < MAX_MESSAGE,
        "a real server sent {longest} bytes of ciphertext against a {MAX_MESSAGE}-byte limit"
    );
}

/// The framing must not depend on how the bytes were delivered.
///
/// TCP segment boundaries and record boundaries are unrelated — the capture
/// already shows 15 client records arriving in 16 segments — so a framer that
/// works only when a whole record is present in one buffer would pass every
/// test that hands it a complete stream.
#[test]
fn segmentation_is_identical_at_every_chunk_size() {
    let capture = capture();
    let response = stream(&capture, SESSION_SERVER);
    let parsed = upgrade::parse_response(response).unwrap();
    let all = &response[parsed.header_len + RESPONSE_LEN..];

    let (expected, _) = frame(all);

    for chunk in [1usize, 3, 7, 512] {
        let mut pending: Vec<u8> = Vec::new();
        let mut records: Vec<(u8, usize)> = Vec::new();

        for piece in all.chunks(chunk) {
            pending.extend_from_slice(piece);
            loop {
                if pending.len() < HEADER_LEN {
                    break;
                }
                let Ok(len) = Session::ciphertext_len(&pending[..HEADER_LEN]) else {
                    panic!("chunk size {chunk}: a header the whole-stream framer accepted was refused");
                };
                if pending.len() < HEADER_LEN + len {
                    break;
                }
                records.push((pending[0], len));
                pending.drain(..HEADER_LEN + len);
            }
        }
        assert!(pending.is_empty(), "chunk size {chunk} left {} bytes", pending.len());
        assert_eq!(
            records, expected,
            "chunk size {chunk} segmented the same bytes differently"
        );
    }
}

/// A second connection, framed with the same rules and no HTTP prelude.
#[test]
fn the_second_connections_server_stream_also_frames_exactly() {
    let capture = capture();
    let bytes = stream(&capture, SECOND_SERVER);

    let (records, trailing) = frame(bytes);
    assert_eq!(records.len(), 7);
    assert_eq!(trailing, 0);
    assert!(records.iter().all(|&(t, _)| t == TYPE_RECORD));
}

/// The negative: a stream that starts part-way into a record must be refused,
/// not mis-segmented into plausible-looking garbage.
///
/// This is built by offsetting a real stream rather than taken from the capture
/// directly. The second connection was expected to supply this for free, but it
/// turns out to begin cleanly on a record boundary, so the case has to be
/// constructed.
#[test]
fn a_stream_beginning_mid_record_is_refused_rather_than_mis_segmented() {
    let capture = capture();
    let bytes = stream(&capture, SECOND_SERVER);

    let (whole, _) = frame(bytes);
    let mut refused = 0;
    let mut mis_segmented = Vec::new();

    // Every offset inside the first record's body.
    for skip in 1..=whole[0].1 {
        let (records, trailing) = frame(&bytes[skip..]);
        let consumed_everything = trailing == 0;
        if records.is_empty() {
            refused += 1;
        } else if consumed_everything {
            mis_segmented.push(skip);
        }
    }

    assert!(
        mis_segmented.is_empty(),
        "offsets {mis_segmented:?} framed cleanly to the end of the stream \
         despite starting mid-record — the framer cannot tell it is lost"
    );
    assert!(
        refused > 0,
        "no mid-record offset was refused outright; the type-byte and length \
         checks are doing nothing"
    );
}

// ---------------------------------------------------------------------------
// Early payload
// ---------------------------------------------------------------------------

/// The server sends three short records before anything else, and their
/// plaintext lengths are what `early.rs` is sized around. Until now that was a
/// comment.
#[test]
fn the_first_three_server_records_are_the_early_payload_sizes() {
    const TAG_LEN: usize = 16;
    let capture = capture();
    let response = stream(&capture, SESSION_SERVER);
    let parsed = upgrade::parse_response(response).unwrap();
    let (records, _) = frame(&response[parsed.header_len + RESPONSE_LEN..]);

    let ciphertexts: Vec<usize> = records.iter().take(3).map(|&(_, l)| l).collect();
    assert_eq!(ciphertexts, vec![21, 20, 111]);

    let plaintexts: Vec<usize> = ciphertexts.iter().map(|l| l - TAG_LEN).collect();
    assert_eq!(plaintexts, vec![5, 4, 95]);

    // The first plaintext is exactly the early-payload magic; the second is the
    // 4-byte length that follows it.
    assert_eq!(plaintexts[0], ts_noise::EARLY_MAGIC.len());
    assert_eq!(plaintexts[0] + plaintexts[1], ts_noise::PROBE_LEN);
    assert!(plaintexts[2] <= ts_noise::early::MAX_PAYLOAD);
}

// ---------------------------------------------------------------------------

fn decode_base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        if c == b'=' {
            break;
        }
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("not base64: {c:?}")) as u32;
        accumulator = accumulator << 6 | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    out
}
