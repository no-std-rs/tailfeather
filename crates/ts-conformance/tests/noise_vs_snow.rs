//! `ts-noise`'s Noise IK against `snow`, an implementation that passes the Noise
//! specification's own test vectors.
//!
//! This is the largest self-referential gap in the suite closed. Every other
//! test of the handshake compared our encoder to our decoder: it would pass with
//! the prologue omitted, with the mixes in the wrong order, or with the
//! ephemeral mixed into the chaining key — as long as both ends made the same
//! mistake. A real Headscale would reject all three, and the capture cannot help
//! because the handshake it contains is sealed under keys nobody kept.
//!
//! # Why byte equality is available at all
//!
//! ts2021 prefixes its own 5-byte header (`version ‖ type ‖ length`) to the Noise
//! message, and that header is **not** mixed into the transcript. So the mapping
//! is exact rather than approximate:
//!
//! ```text
//! snow's message 1  ==  our initiation[5..101]
//! ```
//!
//! Equality of 96 bytes, not "both were accepted". A single wrong byte anywhere
//! in the hash chain changes the sealed static key and the trailing tag.
//!
//! # What each test anchors
//!
//! Between them the equality tests pin, against an outside party: the 33-byte
//! protocol name being hashed rather than zero-padded; the prologue being mixed
//! before the responder's static key; the `e`-hashed-but-not-mixed rule that
//! `ik.rs` calls the easiest mistake to make; both Diffie-Hellman placements;
//! and the empty-but-still-sealed payload.

use snow::Builder;
use ts_noise::ik::{TYPE_INITIATION, TYPE_RESPONSE};
use ts_noise::{CAPABILITY_VERSION, HEADER_LEN, INITIATION_LEN, RESPONSE_LEN, initiate};
use x25519_dalek::{PublicKey, StaticSecret};

/// The parameter string ts2021 uses. snow parses this into the same primitives
/// `ts-noise` hard-codes.
const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn prologue(version: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{version}").into_bytes()
}

/// Three key triples: `(machine private, server private, client ephemeral)`.
///
/// Server *private*, because snow needs it to act as responder. Fixed rather
/// than random so a failure is reproducible and so the frozen vectors below are
/// stable.
const TRIPLES: &[([u8; 32], [u8; 32], [u8; 32])] = &[
    ([0x11; 32], [0x22; 32], [0x33; 32]),
    ([0x01; 32], [0xfe; 32], [0x7f; 32]),
    ([0xa5; 32], [0x5a; 32], [0xc3; 32]),
    // A machine key whose clamped and unclamped forms differ in both the low
    // three bits and the top two, so a disagreement about clamping shows up.
    ([0xff; 32], [0x00; 32], [0x80; 32]),
];

struct Triple {
    machine: StaticSecret,
    server_private: StaticSecret,
    server_public: PublicKey,
    ephemeral: StaticSecret,
}

fn triples() -> Vec<Triple> {
    TRIPLES
        .iter()
        .map(|&(m, s, e)| {
            let server_private = StaticSecret::from(s);
            Triple {
                machine: StaticSecret::from(m),
                server_public: PublicKey::from(&server_private),
                server_private,
                ephemeral: StaticSecret::from(e),
            }
        })
        .collect()
}

/// Our initiation, header and all.
fn our_initiation(t: &Triple) -> [u8; INITIATION_LEN] {
    let mut out = [0u8; INITIATION_LEN];
    let (len, _) = initiate(&t.machine, &t.server_public, &t.ephemeral, &mut out)
        .expect("our initiate() succeeds");
    assert_eq!(len, INITIATION_LEN);
    out
}

/// snow's message 1 for the same inputs: the 96 Noise bytes, no ts2021 header.
fn snow_initiation(t: &Triple, prologue: &[u8], params: &str) -> Vec<u8> {
    let machine = t.machine.to_bytes();
    let ephemeral = t.ephemeral.to_bytes();
    let server = t.server_public.to_bytes();

    let mut state = Builder::new(params.parse().expect("snow parses the params"))
        .prologue(prologue)
        .unwrap()
        .local_private_key(&machine)
        .unwrap()
        .remote_public_key(&server)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&ephemeral)
        .build_initiator()
        .expect("snow builds an IK initiator");

    let mut buffer = [0u8; 256];
    let len = state
        .write_message(&[], &mut buffer)
        .expect("snow writes message 1");
    buffer[..len].to_vec()
}

// ---------------------------------------------------------------------------
// Byte equality
// ---------------------------------------------------------------------------

#[test]
fn our_initiation_is_byte_equal_to_snows() {
    for (i, t) in triples().iter().enumerate() {
        let ours = our_initiation(t);
        let theirs = snow_initiation(t, &prologue(CAPABILITY_VERSION), PARAMS);

        assert_eq!(theirs.len(), 96, "triple {i}: snow's message 1 is 96 bytes");
        assert_eq!(
            &ours[5..],
            &theirs[..],
            "triple {i}: our Noise payload differs from snow's.\n  ours:  {}\n  snow:  {}",
            hex::encode(&ours[5..]),
            hex::encode(&theirs)
        );

        // The ts2021 header sits in front and is not part of the transcript.
        assert_eq!(u16::from_be_bytes([ours[0], ours[1]]), CAPABILITY_VERSION);
        assert_eq!(ours[2], TYPE_INITIATION);
        assert_eq!(u16::from_be_bytes([ours[3], ours[4]]) as usize, theirs.len());
    }
}

// ---------------------------------------------------------------------------
// Negative controls
//
// Byte equality is only evidence if unequal inputs produce unequal output. Each
// of these perturbs exactly one documented decision and asserts the bytes move.
// ---------------------------------------------------------------------------

#[test]
fn a_different_prologue_version_produces_different_bytes() {
    for t in triples().iter() {
        let ours = our_initiation(t);
        let downgraded = snow_initiation(t, &prologue(130), PARAMS);
        assert_ne!(
            &ours[5..],
            &downgraded[..],
            "v130 and v131 produced identical handshakes, so the prologue is \
             not reaching the transcript and the version is not bound to it"
        );
    }
}

#[test]
fn omitting_the_prologue_entirely_produces_different_bytes() {
    for t in triples().iter() {
        let ours = our_initiation(t);
        let none = snow_initiation(t, b"", PARAMS);
        assert_ne!(&ours[5..], &none[..]);
    }
}

/// The protocol name is hashed into the initial state, so changing the hash
/// function named in it must change every subsequent byte.
///
/// This is also what pins the 33-byte-name rule: Noise zero-pads a name of 32
/// bytes or fewer and hashes anything longer, and `Noise_IK_25519_ChaChaPoly_BLAKE2s`
/// is 33. If we padded where snow hashes, no output would ever agree.
#[test]
fn a_different_protocol_name_produces_different_bytes() {
    for t in triples().iter() {
        let ours = our_initiation(t);
        let sha256 = snow_initiation(t, &prologue(CAPABILITY_VERSION), "Noise_IK_25519_ChaChaPoly_SHA256");
        assert_ne!(&ours[5..], &sha256[..]);
    }
    assert_eq!(PARAMS.len(), 33, "the name is one byte past the padding boundary");
}

/// Different static keys must give different sealed blobs. Guards against the
/// degenerate failure where both implementations emit a constant.
#[test]
fn different_key_material_produces_different_bytes() {
    let all = triples();
    let outputs: Vec<[u8; INITIATION_LEN]> = all.iter().map(our_initiation).collect();
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(outputs[i], outputs[j], "triples {i} and {j} collided");
        }
    }
    // And nothing is all-zero, which equality against an equally broken snow
    // could not rule out on its own.
    assert!(outputs.iter().all(|o| o[5..].iter().any(|&b| b != 0)));
}

// ---------------------------------------------------------------------------
// snow as the responder
// ---------------------------------------------------------------------------

/// snow accepts our initiation, recovers our machine key from the sealed blob,
/// and its reply is accepted by `consume_response`.
///
/// This is the first handshake this crate has ever completed against a
/// counterpart that is not itself.
#[test]
fn snow_accepts_our_initiation_and_we_accept_its_reply() {
    for (i, t) in triples().iter().enumerate() {
        let ours = our_initiation(t);
        let (_, handshake) = {
            let mut out = [0u8; INITIATION_LEN];
            initiate(&t.machine, &t.server_public, &t.ephemeral, &mut out).unwrap()
        };

        let server_private = t.server_private.to_bytes();
        let mut responder = Builder::new(PARAMS.parse().unwrap())
            .prologue(&prologue(CAPABILITY_VERSION))
            .unwrap()
            .local_private_key(&server_private)
            .unwrap()
            .build_responder()
            .expect("snow builds an IK responder");

        // The 5-byte ts2021 header is stripped: it is framing, not transcript.
        let mut payload = [0u8; 256];
        let read = responder
            .read_message(&ours[5..], &mut payload)
            .unwrap_or_else(|e| panic!("triple {i}: snow rejected our initiation: {e}"));
        assert_eq!(read, 0, "the sealed payload is empty");

        // Identity hiding, verified from the outside: our machine key was not in
        // the clear, and snow recovered it by decrypting.
        let recovered = responder.get_remote_static().expect("snow recovered a static key");
        let expected = PublicKey::from(&t.machine);
        assert_eq!(recovered, expected.as_bytes(), "triple {i}: wrong machine key recovered");
        assert!(
            !ours[5..].windows(32).any(|w| w == expected.as_bytes()),
            "triple {i}: the machine key appears in the clear in the initiation"
        );

        // snow's reply, framed the way Headscale frames it.
        let mut reply = [0u8; 256];
        let reply_len = responder.write_message(&[], &mut reply).unwrap();
        assert_eq!(reply_len, 48, "triple {i}: the IK response body is 48 bytes");

        let mut framed = [0u8; RESPONSE_LEN];
        framed[0] = TYPE_RESPONSE;
        framed[1..3].copy_from_slice(&(reply_len as u16).to_be_bytes());
        framed[3..].copy_from_slice(&reply[..reply_len]);
        assert_eq!(&framed[..3], &[0x02, 0x00, 0x30], "the captured response header");

        handshake
            .consume_response(&framed)
            .unwrap_or_else(|e| panic!("triple {i}: we rejected snow's response: {e}"));
    }
}

// ---------------------------------------------------------------------------
// The record nonce, anchored externally
// ---------------------------------------------------------------------------

/// ts2021's record nonce is big-endian; the Noise specification's is
/// little-endian, and snow implements the specification.
///
/// `record.rs` states this in prose and its own test only proves our encoder and
/// our decoder agree. Here the two conventions are separated by an outside
/// implementation: snow's transport keys open our counter-0 record, refuse our
/// counter-1 record, and open a hand-built little-endian one. That triple is
/// what makes the claim a fact rather than a comment.
#[test]
fn the_record_counter_is_big_endian_where_noises_is_little_endian() {
    let t = &triples()[0];

    // Complete the handshake both ways so both sides hold the same Split output.
    let ours = our_initiation(t);
    let (_, handshake) = {
        let mut out = [0u8; INITIATION_LEN];
        initiate(&t.machine, &t.server_public, &t.ephemeral, &mut out).unwrap()
    };
    let server_private = t.server_private.to_bytes();
    let mut responder = Builder::new(PARAMS.parse().unwrap())
        .prologue(&prologue(CAPABILITY_VERSION))
        .unwrap()
        .local_private_key(&server_private)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut scratch = [0u8; 256];
    responder.read_message(&ours[5..], &mut scratch).unwrap();
    let mut reply = [0u8; 256];
    let reply_len = responder.write_message(&[], &mut reply).unwrap();

    let mut framed = [0u8; RESPONSE_LEN];
    framed[0] = TYPE_RESPONSE;
    framed[1..3].copy_from_slice(&(reply_len as u16).to_be_bytes());
    framed[3..].copy_from_slice(&reply[..reply_len]);
    let mut session = handshake.consume_response(&framed).unwrap();

    // snow's Split(), taken from the very responder we just handshook with —
    // its ephemeral is random, so re-running the handshake would produce a
    // different session and compare nothing.
    //
    // The first key is the initiator's sending key: the convention `ik.rs`
    // asserts and could not previously demonstrate.
    let (initiator_to_responder, responder_to_initiator) = responder.dangerously_get_raw_split();

    // Record 0: the conventions agree, so snow must open it.
    let mut record = [0u8; 128];
    let len = session.seal(b"counter zero", &mut record).unwrap();
    let body = &record[HEADER_LEN..len];
    assert_eq!(
        open_chacha(&initiator_to_responder, &nonce_be(0), body).as_deref(),
        Some(&b"counter zero"[..]),
        "snow's Split() output did not open our first record — either the key \
         schedule or the initiator-sends-first-key convention is wrong"
    );

    // Record 1: the conventions diverge. Our big-endian record must NOT open
    // under the little-endian nonce snow's transport layer would use...
    let len = session.seal(b"counter one", &mut record).unwrap();
    let body = &record[HEADER_LEN..len].to_vec();
    assert!(
        open_chacha(&initiator_to_responder, &nonce_le(1), body).is_none(),
        "our counter-1 record opened under a little-endian nonce, which means \
         we are following the Noise specification rather than ts2021"
    );
    // ...and must open under the big-endian one.
    assert_eq!(
        open_chacha(&initiator_to_responder, &nonce_be(1), body).as_deref(),
        Some(&b"counter one"[..])
    );

    // The mirror image: a record built by hand with a little-endian counter must
    // be refused by our reader. Sealed under the *receive* key — snow's second
    // Split() output — so it reaches the AEAD rather than failing on the key.
    let client_rx = responder_to_initiator;

    let mut le_record = vec![0u8; HEADER_LEN];
    let sealed = seal_chacha(&client_rx, &nonce_le(1), b"little endian");
    le_record[0] = ts_noise::record::TYPE_RECORD;
    le_record[1..3].copy_from_slice(&(sealed.len() as u16).to_be_bytes());
    le_record.extend_from_slice(&sealed);

    let mut plain = [0u8; 128];
    // Advance our receive counter to 1 by feeding a correct record first.
    let first = seal_chacha(&client_rx, &nonce_be(0), b"first");
    session.open(&first, &mut plain).expect("counter 0 opens");
    assert!(
        session.open(&le_record[HEADER_LEN..], &mut plain).is_err(),
        "we accepted a little-endian record at counter 1"
    );
}

fn nonce_be(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn nonce_le(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// ChaCha20-Poly1305 open, via `wg-core`'s primitives, with the nonce supplied
/// explicitly rather than derived from a counter.
fn open_chacha(key: &[u8; 32], nonce: &[u8; 12], body: &[u8]) -> Option<Vec<u8>> {
    let (ciphertext, tag) = body.split_at(body.len() - 16);
    let mut plaintext = ciphertext.to_vec();
    wg_core::crypto::aead_open_nonce(key, nonce, &[], &mut plaintext, tag).ok()?;
    Some(plaintext)
}

fn seal_chacha(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    let tag = wg_core::crypto::aead_seal_nonce(key, nonce, &[], &mut out);
    out.extend_from_slice(&tag);
    out
}

// ---------------------------------------------------------------------------
// The frozen vector
// ---------------------------------------------------------------------------

/// Regenerate `tests/vectors/noise-ik.json` from the byte-equal outputs above.
///
/// Run with `--ignored` after a deliberate change. `ts-noise`'s own `kat` test
/// reads the file, which gives that crate an external anchor without taking a
/// dev-dependency on `snow`.
#[test]
#[ignore = "writes tests/vectors/noise-ik.json; run deliberately"]
fn regenerate_the_frozen_vectors() {
    let mut entries = Vec::new();
    for t in triples().iter() {
        let ours = our_initiation(t);
        let theirs = snow_initiation(t, &prologue(CAPABILITY_VERSION), PARAMS);
        assert_eq!(&ours[5..], &theirs[..], "refusing to freeze a disagreement");
        entries.push(serde_json::json!({
            "machine_private":   hex::encode(t.machine.to_bytes()),
            "server_public":     hex::encode(t.server_public.to_bytes()),
            "ephemeral_private": hex::encode(t.ephemeral.to_bytes()),
            "initiation":        hex::encode(ours),
        }));
    }

    let document = serde_json::json!({
        "_comment": "Noise IK initiations for ts2021, byte-equal to snow 0.10.0's \
                     message 1 with the ts2021 5-byte header prefixed. Regenerate with \
                     `cargo test -p ts-conformance --test noise_vs_snow -- --ignored`.",
        "protocol":           PARAMS,
        "prologue":           format!("Tailscale Control Protocol v{CAPABILITY_VERSION}"),
        "capability_version": CAPABILITY_VERSION,
        "generated_by":       "snow 0.10.0",
        "vectors":            entries,
    });

    let path = ts_conformance::pcap::vector_path("noise-ik.json");
    std::fs::write(&path, format!("{:#}\n", document)).expect("write the vector file");
    eprintln!("wrote {}", path.display());
}

/// The committed vectors still describe what the code produces.
///
/// Duplicated deliberately in `ts-noise`'s own test suite: there it runs without
/// `snow`, here it runs beside the generator that produced the file.
#[test]
fn the_frozen_vectors_match_what_we_produce() {
    let path = ts_conformance::pcap::vector_path("noise-ik.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} — run the regenerate test", path.display()));
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert_eq!(document["protocol"].as_str().unwrap(), PARAMS);
    assert_eq!(
        document["capability_version"].as_u64().unwrap(),
        CAPABILITY_VERSION as u64
    );

    let vectors = document["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 3, "at least three key triples");

    for (i, vector) in vectors.iter().enumerate() {
        let machine = StaticSecret::from(hex32(&vector["machine_private"]));
        let server = PublicKey::from(hex32(&vector["server_public"]));
        let ephemeral = StaticSecret::from(hex32(&vector["ephemeral_private"]));

        let mut out = [0u8; INITIATION_LEN];
        initiate(&machine, &server, &ephemeral, &mut out).unwrap();
        assert_eq!(
            hex::encode(out),
            vector["initiation"].as_str().unwrap(),
            "frozen vector {i} no longer matches"
        );
    }
}

fn hex32(value: &serde_json::Value) -> [u8; 32] {
    let bytes = hex::decode(value.as_str().expect("hex string")).expect("valid hex");
    bytes.try_into().expect("32 bytes")
}
