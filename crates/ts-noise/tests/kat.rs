//! Known-answer tests for the Noise IK initiation.
//!
//! The answers in `tests/vectors/noise-ik.json` were produced by `snow`, an
//! independent Noise implementation that passes the specification's own vectors,
//! and were verified byte-for-byte against this crate's output when the file was
//! written — see `ts-conformance`'s `noise_vs_snow` test, which both generates
//! the file and re-checks the agreement on every run.
//!
//! This file exists so that `ts-noise` keeps that anchor without depending on
//! `snow`. Running `cargo test -p ts-noise` alone still compares against bytes
//! this crate did not produce.
//!
//! If these fail, the handshake has changed. That is either a bug or a
//! deliberate protocol change, and in the second case the vectors are
//! regenerated with:
//!
//! ```sh
//! cargo test -p ts-conformance --test noise_vs_snow -- --ignored
//! ```
//!
//! Regenerating without checking that `noise_vs_snow` still passes would replace
//! an external anchor with our own output, which is the failure mode the whole
//! vector file exists to prevent.

use ts_noise::{CAPABILITY_VERSION, INITIATION_LEN, initiate};
use x25519_dalek::{PublicKey, StaticSecret};

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/noise-ik.json");
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("valid JSON")
}

fn hex32(value: &serde_json::Value) -> [u8; 32] {
    hex::decode(value.as_str().expect("hex string"))
        .expect("valid hex")
        .try_into()
        .expect("32 bytes")
}

#[test]
fn every_initiation_matches_the_reference_bytes() {
    let document = vectors();
    let entries = document["vectors"].as_array().expect("vectors");
    assert!(entries.len() >= 3, "at least three key triples");

    for (i, vector) in entries.iter().enumerate() {
        let machine = StaticSecret::from(hex32(&vector["machine_private"]));
        let server = PublicKey::from(hex32(&vector["server_public"]));
        let ephemeral = StaticSecret::from(hex32(&vector["ephemeral_private"]));

        let mut out = [0u8; INITIATION_LEN];
        let (len, _) = initiate(&machine, &server, &ephemeral, &mut out).expect("initiate");
        assert_eq!(len, INITIATION_LEN);

        assert_eq!(
            hex::encode(out),
            vector["initiation"].as_str().unwrap(),
            "vector {i}: this crate no longer reproduces snow's message 1"
        );
    }
}

/// The file must describe the protocol this crate actually speaks.
///
/// Without this, a change to `CAPABILITY_VERSION` would leave the vectors
/// describing a prologue nobody sends any more, and the test above would keep
/// passing only because the vectors were regenerated to match.
#[test]
fn the_vectors_describe_the_protocol_this_crate_speaks() {
    let document = vectors();
    assert_eq!(
        document["protocol"].as_str().unwrap(),
        "Noise_IK_25519_ChaChaPoly_BLAKE2s"
    );
    assert_eq!(
        document["capability_version"].as_u64().unwrap(),
        CAPABILITY_VERSION as u64,
        "the vectors were generated for a different capability version"
    );
    assert_eq!(
        document["prologue"].as_str().unwrap(),
        format!("Tailscale Control Protocol v{CAPABILITY_VERSION}")
    );
    assert!(
        document["generated_by"]
            .as_str()
            .unwrap()
            .starts_with("snow "),
        "the vectors must record which outside implementation produced them"
    );
}

/// A sanity check that the vectors are not degenerate.
///
/// A file of all-zero initiations would satisfy the test above after any
/// regeneration.
#[test]
fn the_vectors_are_distinct_and_well_formed() {
    let document = vectors();
    let entries = document["vectors"].as_array().unwrap();

    let mut seen = std::collections::BTreeSet::new();
    for vector in entries {
        let initiation = hex::decode(vector["initiation"].as_str().unwrap()).unwrap();
        assert_eq!(initiation.len(), INITIATION_LEN);
        assert_eq!(
            u16::from_be_bytes([initiation[0], initiation[1]]),
            CAPABILITY_VERSION
        );
        assert_eq!(initiation[2], 1, "type 1, an initiation");
        assert_eq!(u16::from_be_bytes([initiation[3], initiation[4]]), 96);
        assert!(initiation[5..].iter().any(|&b| b != 0));
        assert!(seen.insert(initiation), "duplicate initiation in the vectors");
    }
}
