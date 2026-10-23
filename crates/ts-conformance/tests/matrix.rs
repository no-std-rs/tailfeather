//! Runs the compatibility matrix under Bazel.
//!
//! The suite is not allowed to fail because work is unfinished — only because
//! something that used to work has broken, or because a behaviour we claim is
//! actually wrong. That keeps it runnable from the very first day rather than
//! only once the project is complete.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ts_conformance::{Env, Report, Status};

fn repo_root() -> PathBuf {
    if let Some(path) = std::env::var_os("TS_CONFORMANCE_VECTORS").map(PathBuf::from) {
        let vectors = if path.is_file() {
            path.parent().unwrap()
        } else {
            path.as_path()
        };
        return vectors
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf();
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/ts-conformance sits two levels below the repository root")
        .to_path_buf()
}

fn env() -> Env {
    Env::offline(&repo_root())
}

fn report() -> Report {
    // The workspace all-features build also selects hosted-policy. The matrix
    // constructs full nodes, so use the hosted runtime's worker stack budget.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| Report::run(&env()))
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn no_known_incompatibilities() {
    let report = report();
    let failures: Vec<String> = report
        .failures()
        .map(|o| match &o.status {
            Status::Fail(detail) => format!("{}: {}", o.id, detail),
            _ => unreachable!("failures() yields only Fail"),
        })
        .collect();
    assert!(
        failures.is_empty(),
        "compatibility regressions:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn every_check_has_a_unique_stable_id() {
    // The ids are referred to from commits and issues, so a duplicate would
    // silently make one of them unaddressable.
    let mut ids: Vec<&str> = ts_conformance::checks::all().iter().map(|c| c.id).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(total, ids.len(), "duplicate check ids");
}

#[test]
fn the_captured_vectors_are_usable() {
    // A vector that has gone missing or become malformed would quietly turn
    // real checks into skips, which reads as progress rather than as breakage.
    let env = env();
    if !env.vectors.join("map_response.json").exists() {
        eprintln!("no vectors captured; run tests/lab/capture.sh");
        return;
    }
    let map = env.vector("map_response.json").expect("map vector parses");
    let responses = map.as_array().expect("captured map is an array");
    assert!(!responses.is_empty(), "captured map is empty");
    assert!(
        responses.iter().any(|r| r.get("Node").is_some()),
        "no response describes this node"
    );
}

#[test]
fn hosted_tls_captures_validate_and_fit_the_embedded_bounds() {
    use base64::Engine as _;
    use embedded_tls::{CertificateEntryRef, CertificateRef, TlsVerifier as _};
    use sha2::Digest as _;
    use tailfeather::control::tls::{
        MAX_CERTIFICATE_BYTES, MAX_CHAIN_CERTIFICATES, TLS_READ_BUFFER, TLS_WRITE_BUFFER,
        TrustVerifier,
    };

    struct EcdsaCaptureClock;
    impl embedded_tls::TlsClock for EcdsaCaptureClock {
        fn now() -> Option<u64> {
            Some(1_785_585_600)
        }
    }
    struct RsaCaptureClock;
    impl embedded_tls::TlsClock for RsaCaptureClock {
        fn now() -> Option<u64> {
            Some(1_786_536_000)
        }
    }

    let path = repo_root().join("tests/vectors/hosted_tls.json");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let captures = [
        (
            &document,
            "hosted-ecdsa-chain.pem",
            1_785_585_600u64,
            verify_capture::<EcdsaCaptureClock> as fn(&[Vec<u8>]),
        ),
        (
            &document["rsa_capture"],
            "hosted-rsa-chain.pem",
            1_786_536_000u64,
            verify_capture::<RsaCaptureClock> as fn(&[Vec<u8>]),
        ),
    ];

    for (metadata, fixture, timestamp, verify) in captures {
        let pem = std::fs::read_to_string(repo_root().join("tests/vectors").join(fixture)).unwrap();
        let certificates = pem
            .split("-----BEGIN CERTIFICATE-----")
            .skip(1)
            .map(|block| {
                let encoded = block
                    .split("-----END CERTIFICATE-----")
                    .next()
                    .unwrap()
                    .lines()
                    .map(str::trim)
                    .collect::<String>();
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let chain = metadata["chain"]
            .as_array()
            .expect("hosted chain is an array");
        assert_eq!(certificates.len(), chain.len());
        let chain_bytes: usize = certificates.iter().map(Vec::len).sum();
        let recorded_bytes: usize = chain
            .iter()
            .map(|certificate| certificate["der_bytes"].as_u64().unwrap() as usize)
            .sum();
        assert_eq!(chain_bytes, recorded_bytes);
        assert!(chain.len() <= MAX_CHAIN_CERTIFICATES);
        assert!(chain_bytes <= MAX_CERTIFICATE_BYTES);
        for (certificate, metadata) in certificates.iter().zip(chain) {
            assert_eq!(
                hex::encode(sha2::Sha256::digest(certificate)),
                metadata["sha256"].as_str().unwrap()
            );
        }
        verify(&certificates);
        verify_with_openssl(fixture, &certificates, timestamp);
    }

    const { assert!(TLS_READ_BUFFER >= 16 * 1024 + 256) };
    const { assert!(TLS_WRITE_BUFFER == 2 * 1024) };
    assert_eq!(
        document["negotiated"]["peer_signature_type"],
        "ecdsa_secp256r1_sha256"
    );
    assert_eq!(
        document["rsa_capture"]["negotiated"]["peer_signature_type"],
        "rsa_pss_rsae_sha256"
    );

    fn verify_capture<Clock: embedded_tls::TlsClock>(certificates: &[Vec<u8>]) {
        let mut chain = CertificateRef::with_context(&[]);
        for certificate in certificates {
            chain.add(CertificateEntryRef::X509(certificate)).unwrap();
        }
        let mut workspace = tailfeather::control::tls::RsaWorkspace::new();
        let mut verifier = TrustVerifier::<Clock>::new(None, &mut workspace);
        verifier
            .set_hostname_verification("controlplane.tailscale.com")
            .unwrap();
        verifier
            .verify_certificate(&sha2::Sha256::new(), chain)
            .unwrap();
    }

    fn verify_with_openssl(name: &str, certificates: &[Vec<u8>], timestamp: u64) {
        use std::fmt::Write as _;

        fn pem(certificate: &[u8]) -> String {
            let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
            let mut result = String::from("-----BEGIN CERTIFICATE-----\n");
            for line in encoded.as_bytes().chunks(64) {
                writeln!(result, "{}", std::str::from_utf8(line).unwrap()).unwrap();
            }
            result.push_str("-----END CERTIFICATE-----\n");
            result
        }

        let prefix = format!("tailfeather-{}-{}", std::process::id(), name);
        let directory = std::env::temp_dir();
        let leaf = directory.join(format!("{prefix}-leaf.pem"));
        let intermediates = directory.join(format!("{prefix}-intermediates.pem"));
        let root = directory.join(format!("{prefix}-root.pem"));
        std::fs::write(&leaf, pem(&certificates[0])).unwrap();
        std::fs::write(
            &intermediates,
            certificates[1..certificates.len() - 1]
                .iter()
                .map(|certificate| pem(certificate))
                .collect::<String>(),
        )
        .unwrap();
        std::fs::write(&root, pem(certificates.last().unwrap())).unwrap();
        let openssl = std::env::var_os("TS_TEST_OPENSSL").unwrap_or_else(|| "openssl".into());
        let status = std::process::Command::new(openssl)
            .args([
                "verify",
                "-partial_chain",
                "-attime",
                &timestamp.to_string(),
                "-purpose",
                "sslserver",
                "-verify_hostname",
                "controlplane.tailscale.com",
                "-CAfile",
                root.to_str().unwrap(),
                "-untrusted",
                intermediates.to_str().unwrap(),
                leaf.to_str().unwrap(),
            ])
            .status()
            .expect("the pinned OpenSSL verifier must be runnable");
        let _ = std::fs::remove_file(leaf);
        let _ = std::fs::remove_file(intermediates);
        let _ = std::fs::remove_file(root);
        assert!(status.success(), "OpenSSL rejected {name}");
    }
}

#[test]
fn print_the_matrix() {
    // Not an assertion — this is how the report reaches anyone running the
    // suite with --nocapture.
    let report = report();
    println!("{report}");
}

/// Every committed baseline names exactly the checks that exist.
///
/// Without this, adding a check leaves the baselines describing a suite that no
/// longer exists, and the omission only surfaces the next time someone runs
/// `--expect` — which, for the offline baseline, may be in CI on someone else's
/// branch. Cheap to check here, and needs no lab.
#[test]
fn the_committed_baselines_cover_every_check() {
    let repo_root = repo_root();
    let expectations = repo_root.join("tests/expectations");
    let current: BTreeSet<&str> = ts_conformance::checks::all().iter().map(|c| c.id).collect();

    let mut found = 0;
    for entry in std::fs::read_dir(&expectations).expect("tests/expectations exists") {
        let path = entry.expect("readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        found += 1;

        let text = std::fs::read_to_string(&path).expect("baseline is readable");
        let document: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let checks = document["checks"]
            .as_object()
            .unwrap_or_else(|| panic!("{}: no \"checks\" object", path.display()));
        let recorded: BTreeSet<&str> = checks.keys().map(String::as_str).collect();

        let added: Vec<&&str> = current.difference(&recorded).collect();
        let removed: Vec<&&str> = recorded.difference(&current).collect();
        assert!(
            added.is_empty() && removed.is_empty(),
            "{} is out of date.\n  checks missing from it: {added:?}\n  \
             checks it names that no longer exist: {removed:?}\n  \
             Regenerate with `bazel run //crates/ts-conformance:conformance -- --write-expect {}`",
            path.display(),
            path.display(),
        );

        // A baseline of nothing but skips would satisfy the above and measure
        // nothing, so require that at least one check is expected to be a real
        // result. The offline baseline still has the vector-backed ones.
        assert!(
            checks.values().any(|v| v == "pass"),
            "{} expects no check to pass at all",
            path.display()
        );
    }
    assert!(
        found >= 2,
        "expected at least the offline and lab baselines"
    );
}

#[test]
fn complete_headscale_baseline_is_all_pass_and_exactly_covers_inventory() {
    let root = repo_root();
    let path = root.join("tests/expectations/lab.json");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let expected = document["checks"].as_object().unwrap();
    assert_eq!(expected.len(), ts_conformance::checks::all().len());
    for (id, status) in expected {
        assert_eq!(status, "pass", "complete baseline permits {id}={status}");
    }
}

#[test]
fn check_ids_are_stable_and_unique() {
    let mut ids = BTreeSet::new();
    for check in ts_conformance::checks::all() {
        assert!(!check.id.is_empty());
        assert!(
            check.id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
            }),
            "check id is not stable machine syntax: {}",
            check.id
        );
        assert!(ids.insert(check.id), "duplicate check id: {}", check.id);
    }
}

/// The doctor's "this disables these checks" lists name checks that exist.
///
/// Those lists are maintained by hand, so without this a renamed check leaves
/// the banner confidently pointing at an id nobody can find — which is worse
/// than saying nothing, because the banner is what someone reads when they are
/// already confused about why a check skipped.
#[test]
fn the_doctor_only_names_checks_that_exist() {
    let current: BTreeSet<&str> = ts_conformance::checks::all().iter().map(|c| c.id).collect();

    // A doctor that found nothing reports every gap, which is what makes this a
    // complete check of the id lists rather than of whichever gaps happen to
    // apply on this machine.
    let nothing = ts_conformance::doctor::Doctor::default();
    let gaps = nothing.gaps();
    assert!(!gaps.is_empty(), "an empty environment should report gaps");

    for gap in gaps {
        for id in gap.disables {
            assert!(
                current.contains(id),
                "the doctor says '{}' disables '{id}', but no such check exists",
                gap.what
            );
        }
    }
}
