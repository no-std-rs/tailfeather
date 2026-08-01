//! Runs the compatibility matrix under `cargo test`.
//!
//! The suite is not allowed to fail because work is unfinished — only because
//! something that used to work has broken, or because a behaviour we claim is
//! actually wrong. That keeps it runnable from the very first day rather than
//! only once the project is complete.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ts_conformance::{Env, Report, Status};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/ts-conformance sits two levels below the repository root")
        .to_path_buf()
}

fn env() -> Env {
    Env::discover(&repo_root())
}

#[test]
fn no_known_incompatibilities() {
    let report = Report::run(&env());
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
fn print_the_matrix() {
    // Not an assertion — this is how the report reaches anyone running the
    // suite with --nocapture.
    let report = Report::run(&env());
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
             Regenerate with `cargo run -p ts-conformance -- --write-expect {}`",
            path.display(),
            path.display(),
        );

        // A baseline of nothing but skips would satisfy the above and measure
        // nothing, so require that at least one check is expected to be a real
        // result. The offline baseline still has the vector-backed ones.
        assert!(
            checks.values().any(|v| v == "pass" || v == "external"),
            "{} expects no check to pass at all",
            path.display()
        );
    }
    assert!(found >= 2, "expected at least the offline and lab baselines");
}
