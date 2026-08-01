//! Prints the compatibility matrix.
//!
//! Exits non-zero only on a genuine incompatibility. Unimplemented behaviour is
//! expected and must not fail a build, or the suite would be unusable until the
//! day it is finished — which is precisely when it is least useful.

use std::path::PathBuf;

use ts_conformance::{Env, Report, Status};

fn main() {
    let code = report();
    std::process::exit(code);
}

/// Run the suite and return the exit code.
///
/// Split from `main` so that `env` — and with it the [`RunScope`] that deletes
/// the nodes this run registered — is dropped *before* `std::process::exit`.
/// `exit` does not unwind and does not run destructors, so calling it while the
/// environment was still alive skipped cleanup on precisely the runs that
/// produce debris: the failing ones.
///
/// That is not a theoretical ordering concern. It was observed: a failing run
/// left six nodes behind, the extra peers pushed the netmap past
/// `ts_netmap::MAX_PEERS`, and the next run failed harder and left six more. Six
/// runs took the lab from 34/34 to 29/34 with 48 orphans.
///
/// [`RunScope`]: ts_conformance::runscope::RunScope
fn report() -> i32 {
    let repo_root = repo_root();
    let env = Env::discover(&repo_root);
    let report = Report::run(&env);

    print!("{report}");

    let failures: Vec<_> = report.failures().collect();
    if failures.is_empty() {
        return 0;
    }

    eprintln!();
    eprintln!("{} incompatibility(ies) found:", failures.len());
    for outcome in &failures {
        if let Status::Fail(detail) = &outcome.status {
            eprintln!("  {}: {}", outcome.id, detail);
        }
    }
    1
}

/// Walk up from the executable or the current directory to the repository root.
fn repo_root() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        // crates/ts-conformance -> repository root
        return PathBuf::from(dir)
            .parent()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("tests/vectors").is_dir() {
            return dir;
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return PathBuf::from("."),
        }
    }
}
