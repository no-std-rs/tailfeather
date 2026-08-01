//! Prints the compatibility matrix.
//!
//! Exits non-zero only on a genuine incompatibility, or on a difference from a
//! baseline when one was named. Unimplemented behaviour is expected and must not
//! fail a build, or the suite would be unusable until the day it is finished —
//! which is precisely when it is least useful.

use std::path::{Path, PathBuf};

use ts_conformance::baseline::Baseline;
use ts_conformance::{Env, Report, Status};

const USAGE: &str = "\
usage: conformance [--json] [--expect <path>] [--write-expect <path>]

  --json                  emit the report as JSON instead of a table
  --expect <path>         compare against a committed baseline and exit
                          non-zero on any difference, in either direction
  --write-expect <path>   record the current run as a baseline

Baselines live in tests/expectations/. Comparing in both directions is
deliberate: a check that quietly degrades to \"skip\" leaves the reported score
at 100% because skips are excluded from the denominator.";

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            2
        }
    };
    std::process::exit(code);
}

/// Run the suite and return the exit code.
///
/// Split from `main` so that `env` — and with it the `RunScope` that deletes the
/// nodes this run registered — is dropped *before* `std::process::exit`. `exit`
/// does not unwind and does not run destructors, so calling it while the
/// environment was still alive skipped cleanup on precisely the runs that
/// produce debris: the failing ones.
///
/// That is not a theoretical ordering concern. It was observed: a failing run
/// left six nodes behind, the extra peers pushed the netmap past
/// `ts_netmap::MAX_PEERS`, and the next run failed harder and left six more. Six
/// runs took the lab from 34/34 to 29/34 with 48 orphans.
fn run() -> Result<i32, String> {
    let options = Options::parse(std::env::args().skip(1))?;

    let repo_root = repo_root();
    let env = Env::discover(&repo_root);
    let report = Report::run(&env);

    if let Some(path) = &options.write_expect {
        Baseline::write(&report, path)?;
        eprintln!("wrote {}", path.display());
    }

    if options.json {
        println!("{:#}", report.to_json());
    } else {
        print!("{report}");
    }

    // A baseline comparison subsumes the failure check: a failure that the
    // baseline already records is not news, and a pass that the baseline does
    // not expect is.
    if let Some(path) = &options.expect {
        let comparison = Baseline::load(path)?.compare(&report);
        if !options.json {
            eprintln!();
        }
        eprint!("{comparison}");
        return Ok(if comparison.agrees() { 0 } else { 1 });
    }

    let failures: Vec<_> = report.failures().collect();
    if failures.is_empty() {
        return Ok(0);
    }

    eprintln!();
    eprintln!("{} incompatibility(ies) found:", failures.len());
    for outcome in &failures {
        if let Status::Fail(detail) = &outcome.status {
            eprintln!("  {}: {}", outcome.id, detail);
        }
    }
    Ok(1)
}

#[derive(Default)]
struct Options {
    json: bool,
    expect: Option<PathBuf>,
    write_expect: Option<PathBuf>,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = Options::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" => options.json = true,
                "--expect" => {
                    options.expect = Some(PathBuf::from(
                        args.next().ok_or("--expect needs a path\n\n".to_string() + USAGE)?,
                    ));
                }
                "--write-expect" => {
                    options.write_expect = Some(PathBuf::from(
                        args.next()
                            .ok_or("--write-expect needs a path\n\n".to_string() + USAGE)?,
                    ));
                }
                "-h" | "--help" => return Err(USAGE.to_string()),
                other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
            }
        }
        Ok(options)
    }
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

/// Where the committed baselines live, for the error message and for tests.
pub fn expectations_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("tests/expectations")
}
