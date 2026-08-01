//! Driving the `no_std` harness as a subprocess.
//!
//! # Why not link it
//!
//! Several checks could be answered by calling the library crates directly from
//! this `std` binary, and the vector-backed ones are. But a claim like "the node
//! completes a ts2021 handshake" is only worth something if it was made by a
//! binary with no libc, no `std` and no allocator — the environment the firmware
//! actually runs in. Linking the crates here would prove they work when `std` is
//! available to prop them up, which is not the question.
//!
//! So these checks run `harness/target/x86_64-unknown-linux-none/release/harness`
//! and read what it reports.
//!
//! # The event channel
//!
//! The harness prints human-readable progress and, separately, lines beginning
//! `#EVT ` carrying one JSON object each. Only the latter are parsed. That split
//! is the whole reason the checks are not brittle: the logging above can be
//! reworded freely, and only a deliberate change to an event breaks a check.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

/// The built harness binary.
pub struct Harness {
    path: PathBuf,
}

/// What one run reported.
pub struct Run {
    pub events: Vec<Value>,
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    /// What some *other* implementation said about the run. Kept separate from
    /// our own output, because a check that quotes the reference client is
    /// making a stronger claim than one quoting us.
    pub note: String,
}

impl Run {
    /// Build a run from output already collected.
    ///
    /// Separate from [`Run::from_output`] for the checks that must read the
    /// harness's stdout *while* it runs — the disco check waits for a readiness
    /// event before nudging the reference client — and so cannot wait for the
    /// process to exit first.
    pub fn from_parts(stdout: String, stderr: String, code: Option<i32>) -> Self {
        let events = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("#EVT "))
            .filter_map(|json| serde_json::from_str(json).ok())
            .collect();
        Self {
            events,
            stdout,
            stderr,
            code,
            note: String::new(),
        }
    }

    pub fn from_output(output: &std::process::Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let events = stdout
            .lines()
            .filter_map(|line| line.strip_prefix("#EVT "))
            .filter_map(|json| serde_json::from_str(json).ok())
            .collect();
        Self {
            events,
            stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            code: output.status.code(),
            note: String::new(),
        }
    }

    /// The first event of a given kind.
    pub fn event(&self, name: &str) -> Option<&Value> {
        self.events
            .iter()
            .find(|e| e["event"].as_str() == Some(name))
    }

    pub fn succeeded(&self) -> bool {
        self.code == Some(0)
    }

    /// A short summary for a failure message, since the harness's own output is
    /// the only diagnostic there is.
    pub fn tail(&self) -> String {
        let combined = format!("{}{}", self.stdout, self.stderr);
        combined
            .lines()
            .filter(|l| !l.starts_with("#EVT "))
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl Harness {
    /// Locate the built binary, if there is one.
    pub fn discover(repo_root: &Path) -> Option<Self> {
        let path = repo_root
            .join("harness/target/x86_64-unknown-linux-none/release/harness");
        path.is_file().then_some(Self { path })
    }

    pub fn run(&self, args: &[&str]) -> Result<Run, String> {
        let output = Command::new(&self.path)
            .args(args)
            .output()
            .map_err(|e| format!("could not run the harness: {e}"))?;
        Ok(Run::from_output(&output))
    }

    /// The binary, for a check that needs to drive it itself rather than wait.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A directory for one check's state, distinct from every other check's.
    ///
    /// Checks that share a state directory would see each other's identities,
    /// and the persistence check in particular would pass for the wrong reason.
    pub fn scratch(&self, name: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ts-conformance-{}-{name}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }
}

/// The message a check reports when the binary has not been built.
pub const NOT_BUILT: &str =
    "the no_std harness is not built; run 'cd harness && cargo build --release' \
     (scripts/conformance.sh does this)";
