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
//! So these checks run the `//harness:harness` Bazel runfile
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
use std::time::Duration;

use serde_json::Value;

/// How many times [`Harness::register`] dials before giving up, and how long it
/// waits after the first failure. Short, because the close is observed within
/// milliseconds of connecting and the whole lab runs under a test timeout.
const REGISTER_ATTEMPTS: u32 = 3;
const REGISTER_BACKOFF: Duration = Duration::from_millis(250);

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

    /// Whether the run ended because the connection went away under it, rather
    /// than because the server answered something. The harness prints the
    /// transport error verbatim, so this is the one string that distinguishes
    /// "nobody was listening any more" from every verdict worth reporting.
    pub fn closed_early(&self) -> bool {
        let closed = "network: connection closed";
        self.stdout.contains(closed) || self.stderr.contains(closed)
    }

    /// Whether registration reached the point where the server may have
    /// accepted the request, even if the response never arrived.
    fn registration_submitted(&self) -> bool {
        self.event("registration_submitted").is_some()
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
    pub fn discover(_repo_root: &Path) -> Option<Self> {
        let path = std::env::var_os("TS_CONFORMANCE_HARNESS").map(PathBuf::from)?;
        path.is_file().then_some(Self { path })
    }

    pub fn run(&self, args: &[&str]) -> Result<Run, String> {
        let output = Command::new(&self.path)
            .args(args)
            .output()
            .map_err(|e| format!("could not run the harness: {e}"))?;
        Ok(Run::from_output(&output))
    }

    /// A `register` run, redialled past a transport-level close.
    ///
    /// Headscale occasionally drops a freshly established Noise connection
    /// before answering on it — the session comes up, the early payload read
    /// returns nothing, and the run reports `network: connection closed`. It is
    /// not a verdict about the request, because the server never read one, and
    /// a real client's response to a hangup is to dial again.
    ///
    /// Only that one signature is retried. Anything the server actually said —
    /// a refused key, a rejected capability version — fails identically on
    /// every attempt, and retrying it would turn a real regression into a
    /// slower real regression.
    ///
    /// The identity lives in the state directory the caller passes, so an
    /// ordinary second attempt presents the same machine and node keys rather
    /// than leaving a stray node behind. A rotation is retried only if the run
    /// closed before starting its POST: after that point the server may have
    /// accepted the generated replacement key even though the harness did not
    /// receive the response and persist it.
    pub fn register(&self, args: &[&str]) -> Result<Run, String> {
        let rotating = args.contains(&"--rotate");
        let mut run = self.run(args)?;
        for attempt in 1..REGISTER_ATTEMPTS {
            if run.event("registered").is_some()
                || !run.closed_early()
                || (rotating && run.registration_submitted())
            {
                break;
            }
            std::thread::sleep(REGISTER_BACKOFF * attempt);
            run = self.run(args)?;
        }
        Ok(run)
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
pub const NOT_BUILT: &str = "the no_std harness is not built; run 'bazel build //harness:harness' \
     (scripts/conformance.sh does this)";

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the harness binary: a shell script that counts its own
    /// invocations in `counter` and misbehaves as the test asks. Registration is
    /// driven through a subprocess, so the only honest way to test the retry is
    /// with a subprocess that misbehaves.
    ///
    /// The harness is `sh` and the script is its first argument, rather than the
    /// script being executable itself. These tests run in parallel with the rest
    /// of the module, and a sibling forking while this file is still open for
    /// writing is exactly the ETXTBSY case — running it as data has no such race.
    fn stub(dir: &Path, body: &str) -> (Harness, String) {
        let path = dir.join("stub.sh");
        std::fs::write(&path, body).unwrap();
        (
            Harness {
                path: PathBuf::from("/bin/sh"),
            },
            path.to_string_lossy().into_owned(),
        )
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ts-conformance-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_closed_connection_is_retried_and_can_succeed() {
        let dir = scratch_dir("retry");
        let counter = dir.join("count");
        let (harness, script) = stub(
            &dir,
            &format!(
                r#"#!/bin/sh
n=$(cat {counter} 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > {counter}
if [ "$n" -eq 1 ]; then
  echo "noise session established"
  echo "FAIL network: connection closed"
  exit 1
fi
echo '#EVT {{"event":"registered","node":"nodekey:abc"}}'
"#,
                counter = counter.display()
            ),
        );

        let run = harness.register(&[&script, "register"]).unwrap();
        assert!(run.event("registered").is_some(), "{}", run.tail());
        assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "2");
    }

    #[test]
    fn a_rotation_closed_before_its_post_is_retried() {
        let dir = scratch_dir("rotation-before-post");
        let counter = dir.join("count");
        let (harness, script) = stub(
            &dir,
            &format!(
                r#"#!/bin/sh
n=$(cat {counter} 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > {counter}
if [ "$n" -eq 1 ]; then
  echo "-> POST /machine/register"
  echo "FAIL network: connection closed"
  exit 1
fi
echo '#EVT {{"event":"registered","node":"nodekey:abc"}}'
"#,
                counter = counter.display()
            ),
        );

        let run = harness
            .register(&[&script, "register", "--rotate"])
            .unwrap();
        assert!(run.event("registered").is_some(), "{}", run.tail());
        assert_eq!(std::fs::read_to_string(&counter).unwrap().trim(), "2");
    }

    #[test]
    fn a_rotation_closed_after_submission_is_not_retried() {
        let dir = scratch_dir("rotation-after-post");
        let counter = dir.join("count");
        let (harness, script) = stub(
            &dir,
            &format!(
                r#"#!/bin/sh
n=$(cat {counter} 2>/dev/null || echo 0)
echo "$((n + 1))" > {counter}
echo "-> POST /machine/register"
echo '#EVT {{"event":"registration_submitted"}}'
echo "FAIL network: connection closed"
exit 1
"#,
                counter = counter.display()
            ),
        );

        let run = harness
            .register(&[&script, "register", "--rotate"])
            .unwrap();
        assert!(run.event("registered").is_none());
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().trim(),
            "1",
            "a possibly accepted rotation must not generate a second replacement key"
        );
    }

    #[test]
    fn a_refusal_is_reported_rather_than_retried() {
        let dir = scratch_dir("refusal");
        let counter = dir.join("count");
        let (harness, script) = stub(
            &dir,
            &format!(
                r#"#!/bin/sh
n=$(cat {counter} 2>/dev/null || echo 0)
echo "$((n + 1))" > {counter}
echo "FAIL unexpected status 401"
exit 1
"#,
                counter = counter.display()
            ),
        );

        let run = harness.register(&[&script, "register"]).unwrap();
        assert!(run.event("registered").is_none());
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().trim(),
            "1",
            "a verdict from the server must not be dialled again"
        );
    }

    #[test]
    fn a_connection_that_keeps_closing_gives_up() {
        let dir = scratch_dir("persistent");
        let counter = dir.join("count");
        let (harness, script) = stub(
            &dir,
            &format!(
                r#"#!/bin/sh
n=$(cat {counter} 2>/dev/null || echo 0)
echo "$((n + 1))" > {counter}
echo "FAIL network: connection closed"
exit 1
"#,
                counter = counter.display()
            ),
        );

        let run = harness.register(&[&script, "register"]).unwrap();
        assert!(run.event("registered").is_none());
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().trim(),
            REGISTER_ATTEMPTS.to_string()
        );
        assert!(run.closed_early());
    }
}
