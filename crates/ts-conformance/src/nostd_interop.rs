//! One memoized namespace session with explicit evidence for every live check.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use crate::{Env, Status};

const IDS: [&str; 10] = [
    "wg.handshake.responder",
    "wg.transport.roundtrip",
    "wg.replay",
    "wg.rekey",
    "wg.handshake.initiator",
    "exit.forward.udp",
    "exit.forward.tcp",
    "dns.peerapi.doh",
    "dns.peerapi.acl",
    "dns.peerapi.concurrency",
];

#[derive(Clone)]
struct Session {
    passed: BTreeSet<String>,
    detail: String,
}

#[derive(Clone)]
enum SessionError {
    Unavailable(String),
    Failed(String),
}

fn sessions() -> &'static Mutex<BTreeMap<String, Result<Session, SessionError>>> {
    static SESSIONS: OnceLock<Mutex<BTreeMap<String, Result<Session, SessionError>>>> =
        OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// A process may produce offline and live reports in succession (notably in
/// tests). Cache only identical inputs; an old skipped probe must never answer
/// a later live run, and vice versa.
fn cache_key(env: &Env) -> String {
    format!(
        "target={:?};control={:?};harness={:?};headscale={};sudo={};vectors={}",
        env.target,
        env.control_url,
        env.harness.as_ref().map(|harness| harness.path()),
        env.doctor.as_ref().is_some_and(|doctor| doctor.headscale),
        env.doctor
            .as_ref()
            .is_some_and(|doctor| doctor.passwordless_sudo),
        env.vectors.display(),
    )
}

fn session(env: &Env) -> Result<Session, SessionError> {
    let key = cache_key(env);
    let mut cache = sessions().lock().expect("no_std session cache lock");
    cache.entry(key).or_insert_with(|| run(env)).clone()
}

fn run(env: &Env) -> Result<Session, SessionError> {
    let harness = env
        .harness
        .as_ref()
        .ok_or_else(|| SessionError::Unavailable(crate::harness::NOT_BUILT.to_string()))?;
    let Some(doctor) = &env.doctor else {
        return Err(SessionError::Unavailable(
            "lab capabilities were not probed; run tests/lab/lab.sh doctor".into(),
        ));
    };
    if !doctor.headscale || env.control_url.is_none() {
        return Err(SessionError::Unavailable(
            "no complete lab session; namespace interop is reserved for the all-pass run".into(),
        ));
    }
    if !doctor.passwordless_sudo {
        return Err(SessionError::Unavailable(
            "no passwordless sudo; the isolated namespace topology did not run".into(),
        ));
    }
    let root = env
        .vectors
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| {
            SessionError::Unavailable("cannot locate repository root from vectors directory".into())
        })?;
    let script = root.join("scripts/nostd-interop.sh");
    let output = Command::new("timeout")
        .args(["-k", "10", "180", "sudo", "-n"])
        .arg(&script)
        .arg(harness.path())
        .output()
        .map_err(|error| {
            SessionError::Failed(format!("could not start {}: {error}", script.display()))
        })?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = stdout
            .lines()
            .chain(stderr.lines())
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("; ");
        return Err(SessionError::Failed(format!(
            "no_std interop topology failed: {tail}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let passed = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("PASS: "))
        .filter(|id| IDS.contains(id))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let missing = IDS
        .iter()
        .filter(|id| !passed.contains(**id))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(SessionError::Failed(format!(
            "no_std topology exited successfully but omitted evidence for {}",
            missing.join(", ")
        )));
    }

    Ok(Session {
        passed,
        detail: "isolated no_std topology produced independent evidence for this check".into(),
    })
}

fn status(result: Result<Session, SessionError>, id: &'static str) -> Status {
    match result {
        Ok(session) if session.passed.contains(id) => Status::Pass(session.detail),
        Ok(_) => Status::Fail(format!("no_std topology omitted evidence for {id}")),
        Err(SessionError::Unavailable(reason)) => Status::Skip(reason),
        Err(SessionError::Failed(reason)) => Status::Fail(reason),
    }
}

fn check(env: &Env, id: &'static str) -> Status {
    status(session(env), id)
}

pub fn responder(env: &Env) -> Status {
    check(env, "wg.handshake.responder")
}

pub fn transport(env: &Env) -> Status {
    check(env, "wg.transport.roundtrip")
}

pub fn replay(env: &Env) -> Status {
    check(env, "wg.replay")
}

pub fn rekey(env: &Env) -> Status {
    check(env, "wg.rekey")
}

pub fn initiator(env: &Env) -> Status {
    check(env, "wg.handshake.initiator")
}

pub fn udp(env: &Env) -> Status {
    check(env, "exit.forward.udp")
}

pub fn tcp(env: &Env) -> Status {
    check(env, "exit.forward.tcp")
}

pub fn doh(env: &Env) -> Status {
    check(env, "dns.peerapi.doh")
}

pub fn acl(env: &Env) -> Status {
    check(env, "dns.peerapi.acl")
}

pub fn concurrency(env: &Env) -> Status {
    check(env, "dns.peerapi.concurrency")
}

#[cfg(test)]
mod tests {
    use super::{IDS, SessionError, cache_key, status};
    use crate::{Env, Status};

    const TOPOLOGY_SCRIPT: &str = include_str!("../../../scripts/nostd-interop.sh");

    #[test]
    fn cache_key_separates_offline_and_live_environment_inputs() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .unwrap();
        let offline = Env::offline(root);
        let mut changed = Env::offline(root);
        changed.control_url = Some("http://127.0.0.1:8080".into());
        assert_ne!(cache_key(&offline), cache_key(&changed));
    }

    #[test]
    fn topology_script_emits_evidence_for_every_collected_check() {
        for id in IDS {
            let marker = format!("echo \"PASS: {id}\"");
            assert!(
                TOPOLOGY_SCRIPT.lines().any(|line| line == marker),
                "the topology script does not emit {id}"
            );
        }
    }

    #[test]
    fn launched_topology_failures_are_not_reported_as_skips() {
        assert!(matches!(
            status(Err(SessionError::Failed("probe failed".into())), IDS[0]),
            Status::Fail(reason) if reason == "probe failed"
        ));
        assert!(matches!(
            status(
                Err(SessionError::Unavailable("no lab".into())),
                IDS[0]
            ),
            Status::Skip(reason) if reason == "no lab"
        ));
    }
}
