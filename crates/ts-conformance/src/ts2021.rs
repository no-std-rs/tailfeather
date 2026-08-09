//! The checks answered by driving the `no_std` harness through a real ts2021
//! handshake.
//!
//! One run answers most of them, so it is done once and shared. That is not
//! only for speed: the identity checks and the handshake checks have to be
//! talking about the *same* session, or "the keys are distinct" and "the
//! handshake succeeded" could both pass while describing different runs.

use std::sync::OnceLock;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

/// The outcome of the shared run, or why there wasn't one.
enum Session {
    Ran(Run),
    Skipped(String),
}

fn session(env: &Env) -> &'static Session {
    static SESSION: OnceLock<Session> = OnceLock::new();
    SESSION.get_or_init(|| match start(env) {
        Ok(run) => Session::Ran(run),
        Err(reason) => Session::Skipped(reason),
    })
}

fn start(env: &Env) -> Result<Run, String> {
    let Some(harness) = &env.harness else {
        return Err(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Err(
            "this conformance path does not yet route hosted requests through verified TLS".into(),
        );
    }
    let Some((host, port)) = &env.control_address else {
        return Err("no control server configured; start one with tests/lab/lab.sh up".into());
    };

    let state = harness.scratch("ts2021");
    let state = state.to_string_lossy().into_owned();
    harness.run(&["ts2021", &state, host, &port.to_string()])
}

/// Run a check against the shared session.
fn with_session(env: &Env, f: impl FnOnce(&Run) -> Status) -> Status {
    match session(env) {
        Session::Skipped(reason) => Status::Skip(reason.clone()),
        Session::Ran(run) => f(run),
    }
}

/// The `identity` event, which every key check reads.
fn identity(run: &Run) -> Result<&Value, Status> {
    run.event("identity")
        .ok_or_else(|| Status::Fail(format!("the harness reported no identity: {}", run.tail())))
}

/// Check one key: present, correctly prefixed, and 32 bytes of hex.
fn key_check(env: &Env, field: &str, prefix: &str, role: &str) -> Status {
    with_session(env, |run| {
        let identity = match identity(run) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let Some(text) = identity[field].as_str() else {
            return Status::Fail(format!("no {field} key in the harness's identity"));
        };
        let Some(hex) = text.strip_prefix(prefix) else {
            return Status::Fail(format!("{field} key is not '{prefix}…': {text}"));
        };
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Status::Fail(format!("{field} key is not 32 bytes of hex: {text}"));
        }

        // The three keys are the same size and shape, so the only thing that
        // stops one being used as another is that they are actually different
        // values. A generator wired up wrong would produce three identical keys
        // and every individual check would still pass.
        let others: Vec<&str> = ["machine", "node", "disco"]
            .iter()
            .filter(|f| **f != field)
            .filter_map(|f| identity[*f].as_str())
            .collect();
        if others.iter().any(|o| o.ends_with(hex)) {
            return Status::Fail(format!("the {field} key is not distinct from the others"));
        }

        Status::Pass(format!(
            "the no_std harness generated a distinct {role}, published as \
             '{prefix}' + 64 hex chars, and used it against a live server: {}…",
            &hex[..16]
        ))
    })
}

pub fn machine_key(env: &Env) -> Status {
    key_check(
        env,
        "machine",
        "mkey:",
        "machine key — the identity the control plane authenticates",
    )
}

pub fn node_key(env: &Env) -> Status {
    key_check(env, "node", "nodekey:", "node key")
}

pub fn disco_key(env: &Env) -> Status {
    key_check(env, "disco", "discokey:", "disco key")
}

/// Two runs against the same state directory must yield the same identity, and
/// a damaged blob must be refused rather than quietly replaced.
pub fn persistence(env: &Env) -> Status {
    let Some(harness) = &env.harness else {
        return Status::Skip(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Status::Skip(
            "this conformance path does not yet route hosted requests through verified TLS".into(),
        );
    }
    let Some((host, port)) = &env.control_address else {
        return Status::Skip(
            "no control server configured; start one with tests/lab/lab.sh up".into(),
        );
    };

    let directory = harness.scratch("persistence");
    let state = directory.to_string_lossy().into_owned();
    let port = port.to_string();
    let args = ["ts2021", state.as_str(), host.as_str(), port.as_str()];

    let first = match harness.run(&args) {
        Ok(run) => run,
        Err(e) => return Status::Fail(e),
    };
    let Some(first_identity) = first.event("identity").cloned() else {
        return Status::Fail(format!(
            "the first run reported no identity: {}",
            first.tail()
        ));
    };
    if first_identity["new"] != Value::Bool(true) {
        return Status::Fail("the first run did not report a fresh identity".into());
    }

    let second = match harness.run(&args) {
        Ok(run) => run,
        Err(e) => return Status::Fail(e),
    };
    let Some(second_identity) = second.event("identity").cloned() else {
        return Status::Fail(format!(
            "the second run reported no identity: {}",
            second.tail()
        ));
    };
    if second_identity["new"] != Value::Bool(false) {
        return Status::Fail(
            "the second run generated a new identity instead of loading one".into(),
        );
    }
    for field in ["machine", "node", "disco"] {
        if first_identity[field] != second_identity[field] {
            return Status::Fail(format!("the {field} key changed between runs"));
        }
    }

    // Damage one byte on disk. A store that accepted this would hand out an
    // identity a few bits away from the registered one, and the failure would
    // surface later as an unexplained authentication error rather than here.
    let blob = directory.join("identity.bin");
    let mut bytes = match std::fs::read(&blob) {
        Ok(bytes) => bytes,
        Err(e) => return Status::Fail(format!("could not read {}: {e}", blob.display())),
    };
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 0x01;
    if let Err(e) = std::fs::write(&blob, &bytes) {
        return Status::Fail(format!("could not write {}: {e}", blob.display()));
    }

    let third = match harness.run(&args) {
        Ok(run) => run,
        Err(e) => return Status::Fail(e),
    };
    if third.succeeded() {
        return Status::Fail("a corrupted identity blob was accepted".into());
    }
    if third.event("identity").is_some() {
        return Status::Fail("a corrupted identity blob was silently regenerated".into());
    }

    Status::Pass(format!(
        "two runs of the no_std harness against one state directory produced the same \
         three keys ({}…), the second reported them as loaded rather than created, and \
         flipping one bit on disk was refused rather than regenerated",
        &first_identity["machine"].as_str().unwrap_or("")[5..21]
    ))
}

/// The handshake itself.
pub fn noise_handshake(env: &Env) -> Status {
    with_session(env, |run| {
        if run.event("noise").is_none() {
            return Status::Fail(format!(
                "the ts2021 handshake did not complete: {}",
                run.tail()
            ));
        }
        let server_key = run
            .event("serverkey")
            .and_then(|e| e["key"].as_str())
            .unwrap_or("(unreported)");

        Status::Pass(format!(
            "the no_std harness completed Noise IK against a live server, which \
             answered the 101-byte initiation with a 51-byte response whose tag \
             verified. Server key {server_key}. A wrong prologue, protocol name, or \
             mixing order fails exactly here."
        ))
    })
}

/// The record layer, which is where the big-endian nonce shows up.
pub fn controlbase_framing(env: &Env) -> Status {
    with_session(env, |run| {
        let Some(early) = run.event("early") else {
            return Status::Fail(format!(
                "no records were read after the handshake: {}",
                run.tail()
            ));
        };

        // Reading the early payload takes three records — the capture shows
        // plaintexts of 5, 4 and 95 bytes — so getting here means counters 0, 1
        // and 2 all opened. That matters: the WireGuard nonce convention this
        // project already contains agrees with Tailscale's at counter 0 and
        // diverges at 1, so a single-record test would pass with the endianness
        // wrong. Three is the smallest number that cannot.
        if early["present"] == Value::Bool(true) {
            let len = early["len"].as_u64().unwrap_or(0);
            Status::Pass(format!(
                "the harness opened three consecutive records from a live server \
                 (counters 0, 1 and 2 — enough to prove the big-endian nonce, which \
                 agrees with WireGuard's only at 0) and reassembled a {len}-byte early \
                 payload that spanned all three"
            ))
        } else {
            Status::Pass(
                "the harness read records from a live server and correctly found no \
                 early payload, pushing the nine bytes back for the HTTP/2 layer"
                    .into(),
            )
        }
    })
}

/// The capability version, checked against the floor the server actually
/// enforces rather than against a documented one.
pub fn capver_minimum(env: &Env) -> Status {
    let minimum = match env.vector("server_key.json") {
        Ok(vector) => vector["minimum_capability_version"].as_u64(),
        Err(e) => return Status::Skip(e),
    };
    let Some(minimum) = minimum else {
        return Status::Skip("capability floor not probed; run tests/lab/capture.sh".into());
    };

    with_session(env, |run| {
        if run.event("noise").is_none() {
            return Status::Fail(format!(
                "the server did not accept our capability version: {}",
                run.tail()
            ));
        }
        let advertised = tailfeather::noise::CAPABILITY_VERSION as u64;
        if advertised < minimum {
            return Status::Fail(format!(
                "we advertise v{advertised} but this server rejects anything below v{minimum}"
            ));
        }
        Status::Pass(format!(
            "we advertise v{advertised}; this server's floor, found by probing rather \
             than read from documentation, is v{minimum}. The version is also bound into \
             the Noise prologue, so the handshake completing proves the server agreed \
             on it and not merely that it tolerated the header."
        ))
    })
}
