//! The TLS check.
//!
//! # What is being claimed
//!
//! Not "a handshake completed" — a client that negotiates a session without
//! checking who answered is worse than no TLS, because it costs the same and
//! implies a guarantee it does not provide. So this asserts three things: a real
//! TLS 1.3 chain verifies against a pinned anchor, a chain leading somewhere
//! else is refused, and a certificate for a different name is refused.
//!
//! The negative cases are the check. Without them, a verifier that returned
//! `Ok(())` unconditionally would pass.
//!
//! # And what is not being claimed
//!
//! A pass here is against the lab's TLS front, and says nothing about the hosted
//! service. The front uses an RSA certificate chain and TLS 1.3 RSA-PSS
//! CertificateVerify so the same allocation-free verifier used by firmware is
//! exercised end to end. The independently validated hosted captures live in
//! `tests/vectors/hosted_tls.json`.
//!
//! The distinction still matters for this check: the lab's front is one server
//! with one chain, and a hosted result has to be measured rather than inferred
//! from it.

use std::sync::OnceLock;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

struct Session {
    trusted: Run,
    wrong_anchor: Run,
    wrong_name: Run,
}

fn session(env: &Env) -> &'static Result<Session, String> {
    static SESSION: OnceLock<Result<Session, String>> = OnceLock::new();
    SESSION.get_or_init(|| start(env))
}

fn lab_root(env: &Env) -> std::path::PathBuf {
    env.vectors
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf()
}

fn start(env: &Env) -> Result<Session, String> {
    let Some(harness) = &env.harness else {
        return Err(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Err(
            "this repository conformance command does not provision hosted credentials or \
             devices. The shared verifier supports the measured ECDSA and RSA chains, \
             stops at embedded ISRG Root X2 or Root YR, and its record/certificate bounds are checked \
             against tests/vectors/hosted_tls.json. A hosted result still requires the \
             separate same-commit device acceptance run"
                .into(),
        );
    }

    if env.control_url.is_none() {
        return Err("no live lab control server behind the TLS front".into());
    }

    if !env.doctor.as_ref().is_some_and(|doctor| doctor.tls_front) {
        return Err("no live TLS front reported by tests/lab/lab.sh doctor".into());
    }

    let root = lab_root(env);
    let ca = root.join(".lab/tls-rsa/ca.der");
    if !ca.exists() {
        return Err("no TLS front; start one with tests/lab/tls.sh up".into());
    }
    let ca = ca.to_string_lossy().into_owned();

    let port = std::env::var("LAB_TLS_PORT").unwrap_or_else(|_| "8443".into());
    let trusted = harness.run(&["tls", "127.0.0.1", &port, "localhost", &ca])?;

    // An unrelated anchor, generated here so the check does not depend on one
    // being lying around.
    let other = root.join(".lab/tls/unrelated-ca.der");
    if !other.exists() {
        make_unrelated_ca(&other)?;
    }
    let other = other.to_string_lossy().into_owned();
    let wrong_anchor = harness.run(&["tls", "127.0.0.1", &port, "localhost", &other])?;
    let wrong_name = harness.run(&["tls", "127.0.0.1", &port, "wrong.example.com", &ca])?;

    Ok(Session {
        trusted,
        wrong_anchor,
        wrong_name,
    })
}

/// A self-signed CA that signed nothing, for the negative case.
fn make_unrelated_ca(path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let key = path.with_extension("key");
    let run = |args: &[&str]| -> Result<(), String> {
        let output = std::process::Command::new("openssl")
            .args(args)
            .output()
            .map_err(|e| format!("openssl: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "openssl {}: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    };
    run(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        &key.to_string_lossy(),
    ])?;
    run(&[
        "req",
        "-x509",
        "-new",
        "-key",
        &key.to_string_lossy(),
        "-sha256",
        "-days",
        "30",
        "-subj",
        "/CN=unrelated CA",
        "-outform",
        "DER",
        "-out",
        &path.to_string_lossy(),
    ])
}

pub fn tls(env: &Env) -> Status {
    let session = match session(env) {
        Ok(session) => session,
        Err(reason) => return Status::Skip(reason.clone()),
    };

    if session
        .trusted
        .event("handshake")
        .and_then(|e| e["verified"].as_bool())
        != Some(true)
    {
        return Status::Fail(format!(
            "the TLS handshake did not complete: {}",
            session.trusted.tail()
        ));
    }
    // Bytes had to cross it in both directions, not merely a handshake.
    let Some(key) = session.trusted.event("key").and_then(|e| e["key"].as_str()) else {
        return Status::Fail("no control-plane traffic crossed the TLS connection".into());
    };

    // The negative cases are what make the positive one mean anything.
    if session.wrong_anchor.event("handshake").is_some()
        || session
            .wrong_anchor
            .event("tls")
            .map(|e| e["result"].clone())
            == Some(Value::String("ok".into()))
    {
        return Status::Fail(
            "a chain that does not lead to the pinned anchor was accepted, so nothing is \
             being verified"
                .into(),
        );
    }
    if session.wrong_name.event("handshake").is_some() {
        return Status::Fail(
            "a certificate for a different name was accepted, so an attacker with any \
             valid certificate could impersonate the server"
                .into(),
        );
    }

    Status::Pass(format!(
        "TLS 1.3 against a real server with the chain verified against a pinned anchor \
         and the hostname checked; the control plane's key came back over it ({}…). A \
         chain leading elsewhere and a certificate for another name were both refused. \
         This is the lab's front, not the hosted service; hosted acceptance is a separate \
         same-commit device run.",
        &key[..21]
    ))
}
