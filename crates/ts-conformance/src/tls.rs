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
//! service. It used to say something stronger and false — that
//! `controlplane.tailscale.com` serves an RSA-PSS-only chain and is therefore
//! unreachable without an allocation-free RSA verifier. Measured, it is
//! dual-chain and serves ECDSA to a client offering ECDSA sigalgs; see
//! `tests/vectors/hosted_tls.json` and the module comment in
//! `harness/src/tls.rs` for what actually stands in the way.
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
            "no hosted TLS run yet. Not for the reason this check used to give: \
             controlplane.tailscale.com serves ECDSA to a client offering ECDSA \
             sigalgs (measured, tests/vectors/hosted_tls.json), and embedded-tls \
             already offers the P-256 group its IPv4 frontend requires. What is \
             missing is the p384 feature for the ecdsa-with-SHA384 chain \
             signatures — allocation-free, unlike rsa — an anchor model that can \
             stop before the topmost presented certificate, and MAX_CERT raised \
             above the measured 3411-byte chain. See harness/src/tls.rs"
                .into(),
        );
    }

    let root = lab_root(env);
    let ca = root.join(".lab/tls/ca.der");
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

    if session.trusted.event("handshake").and_then(|e| e["verified"].as_bool()) != Some(true) {
        return Status::Fail(format!(
            "the TLS handshake did not complete: {}",
            session.trusted.tail()
        ));
    }
    // Bytes had to cross it in both directions, not merely a handshake.
    let Some(key) = session
        .trusted
        .event("key")
        .and_then(|e| e["key"].as_str())
    else {
        return Status::Fail("no control-plane traffic crossed the TLS connection".into());
    };

    // The negative cases are what make the positive one mean anything.
    if session.wrong_anchor.event("handshake").is_some()
        || session.wrong_anchor.event("tls").map(|e| e["result"].clone())
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
         This is the lab's front, not the hosted service: hosted serves a four-entry \
         chain whose intermediates are ecdsa-with-SHA384, which needs embedded-tls's \
         p384 feature and an anchor set rather than a single pinned root.",
        &key[..21]
    ))
}
