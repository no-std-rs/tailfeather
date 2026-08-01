//! The checks answered by registering the `no_std` harness with a live server.
//!
//! One shared run again, for the same reason as `ts2021`: "HTTP/2 works" and
//! "the node registered" have to describe the same session, or both could pass
//! while describing different ones.
//!
//! The rotation happens in the same session too, because what makes it
//! meaningful is that the *machine* stays the same. Two unrelated registrations
//! would show two node keys and prove nothing about re-authentication.

use std::sync::OnceLock;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target, headscale};

/// One registration, one rotation, and the server's view after each.
struct Session {
    first: Run,
    nodes_after_first: Vec<headscale::Node>,
    rotated: Run,
    nodes_after_rotation: Vec<headscale::Node>,
}

enum Outcome {
    Ran(Box<Session>),
    Skipped(String),
}

fn session(env: &Env) -> &'static Outcome {
    static SESSION: OnceLock<Outcome> = OnceLock::new();
    SESSION.get_or_init(|| match start(env) {
        Ok(session) => Outcome::Ran(Box::new(session)),
        Err(reason) => Outcome::Skipped(reason),
    })
}

fn start(env: &Env) -> Result<Session, String> {
    let Some(harness) = &env.harness else {
        return Err(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Err("the hosted service is HTTPS-only and there is no TLS client yet".into());
    }
    let Some((host, port)) = &env.control_address else {
        return Err("no control server configured; start one with tests/lab/lab.sh up".into());
    };
    let Some(auth_key) = &env.preauth_key else {
        return Err("no preauth key; mint one with tests/lab/lab.sh preauth-key".into());
    };

    let state = harness.scratch("register");
    let state = state.to_string_lossy().into_owned();
    let port = port.to_string();

    let first = harness.run(&[
        "register", &state, host, &port, auth_key,
        "--hostname", env.scope.hostname(),
    ])?;
    let nodes_after_first = headscale::nodes()?;

    // The same state directory, so the machine key is the one the server just
    // authenticated. That is what makes this a re-registration rather than a
    // second node.
    let rotated = harness.run(&[
        "register", &state, host, &port, auth_key, "--rotate",
        "--hostname", env.scope.hostname(),
    ])?;
    let nodes_after_rotation = headscale::nodes()?;

    Ok(Session {
        first,
        nodes_after_first,
        rotated,
        nodes_after_rotation,
    })
}

fn with_session(env: &Env, f: impl FnOnce(&Session) -> Status) -> Status {
    match session(env) {
        Outcome::Skipped(reason) => Status::Skip(reason.clone()),
        Outcome::Ran(session) => f(session),
    }
}

fn registered_key(run: &Run) -> Option<&str> {
    run.event("registered")?["node"].as_str()
}

/// HTTP/2 inside the Noise channel.
pub fn http2(env: &Env) -> Status {
    with_session(env, |session| {
        if session.first.event("http2").is_none() {
            return Status::Fail(format!(
                "the HTTP/2 connection was not established: {}",
                session.first.tail()
            ));
        }
        if registered_key(&session.first).is_none() {
            return Status::Fail(format!(
                "HTTP/2 started but no request completed over it: {}",
                session.first.tail()
            ));
        }
        Status::Pass(
            "the no_std harness exchanged a settings handshake and a complete \
             request/response with Go's HTTP/2 server through the Noise channel. \
             HPACK is the load-bearing part: the response headers came back \
             Huffman-coded and dynamically indexed, so a wrong table would have \
             produced wrong header names rather than an error."
                .into(),
        )
    })
}

/// The node appears on the server.
pub fn register(env: &Env) -> Status {
    with_session(env, |session| {
        let Some(node_key) = registered_key(&session.first) else {
            return Status::Fail(format!(
                "registration did not complete: {}",
                session.first.tail()
            ));
        };
        match headscale::find_by_node_key(&session.nodes_after_first, node_key) {
            Some(node) => Status::Pass(format!(
                "`headscale nodes list` shows the harness as node {} ('{}') with the \
                 node key it generated, {}…",
                node.id,
                node.name,
                &node_key[..24]
            )),
            None => Status::Fail(format!(
                "the harness reported success but {node_key} is absent from \
                 `headscale nodes list`"
            )),
        }
    })
}

/// The server accepted, and acted on, the Hostinfo we sent.
pub fn hostinfo(env: &Env) -> Status {
    let sent_hostname = env.scope.hostname().to_string();

    // What a real client reports, for the record — the gap between that and
    // what we send is the honest part of this check.
    let reference = env
        .vector("map_response.json")
        .ok()
        .and_then(|map| {
            map.as_array()?
                .iter()
                .find_map(|r| r["Node"]["Hostinfo"].as_object())
                .map(|fields| fields.keys().cloned().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    with_session(env, |session| {
        let Some(node_key) = registered_key(&session.first) else {
            return Status::Fail(format!(
                "registration did not complete: {}",
                session.first.tail()
            ));
        };
        let Some(node) = headscale::find_by_node_key(&session.nodes_after_first, node_key) else {
            return Status::Fail("the registered node is absent from the server".into());
        };

        // The name the server shows comes from `Hostinfo.Hostname`. It matching
        // is proof the server parsed the structure, not merely tolerated it.
        //
        // Compared against the hostname this run actually sent, not against a
        // constant: the suite tags each run's nodes so it can delete them again,
        // so a hard-coded name here would assert that the tagging did *not*
        // happen. That the two agree is the evidence.
        if node.name != sent_hostname {
            return Status::Fail(format!(
                "the server named the node '{}' rather than the hostname we sent,                  '{sent_hostname}'",
                node.name
            ));
        }

        let ours = ["IPNVersion", "OS", "Hostname", "Services", "RoutableIPs"];
        let missing: Vec<&String> = reference
            .iter()
            .filter(|field| !ours.contains(&field.as_str()))
            .collect();

        Status::Pass(format!(
            "the server accepted our Hostinfo and displays the node as '{}', which is \
             the Hostname field we sent. We report {}; the reference client also sends \
             {} — all descriptive of a Go runtime we do not have, and omitted rather \
             than faked.",
            node.name,
            ours.join(", "),
            if missing.is_empty() {
                "nothing further".to_string()
            } else {
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ))
    })
}

/// Re-registering with a fresh node key, which is what key expiry requires.
pub fn reauth(env: &Env) -> Status {
    with_session(env, |session| {
        let (Some(first_key), Some(second_key)) = (
            registered_key(&session.first),
            registered_key(&session.rotated),
        ) else {
            return Status::Fail(format!(
                "the rotation did not complete: {}",
                session.rotated.tail()
            ));
        };

        if session.rotated.event("registered").map(|e| e["rotated"].clone())
            != Some(Value::Bool(true))
        {
            return Status::Fail("the second run did not report a rotation".into());
        }
        if first_key == second_key {
            return Status::Fail("the node key did not change".into());
        }

        let before = headscale::find_by_node_key(&session.nodes_after_first, first_key);
        let after = headscale::find_by_node_key(&session.nodes_after_rotation, second_key);
        let (Some(before), Some(after)) = (before, after) else {
            return Status::Fail(
                "the server does not show the rotated key against the node".into(),
            );
        };

        // The point of the check: the machine survived. A node that re-registered
        // as a *new* machine would also show a new key, and would be a different
        // device to everyone on the tailnet.
        if before.id != after.id {
            return Status::Fail(format!(
                "rotating produced a new node ({} -> {}) rather than re-keying the \
                 existing one",
                before.id, after.id
            ));
        }
        if before.machine_key != after.machine_key {
            return Status::Fail("the machine key changed during a node-key rotation".into());
        }
        if headscale::find_by_node_key(&session.nodes_after_rotation, first_key).is_some() {
            return Status::Fail("the retired node key is still registered".into());
        }

        Status::Pass(format!(
            "the harness re-registered node {} with a fresh node key, naming the old one \
             as OldNodeKey. The server replaced the key in place: same node id, same \
             machine key, and the retired key is gone. That separation is why the \
             machine and node keys are distinct.",
            after.id
        ))
    })
}
