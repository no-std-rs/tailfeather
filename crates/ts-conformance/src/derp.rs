//! The DERP relay check.
//!
//! Two nodes connect to Headscale's embedded relay and one sends the other a
//! packet. Both endpoints are ours; the relay is not, and the relay is what is
//! under test. It decides whether the framing is valid, whether the sealed hello
//! proves we hold the node key we claim, and whether that key belongs to a node
//! it will carry traffic for — it turned an unregistered key away with
//! "admission controller: … not allowed", which is how that was learned.
//!
//! A relay that disagreed with any of it would simply never deliver.

use std::sync::OnceLock;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

fn session(env: &Env) -> &'static Result<Run, String> {
    static SESSION: OnceLock<Result<Run, String>> = OnceLock::new();
    SESSION.get_or_init(|| start(env))
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
    let (Some((host, port)), Some(auth_key)) = (&env.control_address, &env.preauth_key) else {
        return Err("no lab; start one with tests/lab/lab.sh up".into());
    };
    let port = port.to_string();

    // The relay only carries traffic for nodes the server knows, so both ends
    // have to be registered first.
    let mut directories = Vec::new();
    for name in ["derp-a", "derp-b"] {
        let state = harness.scratch(name);
        let state = state.to_string_lossy().into_owned();
        let run = harness.register(&[
            "register",
            &state,
            host,
            &port,
            auth_key,
            "--hostname",
            env.scope.hostname(),
        ])?;
        if run.event("registered").is_none() {
            return Err(format!("could not register {name}: {}", run.tail()));
        }
        directories.push(state);
    }

    harness.run(&["derp", host, &port, &directories[0], &directories[1]])
}

pub fn relay(env: &Env) -> Status {
    let run = match session(env) {
        Ok(run) => run,
        Err(reason) => return Status::Skip(reason.clone()),
    };

    let Some(connected) = run.event("derp-connected") else {
        return Status::Fail(format!(
            "no connection to the relay was established: {}",
            run.tail()
        ));
    };
    let Some(relayed) = run.event("relayed") else {
        return Status::Fail(format!(
            "the relay did not deliver the packet: {}",
            run.tail()
        ));
    };
    if relayed["intact"] != Value::Bool(true) {
        return Status::Fail("the relayed bytes were not the ones sent".into());
    }
    // Version 2 of the protocol adds the sender's key to a delivered packet;
    // without it a receiver has to guess who a packet came from.
    if relayed["from"] != connected["sender"] {
        return Status::Fail(
            "the relay attributed the packet to the wrong sender, or the sender key was \
             not read from the frame"
                .into(),
        );
    }

    Status::Pass(format!(
        "two registered nodes connected to Headscale's embedded DERP and one relayed {} \
         bytes to the other, delivered intact and attributed to the right sender. The \
         relay is the reference implementation here: it validated the framing, opened \
         the sealed hello proving each node holds the key it claims, and checked that \
         key against its node list — an unregistered one is refused outright.",
        relayed["bytes"].as_u64().unwrap_or(0)
    ))
}

/// The session survives an idle period longer than the server's keepalive.
///
/// What is asserted is survival and a second delivery, not that a `Ping` was
/// observed. Headscale's embedded relay sends `KeepAlive` on an idle connection
/// and a server-initiated `Ping` is not guaranteed, so requiring one would fail
/// for a reason that says nothing about this client. The frames that did arrive
/// are reported instead, which is what makes the length of the hold reviewable.
pub fn keepalive(env: &Env) -> Status {
    let run = match session(env) {
        Ok(run) => run,
        Err(reason) => return Status::Skip(reason.clone()),
    };

    let Some(held) = run.event("held") else {
        return Status::Fail(format!(
            "the session did not survive the idle hold: {}",
            run.tail()
        ));
    };
    if held["relayed"] != Value::Bool(true) {
        return Status::Fail(
            "the session outlived the hold but no longer relays, so the connection is open \
             and useless"
                .into(),
        );
    }
    let seconds = held["seconds"].as_u64().unwrap_or(0);
    if seconds == 0 {
        return Status::Fail("the hold reported no elapsed time".into());
    }

    Status::Pass(format!(
        "a registered DERP session sat idle for {seconds}s — past Headscale's keepalive \
         interval — answering {} ping(s) and receiving {} keepalive(s) and {} other \
         frame(s), then relayed a second packet successfully. The delivery is the claim; \
         the counts say how much idling was actually crossed, since a silent server would \
         make survival true but prove less.",
        held["pings"].as_u64().unwrap_or(0),
        held["keepalives"].as_u64().unwrap_or(0),
        held["other"].as_u64().unwrap_or(0),
    ))
}

/// A dropped connection can be replaced under the same registered node key.
pub fn reconnect(env: &Env) -> Status {
    let run = match session(env) {
        Ok(run) => run,
        Err(reason) => return Status::Skip(reason.clone()),
    };

    let Some(reconnected) = run.event("reconnected") else {
        return Status::Fail(format!(
            "the relay did not carry traffic after the receiver reconnected: {}",
            run.tail()
        ));
    };
    if reconnected["relayed"] != Value::Bool(true) {
        return Status::Fail(
            "the receiver reconnected but nothing was relayed to it afterwards".into(),
        );
    }

    Status::Pass(
        "the receiver's TCP connection was dropped and dialed again under the same \
         registered node key, and the relay delivered to it. Two things could have failed \
         and did not: the server re-admitting a key whose sealed hello it has already \
         seen, and its key-to-connection mapping releasing the dead session rather than \
         holding the key against a socket that no longer exists — which is what every \
         real network blip asks of it."
            .into(),
    )
}
