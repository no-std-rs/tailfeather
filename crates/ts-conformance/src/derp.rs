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
        return Err("the hosted service is HTTPS-only and there is no TLS client yet".into());
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
        let run = harness.run(&["register", &state, host, &port, auth_key,
            "--hostname", env.scope.hostname()])?;
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
        return Status::Fail(format!("the relay did not deliver the packet: {}", run.tail()));
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
