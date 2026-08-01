//! Advertising this node as an exit node.
//!
//! There is no flag for it. A node becomes an exit node by advertising the two
//! default routes in its `Hostinfo.RoutableIPs`, and then only once an operator
//! approves them — a node that could route all traffic for a tailnet by simply
//! saying so would be a serious hole. Both halves are checked here, because
//! either alone leaves the node unusable as an exit.

use std::sync::OnceLock;

use crate::harness::NOT_BUILT;
use crate::{Env, Status, Target, headscale};

/// Both default routes. A node offering only the IPv4 one is not an exit node
/// as far as a client is concerned.
const DEFAULT_ROUTES: [&str; 2] = ["0.0.0.0/0", "::/0"];

struct Session {
    node_id: u64,
    before: headscale::Routes,
    after: headscale::Routes,
}

fn session(env: &Env) -> &'static Result<Session, String> {
    static SESSION: OnceLock<Result<Session, String>> = OnceLock::new();
    SESSION.get_or_init(|| start(env))
}

fn start(env: &Env) -> Result<Session, String> {
    let Some(harness) = &env.harness else {
        return Err(NOT_BUILT.into());
    };
    if env.target == Target::TailscaleSaas {
        return Err("the hosted service is HTTPS-only and there is no TLS client yet".into());
    }
    let (Some((host, port)), Some(auth_key)) = (&env.control_address, &env.preauth_key) else {
        return Err("no lab; start one with tests/lab/lab.sh up".into());
    };

    let state = harness.scratch("exit");
    let state = state.to_string_lossy().into_owned();
    let port = port.to_string();

    let run = harness.run(&[
        "register", &state, host, &port, auth_key, "--exit-node",
        "--hostname", env.scope.hostname(),
    ])?;
    let Some(node_key) = run.event("registered").and_then(|e| e["node"].as_str()) else {
        return Err(format!("could not register: {}", run.tail()));
    };
    if run.event("registered").and_then(|e| e["exit_node"].as_bool()) != Some(true) {
        return Err("the harness did not report advertising exit routes".into());
    }

    let nodes = headscale::nodes()?;
    let node = headscale::find_by_node_key(&nodes, node_key)
        .ok_or("the registered node is absent from the server")?;

    let before = headscale::routes(node.id)?;
    headscale::approve_routes(node.id, &DEFAULT_ROUTES)?;
    let after = headscale::routes(node.id)?;

    Ok(Session {
        node_id: node.id,
        before,
        after,
    })
}

pub fn advertise(env: &Env) -> Status {
    let session = match session(env) {
        Ok(session) => session,
        Err(reason) => return Status::Skip(reason.clone()),
    };

    let missing: Vec<&str> = DEFAULT_ROUTES
        .iter()
        .copied()
        .filter(|route| !session.before.available.contains(&route.to_string()))
        .collect();
    if !missing.is_empty() {
        return Status::Fail(format!(
            "the server did not see {} advertised, so Hostinfo.RoutableIPs did not reach it",
            missing.join(" and ")
        ));
    }

    // Before approval the node advertises but serves nothing. That gap is the
    // point of the mechanism, so it is asserted rather than assumed.
    if !session.before.approved.is_empty() {
        return Status::Fail(format!(
            "routes were approved before anyone approved them: {:?}",
            session.before.approved
        ));
    }

    for route in DEFAULT_ROUTES {
        if !session.after.approved.contains(&route.to_string()) {
            return Status::Fail(format!("{route} was not approved"));
        }
        if !session.after.serving.contains(&route.to_string()) {
            return Status::Fail(format!(
                "{route} is approved but the node is not serving it"
            ));
        }
    }

    Status::Pass(format!(
        "the no_std harness advertised {} in Hostinfo.RoutableIPs and the server listed \
         both as available on node {} while approving neither — a node cannot make \
         itself an exit. After `headscale nodes approve-routes` it serves both. The \
         data plane behind this is already verified: exit.forward.udp and \
         exit.forward.tcp on real hardware.",
        DEFAULT_ROUTES.join(" and "),
        session.node_id
    ))
}
