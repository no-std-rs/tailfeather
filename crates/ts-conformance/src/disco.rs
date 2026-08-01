//! The disco checks, against a real Tailscale client.
//!
//! Nothing here can be answered by our own code. A disco message is sealed in a
//! NaCl box, so it either opens on the other side or the exchange is silent —
//! there is no partial credit and no error message to interpret. The first
//! version of `ts-disco` appended the Poly1305 tag the way every other AEAD in
//! this project does, sealed and opened perfectly against itself, and was
//! rejected by `tailscaled` with "failed to open naclbox (wrong rcpt?)". NaCl
//! puts the tag first.
//!
//! So the reference client is the oracle, in both directions: it must answer our
//! probe, and it must accept our answer to its own.

use std::io::{BufRead, BufReader};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::mpsc;

use serde_json::Value;

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

/// How long the harness listens for disco traffic.
const LISTEN_SECONDS: u64 = 20;

/// How long to wait for the harness to say it is listening before nudging the
/// reference client anyway.
///
/// This is a backstop, not the normal path. The nudge used to fire on a fixed
/// eight-second sleep, which was the flakiest thing in the suite: too early and
/// the probe arrives before the socket is bound and the ping is simply lost;
/// too late and it eats the listening window. Both failures look like "disco
/// does not work".
///
/// The harness already announces readiness on its event stream, so the nudge now
/// waits for that instead. Reaching this timeout means the harness never became
/// ready, and firing regardless produces a clearer failure than hanging.
const READY_TIMEOUT_SECONDS: u64 = 15;

/// The event the harness emits once its disco socket is bound and its endpoint
/// has been advertised to the server.
const READY_EVENT: &str = "self";

/// How long to wait for the reference client to learn about us.
///
/// Our own readiness is not the precondition for the nudge. `tailscale ping`
/// only probes a peer the client already has in its netmap, so nudging as soon
/// as *we* are listening makes the ping a no-op and `disco.pong` fails —
/// measured, not assumed: conditioning on our own readiness alone failed three
/// runs out of three. The condition that matters is the server having pushed
/// our node to the reference client, which is what `peer_is_visible` polls for.
const PEER_VISIBLE_TIMEOUT_SECONDS: u64 = 20;
const POLL_INTERVAL_MS: u64 = 250;

/// How many times to nudge before giving up.
const NUDGE_ATTEMPTS: usize = 4;

/// What the stdout reader tells the main thread about, as it happens.
enum Signal {
    /// The harness has bound its socket and advertised its endpoint.
    Ready,
    /// The harness answered a probe from the reference client.
    PingAnswered,
}

/// Where the lab's reference client listens.
fn socket_path(env: &Env) -> std::path::PathBuf {
    env.vectors
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."))
        .join(".lab/tailscaled.sock")
}

/// One disco session: our probes, and the reference client's.
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

    let socket = socket_path(env);
    if !socket.exists() {
        return Err(
            "no reference client; start one with tests/lab/lab.sh reference — disco cannot \
             be checked against our own code"
                .into(),
        );
    }

    let state = harness.scratch("disco");
    let state = state.to_string_lossy().into_owned();
    let port = port.to_string();

    let registered = harness.run(&[
        "register", &state, host, &port, auth_key,
        "--hostname", env.scope.hostname(),
    ])?;
    let Some(node_key) = registered
        .event("registered")
        .and_then(|e| e["node"].as_str())
    else {
        return Err(format!("could not register: {}", registered.tail()));
    };

    // The reference client only probes a peer it is trying to reach, so it has
    // to be given a reason. Its own address for us comes from the netmap, which
    // means asking the server what address we were given.
    let address = tailnet_address(node_key)?;

    // The harness listens while a nudge is delivered partway through.
    let seconds = LISTEN_SECONDS.to_string();
    let mut child = Command::new(harness.path())
        .args(["disco", &state, host, &port, &seconds])
        .args(["--hostname", env.scope.hostname()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start the harness: {e}"))?;

    // Read the harness's stdout on a thread, both to learn when it is ready and
    // because a piped child that fills its stdout buffer blocks forever. The
    // previous version only read after the process exited, which worked solely
    // because the output happened to stay under the pipe capacity.
    let stdout = child.stdout.take().expect("stdout was piped");
    let (event_tx, event_rx) = mpsc::channel::<Signal>();
    let reader = std::thread::spawn(move || {
        let mut collected = String::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(json) = line.strip_prefix("#EVT ")
                && let Ok(event) = serde_json::from_str::<Value>(json)
            {
                match event["event"].as_str() {
                    Some(READY_EVENT) => {
                        let _ = event_tx.send(Signal::Ready);
                    }
                    // The reference client probed us and we answered — the
                    // condition `disco.pong` is waiting for.
                    Some("ping") => {
                        let _ = event_tx.send(Signal::PingAnswered);
                    }
                    _ => {}
                }
            }
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });

    // Wait for readiness rather than for the clock: first ours, then the
    // reference client's view of us.
    let mut ready = false;
    let mut answered = false;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECONDS);
    while std::time::Instant::now() < deadline && !ready {
        match event_rx.recv_timeout(std::time::Duration::from_millis(POLL_INTERVAL_MS)) {
            Ok(Signal::Ready) => ready = true,
            Ok(Signal::PingAnswered) => answered = true,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let visible = wait_for_peer(&socket, node_key, PEER_VISIBLE_TIMEOUT_SECONDS);

    // Nudge until the harness reports having answered a probe, rather than once
    // and hoping.
    //
    // A single nudge is still a race even once the peer is visible: the
    // reference client can have our node in its netmap without yet having our
    // endpoint, and `tailscale ping` then resolves over DERP without ever
    // probing the address we are listening on. That failed two runs in three.
    // Retrying costs nothing when the first attempt works, which is the usual
    // case.
    let mut nudge = None;
    for _ in 0..NUDGE_ATTEMPTS {
        if answered {
            break;
        }
        // `--until-direct=false` because the tunnel itself is not up: what is
        // being checked is the path discovery, not the traffic that would
        // follow it.
        nudge = Command::new("sudo")
            .args([
                "-n",
                "tailscale",
                &format!("--socket={}", socket.display()),
                "ping",
                "--c",
                "3",
                "--until-direct=false",
                &address,
            ])
            .output()
            .ok();

        // Give the answer a moment to come back before trying again.
        let wait = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < wait && !answered {
            match event_rx.recv_timeout(std::time::Duration::from_millis(POLL_INTERVAL_MS)) {
                Ok(Signal::PingAnswered) => answered = true,
                Ok(Signal::Ready) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    let status = child
        .wait()
        .map_err(|e| format!("the harness did not finish: {e}"))?;
    let stdout = reader.join().unwrap_or_default();
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        use std::io::Read as _;
        let _ = handle.read_to_string(&mut stderr);
    }

    let mut run = Run::from_parts(stdout, stderr, status.code());
    if !ready {
        run.note = format!(
            "the harness never emitted its '{READY_EVENT}' event within              {READY_TIMEOUT_SECONDS}s, so the nudge was sent blind; "
        );
    }
    if !visible {
        run.note.push_str(&format!(
            "the reference client still did not list {node_key} as a peer after \
             {PEER_VISIBLE_TIMEOUT_SECONDS}s, so its probe had nothing to aim at; "
        ));
    }
    if let Some(nudge) = nudge {
        run.note
            .push_str(&String::from_utf8_lossy(&nudge.stdout));
    }
    Ok(run)
}

/// Poll the reference client until it lists `node_key` among its peers.
///
/// Returns whether it appeared. This replaces a fixed sleep, so the nudge is
/// sent as soon as the precondition holds rather than after a hopeful interval.
///
/// Keyed on the node key, not the tailnet address. Headscale reuses addresses
/// as nodes come and go, so a stale peer left over from an earlier run can carry
/// the address this run was just assigned — which satisfied an address-based
/// check instantly and put the flakiness straight back. The node key is freshly
/// generated per run and cannot collide that way.
fn wait_for_peer(socket: &std::path::Path, node_key: &str, timeout_seconds: u64) -> bool {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    while std::time::Instant::now() < deadline {
        if peer_is_visible(socket, node_key) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }
    false
}

/// Whether the reference client's own status lists `node_key` as a peer.
fn peer_is_visible(socket: &std::path::Path, node_key: &str) -> bool {
    let Ok(output) = Command::new("sudo")
        .args([
            "-n",
            "tailscale",
            &format!("--socket={}", socket.display()),
            "status",
            "--json",
        ])
        .output()
    else {
        return false;
    };
    let Ok(status) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    let Some(peers) = status["Peer"].as_object() else {
        return false;
    };
    // The map is keyed by node key; `PublicKey` repeats it inside each entry.
    peers.iter().any(|(key, peer)| {
        key == node_key || peer["PublicKey"].as_str() == Some(node_key)
    })
}

/// The tailnet address the server gave a node key.
fn tailnet_address(node_key: &str) -> Result<String, String> {
    let nodes = crate::headscale::nodes()?;
    let node = crate::headscale::find_by_node_key(&nodes, node_key)
        .ok_or("the registered node is absent from the server")?;
    node.addresses
        .iter()
        .find(|address| address.contains('.'))
        .cloned()
        .ok_or_else(|| "the node has no IPv4 tailnet address".into())
}

fn with_session(env: &Env, f: impl FnOnce(&Run) -> Status) -> Status {
    match session(env) {
        Ok(run) => f(run),
        Err(reason) => Status::Skip(reason.clone()),
    }
}

/// We probe, and a real client answers.
pub fn ping(env: &Env) -> Status {
    with_session(env, |run| {
        let pongs = run
            .event("disco")
            .and_then(|e| e["pongs"].as_u64())
            .unwrap_or(0);
        if pongs == 0 {
            return Status::Fail(format!(
                "no pong from the reference client, so it could not open our box: {}",
                run.tail()
            ));
        }
        let Some(pong) = run.event("pong") else {
            return Status::Fail("a pong was counted but not reported".into());
        };
        if pong["txid_matches"] != Value::Bool(true) {
            return Status::Fail(
                "the pong did not echo our transaction id, so it cannot be attributed to \
                 the probe — or to the path the probe took"
                    .into(),
            );
        }
        Status::Pass(format!(
            "a real tailscaled opened our NaCl box and answered: it sees us at {}, and \
             echoed the transaction id that ties the answer to the path. The box is \
             unforgeable, so this is the whole format — magic, key, nonce, and NaCl's \
             tag-before-ciphertext layout — verified at once.",
            pong["observed"].as_str().unwrap_or("(unreported)")
        ))
    })
}

/// A real client probes us, and accepts our answer.
pub fn pong(env: &Env) -> Status {
    with_session(env, |run| {
        let pings = run
            .event("disco")
            .and_then(|e| e["pings"].as_u64())
            .unwrap_or(0);
        if pings == 0 {
            return Status::Fail(format!(
                "the reference client never probed us, so our pong was not exercised: {}",
                run.tail()
            ));
        }

        // Our own count says we answered. That it was *accepted* is the
        // reference client's to report: `tailscale ping` prints a pong line
        // only when it got a valid one back.
        let accepted = run.note.contains("pong from");
        if !accepted {
            return Status::Fail(format!(
                "we answered {pings} ping(s) but the reference client did not report a \
                 valid pong: {}",
                run.note.trim()
            ));
        }
        Status::Pass(format!(
            "the reference client probed us on the shared socket and accepted our answer: \
             {}. Its own words, not ours — a pong it could not open would simply be \
             silence.",
            run.note
                .lines()
                .find(|line| line.contains("pong from"))
                .unwrap_or("")
                .trim()
        ))
    })
}

/// Our endpoints reach the server, and peers use them.
pub fn endpoints(env: &Env) -> Status {
    with_session(env, |run| {
        let Some(advertised) = run
            .event("endpoint")
            .and_then(|e| e["advertised"].as_str())
        else {
            return Status::Fail(format!("no endpoint was advertised: {}", run.tail()));
        };
        if advertised.starts_with("127.") || advertised.starts_with("0.0.0.0") {
            return Status::Fail(format!(
                "advertised {advertised}, which no peer on another machine can reach"
            ));
        }

        // The proof is not that we sent it, but that a peer used it. The
        // reference client had no other way to learn where to probe.
        let pings = run
            .event("disco")
            .and_then(|e| e["pings"].as_u64())
            .unwrap_or(0);
        if pings == 0 {
            return Status::Fail(format!(
                "advertised {advertised} but nothing arrived there, so the server \
                 either did not accept the endpoint or did not pass it on"
            ));
        }

        let observed = run
            .event("pong")
            .and_then(|e| e["observed"].as_str())
            .unwrap_or("");
        Status::Pass(format!(
            "advertised {advertised} in the MapRequest, and the reference client — which \
             had no other source for it — probed us there. Its pong reports seeing us at \
             {observed}. No STUN: this is the address on our side of any NAT, which is \
             enough on a LAN and is what the pong's observed address exists to correct."
        ))
    })
}
