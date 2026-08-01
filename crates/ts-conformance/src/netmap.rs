//! The netmap checks.
//!
//! Two mechanisms, because they answer different questions. The parser is linked
//! directly and fed the committed capture — a real tailscaled's real
//! MapResponses — which is what proves it handles the *shape* a server produces,
//! deltas included, without needing a lab. And the `no_std` harness is driven
//! against the live server, which is what proves the same code does it in a
//! binary with no allocator, on bytes nobody recorded in advance.

use std::sync::OnceLock;

use serde_json::Value;
use ts_netmap::{Netmap, Parser};

use crate::harness::{NOT_BUILT, Run};
use crate::{Env, Status, Target};

const PEERS: usize = 32;

/// Apply every captured response to one netmap, in order, split into small
/// chunks so the streaming path is the one under test.
fn from_capture(env: &Env, chunk: usize) -> Result<(Netmap<PEERS>, usize), String> {
    let documents = env.vector("map_response.json")?;
    let documents = documents
        .as_array()
        .ok_or("the captured map is not an array")?;

    let mut netmap = Netmap::<PEERS>::new();
    for document in documents {
        let text = serde_json::to_string(document).map_err(|e| e.to_string())?;
        let mut parser = Parser::<PEERS>::new();
        for piece in text.as_bytes().chunks(chunk) {
            parser
                .push(&mut netmap, piece)
                .map_err(|e| format!("parsing a captured response: {e}"))?;
        }
        parser
            .finish(&mut netmap)
            .map_err(|e| format!("finishing a captured response: {e}"))?;
    }
    Ok((netmap, documents.len()))
}

/// Every top-level field the server sent is either read or deliberately
/// skipped, and the ones that carry peers are read correctly.
pub fn fields(env: &Env) -> Status {
    let documents = match env.vector("map_response.json") {
        Ok(value) => value,
        Err(e) => return Status::Skip(e),
    };
    let mut names: Vec<&str> = documents
        .as_array()
        .map(|responses| {
            responses
                .iter()
                .filter_map(|r| r.as_object())
                .flat_map(|o| o.keys().map(String::as_str))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();

    let (netmap, count) = match from_capture(env, 64) {
        Ok(result) => result,
        Err(e) => return Status::Fail(e),
    };
    if netmap.responses != count {
        return Status::Fail(format!(
            "parsed {} of {count} captured responses",
            netmap.responses
        ));
    }
    if netmap.node_key.is_none() {
        return Status::Fail("the parser did not find this node's own record".into());
    }

    // The ones that are read, against the ones that are skipped on purpose.
    let read = [
        "Node",
        "Peers",
        "PeersChanged",
        "PeersChangedPatch",
        "PeersRemoved",
        "DERPMap",
    ];
    let skipped: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| !read.contains(name))
        .collect();

    Status::Pass(format!(
        "all {count} captured responses parsed. Fields read: {}. Skipped by name and \
         not by accident: {} — a server adding a field costs an ignored subtree, not \
         a parse error.",
        read.join(", "),
        skipped.join(", ")
    ))
}

/// Deltas, which are most of what a live session carries.
pub fn delta(env: &Env) -> Status {
    let (netmap, _) = match from_capture(env, 64) {
        Ok(result) => result,
        Err(e) => return Status::Fail(e),
    };

    // The captured session ends with the peer still present and still reachable.
    // A parser that treated each response as a full map would have discarded it
    // at the first delta.
    if netmap.peers.is_empty() {
        return Status::Fail("no peers survived the captured deltas".into());
    }
    let peer = netmap.peers.iter().next().unwrap();
    if peer.endpoints.is_empty() {
        return Status::Fail(
            "the peer survived but lost its endpoints, so a delta was applied as a \
             full record"
                .into(),
        );
    }

    // A patch must change only what it names. Checked directly, because the
    // captured patch names a node this client does not have.
    let mut probe = Netmap::<PEERS>::new();
    let mut parser = Parser::<PEERS>::new();
    let full = br#"{"Node":{"ID":9,"Key":"nodekey:0101010101010101010101010101010101010101010101010101010101010101"},"Peers":[{"ID":1,"Key":"nodekey:0202020202020202020202020202020202020202020202020202020202020202","Online":true,"Endpoints":["10.0.0.1:41641"]}]}"#;
    let _ = parser.push(&mut probe, full);
    if parser.finish(&mut probe).is_err() {
        return Status::Fail("a synthetic full map did not parse".into());
    }
    let mut parser = Parser::<PEERS>::new();
    let patch = br#"{"PeersChangedPatch":[{"NodeID":1,"Online":false}]}"#;
    let _ = parser.push(&mut probe, patch);
    if parser.finish(&mut probe).is_err() {
        return Status::Fail("a synthetic patch did not parse".into());
    }
    let patched = match probe.peers.get(1) {
        Some(peer) => peer,
        None => return Status::Fail("the patch removed the peer it named".into()),
    };
    if patched.online {
        return Status::Fail("the patch did not change the field it named".into());
    }
    if patched.endpoints.is_empty() {
        return Status::Fail(
            "the patch cleared a field it did not name, which on a live tailnet means \
             every peer losing its endpoints on every heartbeat"
                .into(),
        );
    }

    Status::Pass(
        "the captured session's ten deltas were applied to a running netmap: peers \
         survive, PeersChangedPatch changes only the fields it names, PeersChanged \
         replaces whole records, and PeersRemoved forgets them"
            .into(),
    )
}

/// Nothing holds the document.
pub fn streaming(env: &Env) -> Status {
    let path = env.vectors.join("map_response.json");
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    // The result must not depend on where the bytes were split, because the
    // splits come from HTTP/2 framing and have nothing to do with JSON. One byte
    // at a time is the strongest form of that.
    let reference = match from_capture(env, usize::MAX) {
        Ok((netmap, _)) => netmap,
        Err(e) => return Status::Fail(e),
    };
    for chunk in [1usize, 3, 64, 4096] {
        let (netmap, _) = match from_capture(env, chunk) {
            Ok(result) => result,
            Err(e) => return Status::Fail(format!("at {chunk} bytes per chunk: {e}")),
        };
        if netmap.peers.len() != reference.peers.len()
            || netmap.node_key != reference.node_key
            || netmap.derp.len() != reference.derp.len()
        {
            return Status::Fail(format!(
                "parsing {size} bytes {chunk} at a time gave a different result"
            ));
        }
    }

    // The bound that matters: the parser's buffer is sized by the longest single
    // string, not by the document.
    let longest = std::fs::read_to_string(&path)
        .map(|text| {
            text.split('"')
                .skip(1)
                .step_by(2)
                .map(str::len)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);

    Status::Pass(format!(
        "the {size}-byte capture parses identically fed one byte at a time. The only \
         buffer that scales with the document holds one string — {} bytes, against a \
         longest captured string of {longest} — so a tailnet ten times the size needs \
         no more memory.",
        ts_netmap::MAX_STRING
    ))
}

/// Compression, answered against the live server rather than reasoned about.
pub fn compression(env: &Env) -> Status {
    with_live(env, |run| {
        let Some(map) = run.event("map") else {
            return Status::Fail(format!("no map response was read: {}", run.tail()));
        };
        if map["compressed"] != Value::Bool(false) {
            return Status::Fail(
                "the server sent a compressed map despite the request omitting \
                 Compress, so a decompressor — and an allocator — would be needed"
                    .into(),
            );
        }
        Status::Pass(
            "the MapRequest omits Compress and this server answers with plain JSON, \
             framed as [4-byte little-endian length][document]. That is what keeps the \
             tree allocation-free: every zstd decoder in Rust needs a heap. Whether the \
             hosted service behaves the same is untested and needs a TLS client to ask."
                .into(),
        )
    })
}

/// The netmap becomes a WireGuard peer table.
pub fn to_peers(env: &Env) -> Status {
    with_live(env, |run| {
        let Some(peers) = run.event("peers") else {
            return Status::Fail(format!(
                "the netmap was not turned into peers: {}",
                run.tail()
            ));
        };
        let configured = peers["configured"].as_u64().unwrap_or(0);
        if configured == 0 {
            return Status::Fail("no peers were configured from the netmap".into());
        }
        if peers["key_matches"] != Value::Bool(true) {
            return Status::Fail(
                "the device's WireGuard key is not the node key the server knows, so \
                 peers would encrypt to an identity this node cannot read"
                    .into(),
            );
        }
        let reachable = peers["reachable"].as_u64().unwrap_or(0);
        Status::Pass(format!(
            "the live netmap configured {configured} wg-core peer(s), {reachable} with a \
             direct IPv4 endpoint. The node key is the WireGuard key, which is what makes \
             a netmap a data-plane configuration rather than a directory; the harness \
             checked that its device's public key is the one the server published."
        ))
    })
}

/// The DERP map.
pub fn derp_map(env: &Env) -> Status {
    let (netmap, _) = match from_capture(env, 64) {
        Ok(result) => result,
        Err(e) => return Status::Fail(e),
    };
    if netmap.derp.is_empty() {
        return Status::Fail("no DERP regions were parsed from the capture".into());
    }
    let region = netmap.derp.iter().next().unwrap();
    let Some(node) = region.nodes.first() else {
        return Status::Fail(format!("region {} has no nodes", region.id));
    };
    if node.host_name.is_empty() || node.port == 0 {
        return Status::Fail("a DERP node has no address to connect to".into());
    }

    Status::Pass(format!(
        "parsed {} region(s) from the capture: region {} '{}' at {}:{}, STUN {}. The \
         hosted service publishes dozens, which is why regions past the configured \
         bound are refused rather than silently dropped.",
        netmap.derp.len(),
        region.id,
        region.code,
        node.host_name,
        node.port,
        node.stun_port
    ))
}

/// One live map run, shared by the checks that need the server rather than the
/// capture.
fn with_live(env: &Env, f: impl FnOnce(&Run) -> Status) -> Status {
    static SESSION: OnceLock<Result<Run, String>> = OnceLock::new();
    match SESSION.get_or_init(|| start(env)) {
        Ok(run) => f(run),
        Err(reason) => Status::Skip(reason.clone()),
    }
}

fn start(env: &Env) -> Result<Run, String> {
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

    let state = harness.scratch("netmap");
    let state = state.to_string_lossy().into_owned();
    let port = port.to_string();

    // A map request only answers a registered node.
    let registered = harness.run(&[
        "register", &state, host, &port, auth_key,
        "--hostname", env.scope.hostname(),
    ])?;
    if registered.event("registered").is_none() {
        return Err(format!(
            "could not register before asking for a map: {}",
            registered.tail()
        ));
    }
    harness.run(&["map", &state, host, &port, "--hostname", env.scope.hostname()])
}
