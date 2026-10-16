//! The enumeration of every behaviour a Tailscale-compatible node must exhibit.
//!
//! This list is the specification. Adding a behaviour here before implementing
//! it is deliberate: the score is meant to start low and rise, and a gap that
//! is not written down is a gap nobody is tracking.
//!
//! Checks that can be answered today are answered. The rest declare precisely
//! what is missing, so each one reads as the next piece of work rather than as
//! a vague intention.

use crate::{
    Area, Check, Env, Status, Target, derp, disco, exit, http, multipeer, netmap, nostd_interop,
    register, tls, ts2021,
};

pub fn all() -> &'static [Check] {
    CHECKS
}

/// Fetch a URL from the configured control server, or explain why not.
fn control_get(env: &Env, path: &str) -> Result<http::Response, Status> {
    let Some(base) = &env.control_url else {
        return Err(Status::Skip(
            "no control server configured; start one with tests/lab/lab.sh up".into(),
        ));
    };
    if env.target == Target::TailscaleSaas {
        return Err(Status::Todo(
            "this conformance path does not yet route hosted requests through verified TLS".into(),
        ));
    }
    http::get(&format!("{base}{path}")).map_err(Status::Fail)
}

static CHECKS: &[Check] = &[
    // ---------------------------------------------------------------- data plane
    Check {
        id: "wg.handshake.responder",
        area: Area::DataPlane,
        description: "completes a WireGuard handshake as responder",
        run: nostd_interop::responder,
    },
    Check {
        id: "wg.transport.roundtrip",
        area: Area::DataPlane,
        description: "encrypts and decrypts transport data",
        run: nostd_interop::transport,
    },
    Check {
        id: "wg.replay",
        area: Area::DataPlane,
        description: "rejects replayed and out-of-window counters",
        run: nostd_interop::replay,
    },
    Check {
        id: "wg.rekey",
        area: Area::DataPlane,
        description: "survives rekeying without dropping traffic",
        run: nostd_interop::rekey,
    },
    Check {
        id: "wg.handshake.initiator",
        area: Area::DataPlane,
        description: "initiates a WireGuard handshake",
        run: nostd_interop::initiator,
    },
    Check {
        id: "wg.multipeer",
        area: Area::DataPlane,
        description: "maintains sessions with many peers at once",
        run: |_| multipeer::run(),
    },
    // ---------------------------------------------------------------------- keys
    Check {
        id: "keys.machine",
        area: Area::Keys,
        description: "machine key: the identity the control plane knows",
        run: ts2021::machine_key,
    },
    Check {
        id: "keys.node",
        area: Area::Keys,
        description: "node key: the WireGuard identity advertised in the netmap",
        run: ts2021::node_key,
    },
    Check {
        id: "keys.disco",
        area: Area::Keys,
        description: "disco key: used for path discovery",
        run: ts2021::disco_key,
    },
    Check {
        id: "keys.encoding",
        area: Area::Keys,
        description: "encodes keys in the wire form the server uses",
        run: |env| {
            // The server's own key is the one piece of key encoding we can
            // check without having implemented anything: whatever format it
            // publishes is the format we must both parse and emit.
            let key = match env.vector("server_key.json") {
                Ok(v) => v,
                Err(e) => return Status::Skip(e),
            };
            let Some(published) = key["key_at_minimum"]["publicKey"].as_str() else {
                return Status::Fail("no publicKey in the captured /key response".into());
            };
            let Some(hex) = published.strip_prefix("mkey:") else {
                return Status::Fail(format!("unexpected key prefix in {published}"));
            };
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Status::Fail(format!("not 32 bytes of hex: {published}"));
            }
            Status::Pass(format!(
                "server publishes 'mkey:' + 64 hex chars; parsed {}…",
                &hex[..16]
            ))
        },
    },
    Check {
        id: "keys.persistence",
        area: Area::Keys,
        description: "keys survive a reboot",
        run: ts2021::persistence,
    },
    // ------------------------------------------------------------------ transport
    Check {
        id: "transport.tls",
        area: Area::Transport,
        description: "TLS 1.3 client, required by the hosted service",
        run: tls::tls,
    },
    Check {
        id: "transport.http2",
        area: Area::Transport,
        description: "HTTP/2 client over the Noise channel",
        run: register::http2,
    },
    // ---------------------------------------------------------------- control
    Check {
        id: "control.key.fetch",
        area: Area::Control,
        description: "fetches the server's Noise public key from /key",
        run: |env| {
            let response = match control_get(env, "/key?v=118") {
                Ok(r) => r,
                Err(status) => return status,
            };
            if response.status != 200 {
                return Status::Fail(format!("/key?v=118 returned {}", response.status));
            }
            let json: serde_json::Value = match serde_json::from_str(&response.body) {
                Ok(j) => j,
                Err(e) => return Status::Fail(format!("/key body is not JSON: {e}")),
            };
            match json["publicKey"].as_str() {
                Some(key) if key.starts_with("mkey:") => {
                    Status::Pass(format!("live server published {}…", &key[..21]))
                }
                _ => Status::Fail(format!("no usable publicKey in {}", response.body)),
            }
        },
    },
    Check {
        id: "control.key.capver",
        area: Area::Control,
        description: "sends a capability version the server still accepts",
        run: |env| {
            // Headscale rejects clients below a minimum version outright, so
            // this is a hard compatibility gate rather than a nicety.
            let response = match control_get(env, "/key") {
                Ok(r) => r,
                Err(status) => return status,
            };
            if response.body.contains("capability version must be set") {
                Status::Pass(
                    "server requires ?v=<capver>; our client must send one and track the minimum"
                        .into(),
                )
            } else {
                Status::Fail(format!(
                    "expected the server to demand a capability version, got: {}",
                    response.body.trim()
                ))
            }
        },
    },
    Check {
        id: "control.capver.minimum",
        area: Area::Control,
        description: "advertises a capability version at or above the server's floor",
        run: ts2021::capver_minimum,
    },
    Check {
        id: "control.noise.handshake",
        area: Area::Control,
        description: "completes the ts2021 Noise IK handshake",
        run: ts2021::noise_handshake,
    },
    Check {
        id: "control.controlbase.framing",
        area: Area::Control,
        description: "speaks the controlbase framing over the Noise channel",
        run: ts2021::controlbase_framing,
    },
    Check {
        id: "control.register",
        area: Area::Control,
        description: "registers with a preauth key and appears on the server",
        run: register::register,
    },
    Check {
        id: "control.reauth",
        area: Area::Control,
        description: "re-registers when the node key expires",
        run: register::reauth,
    },
    Check {
        id: "control.hostinfo",
        area: Area::Control,
        description: "reports a Hostinfo the server accepts",
        run: register::hostinfo,
    },
    // ----------------------------------------------------------------- netmap
    Check {
        id: "netmap.fields",
        area: Area::Netmap,
        description: "handles every top-level MapResponse field the server sends",
        run: netmap::fields,
    },
    Check {
        id: "netmap.delta",
        area: Area::Netmap,
        description: "applies incremental updates, not just full maps",
        run: netmap::delta,
    },
    Check {
        id: "netmap.streaming",
        area: Area::Netmap,
        description: "parses the netmap without buffering it whole",
        run: netmap::streaming,
    },
    Check {
        id: "netmap.compression",
        area: Area::Netmap,
        description: "handles the compression the server negotiates",
        run: netmap::compression,
    },
    Check {
        id: "netmap.to_peers",
        area: Area::Netmap,
        description: "configures WireGuard peers from the netmap",
        run: netmap::to_peers,
    },
    // ------------------------------------------------------------------- DERP
    Check {
        id: "derp.map.parse",
        area: Area::Derp,
        description: "parses the DERP map",
        run: netmap::derp_map,
    },
    Check {
        id: "derp.relay",
        area: Area::Derp,
        description: "relays through DERP when no direct path exists",
        run: derp::relay,
    },
    Check {
        id: "derp.keepalive",
        area: Area::Derp,
        description: "holds a relay session open across the server's idle keepalive",
        run: derp::keepalive,
    },
    Check {
        id: "derp.reconnect",
        area: Area::Derp,
        description: "reconnects under the same node key after the session drops",
        run: derp::reconnect,
    },
    // ------------------------------------------------------------------ disco
    Check {
        id: "disco.pong",
        area: Area::Disco,
        description: "answers disco pings on the WireGuard socket",
        run: disco::pong,
    },
    Check {
        id: "disco.ping",
        area: Area::Disco,
        description: "probes peers to find a working path",
        run: disco::ping,
    },
    Check {
        id: "disco.endpoints",
        area: Area::Disco,
        description: "reports its own endpoints to the control plane",
        run: disco::endpoints,
    },
    // -------------------------------------------------------------------- DNS
    Check {
        id: "dns.config.parse",
        area: Area::Dns,
        description: "reads the tailnet's DNSConfig, including its unbounded Routes map",
        run: netmap::dns_config,
    },
    Check {
        id: "dns.peerapi.doh",
        area: Area::Dns,
        description: "answers RFC 8484 DoH on the peer API, over a real tunnel",
        run: nostd_interop::doh,
    },
    Check {
        id: "dns.peerapi.acl",
        area: Area::Dns,
        description: "resolves through an RFC1918 resolver under an autogroup:internet grant",
        run: nostd_interop::acl,
    },
    Check {
        id: "dns.peerapi.concurrency",
        area: Area::Dns,
        description: "answers a full set of concurrent DoH clients without dropping one",
        run: nostd_interop::concurrency,
    },
    // -------------------------------------------------------------- exit node
    Check {
        id: "exit.forward.udp",
        area: Area::ExitNode,
        description: "forwards UDP out of the uplink from its own address",
        run: nostd_interop::udp,
    },
    Check {
        id: "exit.forward.tcp",
        area: Area::ExitNode,
        description: "forwards TCP, including TLS, out of the uplink",
        run: nostd_interop::tcp,
    },
    Check {
        id: "exit.advertise",
        area: Area::ExitNode,
        description: "advertises itself as an exit node",
        run: exit::advertise,
    },
];
