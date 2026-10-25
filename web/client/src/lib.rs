//! A Tailscale node that runs in a web page, built on tailfeather compiled to
//! `wasm32-unknown-unknown`, with an SSH terminal to tailnet peers.
//!
//! The browser supplies only WebSockets, `fetch`, timers, randomness, and the
//! DOM. Control runs ts2021 over a WebSocket; the data plane is WireGuard
//! relayed through DERP over WebSockets (a page has no UDP); TCP is smoltcp in
//! userspace; SSH is russh.
//!
//! JavaScript API (see `www/app.js`):
//!
//! ```js
//! const client = TailnetClient.start(
//!   { hostname, authKey, ephemeral, relay, target, homeDerp },
//!   { status(text), log(line), authUrl(url), netmap(json) });
//! const session = client.ssh(
//!   { ip, port, user, cols, rows, privateKey },
//!   { write(bytes), prompt(label, echo) /* -> Promise<string|null> */, closed(reason) });
//! session.send(bytes); session.resize(cols, rows); session.close();
//! client.stop(); client.forget();
//! ```

mod logic;
#[cfg(test)]
mod loopback_tests;

mod control;
mod derp;
mod forwarding;
mod js;
mod netstack;
mod runtime;
mod ssh;
mod ws;

use std::net::Ipv4Addr;

use wasm_bindgen::prelude::*;

pub use forwarding::SshForwardPipe;
pub use ssh::SshSession;

use crate::js::{get_bool, get_function, get_number, get_string};

/// A browser node joined to a tailnet.
#[wasm_bindgen]
pub struct TailnetClient {
    runtime: runtime::Shared,
}

fn parse_ip(text: &str) -> Result<Ipv4Addr, JsError> {
    text.trim()
        .parse()
        .map_err(|_| JsError::new(&format!("{text} is not an IPv4 address")))
}

#[wasm_bindgen]
impl TailnetClient {
    /// Start the node: restore or create its identity, connect to control,
    /// and keep the netmap, DERP relays, and tunnels up until `stop()`.
    pub fn start(options: JsValue, callbacks: JsValue) -> Result<TailnetClient, JsError> {
        let hostname = get_string(&options, "hostname")
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "tailfeather-web".to_string());
        let relay = logic::relay_origin(&get_string(&options, "relay").unwrap_or_default())
            .map_err(|error| JsError::new(&error))?;
        let target = match get_string(&options, "target").filter(|text| !text.trim().is_empty()) {
            Some(text) => Some(parse_ip(&text)?),
            None => None,
        };
        let home_override = get_number(&options, "homeDerp")
            .filter(|region| *region >= 1.0 && *region <= f64::from(u16::MAX))
            .map(|region| region as u16);
        let options = runtime::Options {
            hostname,
            auth_key: get_string(&options, "authKey")
                .map(|key| key.trim().to_string())
                .unwrap_or_default(),
            ephemeral: get_bool(&options, "ephemeral").unwrap_or(true),
            relay,
            target,
            home_override,
        };
        let callbacks = runtime::Callbacks {
            status: get_function(&callbacks, "status"),
            log: get_function(&callbacks, "log"),
            auth_url: get_function(&callbacks, "authUrl"),
            netmap: get_function(&callbacks, "netmap"),
        };
        let runtime =
            runtime::Runtime::start(options, callbacks).map_err(|error| JsError::new(&error))?;
        Ok(TailnetClient { runtime })
    }

    /// Open an SSH terminal to a peer.
    pub fn ssh(&self, options: JsValue, callbacks: JsValue) -> Result<SshSession, JsError> {
        let route = ssh::Route::Tailnet {
            runtime: self.runtime.clone(),
            ip: parse_ip(&get_string(&options, "ip").unwrap_or_default())?,
            port: get_number(&options, "port")
                .filter(|port| *port >= 1.0 && *port <= 65_535.0)
                .map_or(22, |port| port as u16),
        };
        start_ssh(route, &options, &callbacks)
    }

    /// The current netmap, as the JSON the `netmap` callback receives.
    pub fn netmap(&self) -> String {
        self.runtime.state.borrow().netmap_json()
    }

    /// Prefer a DERP region for this node (0 clears the override). Published
    /// to control with the next map update.
    #[wasm_bindgen(js_name = setHomeDerp)]
    pub fn set_home_derp(&self, region: u16) {
        runtime::with(&self.runtime, |state| {
            state.set_home_override((region != 0).then_some(region));
        });
    }

    /// Close every connection. The saved identity is kept.
    pub fn stop(&self) {
        self.runtime.stop();
    }

    /// Stop, and delete this browser's node identity.
    pub fn forget(&self) {
        self.runtime.stop();
        forget_node();
    }
}

fn start_ssh(
    route: ssh::Route,
    options: &JsValue,
    callbacks: &JsValue,
) -> Result<SshSession, JsError> {
    let user = get_string(options, "user")
        .map(|user| user.trim().to_string())
        .filter(|user| !user.is_empty())
        .ok_or_else(|| JsError::new("an SSH user name is required"))?;
    let dimension = |name: &str, fallback: u32| {
        get_number(options, name)
            .filter(|value| *value >= 1.0 && *value <= 10_000.0)
            .map_or(fallback, |value| value as u32)
    };
    let options = ssh::SshOptions {
        route,
        user,
        cols: dimension("cols", 80),
        rows: dimension("rows", 24),
        private_key: get_string(options, "privateKey").filter(|key| !key.trim().is_empty()),
    };
    let callbacks = ssh::SshCallbacks {
        write: get_function(callbacks, "write")
            .ok_or_else(|| JsError::new("callbacks.write is required"))?,
        prompt: get_function(callbacks, "prompt")
            .ok_or_else(|| JsError::new("callbacks.prompt is required"))?,
        closed: get_function(callbacks, "closed"),
    };
    Ok(ssh::start(options, callbacks))
}

/// Run the SSH client over a WebSocket that carries a raw TCP byte stream
/// (a websockify-style bridge), without a tailnet. Diagnostic entry point:
/// the end-to-end tests use it to exercise russh in the browser against a
/// local SSH server. Options and callbacks are those of
/// [`TailnetClient::ssh`], with `url` in place of `ip`/`port`.
#[wasm_bindgen(js_name = sshOverWebSocket)]
pub fn ssh_over_websocket(options: JsValue, callbacks: JsValue) -> Result<SshSession, JsError> {
    let url = get_string(&options, "url")
        .filter(|url| url.starts_with("ws://") || url.starts_with("wss://"))
        .ok_or_else(|| JsError::new("options.url must be a ws:// or wss:// URL"))?;
    start_ssh(ssh::Route::WebSocket { url }, &options, &callbacks)
}

/// Delete the saved node identity without a running client.
#[wasm_bindgen(js_name = forgetNode)]
pub fn forget_node() {
    js::storage_remove(runtime::STATE_KEY);
}

/// Forget the remembered SSH host key of `ip:port`.
#[wasm_bindgen(js_name = forgetHostKey)]
pub fn forget_host_key(ip: &str, port: u16) -> Result<(), JsError> {
    js::storage_remove(&logic::host_key_slot(parse_ip(ip)?, port));
    Ok(())
}

/// Open a DERP WebSocket to `host` (optionally through `relay`) and complete
/// the DERP handshake with a throwaway key. Resolves to the server's key.
#[wasm_bindgen(js_name = derpProbe)]
pub async fn derp_probe(host: String, relay: Option<String>) -> Result<String, JsError> {
    if !logic::valid_host(&host) {
        return Err(JsError::new("not a DERP host name"));
    }
    let relay = logic::relay_origin(relay.as_deref().unwrap_or_default())
        .map_err(|error| JsError::new(&error))?;
    let url = logic::derp_url(&host, 443, relay.as_deref());
    runtime::derp_probe(&url)
        .await
        .map_err(|error| JsError::new(&error))
}
