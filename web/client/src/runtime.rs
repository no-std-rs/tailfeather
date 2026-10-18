//! The browser node's runtime: one [`Node`] driven exactly the way the
//! firmware drives it, with WebSockets in place of TCP/TLS and no UDP at all.
//!
//! Everything shares one `RefCell<State>`. Tasks (the control session, one
//! task per DERP region, SSH bridges) borrow it only briefly and never across
//! an `.await`; the driver task drains node actions, runs smoltcp, and sleeps
//! until the next deadline or until a task signals new work. JavaScript
//! callbacks are queued while the state is borrowed and invoked afterwards,
//! so a callback that calls back into the client cannot hit a live borrow.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::rc::{Rc, Weak};

use futures::future::{AbortHandle, Abortable};
use serde_json::json;
use tailfeather::control::authority::Authority;
use tailfeather::control::{CAPABILITY_VERSION, Hostinfo, MapRequest, RegisterRequest};
use tailfeather::derp::Client;
use tailfeather::keys::{Identity, NodePrivate, NodePublic};
use tailfeather::netmap::Netmap;
use tailfeather::node::MAX_CONTROL_BODY;
use tailfeather::{
    ControlCommand, ControlEvent, DerpCommand, DerpEvent, Endpoint, Node, NodeAction, NodeError,
    NodeStatus, PersistState, SecretBuffer,
};
use wasm_bindgen::JsValue;
use web_sys::WebSocket;
use zeroize::Zeroize;

use crate::js::{
    JsRng, Notify, now_ms, random_u64, sleep, storage_get, storage_remove, storage_set,
};
use crate::logic;
use crate::netstack::NetStack;
use crate::ws::{WsError, WsStream};

/// Peers retained from the netmap. The target tailnet has about seventeen.
pub const PEERS: usize = 32;
pub const CONTROL_HOST: &str = "controlplane.tailscale.com";
const CONTROL_URL: &str = "https://controlplane.tailscale.com";
/// Where the node's durable identity lives.
pub const STATE_KEY: &str = "tailfeather.state";
/// Durable lower bound for WireGuard handshake timestamps, in TAI64 seconds.
const TAI64N_FLOOR_KEY: &str = "tailfeather.wg-timestamp-floor";
const VERSION: &str = concat!("tailfeather-web-", env!("CARGO_PKG_VERSION"));
/// The driver's idle tick. WireGuard's timers are the finest-grained
/// deadlines the node has (keepalive at ten seconds, handshake retry at five).
const IDLE_MS: u64 = 500;
/// Node actions handled in one driver turn before yielding to the page.
const TURN_BUDGET: usize = 256;
const DERP_CONNECT_MS: u32 = 20_000;
/// DERP servers send a keepalive frame every minute.
const DERP_LIVENESS_MS: u32 = 150_000;

/// Settings the page supplies. The auth key is a credential: it is never
/// logged and is cleared from memory when the client is dropped.
pub struct Options {
    pub hostname: String,
    pub auth_key: String,
    pub ephemeral: bool,
    pub relay: Option<String>,
    pub target: Option<Ipv4Addr>,
    pub home_override: Option<u16>,
}

impl Drop for Options {
    fn drop(&mut self) {
        self.auth_key.zeroize();
    }
}

/// JavaScript callbacks for the page. Every one is optional.
#[derive(Default)]
pub struct Callbacks {
    pub status: Option<js_sys::Function>,
    pub log: Option<js_sys::Function>,
    pub auth_url: Option<js_sys::Function>,
    pub netmap: Option<js_sys::Function>,
}

enum Ui {
    Status(String),
    Log(String),
    AuthUrl(String),
    Netmap(String),
}

enum Internal {
    ControlDisconnected,
    DerpDisconnected(u16),
}

struct DerpLink {
    id: u64,
    abort: AbortHandle,
    host: String,
    established: Option<(WebSocket, Client)>,
}

struct ControlLink {
    id: u64,
    abort: AbortHandle,
}

/// Rate limit for a repeating log line: the first few, then powers of two.
#[derive(Default)]
struct Counter(u64);

impl Counter {
    fn tick(&mut self) -> Option<u64> {
        self.0 += 1;
        (self.0 <= 3 || self.0.is_power_of_two()).then_some(self.0)
    }
}

#[derive(Default)]
struct Diagnostics {
    node_errors: Counter,
    derp_packet_errors: Counter,
    derp_send_dropped: Counter,
    encapsulate_errors: Counter,
    no_route: Counter,
    inbound_rejected: Counter,
    handshakes: Counter,
}

pub struct State {
    pub node: Box<Node<PEERS>>,
    pub options: Options,
    pub net: NetStack,
    runtime: Weak<Runtime>,
    authority_hash: [u8; 16],
    derp: BTreeMap<u16, DerpLink>,
    control: Option<ControlLink>,
    next_id: u64,
    queue: VecDeque<Internal>,
    ui: Vec<Ui>,
    phase: String,
    tai64n: [u8; 12],
    /// The persisted value behind `tai64n`; see [`logic::tai64n_floor_update`].
    tai64n_floor: u64,
    published_home: u16,
    /// SSH sessions and TCP bridges running on `net`, ended when it goes away.
    ssh_tasks: BTreeMap<u64, AbortHandle>,
    netmap_dirty: bool,
    stopped: bool,
    auth_url_shown: bool,
    /// Peers a decrypted packet has arrived from, to log "tunnel up" once.
    tunnels_up: Vec<NodePublic>,
    diagnostics: Diagnostics,
}

pub struct Runtime {
    pub state: RefCell<State>,
    pub wake: Notify,
    callbacks: Callbacks,
}

pub type Shared = Rc<Runtime>;

/// Run `f` against the state, then deliver queued UI events and wake the
/// driver. Must not be called while the state is already borrowed.
pub fn with<R>(runtime: &Runtime, f: impl FnOnce(&mut State) -> R) -> R {
    let result = f(&mut runtime.state.borrow_mut());
    runtime.flush();
    runtime.wake.notify();
    result
}

impl Runtime {
    pub fn start(options: Options, callbacks: Callbacks) -> Result<Shared, String> {
        let authority_hash = Authority::parse(CONTROL_URL, false)
            .map_err(|_| "invalid control URL".to_string())?
            .digest();
        let (node, restored) = load_node(authority_hash);
        // A peer rejects handshakes whose timestamp is not newer than the last it
        // accepted, so a reload after the clock moved back must not start lower.
        let tai64n_floor = storage_get(TAI64N_FLOOR_KEY)
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0);
        let runtime = Rc::new_cyclic(|weak| Runtime {
            state: RefCell::new(State {
                node,
                options,
                net: NetStack::new(random_u64()),
                runtime: weak.clone(),
                authority_hash,
                derp: BTreeMap::new(),
                control: None,
                next_id: 1,
                queue: VecDeque::new(),
                ui: Vec::new(),
                phase: String::new(),
                tai64n: logic::tai64n_at_floor(tai64n_floor),
                tai64n_floor,
                published_home: 0,
                ssh_tasks: BTreeMap::new(),
                netmap_dirty: true,
                stopped: false,
                auth_url_shown: false,
                tunnels_up: Vec::new(),
                diagnostics: Diagnostics::default(),
            }),
            wake: Notify::default(),
            callbacks,
        });
        {
            let mut state = runtime.state.borrow_mut();
            let key = state.node_key_text();
            if restored {
                state.log(format!("Restored this browser's node identity ({key})."));
            } else {
                state.log(format!("Generated a new node identity ({key})."));
            }
            if let Some(relay) = state.options.relay.clone() {
                state.log(format!("WebSockets go through the relay {relay}."));
            }
            state.set_phase("starting");
        }
        runtime.flush();
        wasm_bindgen_futures::spawn_local(drive(runtime.clone()));
        Ok(runtime)
    }

    /// Deliver queued UI events. Callbacks run with no borrow held.
    pub fn flush(&self) {
        let events = match self.state.try_borrow_mut() {
            Ok(mut state) => std::mem::take(&mut state.ui),
            Err(_) => return,
        };
        for event in events {
            let (callback, value) = match event {
                Ui::Status(text) => (&self.callbacks.status, text),
                Ui::Log(text) => (&self.callbacks.log, text),
                Ui::AuthUrl(url) => (&self.callbacks.auth_url, url),
                Ui::Netmap(json) => (&self.callbacks.netmap, json),
            };
            if let Some(callback) = callback {
                let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(&value));
            }
        }
    }

    pub fn stop(&self) {
        with(self, |state| state.shutdown());
    }
}

fn load_node(authority_hash: [u8; 16]) -> (Box<Node<PEERS>>, bool) {
    use base64::Engine as _;
    let restored = storage_get(STATE_KEY)
        .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
        .and_then(|bytes| PersistState::from_bytes(&bytes).ok())
        .and_then(|state| Node::<PEERS>::restore_for_authority(&state, authority_hash).ok());
    let (node, restored) = match restored {
        Some(node) => (node, true),
        None => (
            Node::factory_reset_for_authority(Identity::generate(&mut JsRng), 1, authority_hash),
            false,
        ),
    };
    (configure(Box::new(node)), restored)
}

fn configure(mut node: Box<Node<PEERS>>) -> Box<Node<PEERS>> {
    node.set_control_endpoint(Endpoint::new(CONTROL_HOST, 443).expect("static host fits"));
    // A browser has no UDP: every packet goes through DERP, and only the peer
    // being addressed is handshaken with.
    node.set_direct_paths(false);
    node.set_initiate_on_demand(true);
    // Date.now() is this platform's trusted clock. Advancing the floor asks
    // for one persistence round before control traffic starts.
    let _ = node.advance_trusted_time(now_ms() / 1000);
    node
}

async fn drive(runtime: Shared) {
    loop {
        let delay = {
            let mut state = runtime.state.borrow_mut();
            if state.stopped {
                break;
            }
            state.pump()
        };
        runtime.flush();
        let wake = runtime.wake.wait();
        let timer = sleep(delay as u32);
        futures::future::select(std::pin::pin!(wake), std::pin::pin!(timer)).await;
    }
    runtime.flush();
}

impl State {
    pub fn log(&mut self, line: impl Into<String>) {
        let mut line = line.into();
        // Belt and braces: nothing logs the auth key, but a server error
        // message could quote it back.
        if !self.options.auth_key.is_empty() && line.contains(&self.options.auth_key) {
            line = line.replace(&self.options.auth_key, "[redacted]");
        }
        self.ui.push(Ui::Log(line));
    }

    fn set_phase(&mut self, phase: impl Into<String>) {
        let phase = phase.into();
        if phase != self.phase {
            self.phase = phase.clone();
            self.ui.push(Ui::Status(phase));
            self.netmap_dirty = true;
        }
    }

    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn runtime(&self) -> Option<Shared> {
        self.runtime.upgrade()
    }

    fn node_key_text(&self) -> String {
        key_text(&self.node.identity().node.public())
    }

    pub fn own_ipv4(&self) -> Option<Ipv4Addr> {
        self.node
            .netmap()
            .addresses
            .iter()
            .find_map(|cidr| match cidr.address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
    }

    /// One driver turn: drain node work, run smoltcp, and report how long the
    /// driver may sleep.
    fn pump(&mut self) -> u64 {
        let now = now_ms();
        for _ in 0..TURN_BUDGET {
            let mut progressed = false;
            while let Some(event) = self.queue.pop_front() {
                self.internal(event, now);
                progressed = true;
            }
            let result = self.node.poll(now);
            progressed |= self.handle(result, now, "node");
            let result = self.node.poll_derp();
            progressed |= self.handle(result, now, "DERP");
            let tai64n = logic::next_tai64n(&mut self.tai64n, now);
            if let Some(floor) = logic::tai64n_floor_update(&self.tai64n, self.tai64n_floor) {
                if !storage_set(TAI64N_FLOOR_KEY, &floor.to_string()) {
                    self.log("Could not save the WireGuard timestamp floor; a reload after a clock change may need a minute to reconnect.");
                }
                self.tai64n_floor = floor;
            }
            let result = self.node.poll_tunnel(now, &tai64n, &mut JsRng);
            progressed |= self.handle(result, now, "WireGuard handshake");
            let result = self.node.poll_tunnel_timers(now);
            progressed |= self.handle(result, now, "WireGuard timers");
            for packet in self.net.poll(now) {
                self.transmit(&packet, now);
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        if self.netmap_dirty {
            self.netmap_dirty = false;
            let json = self.netmap_json();
            self.ui.push(Ui::Netmap(json));
        }
        self.net
            .poll_delay(now)
            .unwrap_or(IDLE_MS)
            .clamp(1, IDLE_MS)
    }

    fn handle(
        &mut self,
        result: Result<Option<NodeAction>, NodeError>,
        now: u64,
        context: &str,
    ) -> bool {
        match result {
            Ok(Some(action)) => {
                self.dispatch(action, now);
                true
            }
            Ok(None) => false,
            Err(error) => {
                if let Some(count) = self.diagnostics.node_errors.tick() {
                    self.log(format!("{context}: {error} (#{count})"));
                }
                false
            }
        }
    }

    fn internal(&mut self, event: Internal, now: u64) {
        match event {
            Internal::ControlDisconnected => {
                let result = self.node.handle_control_event(ControlEvent::Disconnected);
                self.handle(result, now, "control");
            }
            Internal::DerpDisconnected(region) => {
                let result = self.node.handle_derp_event(
                    DerpEvent::Disconnected { region },
                    now,
                    &mut JsRng,
                );
                self.handle(result, now, "DERP");
                self.netmap_dirty = true;
            }
        }
    }

    /// Execute one node action. Anything that needs a network round trip is
    /// started here and reports back through [`with`].
    fn dispatch(&mut self, action: NodeAction, now: u64) {
        match action {
            NodeAction::DirectTransmit { .. } => {
                // Relay-only mode never asks for this; a browser cannot send UDP.
                self.log("dropped a direct UDP transmit (relay-only node)");
            }
            NodeAction::Control(ControlCommand::Connect { endpoint }) => {
                self.start_control(endpoint);
            }
            NodeAction::Control(ControlCommand::Disconnect) => {
                if let Some(link) = self.control.take() {
                    link.abort.abort();
                }
                self.queue.push_back(Internal::ControlDisconnected);
            }
            // The control session consumes these inline; see `control_*`.
            NodeAction::Control(ControlCommand::Register { .. } | ControlCommand::RequestMap) => {}
            NodeAction::Derp(DerpCommand::Connect { region, endpoint }) => {
                self.start_derp(region, &endpoint);
            }
            NodeAction::Derp(DerpCommand::Send {
                region,
                peer,
                packet,
            }) => self.derp_send(region, &peer, packet.as_slice()),
            NodeAction::Derp(DerpCommand::Disconnect { region }) => {
                if let Some(link) = self.derp.remove(&region) {
                    link.abort.abort();
                    self.log(format!("DERP region {region}: disconnecting"));
                }
                self.queue.push_back(Internal::DerpDisconnected(region));
            }
            NodeAction::DeliveredIpv4 { peer, packet } => self.deliver(&peer, packet.as_slice()),
            NodeAction::PersistState(state) => {
                use base64::Engine as _;
                let saved = storage_set(
                    STATE_KEY,
                    &base64::engine::general_purpose::STANDARD.encode(state.as_bytes()),
                );
                if !saved {
                    // The node refuses control traffic until its identity is
                    // durable. Leaving the save unacknowledged parks it there
                    // instead of retrying in a tight loop.
                    self.log("Could not save the node identity to localStorage; not connecting.");
                    self.set_phase("cannot save identity");
                    return;
                }
                let result = self.node.persistence_result(state.generation(), saved);
                self.handle(result, now, "persistence");
            }
            NodeAction::StatusChanged(status) => self.status_changed(status),
        }
    }

    fn status_changed(&mut self, status: NodeStatus) {
        let phase = match status {
            NodeStatus::PersistenceRequired => "saving identity",
            NodeStatus::Offline => "offline",
            NodeStatus::Connecting => "connecting",
            NodeStatus::Registered => {
                self.log("Registered with the tailnet; reconnecting to fetch the netmap.");
                "registered"
            }
            NodeStatus::MapChanged | NodeStatus::AwaitingRouteApproval | NodeStatus::MapActive => {
                "netmap received"
            }
            NodeStatus::DerpConnected => "DERP connected",
            NodeStatus::ExitReady => "ready",
        };
        self.set_phase(phase);
    }

    fn registration_body(&self, followup: &str) -> Result<Vec<u8>, String> {
        let node_key = self.node.identity().node.public();
        let request = RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: &node_key,
            old_node_key: self.node.rotation_old_node_key(),
            auth_key: self.node.registration_auth_key(&self.options.auth_key),
            hostinfo: self.hostinfo(0),
            ephemeral: self.options.ephemeral,
        };
        let mut buffer = [0u8; MAX_CONTROL_BODY];
        let body = request
            .write_followup(followup, &mut buffer)
            .map_err(|error| format!("registration request: {error}"))?
            .to_vec();
        buffer.zeroize();
        Ok(body)
    }

    fn hostinfo(&self, preferred_derp: u16) -> Hostinfo<'_> {
        Hostinfo {
            hostname: &self.options.hostname,
            version: VERSION,
            os: "js",
            routable_ips: &[],
            preferred_derp,
            peer_api_port: None,
            ssh_host_keys: &[],
        }
    }

    /// A map request. No endpoints: this node is reachable only through its
    /// preferred DERP region, which `Hostinfo.NetInfo` names.
    fn map_body(&self, stream: bool) -> Result<Vec<u8>, String> {
        let node_key = self.node.identity().node.public();
        let disco_key = self.node.identity().disco.public();
        let request = MapRequest {
            version: CAPABILITY_VERSION,
            node_key: &node_key,
            disco_key: &disco_key,
            hostinfo: self.hostinfo(self.published_home),
            stream,
            omit_peers: !stream,
            read_only: false,
            endpoints: &[],
        };
        let mut buffer = [0u8; MAX_CONTROL_BODY];
        Ok(request
            .write(&mut buffer)
            .map_err(|error| format!("map request: {error}"))?
            .to_vec())
    }

    fn start_control(&mut self, endpoint: Endpoint) {
        let Some(runtime) = self.runtime() else {
            return;
        };
        let problem = match self.registration_body("") {
            Ok(mut body) => {
                let result = self.node.set_registration_body(&body);
                body.zeroize();
                result
                    .err()
                    .map(|error| format!("registration request: {error}"))
            }
            Err(error) => Some(error),
        };
        if let Some(problem) = problem {
            // Every retry would build the same request and fail the same way,
            // so stop and let the user correct the input.
            self.log(format!(
                "{problem}. Check the hostname and auth key, then Connect again."
            ));
            self.shutdown();
            return;
        }
        if let Some(link) = self.control.take() {
            link.abort.abort();
        }
        let id = self.next_id();
        let (abort, registration) = AbortHandle::new_pair();
        self.control = Some(ControlLink { id, abort });
        self.set_phase("connecting to control");
        self.log(format!(
            "Control: connecting to {} (ts2021 over WebSocket{}).",
            endpoint.host,
            if self.options.relay.is_some() {
                ", via relay"
            } else {
                ""
            }
        ));
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(crate::control::session(runtime, id), registration).await;
        });
    }

    pub fn control_is_current(&self, id: u64) -> bool {
        !self.stopped && self.control.as_ref().is_some_and(|link| link.id == id)
    }

    pub fn control_log(&mut self, id: u64, line: impl Into<String>) {
        if self.control_is_current(id) {
            self.log(line);
        }
    }

    /// The Noise and HTTP/2 layers are up: the node answers with the
    /// registration body it was given for this attempt.
    pub fn control_connected(&mut self, id: u64) -> Result<SecretBuffer<MAX_CONTROL_BODY>, String> {
        if !self.control_is_current(id) {
            return Err("superseded".into());
        }
        self.set_phase("registering");
        match self.node.handle_control_event(ControlEvent::Connected) {
            Ok(Some(NodeAction::Control(ControlCommand::Register { body }))) => Ok(body),
            Ok(Some(action)) => {
                self.dispatch(action, now_ms());
                Err("the node did not ask to register".into())
            }
            Ok(None) => Err("the node did not ask to register".into()),
            Err(error) => Err(format!("node: {error}")),
        }
    }

    /// Build the follow-up for an interactive login, and show its URL.
    pub fn control_needs_login(&mut self, id: u64, url: &str) -> Result<Vec<u8>, ControlError> {
        if !self.control_is_current(id) {
            return Err(ControlError::Failed("superseded".into()));
        }
        if self.node.is_enrolled() && !self.options.auth_key.is_empty() {
            // An enrolled identity the server no longer knows (an ephemeral
            // node removed after going offline, say). The auth key is never
            // re-sent for an enrolled identity, so enroll a fresh one.
            return Err(ControlError::Reenroll);
        }
        if !self.auth_url_shown {
            self.auth_url_shown = true;
            self.log("Control: this node needs to be approved. Open the login link to continue.");
        }
        self.set_phase("waiting for login");
        self.ui.push(Ui::AuthUrl(url.to_string()));
        self.registration_body(url).map_err(ControlError::Failed)
    }

    /// Registration succeeded. Returns whether this session should stream
    /// the netmap; after a first enrollment the node instead persists that
    /// fact and reconnects without the auth key.
    pub fn control_registered(&mut self, id: u64, login: &str) -> Result<bool, String> {
        if !self.control_is_current(id) {
            return Err("superseded".into());
        }
        self.auth_url_shown = false;
        if !login.is_empty() {
            self.log(format!("Control: registered as {login}."));
        }
        self.ui.push(Ui::AuthUrl(String::new()));
        match self.node.handle_control_event(ControlEvent::Registered) {
            Ok(Some(NodeAction::Control(ControlCommand::RequestMap))) => {
                self.set_phase("requesting netmap");
                Ok(true)
            }
            Ok(Some(action)) => {
                self.dispatch(action, now_ms());
                Ok(false)
            }
            Ok(None) => Ok(false),
            Err(error) => Err(format!("node: {error}")),
        }
    }

    pub fn control_map_request(&self, id: u64) -> Result<Vec<u8>, String> {
        if !self.control_is_current(id) {
            return Err("superseded".into());
        }
        self.map_body(true)
    }

    pub fn seed_staging(&self, staging: &mut Netmap<PEERS>) {
        self.node.seed_staging(staging);
    }

    /// A map response was applied to `staging` (when `applied`), or a
    /// keepalive arrived. Returns an endpoint update to send when this node's
    /// preferred DERP region needs publishing.
    pub fn control_map_event(
        &mut self,
        id: u64,
        staging: &mut Netmap<PEERS>,
        applied: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        if !self.control_is_current(id) {
            return Err("superseded".into());
        }
        let now = now_ms();
        if applied {
            let first = self.node.netmap().responses == 0;
            let result = self.node.handle_control_event(ControlEvent::MapFinished {
                lease: &mut *staging,
                result: Ok(()),
            });
            self.handle(result, now, "netmap");
            self.netmap_dirty = true;
            if let Some(address) = self.own_ipv4() {
                if self.net.address() != Some(address) {
                    self.log(format!("Tailnet address {address}."));
                }
                self.net.set_address(address, now, random_u64());
            }
            if first {
                let netmap = self.node.netmap();
                let line = format!(
                    "Netmap: {} peers, {} DERP regions{}.",
                    netmap.peers.len(),
                    netmap.derp.len(),
                    if netmap.peers_truncated {
                        " (truncated)"
                    } else {
                        ""
                    }
                );
                self.log(line);
            }
        }
        // The control plane echoes the published home once it has seen it;
        // until then keep the local choice rather than an older echo.
        if self.published_home != 0 && self.node.netmap().home_derp != self.published_home {
            let _ = self.node.prefer_derp(self.published_home);
        }
        let desired = self.desired_home();
        let mut update = None;
        if desired != 0 && desired != self.published_home && self.node.prefer_derp(desired).is_ok()
        {
            self.published_home = desired;
            self.refresh_derp_preferences();
            let code = self.region_code(desired);
            self.log(format!(
                "Home DERP region {desired} ({code}); publishing it so peers can reach this node."
            ));
            update = Some(self.map_body(false)?);
            self.netmap_dirty = true;
        }
        if applied || update.is_some() {
            self.node.seed_staging(staging);
        }
        Ok(update)
    }

    /// The region peers should reach this node through: the one chosen in the
    /// UI, else the SSH target's home region, else wherever control says we
    /// are, else the first usable region.
    fn desired_home(&self) -> u16 {
        let netmap = self.node.netmap();
        let known = |region: u16| region != 0 && netmap.derp.region(region).is_some();
        if let Some(region) = self.options.home_override.filter(|region| known(*region)) {
            return region;
        }
        if let Some(target) = self.options.target
            && let Some(peer) = netmap
                .peers
                .iter()
                .find(|peer| peer.tailscale_ipv4() == Some(target))
            && known(peer.home_derp)
        {
            return peer.home_derp;
        }
        if known(netmap.home_derp) {
            return netmap.home_derp;
        }
        netmap
            .derp
            .iter()
            .find(|region| region.nodes.iter().any(|node| node.port != 0))
            .map_or(0, |region| region.id)
    }

    fn region_code(&self, region: u16) -> String {
        self.node
            .netmap()
            .derp
            .region(region)
            .map(|region| region.code.to_string())
            .unwrap_or_default()
    }

    pub fn set_home_override(&mut self, region: Option<u16>) {
        self.options.home_override = region;
        self.log(match region {
            Some(region) => {
                format!("Home DERP override: region {region}; applied at the next control update.")
            }
            None => "Home DERP override cleared.".to_string(),
        });
    }

    pub fn control_ended(&mut self, id: u64, result: Result<(), ControlError>) {
        if !self.control_is_current(id) {
            return;
        }
        self.control = None;
        let now = now_ms();
        match result {
            Ok(()) => {}
            Err(ControlError::Reenroll) => {
                self.log(
                    "Control: the saved node is no longer part of the tailnet; enrolling a new identity with the auth key.",
                );
                self.reset_identity();
            }
            Err(ControlError::Failed(error)) => {
                self.log(format!("Control: {error}"));
                self.set_phase("control disconnected; retrying");
                self.node.control_failed(now, (random_u64() % 1000) as u16);
            }
        }
    }

    /// Track an SSH task that runs on this node's network stack.
    pub(crate) fn register_ssh_task(&mut self, abort: AbortHandle) -> u64 {
        let id = self.next_id();
        self.ssh_tasks.insert(id, abort);
        id
    }

    pub(crate) fn ssh_task_done(&mut self, id: u64) {
        self.ssh_tasks.remove(&id);
    }

    /// End every SSH session and bridge before their network stack is dropped
    /// or stops being driven; their wakers live in its sockets, so nothing
    /// else would ever wake them.
    fn abort_ssh_tasks(&mut self, why: &str) {
        let tasks = std::mem::take(&mut self.ssh_tasks);
        if !tasks.is_empty() {
            self.log(format!("SSH: ending open sessions: {why}."));
        }
        for abort in tasks.into_values() {
            abort.abort();
        }
    }

    /// Replace the node with a fresh identity, as a factory reset would.
    fn reset_identity(&mut self) {
        self.abort_ssh_tasks("this node is re-enrolling with a new identity");
        self.close_links();
        storage_remove(STATE_KEY);
        let node = Node::factory_reset_for_authority(
            Identity::generate(&mut JsRng),
            1,
            self.authority_hash,
        );
        self.node = configure(Box::new(node));
        self.net = NetStack::new(random_u64());
        self.published_home = 0;
        self.tunnels_up.clear();
        self.queue.clear();
        self.netmap_dirty = true;
        let key = self.node_key_text();
        self.log(format!("Generated a new node identity ({key})."));
    }

    fn close_links(&mut self) {
        if let Some(link) = self.control.take() {
            link.abort.abort();
        }
        for (_, link) in std::mem::take(&mut self.derp) {
            link.abort.abort();
        }
    }

    fn shutdown(&mut self) {
        if !self.stopped {
            self.abort_ssh_tasks("the tailnet client stopped");
            self.close_links();
            self.stopped = true;
            self.set_phase("stopped");
            self.log("Stopped.");
        }
    }

    fn start_derp(&mut self, region: u16, endpoint: &Endpoint) {
        let Some(runtime) = self.runtime() else {
            return;
        };
        // The browser does TLS itself, so connect by the name the relay's
        // certificate covers, never a bare address.
        let host = endpoint
            .tls_name
            .as_ref()
            .map_or(endpoint.host.as_str(), |name| name.as_str())
            .to_string();
        if let Some(link) = self.derp.remove(&region) {
            link.abort.abort();
        }
        let id = self.next_id();
        let (abort, registration) = AbortHandle::new_pair();
        let code = self.region_code(region);
        self.log(format!(
            "DERP region {region} ({code}): connecting to {host}."
        ));
        self.derp.insert(
            region,
            DerpLink {
                id,
                abort,
                host: host.clone(),
                established: None,
            },
        );
        let url = if logic::valid_host(&host) {
            Some(logic::derp_url(
                &host,
                endpoint.port,
                self.options.relay.as_deref(),
            ))
        } else {
            None
        };
        let identity = self.node.identity().node.clone();
        let preferred = self.home_region() == region;
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(
                derp_session(runtime, region, id, url, identity, preferred),
                registration,
            )
            .await;
        });
    }

    fn derp_established(&mut self, region: u16, id: u64, socket: WebSocket, client: Client) {
        let Some(link) = self.derp.get_mut(&region).filter(|link| link.id == id) else {
            return;
        };
        link.established = Some((socket, client));
        let host = link.host.clone();
        // The handshake carried the preference from when the link was
        // opened; the home may have moved while it connected.
        self.note_derp_preference(region);
        let code = self.region_code(region);
        self.log(format!(
            "DERP region {region} ({code}): connected to {host}."
        ));
        let result =
            self.node
                .handle_derp_event(DerpEvent::Connected { region }, now_ms(), &mut JsRng);
        self.handle(result, now_ms(), "DERP");
        self.netmap_dirty = true;
    }

    fn derp_packet(&mut self, region: u16, id: u64, peer: NodePublic, payload: &[u8]) {
        if !self.derp.get(&region).is_some_and(|link| link.id == id) {
            return;
        }
        let now = now_ms();
        match self.node.handle_derp_event(
            DerpEvent::Packet {
                region,
                peer,
                payload,
            },
            now,
            &mut JsRng,
        ) {
            Ok(Some(action)) => self.dispatch(action, now),
            Ok(None) => {}
            Err(error) => {
                if let Some(count) = self.diagnostics.derp_packet_errors.tick() {
                    self.log(format!(
                        "DERP packet from {}: {error} (#{count})",
                        key_text(&peer)
                    ));
                }
            }
        }
    }

    fn derp_peer_gone(&mut self, region: u16, id: u64, peer: NodePublic) {
        if self.derp.get(&region).is_some_and(|link| link.id == id) {
            self.node.forget_relay(&peer, region);
        }
    }

    fn derp_ended(&mut self, region: u16, id: u64, reason: &str) {
        if self.stopped || !self.derp.get(&region).is_some_and(|link| link.id == id) {
            return;
        }
        self.derp.remove(&region);
        let code = self.region_code(region);
        self.log(format!("DERP region {region} ({code}): {reason}"));
        self.queue.push_back(Internal::DerpDisconnected(region));
    }

    /// Tell every DERP link that is already up whether it is now the home
    /// region. The handshake sends this only once, when a link opens, so a home
    /// change would otherwise leave the old region marked preferred while
    /// peers are told to reach this node through the new one.
    fn refresh_derp_preferences(&self) {
        for region in self.derp.keys() {
            self.note_derp_preference(*region);
        }
    }

    /// The region this node calls home: what it published, or before that
    /// what the netmap says.
    fn home_region(&self) -> u16 {
        if self.published_home != 0 {
            self.published_home
        } else {
            self.node.netmap().home_derp
        }
    }

    fn note_derp_preference(&self, region: u16) {
        if let Some((socket, _)) = self
            .derp
            .get(&region)
            .and_then(|link| link.established.as_ref())
            && let Some(frame) = crate::derp::note_preferred(region == self.home_region())
        {
            let _ = crate::ws::send(socket, &frame);
        }
    }

    fn derp_send(&mut self, region: u16, peer: &NodePublic, packet: &[u8]) {
        let sent = self
            .derp
            .get(&region)
            .and_then(|link| link.established.as_ref())
            .and_then(|(socket, client)| {
                let frame = crate::derp::frame_packet(client, peer, packet)?;
                crate::ws::send(socket, &frame).ok()
            })
            .is_some();
        if !sent && let Some(count) = self.diagnostics.derp_send_dropped.tick() {
            self.log(format!(
                "DERP region {region}: dropped an outbound packet (#{count})"
            ));
        }
        if sent
            && packet.first().copied() == Some(tailfeather::tunnel::messages::TYPE_INITIATION)
            && let Some(count) = self.diagnostics.handshakes.tick()
        {
            let name = self.peer_name(peer);
            self.log(format!(
                "WireGuard: handshake initiation to {name} via DERP region {region} (#{count})"
            ));
        }
    }

    fn peer_name(&self, peer: &NodePublic) -> String {
        self.node
            .netmap()
            .peers
            .by_node_key(peer)
            .map(|peer| {
                if peer.name.is_empty() {
                    peer.tailscale_ipv4()
                        .map_or_else(|| key_text(&peer.node_key), |ip| ip.to_string())
                } else {
                    peer.name.to_string()
                }
            })
            .unwrap_or_else(|| key_text(peer))
    }

    /// A packet the tunnel decrypted: enforce cryptokey routing, then hand it
    /// to smoltcp.
    fn deliver(&mut self, peer: &NodePublic, packet: &[u8]) {
        let accepted = self.net.address().is_some_and(|own| {
            logic::inbound_allowed(packet, peer, self.node.netmap().peers.iter(), own)
        });
        if accepted {
            if !self.tunnels_up.contains(peer) && self.tunnels_up.len() < PEERS {
                self.tunnels_up.push(*peer);
                let name = self.peer_name(peer);
                self.log(format!(
                    "WireGuard: tunnel to {name} is up (first packet received over DERP)."
                ));
            }
            self.net.deliver(packet);
        } else if let Some(count) = self.diagnostics.inbound_rejected.tick() {
            let name = self.peer_name(peer);
            self.log(format!(
                "dropped an inbound packet from {name} with a source it may not use (#{count})"
            ));
        }
    }

    /// A packet smoltcp sent: find the owning peer and encrypt it.
    fn transmit(&mut self, packet: &[u8], now: u64) {
        let Some((_, destination)) = logic::ipv4_addresses(packet) else {
            return;
        };
        let Some(peer) = logic::route_ipv4(self.node.netmap().peers.iter(), destination) else {
            if let Some(count) = self.diagnostics.no_route.tick() {
                self.log(format!("no peer routes {destination} (#{count})"));
            }
            return;
        };
        match self.node.encapsulate_ipv4(&peer, packet, now) {
            Ok(Some(action)) => self.dispatch(action, now),
            Ok(None) => {}
            Err(NodeError::Tunnel(tailfeather::tunnel::Error::NoSession)) => {
                // Arms an on-demand handshake; TCP retransmits the packet.
            }
            Err(error) => {
                if let Some(count) = self.diagnostics.encapsulate_errors.tick() {
                    self.log(format!("WireGuard to {destination}: {error} (#{count})"));
                }
            }
        }
    }

    pub fn describe_path(&self, address: Ipv4Addr) -> String {
        let netmap = self.node.netmap();
        match netmap
            .peers
            .iter()
            .find(|peer| peer.tailscale_ipv4() == Some(address))
        {
            Some(peer) => {
                let name = self.peer_name(&peer.node_key);
                format!(
                    "{name} (home DERP region {} {}, {})",
                    peer.home_derp,
                    self.region_code(peer.home_derp),
                    if peer.online() { "online" } else { "offline" }
                )
            }
            None => format!("{address} (not in the netmap)"),
        }
    }

    pub fn netmap_json(&self) -> String {
        let netmap = self.node.netmap();
        let home = netmap.home_derp;
        let mut peers: Vec<_> = netmap
            .peers
            .iter()
            .map(|peer| {
                json!({
                    "name": peer.name.as_str(),
                    "ip": peer.tailscale_ipv4().map(|ip| ip.to_string()),
                    "online": peer.online(),
                    "endpoints": peer.endpoints.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
                    "homeDerp": peer.home_derp,
                    "nodeKey": key_text(&peer.node_key),
                })
            })
            .collect();
        peers.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let regions: Vec<_> = netmap
            .derp
            .iter()
            .map(|region| {
                let link = self.derp.get(&region.id);
                json!({
                    "id": region.id,
                    "code": region.code.as_str(),
                    "nodes": region.nodes.iter().map(|node| json!({
                        "host": node.host_name.as_str(),
                        "port": node.port,
                        "stunPort": node.stun_port,
                    })).collect::<Vec<_>>(),
                    "connected": link.is_some_and(|link| link.established.is_some()),
                    "connecting": link.is_some_and(|link| link.established.is_none()),
                    "home": region.id == home,
                })
            })
            .collect();
        json!({
            "self": {
                "name": netmap.name.as_str(),
                "ip": self.own_ipv4().map(|ip| ip.to_string()),
                "nodeKey": self.node_key_text(),
                "homeDerp": home,
                "status": self.phase,
                "enrolled": self.node.is_enrolled(),
            },
            "peers": peers,
            "derp": regions,
            "truncated": netmap.peers_truncated,
        })
        .to_string()
    }
}

/// Why a control session ended.
pub enum ControlError {
    Failed(String),
    /// The saved identity must be replaced before registering again.
    Reenroll,
}

impl From<String> for ControlError {
    fn from(value: String) -> Self {
        Self::Failed(value)
    }
}

pub fn key_text(key: &NodePublic) -> String {
    let mut buffer = [0u8; 128];
    key.encode(&mut buffer)
        .map(logic::short_key)
        .unwrap_or_else(|_| "nodekey:?".into())
}

async fn derp_session(
    runtime: Shared,
    region: u16,
    id: u64,
    url: Option<String>,
    identity: NodePrivate,
    preferred: bool,
) {
    let reason = match url {
        Some(url) => match derp_run(&runtime, region, id, &url, &identity, preferred).await {
            Ok(()) => "connection closed".to_string(),
            Err(error) => error.0,
        },
        None => "relay host name is not usable from a browser".to_string(),
    };
    // Pace reconnects: the node asks again as soon as it hears of the loss.
    sleep(1_000).await;
    with(&runtime, |state| state.derp_ended(region, id, &reason));
}

async fn derp_run(
    runtime: &Shared,
    region: u16,
    id: u64,
    url: &str,
    identity: &NodePrivate,
    preferred: bool,
) -> Result<(), WsError> {
    let ws = WsStream::connect(url, logic::DERP_PROTOCOL)?;
    crate::js::timeout(DERP_CONNECT_MS, ws.opened())
        .await
        .map_err(|_| WsError("WebSocket connect timed out".into()))??;
    let client = crate::js::timeout(
        DERP_CONNECT_MS,
        crate::derp::handshake(&ws, identity, preferred),
    )
    .await
    .map_err(|_| WsError("DERP handshake timed out".into()))??;
    with(runtime, |state| {
        state.derp_established(region, id, ws.socket(), client)
    });
    let mut payload = Vec::new();
    loop {
        let frame =
            crate::js::timeout(DERP_LIVENESS_MS, crate::derp::read_frame(&ws, &mut payload))
                .await
                .map_err(|_| WsError("no frames from the server; reconnecting".into()))??;
        match crate::derp::classify(&ws, frame, &mut payload)? {
            crate::derp::Inbound::Packet(peer) => {
                with(runtime, |state| {
                    state.derp_packet(region, id, peer, &payload)
                });
            }
            crate::derp::Inbound::PeerGone(peer) => {
                with(runtime, |state| state.derp_peer_gone(region, id, peer));
            }
            crate::derp::Inbound::Restarting => {
                return Err(WsError("server restarting".into()));
            }
            crate::derp::Inbound::Health => {
                let text = String::from_utf8_lossy(&payload).into_owned();
                if !text.is_empty() {
                    with(runtime, |state| {
                        state.log(format!("DERP region {region} health: {text}"))
                    });
                }
            }
            crate::derp::Inbound::Other => {}
        }
    }
}

/// Probe one DERP server with a throwaway identity: open the WebSocket and
/// complete the handshake. Used by the credential-free end-to-end test.
pub async fn derp_probe(url: &str) -> Result<String, String> {
    let identity = NodePrivate::generate(&mut JsRng);
    let ws = WsStream::connect(url, logic::DERP_PROTOCOL).map_err(|error| error.0)?;
    crate::js::timeout(DERP_CONNECT_MS, ws.opened())
        .await
        .map_err(|_| "WebSocket connect timed out".to_string())?
        .map_err(|error| error.0)?;
    let client = crate::js::timeout(
        DERP_CONNECT_MS,
        crate::derp::handshake(&ws, &identity, false),
    )
    .await
    .map_err(|_| "DERP handshake timed out".to_string())?
    .map_err(|error| error.0)?;
    Ok(key_text(client.server()))
}
