//! The control session: ts2021 over WebSocket, then tailfeather's own Noise,
//! HTTP/2, registration, and streaming-map machinery, unchanged.
//!
//! The server's `/key` is fetched with `fetch()`. The Noise initiation is
//! computed before the WebSocket exists and travels in its URL; after the
//! upgrade the server's Noise response is the first thing on the socket.

use tailfeather::control::register::{self, RegisterResponse};
use tailfeather::control::transport::{self, MapEvent, MapStream};
use tailfeather::keys::MachinePublic;
use tailfeather::netmap::Netmap;

use crate::js::{JsRng, fetch_json_string, timeout};
use crate::logic;
use crate::runtime::{CONTROL_HOST, ControlError, PEERS, Shared, with};
use crate::ws::{WsError, WsStream};

type Http2 = transport::Http2<WsStream>;

/// Bound on each request/response step that should answer promptly. A step
/// that times out abandons the whole session, which then reconnects.
const STEP_MS: u32 = 60_000;
/// Control sends a keepalive map response about once a minute.
const MAP_LIVENESS_MS: u32 = 150_000;
const REGISTER_RESPONSE: usize = 64 * 1024;

pub async fn session(runtime: Shared, id: u64) {
    let result = run(&runtime, id).await;
    with(&runtime, |state| state.control_ended(id, result));
}

fn failed(stage: &str, error: impl core::fmt::Display) -> ControlError {
    ControlError::Failed(format!("{stage}: {error}"))
}

async fn run(runtime: &Shared, id: u64) -> Result<(), ControlError> {
    let url = logic::key_url(CONTROL_HOST, tailfeather::control::CAPABILITY_VERSION);
    // Like every later step, the key fetch must end, or the node would sit at
    // "connecting" without ever entering its reconnect backoff.
    let key = timeout(STEP_MS, fetch_json_string(&url, "publicKey"))
        .await
        .map_err(|_| failed("server key", "request timed out"))??;
    let server_key = MachinePublic::parse(&key).map_err(|error| failed("server key", error))?;
    let (identity, relay) = with(runtime, |state| {
        state.control_log(id, "Control: fetched the server's machine key.");
        (state.node.identity().clone(), state.options.relay.clone())
    });

    let (initiation, pending) =
        transport::initiate(&identity, &server_key, &mut JsRng).map_err(|e| failed("Noise", e))?;
    drop(identity);
    let url = logic::control_url(CONTROL_HOST, relay.as_deref(), initiation.as_bytes());
    let ws =
        WsStream::connect(&url, logic::CONTROL_PROTOCOL).map_err(|e| failed("WebSocket", e))?;
    timeout(STEP_MS, ws.opened())
        .await
        .map_err(|_| failed("WebSocket", "connect timed out"))?
        .map_err(|e| failed("WebSocket", e))?;
    with(runtime, |state| {
        state.control_log(
            id,
            "Control: WebSocket open; completing the Noise handshake.",
        )
    });
    let received = ws.received_counter();
    let noise = timeout(STEP_MS, transport::complete(ws, pending))
        .await
        .map_err(|_| {
            failed(
                "Noise",
                format!("handshake timed out after {} bytes", received.get()),
            )
        })?
        .map_err(|e| failed("Noise", e))?;
    let mut http2: Box<Http2> = Box::new(
        timeout(STEP_MS, noise.into_https2())
            .await
            .map_err(|_| failed("HTTP/2", "no response to the client preface"))?
            .map_err(|e| failed("HTTP/2", e))?,
    );
    with(runtime, |state| {
        state.control_log(id, "Control: Noise and HTTP/2 established.")
    });

    let body = with(runtime, |state| state.control_connected(id))?;
    let mut response = vec![0u8; REGISTER_RESPONSE];
    let (mut status, mut len) = timeout(
        STEP_MS,
        http2.request(
            "POST",
            register::PATH,
            CONTROL_HOST,
            body.as_slice(),
            &mut response,
        ),
    )
    .await
    .map_err(|_| failed("registration", "no response"))?
    .map_err(|e| failed("registration", e))?;
    drop(body);
    let login = loop {
        if status != 200 {
            let text = String::from_utf8_lossy(&response[..len.min(200)]).into_owned();
            return Err(failed(
                "registration",
                format!("server answered {status}: {text}"),
            ));
        }
        let text = std::str::from_utf8(&response[..len])
            .map_err(|_| failed("registration", "response is not UTF-8"))?;
        let parsed = RegisterResponse::parse(text);
        if !parsed.error.is_empty() {
            return Err(failed("registration refused", parsed.error));
        }
        if parsed.node_key_expired {
            return Err(failed(
                "registration",
                "this node's key has expired; use \"Forget this browser node\" and log in again",
            ));
        }
        if parsed.machine_authorized {
            break parsed.login_name.to_string();
        }
        if parsed.auth_url.is_empty() {
            return Err(failed(
                "registration",
                "not authorized, and no login URL given",
            ));
        }
        let auth_url = parsed.auth_url.to_string();
        let followup = with(runtime, |state| state.control_needs_login(id, &auth_url))?;
        // Held open by the server until the login completes (or it gives up,
        // in which case the answer repeats the URL and this asks again), so
        // this one has no timeout.
        (status, len) = http2
            .request(
                "POST",
                register::PATH,
                CONTROL_HOST,
                &followup,
                &mut response,
            )
            .await
            .map_err(|e| failed("waiting for login", e))?;
    };
    drop(response);
    if !with(runtime, |state| state.control_registered(id, &login))? {
        // First enrollment: the node persists that it is enrolled and asks
        // for a fresh connection, like the firmware's reboot.
        return Ok(());
    }

    let body = with(runtime, |state| state.control_map_request(id))?;
    let mut map: Box<MapStream<PEERS>> = Box::new(MapStream::new());
    timeout(
        STEP_MS,
        MapStream::start_in(&mut map, &mut http2, CONTROL_HOST, &body),
    )
    .await
    .map_err(|_| failed("map request", "timed out"))?
    .map_err(|e| failed("map request", e))?;
    let mut staging: Box<Netmap<PEERS>> = Box::new(Netmap::new());
    let mut working: Box<Netmap<PEERS>> = Box::new(Netmap::new());
    with(runtime, |state| {
        state.seed_staging(&mut staging);
        state.control_log(id, "Control: streaming the netmap.");
    });
    loop {
        let event = timeout(
            MAP_LIVENESS_MS,
            map.next(&mut http2, &mut staging, &mut working),
        )
        .await
        .map_err(|_| failed("netmap", "no map traffic; reconnecting"))?
        .map_err(|e| failed("netmap", e))?;
        let applied = event == MapEvent::Applied;
        if !applied && map.has_pending_update() {
            // A newer map is already staged; handle it with its own event.
            continue;
        }
        let update = with(runtime, |state| {
            state.control_map_event(id, &mut staging, applied)
        })?;
        if let Some(update) = update {
            timeout(
                STEP_MS,
                transport::send_endpoint_update(
                    &mut http2,
                    &mut map,
                    &mut staging,
                    &mut working,
                    CONTROL_HOST,
                    &update,
                ),
            )
            .await
            .map_err(|_| failed("endpoint update", "timed out"))?
            .map_err(|e| failed("endpoint update", e))?;
            with(runtime, |state| {
                state.control_log(id, "Control: published the preferred DERP region.")
            });
        }
    }
}

impl From<WsError> for ControlError {
    fn from(value: WsError) -> Self {
        ControlError::Failed(value.0)
    }
}
