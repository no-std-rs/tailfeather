//! An SSH client session over the tailnet.
//!
//! russh needs a `Send` byte stream and there is no Tokio runtime in a page,
//! so russh gets one end of an in-memory `tokio::io::duplex` and a local task
//! pumps the other end to and from a smoltcp TCP socket. russh itself spawns
//! with `spawn_local` on wasm and, with keepalive and inactivity timers off,
//! never polls a Tokio timer.
//!
//! The same client also runs over a plain WebSocket byte stream
//! ([`Route::WebSocket`]), which the end-to-end tests use to exercise russh in
//! the browser against a local SSH server without a tailnet.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use futures::channel::mpsc;
use futures::future::{AbortHandle, Abortable};
use futures::{FutureExt, StreamExt};
use russh::client::{self, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, MethodKind};
use smoltcp::socket::tcp::State as TcpState;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::js::{random_u64, storage_get, storage_set, timeout};
use crate::logic::{self, AuthStep, HostKeyDecision};
use crate::netstack::TcpHandle;
use crate::runtime::{Shared, with};
use crate::ws::WsStream;

const TCP_CONNECT_MS: u32 = 45_000;
const INPUT_QUEUE: usize = 1024;
const BRIDGE_BUFFER: usize = 64 * 1024;

/// Where the SSH byte stream comes from.
pub enum Route {
    /// TCP over the tailnet, through the node's userspace stack.
    Tailnet {
        runtime: Shared,
        ip: Ipv4Addr,
        port: u16,
    },
    /// A WebSocket whose binary messages carry the raw TCP byte stream.
    WebSocket { url: String },
}

impl Route {
    /// What to call the server in messages.
    fn label(&self) -> String {
        match self {
            Self::Tailnet { ip, port, .. } => format!("{ip}:{port}"),
            Self::WebSocket { url } => url.clone(),
        }
    }

    /// Where its host key is remembered.
    fn host_key_slot(&self) -> String {
        match self {
            Self::Tailnet { ip, port, .. } => logic::host_key_slot(*ip, *port),
            Self::WebSocket { url } => format!("tailfeather.hostkey.{url}"),
        }
    }

    fn log(&self, line: String) {
        if let Self::Tailnet { runtime, .. } = self {
            with(runtime, |state| state.log(line));
        }
    }
}

pub struct SshOptions {
    pub route: Route,
    pub user: String,
    pub cols: u32,
    pub rows: u32,
    /// An OpenSSH private key pasted into the page, kept in memory only for
    /// this session.
    pub private_key: Option<String>,
}

impl Drop for SshOptions {
    fn drop(&mut self) {
        if let Some(key) = self.private_key.as_mut() {
            key.zeroize();
        }
    }
}

pub struct SshCallbacks {
    pub write: js_sys::Function,
    pub prompt: js_sys::Function,
    pub closed: Option<js_sys::Function>,
}

impl SshCallbacks {
    fn write(&self, bytes: &[u8]) {
        let array = js_sys::Uint8Array::from(bytes);
        let _ = self.write.call1(&JsValue::NULL, &array);
    }

    fn text(&self, text: &str) {
        self.write(logic::terminal_text(text).as_bytes());
    }

    /// Ask the user through the page. `None` means they cancelled.
    async fn prompt(&self, label: &str, echo: bool) -> Option<String> {
        let promise = self
            .prompt
            .call2(
                &JsValue::NULL,
                &JsValue::from_str(label),
                &JsValue::from_bool(echo),
            )
            .ok()?;
        let promise = js_sys::Promise::resolve(&promise);
        wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .ok()
            .and_then(|value| value.as_string())
    }
}

enum Input {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
    Forward(crate::forwarding::Request),
}

/// A running terminal session, handed to the page.
#[wasm_bindgen]
pub struct SshSession {
    input: mpsc::Sender<Input>,
    abort: AbortHandle,
}

#[wasm_bindgen]
impl SshSession {
    /// Open a loopback channel through this exact authenticated SSH session.
    /// `eof` ends the remote-to-local half; `closed` releases the entire pipe.
    pub async fn open_forward(
        &self,
        host: String,
        port: u16,
        write: js_sys::Function,
        eof: js_sys::Function,
        closed: js_sys::Function,
    ) -> Result<crate::forwarding::SshForwardPipe, JsError> {
        use futures::SinkExt;
        let (request, pipe, ready) = crate::forwarding::request(host, port, write, eof, closed)?;
        self.input
            .clone()
            .send(Input::Forward(request))
            .await
            .map_err(|_| JsError::new("SSH session closed"))?;
        ready
            .await
            .map_err(|_| JsError::new("SSH session closed"))?
            .map_err(|error| JsError::new(&error))?;
        Ok(pipe)
    }
    /// Keystrokes or pasted text for the remote shell.
    pub fn send(&self, data: &[u8]) {
        let _ = self.input.clone().try_send(Input::Data(data.to_vec()));
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.input.clone().try_send(Input::Resize(cols, rows));
    }

    pub fn close(&self) {
        // The queue can be full while a write is blocked; a disconnect must
        // not be lost then, so fall back to ending the task outright.
        if self.input.clone().try_send(Input::Close).is_err() {
            self.abort.abort();
        }
    }
}

pub fn start(options: SshOptions, callbacks: SshCallbacks) -> SshSession {
    let (sender, receiver) = mpsc::channel(INPUT_QUEUE);
    let (abort, registration) = AbortHandle::new_pair();
    // A session over the tailnet lives on the runtime's network stack; the
    // runtime ends it when that stack is replaced or stopped.
    let task = match &options.route {
        Route::Tailnet { runtime, .. } => Some((
            runtime.clone(),
            with(runtime, |state| state.register_ssh_task(abort.clone())),
        )),
        Route::WebSocket { .. } => None,
    };
    wasm_bindgen_futures::spawn_local(async move {
        let reason = match Abortable::new(run(&options, &callbacks, receiver), registration).await {
            Ok(Ok(reason)) => reason,
            Ok(Err(error)) => {
                callbacks.text(&format!("\r\n\x1b[31m{error}\x1b[0m\r\n"));
                error
            }
            Err(_) => {
                let reason = format!("Disconnected from {}.", options.route.label());
                callbacks.text(&format!("\r\n{reason}\r\n"));
                reason
            }
        };
        if let Some((runtime, id)) = task {
            with(&runtime, |state| state.ssh_task_done(id));
        }
        options
            .route
            .log(format!("SSH to {}: {reason}", options.route.label()));
        if let Some(closed) = &callbacks.closed {
            let _ = closed.call1(&JsValue::NULL, &JsValue::from_str(&reason));
        }
    });
    SshSession {
        input: sender,
        abort,
    }
}

struct Handler {
    known: Option<String>,
    presented: Arc<Mutex<Option<String>>>,
    banners: tokio::sync::mpsc::Sender<String>,
}

fn fingerprint(key: &PublicKeyOrCertificate) -> String {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => {
            key.fingerprint(HashAlg::Sha256).to_string()
        }
        PublicKeyOrCertificate::Certificate(certificate) => certificate
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    }
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented = fingerprint(server_public_key);
        let decision = logic::host_key_decision(self.known.as_deref(), &presented);
        *self.presented.lock().expect("single-threaded") = Some(presented);
        // A changed key fails the handshake here; the caller explains why.
        Ok(!matches!(decision, HostKeyDecision::Changed { .. }))
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.banners.try_send(banner.to_string());
        Ok(())
    }
}

async fn wait_established(runtime: &Shared, handle: TcpHandle) -> Result<(), String> {
    std::future::poll_fn(|cx| {
        let mut state = runtime.state.borrow_mut();
        let Some(socket) = state.net.tcp(handle) else {
            return Poll::Ready(Err("the node restarted".to_string()));
        };
        match socket.state() {
            TcpState::Established => Poll::Ready(Ok(())),
            TcpState::SynSent | TcpState::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            other => Poll::Ready(Err(format!("TCP connection failed ({other})"))),
        }
    })
    .await
}

/// Move bytes between russh's end of the duplex and the smoltcp socket until
/// either side closes.
async fn bridge(runtime: Shared, handle: TcpHandle, stream: DuplexStream) {
    let (mut from_ssh, mut to_ssh) = tokio::io::split(stream);
    let outbound = {
        let runtime = runtime.clone();
        async move {
            let mut buffer = vec![0u8; BRIDGE_BUFFER];
            loop {
                let len = match from_ssh.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(len) => len,
                };
                let mut offset = 0;
                while offset < len {
                    let sent = std::future::poll_fn(|cx| {
                        let mut state = runtime.state.borrow_mut();
                        let Some(socket) = state.net.tcp(handle) else {
                            return Poll::Ready(None);
                        };
                        if !socket.may_send() {
                            return Poll::Ready(None);
                        }
                        match socket.send_slice(&buffer[offset..len]) {
                            Ok(0) => {
                                socket.register_send_waker(cx.waker());
                                Poll::Pending
                            }
                            Ok(sent) => Poll::Ready(Some(sent)),
                            Err(_) => Poll::Ready(None),
                        }
                    })
                    .await;
                    runtime.wake.notify();
                    match sent {
                        Some(sent) => offset += sent,
                        None => return,
                    }
                }
            }
            if let Some(socket) = runtime.state.borrow_mut().net.tcp(handle) {
                socket.close();
            }
            runtime.wake.notify();
        }
    };
    let inbound = {
        let runtime = runtime.clone();
        async move {
            let mut buffer = vec![0u8; BRIDGE_BUFFER];
            loop {
                let received = std::future::poll_fn(|cx| {
                    let mut state = runtime.state.borrow_mut();
                    let Some(socket) = state.net.tcp(handle) else {
                        return Poll::Ready(0);
                    };
                    if socket.can_recv() {
                        return Poll::Ready(socket.recv_slice(&mut buffer).unwrap_or(0));
                    }
                    if !socket.may_recv() {
                        return Poll::Ready(0);
                    }
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                })
                .await;
                // Reading frees receive window; let the driver advertise it.
                runtime.wake.notify();
                if received == 0 || to_ssh.write_all(&buffer[..received]).await.is_err() {
                    break;
                }
            }
            let _ = to_ssh.shutdown().await;
        }
    };
    futures::future::join(outbound, inbound).await;
    runtime.state.borrow_mut().net.remove(handle);
    runtime.wake.notify();
}

/// Move bytes between russh's end of the duplex and a WebSocket.
async fn websocket_bridge(ws: WsStream, stream: DuplexStream) {
    let (mut from_ssh, mut to_ssh) = tokio::io::split(stream);
    let outbound = async {
        let mut buffer = vec![0u8; BRIDGE_BUFFER];
        loop {
            match from_ssh.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    if ws.send(&buffer[..len]).is_err() {
                        break;
                    }
                }
            }
        }
    };
    let inbound = async {
        let mut buffer = vec![0u8; BRIDGE_BUFFER];
        loop {
            match ws.read_some(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    if to_ssh.write_all(&buffer[..len]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to_ssh.shutdown().await;
    };
    futures::future::join(outbound, inbound).await;
}

/// A TCP socket that has not been handed to [`bridge`] yet. Dropping it removes
/// the socket, so an abandoned connect does not keep retrying in the stack.
struct PendingTcp {
    runtime: Shared,
    handle: Option<TcpHandle>,
}

impl PendingTcp {
    /// The bridge owns the socket from here on.
    fn release(mut self) {
        self.handle = None;
    }
}

impl Drop for PendingTcp {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take()
            && let Ok(mut state) = self.runtime.state.try_borrow_mut()
        {
            state.net.remove(handle);
            drop(state);
            self.runtime.wake.notify();
        }
    }
}

/// Open the byte stream russh will run over.
async fn connect(
    route: &Route,
    callbacks: &SshCallbacks,
    user: &str,
) -> Result<DuplexStream, String> {
    let (ssh_end, network_end) = tokio::io::duplex(BRIDGE_BUFFER);
    match route {
        Route::Tailnet { runtime, ip, port } => {
            let target = route.label();
            let path = with(runtime, |state| state.describe_path(*ip));
            callbacks.text(&format!(
                "Connecting to {target} as {user} — {path}.\nThe tunnel runs over DERP; the first packets wait for the WireGuard handshake.\n"
            ));
            let local_port = 49152 + (random_u64() % 16384) as u16;
            let handle = with(runtime, |state| {
                state.log(format!("SSH: opening TCP to {target}"));
                state.net.connect(*ip, *port, local_port)
            })?;
            // Removes the socket on timeout, and also when the user
            // disconnects and this future is dropped mid-connect.
            let pending = PendingTcp {
                runtime: runtime.clone(),
                handle: Some(handle),
            };
            timeout(TCP_CONNECT_MS, wait_established(runtime, handle))
                .await
                .unwrap_or_else(|_| Err("TCP connection timed out".into()))?;
            pending.release();
            route.log(format!("SSH: TCP connected to {target}"));
            callbacks.text("TCP connected; starting SSH.\n");
            // The bridge waits on wakers inside the stack's socket; if the
            // stack is replaced, nothing would wake it again, so it is
            // registered to be ended with the stack.
            let (abort, registration) = AbortHandle::new_pair();
            let id = with(runtime, |state| state.register_ssh_task(abort));
            let runtime = runtime.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = Abortable::new(bridge(runtime.clone(), handle, network_end), registration)
                    .await;
                with(&runtime, |state| state.ssh_task_done(id));
            });
        }
        Route::WebSocket { url } => {
            callbacks.text(&format!("Connecting to {url} as {user}.\n"));
            let ws = WsStream::connect(url, "binary").map_err(|error| error.0)?;
            timeout(TCP_CONNECT_MS, ws.opened())
                .await
                .map_err(|_| "WebSocket connect timed out".to_string())?
                .map_err(|error| error.0)?;
            wasm_bindgen_futures::spawn_local(websocket_bridge(ws, network_end));
        }
    }
    Ok(ssh_end)
}

async fn run(
    options: &SshOptions,
    callbacks: &SshCallbacks,
    mut input: mpsc::Receiver<Input>,
) -> Result<String, String> {
    let target = options.route.label();
    // Everything before the shell can wait on the network or on a prompt the
    // user may never answer, so Disconnect has to be able to interrupt it too.
    // Dropping the setup future drops the connection with it.
    let mut size = (options.cols, options.rows);
    let established = {
        let setup = establish(options, callbacks).fuse();
        futures::pin_mut!(setup);
        loop {
            futures::select! {
                result = setup => break Some(result),
                command = input.next() => match command {
                    Some(Input::Resize(cols, rows)) => size = (cols, rows),
                    // There is no channel to type into yet.
                    Some(Input::Data(_)) => {}
                    Some(Input::Forward(request)) => {
                        let _ = request.ready.send(Err("SSH is not authenticated yet".into()));
                    }
                    Some(Input::Close) | None => break None,
                },
            }
        }
    };
    let Some(established) = established else {
        return Ok(format!(
            "Disconnected from {target} before the session started."
        ));
    };
    let (session, channel) = established?;
    let (mut reader, writer) = channel.split();
    if size != (options.cols, options.rows) {
        let _ = writer.window_change(size.0, size.1, 0, 0).await;
    }
    let mut exit_status = None;
    let mut forwards = futures::stream::FuturesUnordered::new();
    loop {
        futures::select! {
            _ = async {
                if forwards.is_empty() { futures::future::pending::<()>().await; }
                else { forwards.next().await; }
            }.fuse() => {},
            message = reader.wait().fuse() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    callbacks.write(&data);
                }
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::Eof) => {}
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            command = input.next() => match command {
                Some(Input::Forward(request)) => {
                    if forwards.len() < 32 {
                        forwards.push(crate::forwarding::run(&session, request));
                    } else {
                        let _ = request.ready.send(Err("too many forwarding channels".into()));
                    }
                }
                Some(Input::Data(bytes)) => {
                    if writer.data_bytes(bytes).await.is_err() {
                        break;
                    }
                }
                Some(Input::Resize(cols, rows)) => {
                    let _ = writer.window_change(cols, rows, 0, 0).await;
                }
                Some(Input::Close) | None => {
                    let _ = writer.eof().await;
                    let _ = writer.close().await;
                    break;
                }
            },
        }
    }
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
    Ok(match exit_status {
        Some(status) => format!("Connection to {target} closed (exit status {status})."),
        None => format!("Connection to {target} closed."),
    })
}

/// Connect, verify the host key, authenticate and start a shell.
async fn establish(
    options: &SshOptions,
    callbacks: &SshCallbacks,
) -> Result<(client::Handle<Handler>, russh::Channel<client::Msg>), String> {
    let route = &options.route;
    let target = route.label();
    let ssh_end = connect(route, callbacks, &options.user).await?;

    let slot = route.host_key_slot();
    let known = storage_get(&slot);
    let presented = Arc::new(Mutex::new(None));
    let (banners, mut banner_rx) = tokio::sync::mpsc::channel::<String>(16);
    let handler = Handler {
        known: known.clone(),
        presented: presented.clone(),
        banners,
    };
    // Banners can arrive while an authentication request is still pending —
    // Tailscale SSH's "check" mode sends its login link this way — so print
    // them as they come rather than after each step.
    {
        let write = callbacks.write.clone();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(banner) = banner_rx.recv().await {
                let text = logic::terminal_text(&banner);
                let _ = write.call1(&JsValue::NULL, &js_sys::Uint8Array::from(text.as_bytes()));
            }
        });
    }

    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: None,
        ..Default::default()
    });
    let connected = client::connect_stream(config, ssh_end, handler).await;
    let presented = presented.lock().expect("single-threaded").clone();
    let mut session = match connected {
        Ok(session) => session,
        Err(error) => {
            if let (Some(presented), Some(expected)) = (&presented, &known)
                && presented != expected
            {
                return Err(format!(
                    "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n\
                     The host key of {target} is now {presented}, but {expected} was remembered.\n\
                     Refusing to connect. If the change is expected, use \"Forget host key\" and retry."
                ));
            }
            return Err(format!("SSH handshake failed: {error}"));
        }
    };
    let Some(presented) = presented else {
        return Err("the server presented no host key".into());
    };
    match logic::host_key_decision(known.as_deref(), &presented) {
        HostKeyDecision::FirstUse => {
            // Trust on first use is only worth something if the key is pinned:
            // an unsaved key makes every later connection another "first use"
            // that no substituted host key could fail.
            if !storage_set(&slot, &presented) {
                return Err(format!(
                    "Could not save the host key of {target} ({presented}) in this browser's \
                     storage, so it could not be checked next time. Refusing to connect; free \
                     some site storage and retry."
                ));
            }
            callbacks.text(&format!(
                "Permanently added {target} ({presented}) to the known hosts of this browser.\n"
            ));
        }
        HostKeyDecision::Known => {
            callbacks.text(&format!(
                "Host key {presented} matches the remembered one.\n"
            ));
        }
        HostKeyDecision::Changed { .. } => return Err("host key changed".into()),
    }

    authenticate(&mut session, options, callbacks).await?;

    let channel = session
        .channel_open_session()
        .await
        .map_err(|error| format!("opening a session channel: {error}"))?;
    channel
        .request_pty(
            false,
            "xterm-256color",
            options.cols,
            options.rows,
            0,
            0,
            &[],
        )
        .await
        .map_err(|error| format!("requesting a PTY: {error}"))?;
    channel
        .request_shell(false)
        .await
        .map_err(|error| format!("starting a shell: {error}"))?;
    Ok((session, channel))
}

fn offered(methods: &russh::MethodSet) -> Vec<AuthStep> {
    methods
        .iter()
        .filter_map(|method| match method {
            MethodKind::KeyboardInteractive => Some(AuthStep::KeyboardInteractive),
            MethodKind::Password => Some(AuthStep::Password),
            MethodKind::PublicKey => Some(AuthStep::PublicKey),
            _ => None,
        })
        .collect()
}

async fn authenticate(
    session: &mut client::Handle<Handler>,
    options: &SshOptions,
    callbacks: &SshCallbacks,
) -> Result<(), String> {
    let user = options.user.clone();
    let log = |line: String| options.route.log(line);
    log(format!("SSH: trying auth method none for {user}"));
    let mut remaining = match session
        .authenticate_none(&user)
        .await
        .map_err(|error| format!("authentication: {error}"))?
    {
        client::AuthResult::Success => {
            log("SSH: authenticated (none — tailnet identity)".into());
            return Ok(());
        }
        client::AuthResult::Failure {
            remaining_methods, ..
        } => offered(&remaining_methods),
    };
    let mut tried = Vec::new();
    while let Some(step) = logic::next_auth_step(&remaining, &tried, options.private_key.is_some())
    {
        tried.push(step);
        log(format!("SSH: trying auth method {step:?}"));
        let result = match step {
            AuthStep::KeyboardInteractive => {
                let mut response = session
                    .authenticate_keyboard_interactive_start(&user, None)
                    .await
                    .map_err(|error| format!("authentication: {error}"))?;
                loop {
                    match response {
                        KeyboardInteractiveAuthResponse::Success => {
                            break client::AuthResult::Success;
                        }
                        KeyboardInteractiveAuthResponse::Failure {
                            remaining_methods,
                            partial_success,
                        } => {
                            break client::AuthResult::Failure {
                                remaining_methods,
                                partial_success,
                            };
                        }
                        KeyboardInteractiveAuthResponse::InfoRequest {
                            name,
                            instructions,
                            prompts,
                        } => {
                            for text in [name, instructions] {
                                if !text.is_empty() {
                                    callbacks.text(&format!("{text}\n"));
                                }
                            }
                            let mut answers = Vec::with_capacity(prompts.len());
                            for prompt in prompts {
                                let answer = callbacks
                                    .prompt(&prompt.prompt, prompt.echo)
                                    .await
                                    .ok_or("authentication cancelled")?;
                                answers.push(answer);
                            }
                            response = session
                                .authenticate_keyboard_interactive_respond(answers)
                                .await
                                .map_err(|error| format!("authentication: {error}"))?;
                        }
                    }
                }
            }
            AuthStep::Password => {
                let label = format!("{user}@{}'s password: ", options.route.label());
                let mut password = callbacks
                    .prompt(&label, false)
                    .await
                    .ok_or("authentication cancelled")?;
                let result = session
                    .authenticate_password(&user, password.clone())
                    .await
                    .map_err(|error| format!("authentication: {error}"));
                password.zeroize();
                result?
            }
            AuthStep::PublicKey => {
                let text = options.private_key.as_deref().unwrap_or_default();
                let key = match russh::keys::decode_secret_key(text, None) {
                    Ok(key) => key,
                    Err(_) => {
                        let mut passphrase = callbacks
                            .prompt("Passphrase for the pasted private key: ", false)
                            .await
                            .ok_or("authentication cancelled")?;
                        let key = russh::keys::decode_secret_key(text, Some(&passphrase));
                        passphrase.zeroize();
                        key.map_err(|error| format!("private key: {error}"))?
                    }
                };
                let hash = session
                    .best_supported_rsa_hash()
                    .await
                    .ok()
                    .flatten()
                    .flatten();
                session
                    .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await
                    .map_err(|error| format!("authentication: {error}"))?
            }
        };
        match result {
            client::AuthResult::Success => {
                log(format!("SSH: authenticated ({step:?})"));
                return Ok(());
            }
            client::AuthResult::Failure {
                remaining_methods, ..
            } => remaining = offered(&remaining_methods),
        }
    }
    Err(format!(
        "{user}@{}: permission denied (no remaining authentication method succeeded)",
        options.route.label()
    ))
}
