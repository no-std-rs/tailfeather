//! Loopback-only SSH forwarding on an already authenticated connection.
//! Tasks are polled by the terminal session, so disconnect drops every pipe.

use futures::channel::{mpsc, oneshot};
use futures::future::{AbortHandle, Abortable};
use futures::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasm_bindgen::prelude::*;

pub(crate) enum Command {
    Data(Vec<u8>, oneshot::Sender<Result<(), ()>>),
    Eof,
}

pub(crate) struct Request {
    pub host: String,
    pub port: u16,
    pub write: js_sys::Function,
    pub eof: js_sys::Function,
    pub closed: js_sys::Function,
    pub input: mpsc::Receiver<Command>,
    pub ready: oneshot::Sender<Result<(), String>>,
    pub registration: futures::future::AbortRegistration,
}

#[wasm_bindgen]
pub struct SshForwardPipe {
    input: mpsc::Sender<Command>,
    abort: AbortHandle,
}

#[wasm_bindgen]
impl SshForwardPipe {
    /// Resolve only after SSH accepted the bytes, keeping native TCP bounded.
    pub async fn send(&self, bytes: &[u8]) -> Result<(), JsError> {
        if bytes.len() > 32768 {
            return Err(JsError::new("forwarding frame exceeds 32 KiB"));
        }
        let (ready, done) = oneshot::channel();
        self.input
            .clone()
            .send(Command::Data(bytes.to_vec(), ready))
            .await
            .map_err(|_| JsError::new("forwarding channel closed"))?;
        done.await
            .map_err(|_| JsError::new("forwarding channel closed"))?
            .map_err(|_| JsError::new("forwarding write failed"))
    }

    pub async fn eof(&self) -> Result<(), JsError> {
        self.input
            .clone()
            .send(Command::Eof)
            .await
            .map_err(|_| JsError::new("forwarding channel closed"))
    }

    pub fn close(&self) {
        self.abort.abort();
    }
}

impl Drop for SshForwardPipe {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

pub(crate) fn request(
    host: String,
    port: u16,
    write: js_sys::Function,
    eof: js_sys::Function,
    closed: js_sys::Function,
) -> Result<
    (
        Request,
        SshForwardPipe,
        oneshot::Receiver<Result<(), String>>,
    ),
    JsError,
> {
    if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") || port == 0 {
        return Err(JsError::new(
            "forwarding requires an exact loopback host and nonzero port",
        ));
    }
    let (sender, input) = mpsc::channel(1);
    let (abort, registration) = AbortHandle::new_pair();
    let (ready, done) = oneshot::channel();
    Ok((
        Request {
            host,
            port,
            write,
            eof,
            closed,
            input,
            ready,
            registration,
        },
        SshForwardPipe {
            input: sender,
            abort,
        },
        done,
    ))
}

struct NotifyClosed(js_sys::Function);
impl Drop for NotifyClosed {
    fn drop(&mut self) {
        let _ = self.0.call0(&JsValue::NULL);
    }
}

pub(crate) async fn run<H: russh::client::Handler>(
    session: &russh::client::Handle<H>,
    request: Request,
) {
    let Request {
        host,
        port,
        write,
        eof,
        closed,
        mut input,
        ready,
        registration,
    } = request;
    let _notify = NotifyClosed(closed);
    let opening = session
        .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
        .fuse();
    let cancelled = Abortable::new(futures::future::pending::<()>(), registration).fuse();
    futures::pin_mut!(opening, cancelled);
    let opened = {
        let deadline = crate::js::sleep(15_000).fuse();
        futures::pin_mut!(deadline);
        futures::select! {
            result = opening => Some(result),
            _ = deadline => None,
            _ = cancelled => None,
        }
    };
    let channel = match opened {
        Some(Ok(channel)) => channel,
        Some(Err(_)) => {
            let _ = ready.send(Err("SSH forwarding refused".into()));
            return;
        }
        None => {
            let _ = ready.send(Err("SSH forwarding cancelled or timed out".into()));
            // russh keeps an open request after its waiter is dropped. Drain a
            // late confirmation and close its channel, retaining this task in
            // the session's bounded set until then (or session disconnect).
            if let Ok(channel) = opening.await {
                drop(channel.into_stream());
            }
            return;
        }
    };
    let operation = async {
        let _ = ready.send(Ok(()));
        let (mut reader, mut writer) = tokio::io::split(channel.into_stream());
        // Each direction must progress while the other waits on SSH window
        // capacity or the native TCP consumer; otherwise uploads and early
        // responses can deadlock each other under backpressure.
        let inbound = async {
            let mut buffer = [0u8; 32768];
            loop {
                let len = match reader.read(&mut buffer).await {
                    Ok(0) => {
                        let result = eof.call0(&JsValue::NULL).map_err(|_| ())?;
                        return wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(
                            &result,
                        ))
                        .await
                        .map(|_| ())
                        .map_err(|_| ());
                    }
                    Err(_) => return Err(()),
                    Ok(len) => len,
                };
                let array = js_sys::Uint8Array::from(&buffer[..len]);
                let result = write.call1(&JsValue::NULL, &array).map_err(|_| ())?;
                wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&result))
                    .await
                    .map_err(|_| ())?;
            }
        };
        let outbound = async {
            while let Some(command) = input.next().await {
                match command {
                    Command::Data(data, ready) => {
                        let result = writer.write_all(&data).await.map_err(|_| ());
                        let failed = result.is_err();
                        let _ = ready.send(result);
                        if failed {
                            return Err(());
                        }
                    }
                    Command::Eof => {
                        return writer.shutdown().await.map_err(|_| ());
                    }
                }
            }
            writer.shutdown().await.map_err(|_| ())
        };
        // A clean EOF finishes only that half. An error or cancellation still
        // drops both halves immediately; normal completion waits for both.
        let _ = futures::try_join!(inbound, outbound);
    };
    futures::pin_mut!(operation);
    futures::select! { _ = operation.fuse() => {}, _ = cancelled => {} }
}
