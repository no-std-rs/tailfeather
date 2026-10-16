//! A browser WebSocket as a byte stream.
//!
//! Both protocols carried here (ts2021 records and DERP frames) are byte
//! streams whose framing has nothing to do with WebSocket messages: an inbound
//! message may hold any fragment, and each outbound write is sent as one
//! binary message. [`WsStream`] implements `embedded_io_async` so the
//! tailfeather control transport runs on it unchanged.

use std::cell::RefCell;
use std::rc::Rc;
use std::task::{Poll, Waker};

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

use crate::logic::{ByteQueue, ReadOutcome};

/// Inbound bytes one socket may buffer ahead of its reader. A full netmap is
/// the largest burst; its reader drains it as fast as it arrives.
const INBOUND_LIMIT: usize = 16 * 1024 * 1024;
/// Outbound bytes the browser may hold for a socket before writes are refused
/// rather than queued without bound.
const OUTBOUND_LIMIT: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct WsError(pub String);

impl core::fmt::Display for WsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WsError {}

impl embedded_io_async::Error for WsError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

struct Shared {
    queue: ByteQueue,
    received: usize,
    open: bool,
    reader: Option<Waker>,
    opener: Option<Waker>,
}

impl Shared {
    fn wake(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.opener.take() {
            waker.wake();
        }
    }
}

type Handler<T> = Closure<dyn FnMut(T)>;

pub struct Received(Rc<RefCell<Shared>>);

impl Received {
    pub fn get(&self) -> usize {
        self.0.borrow().received
    }
}

pub struct WsStream {
    socket: WebSocket,
    shared: Rc<RefCell<Shared>>,
    _on_open: Handler<Event>,
    _on_message: Handler<MessageEvent>,
    _on_close: Handler<CloseEvent>,
    _on_error: Handler<Event>,
}

impl WsStream {
    /// Start connecting. Await [`WsStream::opened`] before relying on it.
    pub fn connect(url: &str, protocol: &str) -> Result<Self, WsError> {
        let socket = WebSocket::new_with_str(url, protocol)
            .map_err(|error| WsError(crate::js::describe(&error)))?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let shared = Rc::new(RefCell::new(Shared {
            queue: ByteQueue::new(INBOUND_LIMIT),
            received: 0,
            open: false,
            reader: None,
            opener: None,
        }));

        let state = shared.clone();
        let on_open = Handler::<Event>::new(move |_| {
            let mut state = state.borrow_mut();
            state.open = true;
            state.wake();
        });
        let state = shared.clone();
        let weak_socket = socket.clone();
        let on_message = Handler::<MessageEvent>::new(move |event: MessageEvent| {
            let mut state = state.borrow_mut();
            let result = match event.data().dyn_into::<js_sys::ArrayBuffer>() {
                Ok(buffer) => {
                    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                    state.received += bytes.len();
                    state.queue.push(&bytes)
                }
                Err(_) => {
                    state
                        .queue
                        .close(Err("text message on a binary protocol".into()));
                    Err(String::new())
                }
            };
            if result.is_err() {
                let _ = weak_socket.close();
            }
            state.wake();
        });
        let state = shared.clone();
        let on_close = Handler::<CloseEvent>::new(move |event: CloseEvent| {
            let mut state = state.borrow_mut();
            let result = if event.was_clean() && event.code() == 1000 {
                Ok(())
            } else {
                Err(if event.reason().is_empty() {
                    format!("WebSocket closed (code {})", event.code())
                } else {
                    format!(
                        "WebSocket closed (code {}): {}",
                        event.code(),
                        event.reason()
                    )
                })
            };
            state.queue.close(result);
            state.wake();
        });
        let state = shared.clone();
        let on_error = Handler::<Event>::new(move |_| {
            let mut state = state.borrow_mut();
            state.queue.close(Err("WebSocket error".into()));
            state.wake();
        });
        socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        Ok(Self {
            socket,
            shared,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
            _on_error: on_error,
        })
    }

    /// Resolve once the upgrade completed, or fail if the socket closed first.
    pub async fn opened(&self) -> Result<(), WsError> {
        std::future::poll_fn(|cx| {
            let mut shared = self.shared.borrow_mut();
            if shared.open {
                return Poll::Ready(Ok(()));
            }
            if shared.queue.is_closed() {
                let mut scratch = [0u8; 0];
                return Poll::Ready(Err(WsError(match shared.queue.read(&mut scratch) {
                    ReadOutcome::Failed(error) => error,
                    _ => "WebSocket closed before it opened".into(),
                })));
            }
            shared.opener = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// A live count of bytes received, for diagnostics after the stream
    /// itself has been moved away.
    pub fn received_counter(&self) -> Received {
        Received(self.shared.clone())
    }

    /// The underlying socket, for sending from outside the reading task.
    pub fn socket(&self) -> WebSocket {
        self.socket.clone()
    }

    /// Send one binary message.
    pub fn send(&self, bytes: &[u8]) -> Result<(), WsError> {
        send(&self.socket, bytes)
    }

    /// Read at least one byte, or report the end of the stream (`Ok(0)`).
    pub async fn read_some(&self, out: &mut [u8]) -> Result<usize, WsError> {
        if out.is_empty() {
            return Ok(0);
        }
        std::future::poll_fn(|cx| {
            let mut shared = self.shared.borrow_mut();
            match shared.queue.read(out) {
                ReadOutcome::Data(len) => Poll::Ready(Ok(len)),
                ReadOutcome::Eof => Poll::Ready(Ok(0)),
                ReadOutcome::Failed(error) => Poll::Ready(Err(WsError(error))),
                ReadOutcome::Pending => {
                    shared.reader = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Fill `out` completely; a stream that ends first is an error.
    pub async fn read_exact(&self, out: &mut [u8]) -> Result<(), WsError> {
        let mut filled = 0;
        while filled < out.len() {
            let read = self.read_some(&mut out[filled..]).await?;
            if read == 0 {
                return Err(WsError("connection closed mid-message".into()));
            }
            filled += read;
        }
        Ok(())
    }
}

/// Send one binary message on a socket, refusing to queue without bound.
pub fn send(socket: &WebSocket, bytes: &[u8]) -> Result<(), WsError> {
    if socket.ready_state() != WebSocket::OPEN {
        return Err(WsError("WebSocket is not open".into()));
    }
    if socket.buffered_amount() > OUTBOUND_LIMIT {
        return Err(WsError("WebSocket send buffer is full".into()));
    }
    socket
        .send_with_u8_array(bytes)
        .map_err(|error| WsError(crate::js::describe(&error)))
}

impl Drop for WsStream {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        let _ = self.socket.close();
    }
}

impl embedded_io_async::ErrorType for WsStream {
    type Error = WsError;
}

impl embedded_io_async::Read for WsStream {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, WsError> {
        self.read_some(out).await
    }
}

impl embedded_io_async::Write for WsStream {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, WsError> {
        self.send(bytes)?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), WsError> {
        Ok(())
    }
}
