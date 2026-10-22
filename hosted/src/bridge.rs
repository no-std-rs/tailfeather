use crate::netstack::{NetStack, TcpHandle};
use std::{cell::RefCell, io, rc::Rc, task::Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
type Shared = Rc<RefCell<NetStack>>;
const BRIDGE_BUFFER: usize = 16384;
pub async fn connect(
    net: Shared,
    handle: TcpHandle,
    reply: tokio::sync::oneshot::Sender<io::Result<DuplexStream>>,
) {
    let established = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            if reply.is_closed() {
                return false;
            }
            let state = net.borrow_mut().tcp(handle).map(|s| s.state());
            match state {
                Some(smoltcp::socket::tcp::State::Established) => return true,
                Some(smoltcp::socket::tcp::State::SynSent) => {}
                _ => return false,
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or(false);
    if !established {
        net.borrow_mut().remove(handle);
        let _ = reply.send(Err(io::Error::other("tailnet TCP connection failed")));
        return;
    }
    let (client, stream) = tokio::io::duplex(65536);
    if reply.send(Ok(client)).is_err() {
        net.borrow_mut().remove(handle);
        return;
    }
    bridge(net, handle, stream).await;
}
pub async fn accepted(
    net: Shared,
    handle: TcpHandle,
    incoming: tokio::sync::mpsc::Sender<DuplexStream>,
) {
    let (client, stream) = tokio::io::duplex(65536);
    if incoming.try_send(client).is_err() {
        net.borrow_mut().remove(handle);
        return;
    }
    bridge(net, handle, stream).await;
}
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
                        let mut state = runtime.borrow_mut();
                        let Some(socket) = state.tcp(handle) else {
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

                    match sent {
                        Some(sent) => offset += sent,
                        None => return,
                    }
                }
            }
            if let Some(socket) = runtime.borrow_mut().tcp(handle) {
                socket.close();
            }
        }
    };
    let inbound = {
        let runtime = runtime.clone();
        async move {
            let mut buffer = vec![0u8; BRIDGE_BUFFER];
            loop {
                let received = std::future::poll_fn(|cx| {
                    let mut state = runtime.borrow_mut();
                    let Some(socket) = state.tcp(handle) else {
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

                if received == 0 || to_ssh.write_all(&buffer[..received]).await.is_err() {
                    break;
                }
            }
            let _ = to_ssh.shutdown().await;
        }
    };
    tokio::join!(outbound, inbound);
    runtime.borrow_mut().remove(handle);
}
