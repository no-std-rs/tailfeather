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
    let established = tokio::time::timeout(std::time::Duration::from_secs(90), async {
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
    let abandoned = tokio::sync::Notify::new();
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
        let abandoned = &abandoned;
        async move {
            let mut buffer = vec![0u8; BRIDGE_BUFFER];
            let mut probe = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                let receive = std::future::poll_fn(|cx| {
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
                });
                let received = tokio::select! {
                    received = receive => received,
                    _ = probe.tick() => {
                        // Tokio's in-memory pipe reports a dropped reader even
                        // for a zero-length write. Preserve legitimate TCP
                        // half-closes while detecting a fully dropped stream.
                        if to_ssh.write(&[]).await.is_err() { abandoned.notify_one(); break; }
                        continue;
                    }
                };
                // Reading frees receive window; let the driver advertise it.

                if received == 0 {
                    break;
                }
                if to_ssh.write_all(&buffer[..received]).await.is_err() {
                    abandoned.notify_one();
                    break;
                }
            }
            let _ = to_ssh.shutdown().await;
        }
    };
    tokio::select! {
        _ = async { tokio::join!(outbound, inbound); } => {},
        _ = abandoned.notified() => {},
    }
    runtime.borrow_mut().remove(handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_dropped_stream_releases_a_half_closed_socket_but_shutdown_keeps_reading() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(tokio::task::LocalSet::new().run_until(async {
                let mut local = NetStack::new(1);
                let mut remote = NetStack::new(2);
                local.set_address("100.64.0.1".parse().unwrap(), 0, 1);
                remote.set_address("100.64.0.2".parse().unwrap(), 0, 2);
                let listener = remote.listen(2222).unwrap();
                let handle = local
                    .connect("100.64.0.2".parse().unwrap(), 2222, 49152)
                    .unwrap();
                for now in 0..10 {
                    for bytes in local.poll(now) {
                        remote.deliver(&bytes);
                    }
                    for bytes in remote.poll(now) {
                        local.deliver(&bytes);
                    }
                }
                assert_eq!(
                    local.tcp(handle).unwrap().state(),
                    smoltcp::socket::tcp::State::Established
                );
                let local = Rc::new(RefCell::new(local));
                let (mut client, stream) = tokio::io::duplex(1024);
                let task = tokio::task::spawn_local(bridge(local.clone(), handle, stream));
                let local_driver = local.clone();
                let driver = tokio::task::spawn_local(async move {
                    let mut now = 10;
                    loop {
                        for bytes in local_driver.borrow_mut().poll(now) {
                            remote.deliver(&bytes);
                        }
                        for bytes in remote.poll(now) {
                            local_driver.borrow_mut().deliver(&bytes);
                        }
                        assert!(remote.tcp(listener).is_some());
                        now += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                });
                client.shutdown().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                assert_eq!(
                    local.borrow_mut().tcp(handle).unwrap().state(),
                    smoltcp::socket::tcp::State::FinWait2
                );
                assert!(
                    !task.is_finished(),
                    "a write half-close must retain the response reader"
                );
                drop(client);
                tokio::time::timeout(std::time::Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(local.borrow().sockets.iter().count(), 0);
                driver.abort();
            }));
    }
}
