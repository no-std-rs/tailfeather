//! Two bounded DERP sessions. The actor owns each stream and pending frame state.
use crate::{
    OsRng,
    exec::{self, Either, Reactor},
    net::TcpStream,
    node::{Actions, Error, Shared, enqueue},
};
use core::cell::{Cell, RefCell};
use embedded_io_async::{Read, Write};
use heapless::Deque;
use tailfeather::derp::{
    client::Client,
    frame::{self, Frame, FrameType},
};
use tailfeather::{DerpCommand, DerpEvent, Endpoint};
const FRAME: usize = 4096;
pub struct Slot {
    region: Cell<Option<u16>>,
    queue: RefCell<Deque<DerpCommand, 16>>,
    stop: Cell<bool>,
    ready: tokio::sync::Notify,
    stopped: tokio::sync::Notify,
}
impl Slot {
    pub fn new() -> Self {
        Self {
            region: Cell::new(None),
            queue: RefCell::new(Deque::new()),
            stop: Cell::new(false),
            ready: tokio::sync::Notify::new(),
            stopped: tokio::sync::Notify::new(),
        }
    }
}
pub fn dispatch(
    slots: &[Slot; 2],
    command: DerpCommand,
    node: &Shared,
    actions: &Actions,
    now: u64,
) -> Option<DerpCommand> {
    let region = match &command {
        DerpCommand::Connect { region, .. }
        | DerpCommand::Send { region, .. }
        | DerpCommand::Disconnect { region } => *region,
    };
    let slot = slots
        .iter()
        .find(|s| s.region.get() == Some(region))
        .or_else(|| {
            if matches!(command, DerpCommand::Connect { .. }) {
                slots.iter().find(|s| s.region.get().is_none())
            } else {
                None
            }
        });
    if let Some(slot) = slot {
        slot.region.set(Some(region));
        if matches!(command, DerpCommand::Disconnect { .. }) {
            slot.stop.set(true);
            slot.stopped.notify_waiters();
        } else if let Err(command) = slot.queue.borrow_mut().push_back(command) {
            return Some(command);
        }
        slot.ready.notify_one();
    } else {
        enqueue(
            actions,
            node.borrow_mut()
                .handle_derp_event(DerpEvent::Disconnected { region }, now, &mut OsRng)
                .ok()
                .flatten(),
        );
    }
    None
}
pub async fn worker(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    slot: &Slot,
    ca: &[u8],
) -> Result<(), Error> {
    loop {
        let next = slot.queue.borrow_mut().pop_front();
        let Some(DerpCommand::Connect { region, endpoint }) = next else {
            slot.ready.notified().await;
            continue;
        };
        let stopped = async {
            loop {
                if slot.stop.get() {
                    break;
                }
                slot.stopped.notified().await;
            }
        };
        let result = if slot.stop.get() {
            Ok(())
        } else {
            tokio::select! {
                result=connection(reactor,node,actions,slot,region,&endpoint,ca)=>result,
                _=stopped=>Ok(()),
            }
        };
        if result.is_err() {
            tracing::debug!("POCKETBOOT TAILNET_RELAY_RETRY region={region}");
        }
        slot.queue.borrow_mut().clear();
        slot.region.set(None);
        slot.stop.set(false);
        enqueue(
            actions,
            node.borrow_mut()
                .handle_derp_event(
                    DerpEvent::Disconnected { region },
                    reactor.clock_millis(),
                    &mut OsRng,
                )
                .ok()
                .flatten(),
        );
        reactor.sleep(1000).await;
    }
}
struct Frames {
    bytes: [u8; FRAME],
    filled: usize,
    discard: usize,
    activity: std::rc::Rc<Cell<tokio::time::Instant>>,
}
impl Frames {
    fn new() -> Self {
        Self {
            bytes: [0; FRAME],
            filled: 0,
            discard: 0,
            activity: std::rc::Rc::new(Cell::new(tokio::time::Instant::now())),
        }
    }
    async fn read<S: Read>(&mut self, stream: &mut S) -> Result<Frame, Error> {
        loop {
            if self.discard > 0 {
                if self.filled > 0 {
                    let take = self.discard.min(self.filled);
                    self.bytes.copy_within(take..self.filled, 0);
                    self.filled -= take;
                    self.discard -= take;
                } else {
                    let limit = self.discard.min(FRAME);
                    let n = stream
                        .read(&mut self.bytes[..limit])
                        .await
                        .map_err(|_| "relay drain")?;
                    if n == 0 {
                        return Err("relay EOF");
                    }
                    self.discard -= n;
                }
                if self.discard == 0 {
                    self.activity.set(tokio::time::Instant::now());
                }
                continue;
            }
            if self.filled >= frame::HEADER_LEN {
                let frame = Frame::parse(&self.bytes[..self.filled]).map_err(|_| "relay frame")?;
                if frame.length > FRAME - frame::HEADER_LEN {
                    self.bytes.copy_within(frame::HEADER_LEN..self.filled, 0);
                    self.filled -= frame::HEADER_LEN;
                    self.discard = frame.length;
                    continue;
                }
                if self.filled >= frame::HEADER_LEN + frame.length {
                    self.activity.set(tokio::time::Instant::now());
                    return Ok(frame);
                }
            }
            let n = stream
                .read(&mut self.bytes[self.filled..])
                .await
                .map_err(|_| "relay read")?;
            if n == 0 {
                return Err("relay EOF");
            }
            self.filled += n;
        }
    }
    fn payload(&self, frame: Frame) -> &[u8] {
        &self.bytes[frame::HEADER_LEN..frame::HEADER_LEN + frame.length]
    }
    fn consume(&mut self, frame: Frame) {
        let n = frame::HEADER_LEN + frame.length;
        self.bytes.copy_within(n..self.filled, 0);
        self.filled -= n;
    }
}
async fn send<S: Write>(stream: &mut S, bytes: &[u8]) -> Result<(), Error> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        stream.write_all(bytes).await.map_err(|_| "relay write")?;
        stream.flush().await.map_err(|_| "relay flush")
    })
    .await
    .map_err(|_| "relay write deadline")?
}
async fn receive_liveness(activity: &Cell<tokio::time::Instant>) {
    let interval = std::time::Duration::from_secs(90);
    loop {
        tokio::time::sleep_until(activity.get() + interval).await;
        if tokio::time::Instant::now() >= activity.get() + interval {
            return;
        }
    }
}
async fn connection(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    slot: &Slot,
    region: u16,
    endpoint: &Endpoint,
    ca: &[u8],
) -> Result<(), Error> {
    let socket = TcpStream::connect_host(reactor, &endpoint.host, endpoint.port)
        .await
        .map_err(|_| "relay TCP")?;
    let mut read = [0; tailfeather::control::tls::TLS_READ_BUFFER];
    let mut write = [0; tailfeather::control::tls::TLS_WRITE_BUFFER];
    let name = endpoint
        .tls_name
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(endpoint.host.as_str());
    // Deliberately ignore the insecure test marker in a control map.
    let mut stream = match exec::select(
        crate::tls::connect(socket, name, ca, &mut read, &mut write),
        reactor.sleep(20000),
    )
    .await
    {
        Either::First(Ok(s)) => s,
        _ => return Err("relay TLS"),
    };
    let mut output = [0u8; FRAME];
    let mut frames = Frames::new();
    let client = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let req = tailfeather::derp::client::write_upgrade_request(&endpoint.host, &mut output)
            .map_err(|_| "relay upgrade")?;
        stream
            .write_all(req)
            .await
            .map_err(|_| "relay upgrade write")?;
        stream.flush().await.map_err(|_| "relay flush")?;
        let mut header = [0u8; 2048];
        let mut filled = 0;
        loop {
            if filled == header.len() {
                return Err("relay upgrade size");
            }
            let n = stream
                .read(&mut header[filled..filled + 1])
                .await
                .map_err(|_| "relay upgrade read")?;
            if n == 0 {
                return Err("relay upgrade EOF");
            }
            filled += n;
            if header[..filled].ends_with(b"\r\n\r\n") {
                break;
            }
        }
        tailfeather::derp::client::parse_upgrade(&header[..filled])
            .map_err(|_| "relay upgrade response")?;
        let frame = frames.read(&mut stream).await?;
        let server = Client::read_server_key(frame, frames.payload(frame))
            .map_err(|_| "relay server key")?;
        frames.consume(frame);
        let key = node.borrow().identity().node.clone();
        let len = Client::write_client_info(&key, &key.public(), &server, &mut OsRng, &mut output)
            .map_err(|_| "relay client info")?;
        stream
            .write_all(&output[..len])
            .await
            .map_err(|_| "relay auth write")?;
        stream.flush().await.map_err(|_| "relay auth flush")?;
        let frame = frames.read(&mut stream).await?;
        let client =
            Client::read_server_info(&key, &server, frame, frames.payload(frame), &mut output)
                .map_err(|_| "relay authentication")?;
        frames.consume(frame);
        let preferred = node.borrow().netmap().home_derp == region;
        let len =
            Client::write_note_preferred(preferred, &mut output).map_err(|_| "relay preferred")?;
        stream
            .write_all(&output[..len])
            .await
            .map_err(|_| "relay write")?;
        stream.flush().await.map_err(|_| "relay flush")?;
        Ok::<_, Error>(client)
    })
    .await
    .map_err(|_| "relay protocol handshake deadline")??;
    enqueue(
        actions,
        node.borrow_mut()
            .handle_derp_event(
                DerpEvent::Connected { region },
                reactor.clock_millis(),
                &mut OsRng,
            )
            .ok()
            .flatten(),
    );
    tracing::debug!("POCKETBOOT TAILNET_RELAY_CONNECTED region={region}");
    let activity = frames.activity.clone();
    activity.set(tokio::time::Instant::now());
    let transfer = async {
        loop {
            if slot.stop.get() {
                return Ok(());
            }
            // Drain a bounded batch immediately, then service reads or a queue
            // notification. No per-packet polling delay throttles relay traffic.
            for _ in 0..16 {
                let next = slot.queue.borrow_mut().pop_front();
                let Some(DerpCommand::Send { peer, packet, .. }) = next else {
                    break;
                };
                let len = client
                    .send_packet(&peer, packet.as_slice(), &mut output)
                    .map_err(|_| "relay packet size")?;
                send(&mut stream, &output[..len]).await?;
            }
            actions.ready.notify_one();
            // Stop decoding before the actor high-water mark; dropping
            // local decoded TCP packets here needlessly collapses its window.
            // Queue notifications must interrupt the capacity wait too, so
            // outgoing sends can free actor space while reads are throttled.
            let read = async {
                actions.wait_for_space().await;
                frames.read(&mut stream).await
            };
            // Frames retains partial read progress when a notification cancels it.
            let result = exec::select(read, slot.ready.notified()).await;
            if let Either::First(frame) = result {
                let frame = frame?;
                match frame.kind {
                    FrameType::RecvPacket => {
                        let (peer, payload) = Client::read_packet(frame, frames.payload(frame))
                            .map_err(|_| "relay packet")?;
                        enqueue(
                            actions,
                            node.borrow_mut()
                                .handle_derp_event(
                                    DerpEvent::Packet {
                                        region,
                                        peer,
                                        payload,
                                    },
                                    reactor.clock_millis(),
                                    &mut OsRng,
                                )
                                .ok()
                                .flatten(),
                        );
                    }
                    FrameType::Ping => {
                        let len = Client::write_pong(frame, frames.payload(frame), &mut output)
                            .map_err(|_| "relay ping")?;
                        send(&mut stream, &output[..len]).await?;
                    }
                    FrameType::PeerGone => {
                        if let Ok(peer) = Client::read_peer_gone(frame, frames.payload(frame)) {
                            node.borrow_mut().forget_relay(&peer, region);
                        }
                    }
                    FrameType::Restarting => return Ok(()),
                    _ => {}
                }
                frames.consume(frame);
            }
        }
    };
    tokio::select! {
        result=transfer=>result,
        _=receive_liveness(&activity)=>Err("relay receive liveness deadline"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Input(tokio::io::DuplexStream);
    impl embedded_io_async::ErrorType for Input {
        type Error = std::io::Error;
    }
    impl Read for Input {
        async fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            tokio::io::AsyncReadExt::read(&mut self.0, out).await
        }
    }
    #[test]
    fn drained_valid_extension_frames_count_as_receive_activity() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                use tokio::io::AsyncWriteExt;
                let started = tokio::time::Instant::now();
                let (input, mut output) = tokio::io::duplex(16384);
                let mut input = Input(input);
                let mut frames = Frames::new();
                let activity = frames.activity.clone();
                let writer = async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    let mut frame = vec![0; 5005];
                    let n = frame::write(FrameType::Health, &vec![1; 5000], &mut frame).unwrap();
                    output.write_all(&frame[..n]).await.unwrap();
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    _=frames.read(&mut input)=>panic!("extension frame should be skipped"),
                    _=writer=>unreachable!(),
                    _=receive_liveness(&activity)=>{},
                }
                assert_eq!(started.elapsed(), std::time::Duration::from_secs(150));
            });
    }
    #[test]
    fn a_silent_relay_expires_after_the_last_received_frame() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                let started = tokio::time::Instant::now();
                let activity = Cell::new(started);
                let inbound = async {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    activity.set(tokio::time::Instant::now());
                    std::future::pending::<()>().await;
                };
                tokio::select! {_=receive_liveness(&activity)=>{},_=inbound=>unreachable!()}
                assert_eq!(started.elapsed(), std::time::Duration::from_secs(150));
            });
    }
    #[test]
    fn a_stalled_relay_write_has_a_finite_deadline() {
        struct Blocked;
        impl embedded_io_async::ErrorType for Blocked {
            type Error = std::io::Error;
        }
        impl Write for Blocked {
            async fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                std::future::pending().await
            }
            async fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                let started = tokio::time::Instant::now();
                assert_eq!(
                    send(&mut Blocked, b"packet").await,
                    Err("relay write deadline")
                );
                assert_eq!(started.elapsed(), std::time::Duration::from_secs(15));
            });
    }
    #[test]
    fn oversized_frames_are_drained_across_cancelled_reads() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use tokio::io::AsyncWriteExt;
                let (input, mut output) = tokio::io::duplex(131072);
                let mut input = Input(input);
                let mut header = [0; 5];
                header[0] = 0x14;
                header[1..].copy_from_slice(&65536u32.to_be_bytes());
                output.write_all(&header).await.unwrap();
                output.write_all(&[1; 16]).await.unwrap();
                let mut frames = Frames::new();
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(5),
                        frames.read(&mut input)
                    )
                    .await
                    .is_err()
                );
                output.write_all(&vec![1; 65536 - 16]).await.unwrap();
                let mut ping = [0; 13];
                let n = frame::write(FrameType::Ping, b"12345678", &mut ping).unwrap();
                output.write_all(&ping[..n]).await.unwrap();
                let parsed = frames.read(&mut input).await.unwrap();
                assert_eq!(parsed.kind, FrameType::Ping);
                assert_eq!(frames.payload(parsed), b"12345678");
                frames.consume(parsed);
                drop(output);
                assert!(frames.read(&mut input).await.is_err());
            });
    }
}
