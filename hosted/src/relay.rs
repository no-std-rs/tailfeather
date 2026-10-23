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
}
impl Slot {
    pub fn new() -> Self {
        Self {
            region: Cell::new(None),
            queue: RefCell::new(Deque::new()),
            stop: Cell::new(false),
            ready: tokio::sync::Notify::new(),
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
        slot.stop.set(false);
        if connection(reactor, node, actions, slot, region, &endpoint, ca)
            .await
            .is_err()
        {
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
}
impl Frames {
    fn new() -> Self {
        Self {
            bytes: [0; FRAME],
            filled: 0,
        }
    }
    async fn read<S: Read>(&mut self, stream: &mut S) -> Result<Frame, Error> {
        loop {
            if self.filled >= frame::HEADER_LEN {
                let frame = Frame::parse(&self.bytes[..self.filled]).map_err(|_| "relay frame")?;
                if frame.length > FRAME - frame::HEADER_LEN {
                    return Err("relay frame bound");
                }
                if self.filled >= frame::HEADER_LEN + frame.length {
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
async fn connection(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    slot: &Slot,
    region: u16,
    endpoint: &Endpoint,
    ca: &[u8],
) -> Result<(), Error> {
    let ip = crate::node::resolve_v4(&endpoint.host)
        .await
        .ok_or("relay DNS")?;
    let socket = match exec::select(
        TcpStream::connect(reactor, ip, endpoint.port),
        reactor.sleep(15000),
    )
    .await
    {
        Either::First(Ok(s)) => s,
        _ => return Err("relay TCP"),
    };
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
    let mut frames = Frames::new();
    let frame = frames.read(&mut stream).await?;
    let server =
        Client::read_server_key(frame, frames.payload(frame)).map_err(|_| "relay server key")?;
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
    let client = Client::read_server_info(&key, &server, frame, frames.payload(frame), &mut output)
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
            stream
                .write_all(&output[..len])
                .await
                .map_err(|_| "relay send")?;
            stream.flush().await.map_err(|_| "relay flush")?;
        }
        actions.ready.notify_one();
        // Frames retains partial read progress when a notification cancels it.
        let result = exec::select(frames.read(&mut stream), slot.ready.notified()).await;
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
                    stream
                        .write_all(&output[..len])
                        .await
                        .map_err(|_| "relay pong")?;
                    stream.flush().await.map_err(|_| "relay flush")?;
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
}
