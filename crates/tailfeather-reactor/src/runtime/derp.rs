use super::*;
use core::fmt::Write as _;
use heapless::String;
use tailfeather::derp::{
    client::Client,
    frame::{self, Frame, FrameType},
};
use tailfeather::{DerpEvent, Endpoint};
const FRAME: usize = 4096;

pub(super) struct Slot<const A: usize> {
    region: Cell<Option<u16>>,
    queue: RefCell<Deque<DerpCommand, A>>,
    stop: Cell<bool>,
    ready: Signal<NoopRawMutex, ()>,
    stopped: Signal<NoopRawMutex, ()>,
}
impl<const A: usize> Slot<A> {
    pub const fn new() -> Self {
        Self {
            region: Cell::new(None),
            queue: RefCell::new(Deque::new()),
            stop: Cell::new(false),
            ready: Signal::new(),
            stopped: Signal::new(),
        }
    }
}

pub(super) fn dispatch<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    command: DerpCommand,
) -> Option<DerpCommand> {
    let region = match &command {
        DerpCommand::Connect { region, .. }
        | DerpCommand::Send { region, .. }
        | DerpCommand::Disconnect { region } => *region,
    };
    let slot = runtime
        .slots
        .iter()
        .find(|slot| slot.region.get() == Some(region))
        .or_else(|| {
            if matches!(command, DerpCommand::Connect { .. }) {
                runtime
                    .slots
                    .iter()
                    .find(|slot| slot.region.get().is_none())
            } else {
                None
            }
        });
    if let Some(slot) = slot {
        slot.region.set(Some(region));
        if matches!(command, DerpCommand::Disconnect { .. }) {
            slot.stop.set(true);
            slot.stopped.signal(());
        } else if let Err(command) = slot.queue.borrow_mut().push_back(command) {
            return Some(command);
        }
        slot.ready.signal(());
    } else {
        runtime.enqueue(
            runtime
                .node
                .borrow_mut()
                .handle_derp_event(
                    DerpEvent::Disconnected { region },
                    runtime.network.now_millis(),
                    &mut runtime.network.rng(),
                )
                .ok()
                .flatten(),
        );
    }
    None
}

pub(super) async fn worker<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
    slot: &Slot<A>,
    buffers: &mut LinkBuffers,
) -> Result<(), Error> {
    loop {
        let command = slot.queue.borrow_mut().pop_front();
        let Some(DerpCommand::Connect { region, endpoint }) = command else {
            slot.ready.wait().await;
            continue;
        };
        if !slot.stop.get() {
            let stop = async {
                while !slot.stop.get() {
                    slot.stopped.wait().await;
                }
            };
            let _ = select(
                connection(runtime, reactor, slot, region, &endpoint, buffers),
                stop,
            )
            .await;
        }
        slot.queue.borrow_mut().clear();
        slot.region.set(None);
        slot.stop.set(false);
        slot.stopped.reset();
        runtime.enqueue(
            runtime
                .node
                .borrow_mut()
                .handle_derp_event(
                    DerpEvent::Disconnected { region },
                    reactor.clock_millis(),
                    &mut runtime.network.rng(),
                )
                .ok()
                .flatten(),
        );
        reactor.sleep(1000).await;
    }
}

struct Frames<'a> {
    bytes: [u8; FRAME],
    filled: usize,
    discard: usize,
    activity: &'a Cell<u64>,
}
impl<'a> Frames<'a> {
    fn new(activity: &'a Cell<u64>) -> Self {
        Self {
            bytes: [0; FRAME],
            filled: 0,
            discard: 0,
            activity,
        }
    }
    async fn read<S: Read, C: Clock>(
        &mut self,
        stream: &mut S,
        reactor: &Reactor<C>,
    ) -> Result<Frame, Error> {
        loop {
            if self.discard > 0 {
                if self.filled > 0 {
                    let take = self.discard.min(self.filled);
                    self.bytes.copy_within(take..self.filled, 0);
                    self.filled -= take;
                    self.discard -= take;
                } else {
                    let limit = self.discard.min(FRAME);
                    let len = stream
                        .read(&mut self.bytes[..limit])
                        .await
                        .map_err(|_| "relay drain")?;
                    if len == 0 {
                        return Err("relay EOF");
                    }
                    self.discard -= len;
                }
                if self.discard == 0 {
                    self.activity.set(reactor.clock_millis());
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
                    self.activity.set(reactor.clock_millis());
                    return Ok(frame);
                }
            }
            let len = stream
                .read(&mut self.bytes[self.filled..])
                .await
                .map_err(|_| "relay read")?;
            if len == 0 {
                return Err("relay EOF");
            }
            self.filled += len;
        }
    }
    fn payload(&self, frame: Frame) -> &[u8] {
        &self.bytes[frame::HEADER_LEN..frame::HEADER_LEN + frame.length]
    }
    fn consume(&mut self, frame: Frame) {
        let len = frame::HEADER_LEN + frame.length;
        self.bytes.copy_within(len..self.filled, 0);
        self.filled -= len;
    }
}

async fn send<S: Write, C: Clock>(
    stream: &mut S,
    reactor: &Reactor<C>,
    bytes: &[u8],
) -> Result<(), Error> {
    reactor
        .timeout(15_000, async {
            stream.write_all(bytes).await.map_err(|_| "relay write")?;
            stream.flush().await.map_err(|_| "relay flush")
        })
        .await
        .map_err(|_| "relay write deadline")?
}

async fn connection<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
    slot: &Slot<A>,
    region: u16,
    endpoint: &Endpoint,
    buffers: &mut LinkBuffers,
) -> Result<(), Error> {
    let tls_name = endpoint.tls_name.as_deref().unwrap_or(&endpoint.host);
    let mut stream = reactor
        .timeout(
            35_000,
            runtime.network.connect(
                &endpoint.host,
                endpoint.port,
                tls_name,
                runtime.config.control_ca_der,
                buffers,
            ),
        )
        .await
        .map_err(|_| "relay connection deadline")??;
    let mut output = [0; FRAME];
    let activity = Cell::new(reactor.clock_millis());
    let mut frames = Frames::new(&activity);
    let client = reactor
        .timeout(20_000, async {
            let mut authority = String::<160>::new();
            if endpoint.port == 443 {
                write!(authority, "{}", endpoint.host)
            } else {
                write!(authority, "{}:{}", endpoint.host, endpoint.port)
            }
            .map_err(|_| "relay authority length")?;
            let req = tailfeather::derp::client::write_upgrade_request(&authority, &mut output)
                .map_err(|_| "relay upgrade")?;
            stream
                .write_all(req)
                .await
                .map_err(|_| "relay upgrade write")?;
            stream.flush().await.map_err(|_| "relay upgrade flush")?;
            let mut header = [0; 2048];
            let mut filled = 0;
            loop {
                if filled == header.len() {
                    return Err("relay upgrade size");
                }
                let len = stream
                    .read(&mut header[filled..filled + 1])
                    .await
                    .map_err(|_| "relay upgrade read")?;
                if len == 0 {
                    return Err("relay upgrade EOF");
                }
                filled += len;
                if header[..filled].ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            tailfeather::derp::client::parse_upgrade(&header[..filled])
                .map_err(|_| "relay upgrade response")?;
            let frame = frames.read(&mut stream, reactor).await?;
            let server = Client::read_server_key(frame, frames.payload(frame))
                .map_err(|_| "relay server key")?;
            frames.consume(frame);
            let key = runtime.node.borrow().identity().node.clone();
            let len = Client::write_client_info(
                &key,
                &key.public(),
                &server,
                &mut runtime.network.rng(),
                &mut output,
            )
            .map_err(|_| "relay client info")?;
            stream
                .write_all(&output[..len])
                .await
                .map_err(|_| "relay auth write")?;
            stream.flush().await.map_err(|_| "relay auth flush")?;
            let frame = frames.read(&mut stream, reactor).await?;
            let client =
                Client::read_server_info(&key, &server, frame, frames.payload(frame), &mut output)
                    .map_err(|_| "relay authentication")?;
            frames.consume(frame);
            let len = Client::write_note_preferred(
                runtime.node.borrow().netmap().home_derp == region,
                &mut output,
            )
            .map_err(|_| "relay preference")?;
            stream
                .write_all(&output[..len])
                .await
                .map_err(|_| "relay preferred write")?;
            stream.flush().await.map_err(|_| "relay preferred flush")?;
            Ok::<_, Error>(client)
        })
        .await
        .map_err(|_| "relay handshake deadline")??;
    runtime.enqueue(
        runtime
            .node
            .borrow_mut()
            .handle_derp_event(
                DerpEvent::Connected { region },
                reactor.clock_millis(),
                &mut runtime.network.rng(),
            )
            .ok()
            .flatten(),
    );
    activity.set(reactor.clock_millis());
    let transfer = async {
        let mut alternate = false;
        loop {
            if slot.stop.get() {
                return Ok(());
            }
            for _ in 0..A {
                let command = slot.queue.borrow_mut().pop_front();
                let Some(DerpCommand::Send { peer, packet, .. }) = command else {
                    break;
                };
                let len = client
                    .send_packet(&peer, packet.as_slice(), &mut output)
                    .map_err(|_| "relay packet size")?;
                send(&mut stream, reactor, &output[..len]).await?;
            }
            runtime.ready.signal(());
            let read = async {
                runtime.wait_for_space().await;
                frames.read(&mut stream, reactor).await
            };
            if let Either::First(frame) =
                crate::exec::select_fair(alternate, read, slot.ready.wait()).await
            {
                let frame = frame?;
                match frame.kind {
                    FrameType::RecvPacket => {
                        let (peer, payload) = Client::read_packet(frame, frames.payload(frame))
                            .map_err(|_| "relay packet")?;
                        runtime.enqueue(
                            runtime
                                .node
                                .borrow_mut()
                                .handle_derp_event(
                                    DerpEvent::Packet {
                                        region,
                                        peer,
                                        payload,
                                    },
                                    reactor.clock_millis(),
                                    &mut runtime.network.rng(),
                                )
                                .ok()
                                .flatten(),
                        );
                    }
                    FrameType::Ping => {
                        let len = Client::write_pong(frame, frames.payload(frame), &mut output)
                            .map_err(|_| "relay ping")?;
                        send(&mut stream, reactor, &output[..len]).await?;
                    }
                    FrameType::PeerGone => {
                        if let Ok(peer) = Client::read_peer_gone(frame, frames.payload(frame)) {
                            runtime.node.borrow_mut().forget_relay(&peer, region);
                        }
                    }
                    FrameType::Restarting => return Ok(()),
                    _ => {}
                }
                frames.consume(frame);
            }
            alternate = !alternate;
            crate::exec::yield_now().await;
        }
    };
    let liveness = async {
        loop {
            let deadline = activity.get().saturating_add(90_000);
            reactor.sleep_until(deadline).await;
            if reactor.clock_millis() >= activity.get().saturating_add(90_000) {
                return;
            }
        }
    };
    match select(transfer, liveness).await {
        Either::First(result) => result,
        Either::Second(()) => Err("relay receive liveness deadline"),
    }
}
