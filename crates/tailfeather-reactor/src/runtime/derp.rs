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
    #[cfg(all(test, feature = "std"))]
    pub(super) fn pop_for_test(&self) -> Option<DerpCommand> {
        self.queue.borrow_mut().pop_front()
    }
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

// Called synchronously before removing a packet action. A full relay must not
// rotate its older sends behind later packets while waiting for its writer.
pub(super) fn ready<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    command: &DerpCommand,
) -> bool {
    let DerpCommand::Send { region, .. } = command else {
        return true;
    };
    runtime
        .slots
        .iter()
        .find(|slot| slot.region.get() == Some(*region))
        .is_none_or(|slot| !slot.queue.borrow().is_full())
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
    let (mut reader, mut writer) = stream.split();
    let receive = |frame: Frame, payload: &[u8]| -> Result<bool, Error> {
        match frame.kind {
            FrameType::RecvPacket => {
                let (peer, payload) =
                    Client::read_packet(frame, payload).map_err(|_| "relay packet")?;
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
            FrameType::PeerGone => {
                if let Ok(peer) = Client::read_peer_gone(frame, payload) {
                    runtime.node.borrow_mut().forget_relay(&peer, region);
                }
            }
            FrameType::Restarting => return Ok(false),
            _ => {}
        }
        Ok(true)
    };
    let encode = |command: DerpCommand, output: &mut [u8]| -> Result<usize, Error> {
        let DerpCommand::Send { peer, packet, .. } = command else {
            return Err("relay command state");
        };
        client
            .send_packet(&peer, packet.as_slice(), output)
            .map_err(|_| "relay packet size")
    };
    let transfer = transfer(
        reactor,
        slot,
        (&mut frames, &mut reader, &mut writer),
        || runtime.wait_for_space(),
        || runtime.ready.signal(()),
        encode,
        receive,
    );
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

// Read and write futures persist until the entire connection is discarded.
// Outbound work never cancels a partially consumed TLS record header/body.
async fn transfer<
    R: Read,
    W: Write,
    C: Clock,
    const A: usize,
    F: core::future::Future<Output = ()>,
>(
    reactor: &Reactor<C>,
    slot: &Slot<A>,
    io: (&mut Frames<'_>, &mut R, &mut W),
    mut wait_space: impl FnMut() -> F,
    mut notify_space: impl FnMut(),
    mut encode: impl FnMut(DerpCommand, &mut [u8]) -> Result<usize, Error>,
    mut receive: impl FnMut(Frame, &[u8]) -> Result<bool, Error>,
) -> Result<(), Error> {
    let (frames, reader, writer) = io;
    const PONG: usize = frame::HEADER_LEN + frame::PING_LEN;
    let pongs = RefCell::new(Deque::<[u8; PONG], 8>::new());
    let pong_space = Signal::<NoopRawMutex, ()>::new();
    let input = async {
        loop {
            wait_space().await;
            let frame = frames.read(reader, reactor).await?;
            if frame.kind == FrameType::Ping {
                let mut pong = [0; PONG];
                let len = Client::write_pong(frame, frames.payload(frame), &mut pong)
                    .map_err(|_| "relay ping")?;
                if len != PONG {
                    return Err("relay pong size");
                }
                while pongs.borrow().is_full() {
                    pong_space.wait().await;
                }
                pongs
                    .borrow_mut()
                    .push_back(pong)
                    .map_err(|_| "relay pong capacity")?;
                slot.ready.signal(());
            } else if !receive(frame, frames.payload(frame))? {
                return Ok(());
            }
            frames.consume(frame);
        }
    };
    let output = async {
        let mut bytes = [0; FRAME];
        loop {
            let pong = pongs.borrow_mut().pop_front();
            if let Some(pong) = pong {
                pong_space.signal(());
                send(writer, reactor, &pong).await?;
                continue;
            }
            let next = slot.queue.borrow_mut().pop_front();
            if let Some(command) = next {
                notify_space();
                let len = encode(command, &mut bytes)?;
                send(writer, reactor, &bytes[..len]).await?;
                continue;
            }
            slot.ready.wait().await;
        }
    };
    match select(input, output).await {
        Either::First(result) | Either::Second(result) => result,
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::exec::TokioClock;
    use embedded_io_async::{ErrorKind, ErrorType};
    struct PendingRead<'a> {
        cancelled: &'a Cell<usize>,
        complete: bool,
    }
    impl Drop for PendingRead<'_> {
        fn drop(&mut self) {
            if !self.complete {
                self.cancelled.set(self.cancelled.get() + 1);
            }
        }
    }
    struct Input<'a> {
        bytes: &'a [u8],
        delay: bool,
        cancelled: &'a Cell<usize>,
    }
    impl ErrorType for Input<'_> {
        type Error = ErrorKind;
    }
    impl Read for Input<'_> {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, ErrorKind> {
            let mut pending = PendingRead {
                cancelled: self.cancelled,
                complete: false,
            };
            if self.delay {
                tokio::time::sleep(core::time::Duration::from_millis(5)).await;
            }
            let len = output.len().min(self.bytes.len()).min(2);
            output[..len].copy_from_slice(&self.bytes[..len]);
            self.bytes = &self.bytes[len..];
            pending.complete = true;
            Ok(len)
        }
    }
    struct Output<'a>(&'a RefCell<std::vec::Vec<u8>>);
    impl ErrorType for Output<'_> {
        type Error = ErrorKind;
    }
    impl Write for Output<'_> {
        async fn write(&mut self, input: &[u8]) -> Result<usize, ErrorKind> {
            tokio::task::yield_now().await;
            let len = input.len().min(3);
            self.0.borrow_mut().extend_from_slice(&input[..len]);
            Ok(len)
        }
        async fn flush(&mut self) -> Result<(), ErrorKind> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn relay_writes_keep_partial_record_reads_alive() {
        let reactor = Reactor::with_clock(TokioClock::default());
        let slot = Slot::<8>::new();
        let activity = Cell::new(0);
        let cancelled = Cell::new(0);
        let mut frames = Frames::new(&activity);
        let mut bytes = [0; 64];
        let nonce = b"12345678";
        let first = frame::write(FrameType::Ping, nonce, &mut bytes).unwrap();
        let end = frame::write(FrameType::Restarting, &[], &mut bytes[first..]).unwrap();
        let mut input = Input {
            bytes: &bytes[..first + end],
            delay: true,
            cancelled: &cancelled,
        };
        let written = RefCell::new(std::vec::Vec::new());
        let mut output = Output(&written);
        let encode = |command: DerpCommand, output: &mut [u8]| {
            let DerpCommand::Send { packet, .. } = command else {
                return Err("test command");
            };
            frame::write(FrameType::SendPacket, packet.as_slice(), output).map_err(|_| "test frame")
        };
        let receive = |frame: Frame, _: &[u8]| Ok(frame.kind != FrameType::Restarting);
        let producer = async {
            for byte in 0..3 {
                reactor.sleep(1).await;
                slot.queue
                    .borrow_mut()
                    .push_back(DerpCommand::Send {
                        region: 7,
                        peer: tailfeather::keys::NodePublic::from_bytes([7; 32]),
                        packet: tailfeather::SecretBuffer::try_from_slice(&[byte, 0, 255]).unwrap(),
                    })
                    .unwrap();
                slot.ready.signal(());
            }
        };
        let io = transfer(
            &reactor,
            &slot,
            (&mut frames, &mut input, &mut output),
            || core::future::ready(()),
            || {},
            encode,
            receive,
        );
        tokio::time::timeout(core::time::Duration::from_secs(2), async {
            let (result, ()) = tokio::join!(io, producer);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            cancelled.get(),
            0,
            "queue wake discarded a partially consumed TLS read"
        );
        let written = written.borrow();
        let mut offset = 0;
        for byte in 0..3 {
            let header = Frame::parse(&written[offset..]).unwrap();
            assert_eq!(header.kind, FrameType::SendPacket);
            assert_eq!(
                &written[offset + frame::HEADER_LEN..offset + frame::HEADER_LEN + header.length],
                &[byte, 0, 255]
            );
            offset += frame::HEADER_LEN + header.length;
        }
        assert_eq!(
            Frame::parse(&written[offset..]).unwrap().kind,
            FrameType::Pong
        );
        assert_eq!(&written[offset + frame::HEADER_LEN..], nonce);
    }
    #[tokio::test]
    async fn oversized_extensions_preserve_following_frame_and_liveness() {
        let reactor = Reactor::with_clock(TokioClock::default());
        let cancelled = Cell::new(0);
        for size in [FRAME + 1, frame::MAX_WIRE_FRAME] {
            let mut bytes = std::vec![0x7e;frame::HEADER_LEN+size+32];
            bytes[0] = FrameType::Other(0xfe).to_byte();
            bytes[1..5].copy_from_slice(&(size as u32).to_be_bytes());
            let end = frame::HEADER_LEN + size;
            let nonce = [0, 255, 2, 0, 4, 5, 6, 7];
            let len = frame::write(FrameType::Ping, &nonce, &mut bytes[end..]).unwrap();
            bytes.truncate(end + len);
            let activity = Cell::new(u64::MAX);
            let mut frames = Frames::new(&activity);
            let mut input = Input {
                bytes: &bytes,
                delay: false,
                cancelled: &cancelled,
            };
            let frame = frames.read(&mut input, &reactor).await.unwrap();
            assert_eq!(frame.kind, FrameType::Ping);
            assert_eq!(frames.payload(frame), nonce);
            assert_ne!(activity.get(), u64::MAX);
            frames.consume(frame);
            assert_eq!(frames.read(&mut input, &reactor).await, Err("relay EOF"));
        }
    }
}
