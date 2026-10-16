//! Relaying through a real DERP server.
//!
//! Two connections are opened to the lab's relay under different node keys, and
//! a packet is sent from one to the other. Both endpoints are ours, which is the
//! point: what is under test is the *relay*, and the relay is Headscale's. It
//! decides whether our handshake was valid, whether our claimed node key is one
//! it will deliver to, and whether the frame we sent is one it can forward.
//!
//! A relay that rejected any of that would simply never deliver the packet.
//!
//! # Three phases, one registration
//!
//! Registering a node key with the control plane is the expensive part, and all
//! three phases want the same two identities, so one run does all of it and
//! reports each phase separately.
//!
//! 1. **Relay.** One packet, delivered intact and attributed to its sender.
//! 2. **Hold.** Sit on both connections for longer than the server's idle
//!    keepalive interval, answering whatever housekeeping it sends, then relay a
//!    second packet. A session that only works for the few seconds after the
//!    handshake is not a session.
//! 3. **Reconnect.** Drop the receiver's TCP connection and dial again under the
//!    *same* registered node key, then relay once more. This is what a real
//!    network blip does, and it fails either if the relay will not re-admit a
//!    key it has already seen or if the dead session is still holding that key's
//!    entry in the server's routing table.

use core::net::Ipv4Addr;

use tailfeather::derp::{Client, Frame, FrameType, frame};
use tailfeather::keys::{NodePrivate, NodePublic};

use crate::OsRng;
use crate::control::ControlError;
use crate::exec::{Either, Reactor, block_on, select};
use crate::net::TcpStream;
use crate::time::Clock;

impl tailfeather::derp::client::Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::rt::getrandom(dest);
    }
}

/// How long to wait for the relay to deliver.
const DELIVERY_MS: u64 = 5_000;

/// How long the hold phase keeps the session idle.
///
/// Headscale's embedded relay sends a `KeepAlive` on an idle connection roughly
/// once a minute, so this crosses one interval with margin. It is a lower bound
/// on what is proved, not an assertion: the check requires the session to
/// survive and relay again, and reports the frames actually seen rather than
/// demanding a particular one. A server that stayed silent the whole time would
/// still make the survival claim true, just less interesting.
const HOLD_MS: u64 = 65_000;

/// Bytes buffered per connection. Comfortably more than one relayed frame; the
/// probes here are a couple of dozen bytes.
const READ_BUFFER: usize = 2048;

type Payload = heapless::Vec<u8, { frame::MAX_FRAME }>;

pub fn run(address: Ipv4Addr, port: u16, sender_dir: &str, receiver_dir: &str) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    match block_on(
        &reactor,
        session(&reactor, address, port, sender_dir, receiver_dir),
    ) {
        Ok(()) => {
            evt!("{{\"event\":\"derp\",\"result\":\"ok\"}}");
            crate::rt::exit(0)
        }
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"derp\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

/// The node key a previous registration persisted.
fn load_node_key(state_dir: &str) -> Result<NodePrivate, ControlError> {
    let store =
        crate::store::FileStore::new(state_dir, "identity.bin").map_err(ControlError::Store)?;
    let (identity, is_new) =
        tailfeather::keys::store::load_or_create(&store, &mut OsRng).map_err(|e| match e {
            tailfeather::keys::store::IdentityError::Store(e) => ControlError::Store(e),
            tailfeather::keys::store::IdentityError::Format(e) => ControlError::Identity(e),
        })?;
    if is_new {
        // A key the server has never seen will be turned away, and the reason
        // would look like a protocol fault rather than a missing registration.
        println!("!! {state_dir} held no identity, so this node is not registered");
    }
    Ok(identity.node)
}

/// A socket with the frame-boundary state that goes with it.
///
/// The partially-read frame lives here rather than in a local, so a read that is
/// abandoned — which is what `select` does to the loser of a race — leaves the
/// bytes already received exactly where the next read will find them. TCP
/// coalesces, so a keepalive and a relayed packet routinely arrive together, and
/// a boundary tracked in a dropped future either mis-parses the next frame or
/// loses it.
struct Framed<'r> {
    stream: TcpStream<'r>,
    buffer: [u8; READ_BUFFER],
    filled: usize,
}

impl<'r> Framed<'r> {
    fn new(stream: TcpStream<'r>) -> Self {
        Self {
            stream,
            buffer: [0u8; READ_BUFFER],
            filled: 0,
        }
    }

    /// Read one whole frame, using whatever is already buffered first.
    async fn read_frame(&mut self) -> Result<(Frame, Payload), ControlError> {
        loop {
            if self.filled >= frame::HEADER_LEN {
                let parsed =
                    Frame::parse(&self.buffer[..self.filled]).map_err(ControlError::Derp)?;
                let total = frame::HEADER_LEN + parsed.length;
                if total > self.buffer.len() {
                    return Err(ControlError::Derp(tailfeather::derp::Error::TooLarge));
                }
                if self.filled >= total {
                    let mut payload = Payload::new();
                    payload
                        .extend_from_slice(&self.buffer[frame::HEADER_LEN..total])
                        .map_err(|_| ControlError::Derp(tailfeather::derp::Error::TooLarge))?;
                    // Anything past this frame belongs to the next one.
                    self.buffer.copy_within(total..self.filled, 0);
                    self.filled -= total;
                    return Ok((parsed, payload));
                }
            }
            let read = read_some(&self.stream, &mut self.buffer[self.filled..]).await?;
            self.filled += read;
        }
    }
}

/// One connected client and the socket under it.
struct Connection<'r> {
    framed: Framed<'r>,
    client: Client,
    key: NodePublic,
}

/// What the relay sent while nothing was being asked of it.
#[derive(Default, Clone, Copy)]
struct Housekeeping {
    pings: u32,
    keepalives: u32,
    other: u32,
}

impl Connection<'_> {
    /// Read one frame and deal with the relay's own traffic, returning only what
    /// the caller has to interpret.
    async fn service(
        &mut self,
        seen: &mut Housekeeping,
    ) -> Result<Option<(Frame, Payload)>, ControlError> {
        let (frame, body) = self.framed.read_frame().await?;
        match frame.kind {
            FrameType::Ping => {
                // An unanswered probe gets the connection dropped, which would
                // surface later as an unexplained relay failure rather than as
                // the protocol violation it is.
                seen.pings += 1;
                let mut pong = [0u8; frame::HEADER_LEN + frame::PING_LEN];
                let len =
                    Client::write_pong(frame, &body, &mut pong).map_err(ControlError::Derp)?;
                self.framed
                    .stream
                    .write_all(&pong[..len])
                    .await
                    .map_err(ControlError::Net)?;
                println!("<- ping, answered");
                Ok(None)
            }
            FrameType::KeepAlive => {
                seen.keepalives += 1;
                Ok(None)
            }
            _ => {
                seen.other += 1;
                Ok(Some((frame, body)))
            }
        }
    }
}

async fn connect<'r>(
    reactor: &'r Reactor,
    address: Ipv4Addr,
    port: u16,
    host: &str,
    identity: &NodePrivate,
) -> Result<Connection<'r>, ControlError> {
    let stream = TcpStream::connect(reactor, address, port)
        .await
        .map_err(ControlError::Net)?;

    let mut request = [0u8; 256];
    let request = tailfeather::derp::client::write_upgrade_request(host, &mut request)
        .map_err(ControlError::Derp)?;
    stream.write_all(request).await.map_err(ControlError::Net)?;

    // Read until the blank line. The server's first frame may already be in the
    // same segment, so the parser reports where the headers ended rather than
    // consuming whatever it was handed.
    let mut framed = Framed::new(stream);
    let header_len = loop {
        match tailfeather::derp::client::parse_upgrade(&framed.buffer[..framed.filled]) {
            Ok(end) => break end,
            Err(tailfeather::derp::Error::Incomplete) => {}
            Err(e) => return Err(ControlError::Derp(e)),
        }
        let read = read_some(&framed.stream, &mut framed.buffer[framed.filled..]).await?;
        framed.filled += read;
    };
    // Whatever followed the headers is the start of the server's key frame.
    framed.buffer.copy_within(header_len..framed.filled, 0);
    framed.filled -= header_len;

    let (frame, payload) = framed.read_frame().await?;
    let server = Client::read_server_key(frame, &payload).map_err(ControlError::Derp)?;
    println!("   relay key {server}");

    let mut out = [0u8; 512];
    let len =
        Client::write_client_info(identity, &identity.public(), &server, &mut OsRng, &mut out)
            .map_err(ControlError::Derp)?;
    framed
        .stream
        .write_all(&out[..len])
        .await
        .map_err(ControlError::Net)?;

    let (frame, payload) = framed.read_frame().await?;
    let mut info = [0u8; 512];
    let client = Client::read_server_info(identity, &server, frame, &payload, &mut info)
        .map_err(ControlError::Derp)?;

    Ok(Connection {
        framed,
        client,
        key: identity.public(),
    })
}

/// A read that treats end-of-stream as the error it is. Returning zero forever
/// otherwise spun the enclosing loop until its deadline with no explanation.
async fn read_some(stream: &TcpStream<'_>, out: &mut [u8]) -> Result<usize, ControlError> {
    match stream.read(out).await.map_err(ControlError::Net)? {
        0 => Err(ControlError::Derp(tailfeather::derp::Error::Incomplete)),
        read => Ok(read),
    }
}

/// Send one recognisable payload through the relay and read until it arrives.
///
/// Returns the sender key the relay attributed it to, which version 1 of the
/// protocol did not carry and which is what lets a receiver stop guessing.
async fn relay_probe(
    reactor: &Reactor,
    sender: &mut Connection<'_>,
    receiver: &mut Connection<'_>,
    payload: &[u8],
    seen: &mut Housekeeping,
) -> Result<usize, ControlError> {
    let mut out = [0u8; 512];
    let len = sender
        .client
        .send_packet(&receiver.key, payload, &mut out)
        .map_err(ControlError::Derp)?;
    sender
        .framed
        .stream
        .write_all(&out[..len])
        .await
        .map_err(ControlError::Net)?;
    println!(
        "-> {} bytes addressed to the receiver's node key",
        payload.len()
    );

    let deadline = reactor.clock_millis() + DELIVERY_MS;
    while reactor.clock_millis() < deadline {
        let frame = match select(receiver.service(seen), reactor.sleep(DELIVERY_MS)).await {
            Either::First(Ok(Some(frame))) => frame,
            Either::First(Ok(None)) => continue,
            Either::First(Err(e)) => return Err(e),
            Either::Second(()) => break,
        };
        let (frame, body) = frame;
        if frame.kind != FrameType::RecvPacket {
            println!("<- {:?} frame, {} bytes", frame.kind, frame.length);
            continue;
        }
        let (source, packet) = Client::read_packet(frame, &body).map_err(ControlError::Derp)?;
        println!("<- relayed packet from {source}: {} bytes", packet.len());

        if packet != payload {
            println!("!! the relayed bytes are not the ones sent");
            return Err(ControlError::Derp(tailfeather::derp::Error::Malformed));
        }
        if source != sender.key {
            println!("!! the relay attributed the packet to the wrong sender");
            return Err(ControlError::Derp(tailfeather::derp::Error::Malformed));
        }
        println!("relayed intact, attributed correctly");
        return Ok(packet.len());
    }

    println!("!! the relay did not deliver the packet");
    Err(ControlError::Derp(tailfeather::derp::Error::Incomplete))
}

async fn session(
    reactor: &Reactor,
    address: Ipv4Addr,
    port: u16,
    sender_dir: &str,
    receiver_dir: &str,
) -> Result<(), ControlError> {
    let mut host = [0u8; 32];
    let host = crate::control::write_host(address, port, &mut host);

    // Two identities that the *server* already knows, because its relay checks
    // every client against its node list — "admission controller: … not
    // allowed" is what an unregistered key gets. A relay that forwarded for
    // anyone would let a stranger receive a node's traffic.
    let sender_key = load_node_key(sender_dir)?;
    let receiver_key = load_node_key(receiver_dir)?;

    println!("connecting sender to the relay");
    let mut sender = connect(reactor, address, port, host, &sender_key).await?;
    println!("connecting receiver to the relay");
    let mut receiver = connect(reactor, address, port, host, &receiver_key).await?;
    println!("both connected: {} -> {}", sender.key, receiver.key);
    evt!(
        "{{\"event\":\"derp-connected\",\"relay\":\"{}\",\"sender\":\"{}\",\"receiver\":\"{}\"}}",
        sender.client.server(),
        sender.key,
        receiver.key
    );

    // Something recognisable, so a delivered packet cannot be confused with
    // anything the relay generates on its own.
    let mut seen = Housekeeping::default();
    let bytes = relay_probe(
        reactor,
        &mut sender,
        &mut receiver,
        b"esp-gateway relay probe",
        &mut seen,
    )
    .await?;
    evt!(
        "{{\"event\":\"relayed\",\"bytes\":{bytes},\"from\":\"{}\",\"intact\":true}}",
        sender.key
    );

    hold(reactor, &mut sender, &mut receiver).await?;

    // Close the receiver for real before dialing again. Overlapping the two
    // would leave the server holding two sessions for one key and picking
    // between them, which is a different question from the one being asked.
    println!("dropping the receiver's connection");
    drop(receiver);

    reconnect(reactor, address, port, host, &receiver_key, &mut sender).await?;
    Ok(())
}

/// Phase two: idle across a keepalive interval, then relay again.
async fn hold(
    reactor: &Reactor,
    sender: &mut Connection<'_>,
    receiver: &mut Connection<'_>,
) -> Result<(), ControlError> {
    println!("holding the session idle for {}s", HOLD_MS / 1_000);
    let started = reactor.clock_millis();
    let deadline = started + HOLD_MS;
    // Both connections are serviced, not just the receiver's. The relay probes
    // whichever side it likes, and a sender dropped for an unanswered ping
    // would fail the second relay for a reason that has nothing to do with the
    // hold. They count separately because the two futures are alive at once.
    let mut on_receiver = Housekeeping::default();
    let mut on_sender = Housekeeping::default();
    while reactor.clock_millis() < deadline {
        let remaining = deadline - reactor.clock_millis();
        match select(
            select(
                receiver.service(&mut on_receiver),
                sender.service(&mut on_sender),
            ),
            reactor.sleep(remaining),
        )
        .await
        {
            Either::First(Either::First(result) | Either::Second(result)) => {
                if let Some((frame, _)) = result? {
                    println!("<- {:?} frame while idle", frame.kind);
                }
            }
            Either::Second(()) => break,
        }
    }
    let seen = Housekeeping {
        pings: on_receiver.pings + on_sender.pings,
        keepalives: on_receiver.keepalives + on_sender.keepalives,
        other: on_receiver.other + on_sender.other,
    };

    let held = (reactor.clock_millis() - started) / 1_000;
    println!(
        "held {held}s: {} ping(s), {} keepalive(s), {} other frame(s)",
        seen.pings, seen.keepalives, seen.other
    );

    // The claim is that the session is still usable, which only a second
    // delivery can establish.
    let mut delivery = Housekeeping::default();
    relay_probe(
        reactor,
        sender,
        receiver,
        b"esp-gateway keepalive probe",
        &mut delivery,
    )
    .await?;
    evt!(
        "{{\"event\":\"held\",\"seconds\":{held},\"pings\":{},\"keepalives\":{},\"other\":{},\
         \"relayed\":true}}",
        seen.pings,
        seen.keepalives,
        seen.other
    );
    Ok(())
}

/// Phase three: drop the receiver and dial again under the same node key.
async fn reconnect(
    reactor: &Reactor,
    address: Ipv4Addr,
    port: u16,
    host: &str,
    receiver_key: &NodePrivate,
    sender: &mut Connection<'_>,
) -> Result<(), ControlError> {
    let mut receiver = connect(reactor, address, port, host, receiver_key).await?;
    println!("receiver reconnected under the same node key");

    let mut seen = Housekeeping::default();
    relay_probe(
        reactor,
        sender,
        &mut receiver,
        b"esp-gateway reconnect probe",
        &mut seen,
    )
    .await?;
    evt!("{{\"event\":\"reconnected\",\"relayed\":true}}");
    Ok(())
}
