//! Relaying through a real DERP server.
//!
//! Two connections are opened to the lab's relay under different node keys, and
//! a packet is sent from one to the other. Both endpoints are ours, which is the
//! point: what is under test is the *relay*, and the relay is Headscale's. It
//! decides whether our handshake was valid, whether our claimed node key is one
//! it will deliver to, and whether the frame we sent is one it can forward.
//!
//! A relay that rejected any of that would simply never deliver the packet.

use core::net::Ipv4Addr;

use tailfeather::derp::{Client, Frame, frame};
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

pub fn run(address: Ipv4Addr, port: u16, sender_dir: &str, receiver_dir: &str) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);

    match block_on(
        &reactor,
        relay(&reactor, address, port, sender_dir, receiver_dir),
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

/// One connected client and the socket under it.
struct Connection<'r> {
    stream: TcpStream<'r>,
    client: Client,
    key: NodePublic,
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
    let mut buffer = [0u8; 1024];
    let mut filled = 0;
    let header_len = loop {
        match tailfeather::derp::client::parse_upgrade(&buffer[..filled]) {
            Ok(end) => break end,
            Err(tailfeather::derp::Error::Incomplete) => {}
            Err(e) => return Err(ControlError::Derp(e)),
        }
        filled += stream
            .read(&mut buffer[filled..])
            .await
            .map_err(ControlError::Net)?;
    };

    // Whatever followed the headers is the start of the server's key frame.
    let mut carried = [0u8; 1024];
    let carried_len = filled - header_len;
    carried[..carried_len].copy_from_slice(&buffer[header_len..filled]);

    let (frame, payload) = read_frame(&stream, &mut carried, carried_len).await?;
    let server = Client::read_server_key(frame, &payload).map_err(ControlError::Derp)?;
    println!("   relay key {server}");

    let mut out = [0u8; 512];
    let len =
        Client::write_client_info(identity, &identity.public(), &server, &mut OsRng, &mut out)
            .map_err(ControlError::Derp)?;
    stream
        .write_all(&out[..len])
        .await
        .map_err(ControlError::Net)?;

    let (frame, payload) = read_frame(&stream, &mut carried, 0).await?;
    let mut info = [0u8; 512];
    let client = Client::read_server_info(identity, &server, frame, &payload, &mut info)
        .map_err(ControlError::Derp)?;

    Ok(Connection {
        stream,
        client,
        key: identity.public(),
    })
}

/// Read one whole frame, starting from bytes already in hand.
async fn read_frame(
    stream: &TcpStream<'_>,
    buffer: &mut [u8],
    already: usize,
) -> Result<(Frame, heapless::Vec<u8, { frame::MAX_FRAME }>), ControlError> {
    let mut filled = already;
    while filled < frame::HEADER_LEN {
        filled += stream
            .read(&mut buffer[filled..])
            .await
            .map_err(ControlError::Net)?;
    }
    let parsed = Frame::parse(&buffer[..filled]).map_err(ControlError::Derp)?;
    let total = frame::HEADER_LEN + parsed.length;
    while filled < total {
        filled += stream
            .read(&mut buffer[filled..])
            .await
            .map_err(ControlError::Net)?;
    }

    let mut payload = heapless::Vec::new();
    payload
        .extend_from_slice(&buffer[frame::HEADER_LEN..total])
        .map_err(|_| ControlError::Derp(tailfeather::derp::Error::TooLarge))?;
    // Anything past this frame belongs to the next one.
    buffer.copy_within(total..filled, 0);
    Ok((parsed, payload))
}

async fn relay(
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
    let sender = connect(reactor, address, port, host, &sender_key).await?;
    println!("connecting receiver to the relay");
    let receiver = connect(reactor, address, port, host, &receiver_key).await?;
    println!("both connected: {} -> {}", sender.key, receiver.key);
    evt!(
        "{{\"event\":\"derp-connected\",\"relay\":\"{}\",\"sender\":\"{}\",\"receiver\":\"{}\"}}",
        sender.client.server(),
        sender.key,
        receiver.key
    );

    // Something recognisable, so a delivered packet cannot be confused with
    // anything the relay generates on its own.
    let payload = b"esp-gateway relay probe";
    let mut out = [0u8; 512];
    let len = sender
        .client
        .send_packet(&receiver.key, payload, &mut out)
        .map_err(ControlError::Derp)?;
    sender
        .stream
        .write_all(&out[..len])
        .await
        .map_err(ControlError::Net)?;
    println!(
        "-> {} bytes addressed to the receiver's node key",
        payload.len()
    );

    // The relay also sends keepalives and peer-presence frames, so this reads
    // until the packet arrives rather than assuming it is first.
    let mut buffer = [0u8; 1024];
    let deadline = reactor.clock_millis() + DELIVERY_MS;
    while reactor.clock_millis() < deadline {
        let read = select(
            read_frame(&receiver.stream, &mut buffer, 0),
            reactor.sleep(DELIVERY_MS),
        );
        let (frame, body) = match read.await {
            Either::First(Ok(received)) => received,
            Either::First(Err(e)) => return Err(e),
            Either::Second(()) => break,
        };

        if frame.kind != tailfeather::derp::FrameType::RecvPacket {
            println!("<- {:?} frame, {} bytes", frame.kind, frame.length);
            continue;
        }
        let (source, packet) = Client::read_packet(frame, &body).map_err(ControlError::Derp)?;
        println!("<- relayed packet from {source}: {} bytes", packet.len());

        if packet != payload {
            println!("!! the relayed bytes are not the ones sent");
            return Err(ControlError::Derp(tailfeather::derp::Error::Malformed));
        }
        // The relay reports who sent it, which version 1 did not, and is what
        // lets a receiver attribute a packet without guessing.
        if source != sender.key {
            println!("!! the relay attributed the packet to the wrong sender");
            return Err(ControlError::Derp(tailfeather::derp::Error::Malformed));
        }
        println!("relayed intact, attributed correctly");
        evt!(
            "{{\"event\":\"relayed\",\"bytes\":{},\"from\":\"{source}\",\"intact\":true}}",
            packet.len()
        );
        return Ok(());
    }

    println!("!! the relay did not deliver the packet");
    Err(ControlError::Derp(tailfeather::derp::Error::Incomplete))
}
