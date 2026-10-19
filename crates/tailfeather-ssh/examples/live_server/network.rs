//! Host socket adapters for the same STUN, disco, WireGuard and DERP engines
//! used by the device. All relay TLS is verified, including private lab CAs.
use super::{ControlIo, PEERS, Random, SystemClock};
use std::{
    future::{Future, poll_fn},
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tailfeather::{
    control::tls::{RsaWorkspace, TLS_READ_BUFFER, TLS_WRITE_BUFFER, VerifyingProvider},
    derp::{Client, Frame, FrameType, frame},
    embedded_io_async::{ErrorType, Read, Write},
    embedded_tls::{TlsConfig, TlsConnection, TlsContext},
    keys::{Identity, NodePublic},
    netmap::Netmap,
    node::{DerpCommand, Endpoint, MAX_ACTION_PACKET, SecretBuffer},
};

impl tailfeather::derp::client::Rng for Random {
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        super::rand_core::RngCore::fill_bytes(self, bytes);
    }
}

fn error(value: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{value:?}"))
}

/// Nonblocking transport. Its futures are polled to completion, never cancelled
/// between a partial TLS header and its payload.
struct Socket(TcpStream);
impl Clone for Socket {
    fn clone(&self) -> Self {
        Self(self.0.try_clone().unwrap())
    }
}
impl ErrorType for Socket {
    type Error = ControlIo;
}
impl Read for Socket {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, ControlIo> {
        poll_fn(|_| match self.0.read(out) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result.map_err(ControlIo)),
        })
        .await
    }
}
impl Write for Socket {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ControlIo> {
        poll_fn(|_| match self.0.write(bytes) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result.map_err(ControlIo)),
        })
        .await
    }
    async fn flush(&mut self) -> Result<(), ControlIo> {
        Ok(())
    }
}

fn run<T>(
    future: impl Future<Output = io::Result<T>>,
    stop: &AtomicBool,
    timeout: Option<Duration>,
) -> io::Result<T> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let mut future = std::pin::pin!(future);
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return result;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discovery {
    pub region: u16,
    pub reflexive: Option<SocketAddr>,
}
struct Probe {
    source: SocketAddr,
    transaction: [u8; 12],
    region: u16,
    relay_capable: bool,
    sent: Instant,
}

/// Binding lifetime and NAT mappings can change while the control stream stays
/// up. Refresh on the data socket and publish a changed mapping independently.
pub struct Stun {
    probes: Vec<Probe>,
    deadline: Option<Instant>,
    next_scan: Instant,
    best: Option<(Duration, u16)>,
    reflexive: Option<(Duration, SocketAddr)>,
    fallback: u16,
}
impl Default for Stun {
    fn default() -> Self {
        Self::new()
    }
}
impl Stun {
    pub fn new() -> Self {
        Self {
            probes: Vec::new(),
            deadline: None,
            next_scan: Instant::now() + Duration::from_secs(15),
            best: None,
            reflexive: None,
            fallback: 0,
        }
    }
    fn start(&mut self, udp: &UdpSocket, map: &Netmap<PEERS>) {
        self.probes.clear();
        self.best = None;
        self.reflexive = None;
        self.fallback = map
            .derp
            .iter()
            .find(|region| region.can_be_home())
            .map_or(0, |region| region.id);
        let mut targets = Vec::new();
        // Finish DNS before starting the latency measurement, so DNS lookup
        // order cannot make the first region appear artificially slower.
        for region in map.derp.iter().filter(|region| !region.no_measure_no_home) {
            let relay_capable = region.can_be_home();
            for relay in region.nodes.iter().filter(|n| n.stun_port != 0) {
                let Ok(addresses) = (relay.host_name.as_str(), relay.stun_port).to_socket_addrs()
                else {
                    continue;
                };
                if let Some(source) = addresses.into_iter().find(SocketAddr::is_ipv4) {
                    targets.push((region.id, source, relay_capable));
                }
            }
        }
        let mut random = Random::new();
        for (region, source, relay_capable) in targets {
            let mut transaction = [0; 12];
            super::rand_core::RngCore::fill_bytes(&mut random, &mut transaction);
            let sent = Instant::now();
            if udp
                .send_to(&tailfeather::stun::request(transaction), source)
                .is_ok()
            {
                self.probes.push(Probe {
                    source,
                    transaction,
                    region,
                    relay_capable,
                    sent,
                });
            }
        }
        self.deadline = Some(Instant::now() + Duration::from_secs(2));
    }
    /// Source and transaction must both match. Unsolicited or stale STUN
    /// packets are consumed without affecting the chosen endpoint or region.
    pub fn receive(&mut self, bytes: &[u8], source: SocketAddr) -> bool {
        if bytes.len() < 20 || bytes[..2] != [1, 1] || bytes[4..8] != [0x21, 0x12, 0xa4, 0x42] {
            return false;
        }
        let answer = self.probes.iter().enumerate().find_map(|(index, probe)| {
            if source != probe.source {
                return None;
            }
            let (address, port) = tailfeather::stun::response(bytes, probe.transaction).ok()?;
            Some((index, SocketAddr::from((address, port))))
        });
        if let Some((index, endpoint)) = answer {
            let probe = self.probes.swap_remove(index);
            let latency = probe.sent.elapsed();
            println!(
                "STUN region={} endpoint={endpoint} rtt_us={}",
                probe.region,
                latency.as_micros()
            );
            // A standalone STUN service can discover our mapping but cannot
            // accept a DERP connection. Choose these two results independently.
            if self.reflexive.is_none_or(|best| latency < best.0) {
                self.reflexive = Some((latency, endpoint));
            }
            if probe.relay_capable && self.best.is_none_or(|best| latency < best.0) {
                self.best = Some((latency, probe.region));
            }
        }
        true
    }
    pub fn poll(&mut self, udp: &UdpSocket, map: &Netmap<PEERS>) -> Option<Discovery> {
        if self.deadline.is_none() && Instant::now() >= self.next_scan {
            self.start(udp, map);
        }
        let deadline = self.deadline?;
        if !self.probes.is_empty() && Instant::now() < deadline {
            return None;
        }
        self.deadline = None;
        self.next_scan = Instant::now() + Duration::from_secs(15);
        self.probes.clear();
        Some(Discovery {
            region: self.best.map_or(self.fallback, |b| b.1),
            reflexive: self.reflexive.map(|best| best.1),
        })
    }
}

/// Initial discovery runs before the data-plane reactor takes the socket.
/// Later rounds use Stun::receive/poll in that same reactor, without stealing
/// peer packets or blocking SSH while waiting for a STUN response.
pub fn discover(udp: &UdpSocket, map: &Netmap<PEERS>) -> Discovery {
    let mut stun = Stun::new();
    stun.start(udp, map);
    let mut bytes = [0; MAX_ACTION_PACKET];
    loop {
        if let Some(result) = stun.poll(udp, map) {
            return result;
        }
        match udp.recv_from(&mut bytes) {
            Ok((len, source)) => {
                stun.receive(&bytes[..len], source);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => {
                eprintln!("STUN receive: {e}");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

pub enum RelayEvent {
    Connected(u16),
    Disconnected(u16),
    Packet {
        region: u16,
        peer: NodePublic,
        packet: Vec<u8>,
    },
    PeerGone {
        region: u16,
        peer: NodePublic,
    },
}
struct Event {
    generation: u64,
    region: u16,
    event: RelayEvent,
}
enum Outbound {
    Packet {
        peer: NodePublic,
        packet: Box<SecretBuffer<MAX_ACTION_PACKET>>,
    },
    Pong([u8; frame::PING_LEN]),
    Preferred(bool),
}
struct Connection {
    region: u16,
    generation: u64,
    stop: Arc<AtomicBool>,
    commands: SyncSender<Outbound>,
}

/// Node owns which two relay regions are needed. Workers own their sockets;
/// generation checks discard late events from a connection already replaced.
pub struct Relays {
    identity: Identity,
    ca: Option<Vec<u8>>,
    connections: Vec<Connection>,
    events: Receiver<Event>,
    sender: SyncSender<Event>,
    generation: u64,
    home: u16,
    failures: Vec<(u16, u8, Instant)>,
}
impl Relays {
    pub fn new(identity: Identity) -> Self {
        let (sender, events) = mpsc::sync_channel(64);
        let ca = std::env::var_os("TF_TEST_CA_DER").map(|p| std::fs::read(p).unwrap());
        Self {
            identity,
            ca,
            connections: Vec::new(),
            events,
            sender,
            generation: 0,
            home: 0,
            failures: Vec::new(),
        }
    }
    pub fn home(&mut self, region: u16) {
        if self.home == region {
            return;
        }
        self.home = region;
        for connection in &self.connections {
            if connection
                .commands
                .try_send(Outbound::Preferred(connection.region == region))
                .is_err()
            {
                // Reconnect rather than silently retain an incorrect preference.
                connection.stop.store(true, Ordering::Relaxed);
            }
        }
    }
    pub fn command(&mut self, command: DerpCommand) -> Option<RelayEvent> {
        match command {
            DerpCommand::Connect { region, endpoint } => {
                if self.connections.iter().any(|c| c.region == region) {
                    return None;
                }
                assert!(
                    self.connections.len() < 2,
                    "node exceeded its two-relay contract"
                );
                self.generation += 1;
                let generation = self.generation;
                let (commands, receiver) = mpsc::sync_channel(32);
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = stop.clone();
                let identity = self.identity.clone();
                let ca = self.ca.clone();
                let events = self.sender.clone();
                let pongs = commands.clone();
                let preferred = self.home == region;
                let retry_at = self
                    .failures
                    .iter()
                    .find(|failure| failure.0 == region)
                    .map(|failure| failure.2);
                std::thread::spawn(move || {
                    if let Some(retry_at) = retry_at {
                        while Instant::now() < retry_at && !worker_stop.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    if worker_stop.load(Ordering::Relaxed) {
                        let _ = events.send(Event {
                            region,
                            generation,
                            event: RelayEvent::Disconnected(region),
                        });
                        return;
                    }
                    let result = worker(
                        Dial {
                            region,
                            endpoint: &endpoint,
                            identity: &identity,
                            ca: ca.as_deref(),
                            preferred,
                        },
                        receiver,
                        pongs,
                        |event| {
                            events
                                .send(Event {
                                    region,
                                    generation,
                                    event,
                                })
                                .map_err(error)
                        },
                        &worker_stop,
                    );
                    if let Err(e) = result {
                        eprintln!("DERP region={region}: {e}");
                    }
                    let _ = events.send(Event {
                        region,
                        generation,
                        event: RelayEvent::Disconnected(region),
                    });
                });
                self.connections.push(Connection {
                    region,
                    generation,
                    stop,
                    commands,
                });
            }
            DerpCommand::Send {
                region,
                peer,
                packet,
            } => {
                if let Some(connection) = self.connections.iter().find(|c| c.region == region)
                    && connection
                        .commands
                        .try_send(Outbound::Packet {
                            peer,
                            packet: Box::new(packet),
                        })
                        .is_err()
                {
                    eprintln!("DERP region={region}: outbound queue full or closed");
                }
            }
            DerpCommand::Disconnect { region } => {
                if let Some(index) = self.connections.iter().position(|c| c.region == region) {
                    self.connections
                        .swap_remove(index)
                        .stop
                        .store(true, Ordering::Relaxed);
                }
                return Some(RelayEvent::Disconnected(region));
            }
        }
        None
    }
    pub fn poll(&mut self) -> Option<RelayEvent> {
        while let Ok(event) = self.events.try_recv() {
            let Some(index) = self
                .connections
                .iter()
                .position(|c| c.region == event.region && c.generation == event.generation)
            else {
                continue;
            };
            if matches!(event.event, RelayEvent::Connected(_)) {
                self.failures.retain(|failure| failure.0 != event.region);
            }
            if matches!(event.event, RelayEvent::Disconnected(_)) {
                let failed = if let Some(index) = self
                    .failures
                    .iter()
                    .position(|failure| failure.0 == event.region)
                {
                    &mut self.failures[index]
                } else {
                    self.failures.push((event.region, 0, Instant::now()));
                    self.failures.last_mut().unwrap()
                };
                failed.1 = failed.1.saturating_add(1).min(6);
                failed.2 =
                    Instant::now() + Duration::from_millis((250u64 << (failed.1 - 1)).min(10_000));
                self.connections
                    .swap_remove(index)
                    .stop
                    .store(true, Ordering::Relaxed);
            }
            return Some(event.event);
        }
        None
    }
}
impl Drop for Relays {
    fn drop(&mut self) {
        for connection in &self.connections {
            connection.stop.store(true, Ordering::Relaxed);
        }
    }
}

async fn read_frame(reader: &mut impl Read) -> io::Result<(Frame, Vec<u8>)> {
    loop {
        let mut header = [0; frame::HEADER_LEN];
        reader.read_exact(&mut header).await.map_err(error)?;
        let frame = Frame::parse(&header).map_err(error)?;
        if frame.fits() {
            let mut payload = vec![0; frame.length];
            reader.read_exact(&mut payload).await.map_err(error)?;
            return Ok((frame, payload));
        }
        let mut remaining = frame.length;
        let mut discard = [0; 256];
        while remaining != 0 {
            let take = remaining.min(discard.len());
            reader
                .read_exact(&mut discard[..take])
                .await
                .map_err(error)?;
            remaining -= take;
        }
    }
}

struct Dial<'a> {
    region: u16,
    endpoint: &'a Endpoint,
    identity: &'a Identity,
    ca: Option<&'a [u8]>,
    preferred: bool,
}
fn worker(
    dial: Dial<'_>,
    commands: Receiver<Outbound>,
    pongs: SyncSender<Outbound>,
    event: impl Fn(RelayEvent) -> io::Result<()>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let Dial {
        region,
        endpoint,
        identity,
        ca,
        preferred,
    } = dial;
    let addresses = (endpoint.host.as_str(), endpoint.port).to_socket_addrs()?;
    let mut connected = None;
    for address in addresses.filter(SocketAddr::is_ipv4) {
        match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(e) => eprintln!("DERP connect {address}: {e}"),
        }
    }
    let stream = connected.ok_or_else(|| error("no reachable relay address"))?;
    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)?;
    let mut read = [0; TLS_READ_BUFFER];
    let mut write = [0; TLS_WRITE_BUFFER];
    let mut tls = TlsConnection::new(Socket(stream), &mut read, &mut write);
    let name = endpoint
        .tls_name
        .as_deref()
        .unwrap_or(endpoint.host.as_str());
    let config = TlsConfig::new()
        .with_server_name(name)
        .enable_rsa_signatures();
    let mut rsa = RsaWorkspace::new();
    run(
        async {
            tls.open(TlsContext::new(
                &config,
                VerifyingProvider::<_, SystemClock>::new(Random::new(), ca, &mut rsa),
            ))
            .await
            .map_err(error)
        },
        stop,
        Some(Duration::from_secs(15)),
    )?;
    let client = run(
        async {
            let mut request = [0; 512];
            let request = tailfeather::derp::client::write_upgrade_request(
                endpoint.host.as_str(),
                &mut request,
            )
            .map_err(error)?;
            tls.write_all(request).await.map_err(error)?;
            tls.flush().await.map_err(error)?;
            // Consume exactly the HTTP headers. A coalesced DERP frame remains in
            // the TLS read buffer, where the next read_frame will find it.
            let mut response = Vec::new();
            loop {
                if response.len() == 8192 {
                    return Err(error("DERP upgrade headers too large"));
                }
                let mut byte = [0];
                tls.read_exact(&mut byte).await.map_err(error)?;
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            tailfeather::derp::client::parse_upgrade(&response).map_err(error)?;
            let (frame, payload) = read_frame(&mut tls).await?;
            let server = Client::read_server_key(frame, &payload).map_err(error)?;
            let mut out = [0; 512];
            let len = Client::write_client_info(
                &identity.node,
                &identity.node.public(),
                &server,
                &mut Random::new(),
                &mut out,
            )
            .map_err(error)?;
            tls.write_all(&out[..len]).await.map_err(error)?;
            tls.flush().await.map_err(error)?;
            let (frame, payload) = read_frame(&mut tls).await?;
            let client =
                Client::read_server_info(&identity.node, &server, frame, &payload, &mut out)
                    .map_err(error)?;
            let len = Client::write_note_preferred(preferred, &mut out).map_err(error)?;
            tls.write_all(&out[..len]).await.map_err(error)?;
            tls.flush().await.map_err(error)?;
            Ok(client)
        },
        stop,
        Some(Duration::from_secs(15)),
    )?;
    let (mut reader, mut writer) = tls.split();
    let receiving = async {
        loop {
            let (frame, payload) = read_frame(&mut reader).await?;
            match frame.kind {
                FrameType::RecvPacket => {
                    let (peer, packet) = Client::read_packet(frame, &payload).map_err(error)?;
                    event(RelayEvent::Packet {
                        region,
                        peer,
                        packet: packet.to_vec(),
                    })?;
                }
                FrameType::Ping => {
                    let mut out = [0; 13];
                    Client::write_pong(frame, &payload, &mut out).map_err(error)?;
                    pongs
                        .try_send(Outbound::Pong(out[5..].try_into().unwrap()))
                        .map_err(error)?;
                }
                FrameType::PeerGone => {
                    event(RelayEvent::PeerGone {
                        region,
                        peer: Client::read_peer_gone(frame, &payload).map_err(error)?,
                    })?;
                }
                FrameType::Restarting => return Err(error("relay restarting")),
                FrameType::Health if !payload.is_empty() => {
                    eprintln!("DERP health: {}", String::from_utf8_lossy(&payload))
                }
                _ => {}
            }
            // Yield between frames, while retaining this read future across
            // every outbound write (embedded-tls reads are not cancel-safe).
            let mut yielded = false;
            poll_fn(|_| {
                if std::mem::replace(&mut yielded, true) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    };
    let sending = async {
        loop {
            let command = poll_fn(|_| match commands.try_recv() {
                Ok(command) => Poll::Ready(Ok(command)),
                Err(mpsc::TryRecvError::Empty) => Poll::Pending,
                Err(e) => Poll::Ready(Err(error(e))),
            })
            .await?;
            let mut out = [0; frame::HEADER_LEN + frame::MAX_FRAME];
            let len = match command {
                Outbound::Packet { peer, packet } => {
                    client.send_packet(&peer, packet.as_slice(), &mut out)
                }
                Outbound::Pong(bytes) => frame::write(FrameType::Pong, &bytes, &mut out),
                Outbound::Preferred(preferred) => Client::write_note_preferred(preferred, &mut out),
            }
            .map_err(error)?;
            writer.write_all(&out[..len]).await.map_err(error)?;
            writer.flush().await.map_err(error)?;
        }
    };
    event(RelayEvent::Connected(region))?;
    let mut receiving = std::pin::pin!(receiving);
    let mut sending = std::pin::pin!(sending);
    run(
        poll_fn(|cx| {
            if let Poll::Ready(result) = receiving.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            sending.as_mut().poll(cx)
        }),
        stop,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(stun: SocketAddr) -> Netmap<PEERS> {
        // A standalone STUN service precedes a usable relay with STUN disabled.
        let json = format!(
            r#"{{"DERPMap":{{"Regions":{{"900":{{"Nodes":[{{"HostName":"127.0.0.1","STUNPort":{},"STUNOnly":true}}]}},"999":{{"Nodes":[{{"HostName":"127.0.0.1","DERPPort":443,"STUNPort":-1}}]}}}}}}}}"#,
            stun.port()
        );
        let mut map = Netmap::new();
        let mut parser = tailfeather::netmap::Parser::new();
        parser.push(&mut map, json.as_bytes()).unwrap();
        parser.finish(&mut map).unwrap();
        map
    }

    fn response(transaction: [u8; 12]) -> [u8; 32] {
        // Binding success, XOR-MAPPED-ADDRESS 203.0.113.7:41641.
        let mut bytes = [
            0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x20, 0x00, 0x08, 0, 1, 0x83, 0xbb, 0xea, 0x12, 0xd5, 0x45,
        ];
        bytes[8..20].copy_from_slice(&transaction);
        bytes
    }

    #[test]
    fn no_measure_no_home_region_is_neither_probed_nor_a_fallback_home() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let mut map = map(server.local_addr().unwrap());
        let mut region = map.derp.region(900).unwrap().clone();
        region.no_measure_no_home = true;
        region.nodes[0].port = 443;
        map.derp.insert(region).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut stun = Stun::new();
        stun.start(&udp, &map);
        assert_eq!(
            server.recv_from(&mut [0; 64]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            stun.poll(&udp, &map),
            Some(Discovery {
                region: 999,
                reflexive: None
            })
        );
    }

    #[test]
    fn standalone_stun_discovers_an_endpoint_without_becoming_home_derp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = server.local_addr().unwrap();
        let map = map(source);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut stun = Stun::new();
        stun.start(&udp, &map);
        let transaction = stun.probes[0].transaction;
        assert!(stun.receive(&response(transaction), source));
        let discovery = stun.poll(&udp, &map).unwrap();
        assert_eq!(
            discovery.reflexive,
            Some("203.0.113.7:41641".parse().unwrap())
        );
        assert_eq!(discovery.region, 999);
    }

    #[test]
    fn blocked_stun_falls_back_to_a_region_with_a_relay() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let map = map(server.local_addr().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut stun = Stun::new();
        stun.start(&udp, &map);
        stun.deadline = Some(Instant::now());
        assert_eq!(
            stun.poll(&udp, &map),
            Some(Discovery {
                region: 999,
                reflexive: None
            })
        );
    }

    #[test]
    fn fastest_reflexive_probe_and_home_relay_are_selected_independently() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut map = map(server.local_addr().unwrap());
        let mut region = map.derp.region(999).unwrap().clone();
        region.nodes[0].stun_port = relay.local_addr().unwrap().port();
        map.derp.insert(region).unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut stun = Stun::new();
        stun.start(&udp, &map);
        let transaction = stun
            .probes
            .iter()
            .find(|p| p.region == 900)
            .unwrap()
            .transaction;
        stun.receive(&response(transaction), server.local_addr().unwrap());
        let probe = stun.probes.iter_mut().find(|p| p.region == 999).unwrap();
        // A deterministic slower measurement without sleeping in the test.
        probe.sent = Instant::now() - Duration::from_secs(1);
        let mut packet = response(probe.transaction);
        packet[27] ^= 3; // Different mapping: 41642 instead of 41641.
        stun.receive(&packet, relay.local_addr().unwrap());
        let discovery = stun.poll(&udp, &map).unwrap();
        assert_eq!(discovery.region, 999);
        assert_eq!(
            discovery.reflexive,
            Some("203.0.113.7:41641".parse().unwrap())
        );
    }

    #[test]
    fn wrong_source_or_transaction_cannot_supply_a_reflexive_endpoint() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = server.local_addr().unwrap();
        let map = map(source);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut stun = Stun::new();
        stun.start(&udp, &map);
        let transaction = stun.probes[0].transaction;
        let wrong_source = SocketAddr::from(([127, 0, 0, 2], source.port()));
        stun.receive(&response(transaction), wrong_source);
        let mut wrong_transaction = transaction;
        wrong_transaction[0] ^= 1;
        stun.receive(&response(wrong_transaction), source);
        stun.deadline = Some(Instant::now());
        assert!(stun.poll(&udp, &map).unwrap().reflexive.is_none());
    }
}
