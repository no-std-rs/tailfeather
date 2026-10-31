//! Disposable live interoperability server for loopback Headscale or hosted
//! Tailscale. Hosted control uses the core TLS verifier and system clock.
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    rc::Rc,
    sync::{Arc, mpsc},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tailfeather::{
    Node, NodeAction,
    control::{self, Hostinfo, map::MapRequest, register::RegisterRequest, transport},
    keys::{Identity, NodePublic},
    local_tcp::{self, Stack, StreamId},
    netmap::Netmap,
};
use tailfeather_ssh::{Authorizer, Console, HostKey, Reply, TailnetAccess, rand_core};

#[path = "live_server/network.rs"]
mod network;

struct Underlay {
    udp: Arc<UdpSocket>,
    endpoint: String,
    relay_only: bool,
    publications: mpsc::Receiver<network::Discovery>,
    initial: mpsc::SyncSender<network::Discovery>,
}

// A hosted tailnet can contain more than the isolated lab's two nodes.
const PEERS: usize = tailfeather::netmap::MAX_PEERS;
type SharedNode = Rc<RefCell<Node<PEERS>>>;
type SharedTcp = Rc<RefCell<Stack<'static, 2>>>;

struct Random(std::fs::File);
impl Random {
    fn new() -> Self {
        Self(std::fs::File::open("/dev/urandom").unwrap())
    }
}
impl rand_core::RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_ne_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_ne_bytes(bytes)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.read_exact(bytes).unwrap();
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl rand_core::CryptoRng for Random {}
impl tailfeather::keys::Rng for Random {
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, bytes);
    }
}
impl tailfeather::tunnel::Rng for Random {
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, bytes);
    }
}
impl tailfeather::disco::packet::Rng for Random {
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, bytes);
    }
}

struct Control(TcpStream);
#[derive(Debug)]
struct ControlIo(std::io::Error);
impl std::fmt::Display for ControlIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ControlIo {}
impl tailfeather::embedded_io_async::Error for ControlIo {
    fn kind(&self) -> tailfeather::embedded_io_async::ErrorKind {
        tailfeather::embedded_io_async::ErrorKind::Other
    }
}
impl tailfeather::embedded_io_async::ErrorType for Control {
    type Error = ControlIo;
}
impl tailfeather::embedded_io_async::Read for Control {
    async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ControlIo> {
        self.0.read(bytes).map_err(ControlIo)
    }
}
impl tailfeather::embedded_io_async::Write for Control {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ControlIo> {
        self.0.write(bytes).map_err(ControlIo)
    }
    async fn flush(&mut self) -> Result<(), ControlIo> {
        self.0.flush().map_err(ControlIo)
    }
}

fn blocking<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("blocking control adapter suspended"),
    }
}

struct SystemClock;
impl tailfeather::embedded_tls::TlsClock for SystemClock {
    fn now() -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }
}

fn control_loop(
    address: SocketAddr,
    hosted: bool,
    identity: Identity,
    host_key: String,
    underlay: Underlay,
    maps: mpsc::Sender<Netmap<PEERS>>,
) {
    let connect = move || {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(10)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(150)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        Control(stream)
    };
    if hosted {
        use tailfeather::{
            control::tls::*,
            embedded_tls::{TlsConfig, TlsConnection, TlsContext},
        };
        let connect_tls = move || {
            let read = Box::leak(Box::new([0; TLS_READ_BUFFER]));
            let write = Box::leak(Box::new([0; TLS_WRITE_BUFFER]));
            let config = TlsConfig::new()
                .with_server_name("controlplane.tailscale.com")
                .enable_rsa_signatures();
            let mut connection = TlsConnection::new(connect(), read, write);
            let mut rsa = RsaWorkspace::new();
            blocking(connection.open(TlsContext::new(
                &config,
                VerifyingProvider::<_, SystemClock>::new(Random::new(), None, &mut rsa),
            )))
            .unwrap();
            connection
        };
        control_session(
            connect_tls,
            "controlplane.tailscale.com",
            true,
            identity,
            host_key,
            underlay,
            maps,
        );
    } else {
        control_session(
            connect,
            &address.to_string(),
            false,
            identity,
            host_key,
            underlay,
            maps,
        );
    }
}

fn control_session<
    S: tailfeather::embedded_io_async::Read + tailfeather::embedded_io_async::Write + Send + 'static,
>(
    connect: impl Fn() -> S + Send + 'static,
    authority: &str,
    secure: bool,
    identity: Identity,
    host_key: String,
    underlay: Underlay,
    maps: mpsc::Sender<Netmap<PEERS>>,
) {
    let server_key = blocking(transport::fetch_server_key(&mut connect(), authority)).unwrap();
    let noise = blocking(transport::establish(
        connect(),
        authority,
        &identity,
        &server_key,
        &mut Random::new(),
    ))
    .unwrap();
    let mut http2 = if secure {
        blocking(noise.into_https2()).unwrap()
    } else {
        blocking(noise.into_http2()).unwrap()
    };
    let host_keys = [host_key.as_str()];
    let mut hostinfo = Hostinfo {
        hostname: "tailfeather-ssh-live",
        os: "linux",
        ssh_host_keys: &host_keys,
        ..Hostinfo::default()
    };
    let key = identity.node.public();
    let disco = identity.disco.public();
    let auth = std::env::var("TF_TEST_AUTH_KEY").unwrap();
    let request = RegisterRequest {
        version: control::CAPABILITY_VERSION,
        node_key: &key,
        old_node_key: None,
        auth_key: &auth,
        hostinfo,
        ephemeral: true,
    };
    let mut body = zeroize::Zeroizing::new([0; 2048]);
    let body = request.write(&mut *body).unwrap();
    let mut response = [0; 65536];
    let (status, len) = blocking(http2.request(
        "POST",
        control::register::PATH,
        authority,
        body,
        &mut response,
    ))
    .unwrap();
    assert_eq!(status, 200);
    let registration =
        control::register::RegisterResponse::parse(std::str::from_utf8(&response[..len]).unwrap());
    assert!(registration.is_success(), "registration refused");
    println!("REGISTERED {key}");
    let endpoints: Vec<&str> = if underlay.relay_only {
        Vec::new()
    } else {
        vec![underlay.endpoint.as_str()]
    };
    // At current capability versions hosted control ignores endpoint/hostinfo
    // changes on streaming requests. Publish them with a non-streaming update.
    let mut publication = [0; 2048];
    let publication = MapRequest {
        version: control::CAPABILITY_VERSION,
        node_key: &key,
        disco_key: &disco,
        hostinfo,
        stream: false,
        omit_peers: true,
        read_only: false,
        endpoints: &endpoints,
    }
    .write(&mut publication)
    .unwrap();
    let (status, _) = blocking(http2.request(
        "POST",
        control::map::PATH,
        authority,
        publication,
        &mut response,
    ))
    .unwrap();
    assert_eq!(status, 200);
    let mut body = [0; 2048];
    let body = MapRequest {
        version: control::CAPABILITY_VERSION,
        node_key: &key,
        disco_key: &disco,
        hostinfo,
        stream: true,
        omit_peers: false,
        read_only: false,
        endpoints: &endpoints,
    }
    .write(&mut body)
    .unwrap();
    let mut stream = blocking(transport::MapStream::<PEERS>::start(
        &mut http2, authority, body,
    ))
    .unwrap();
    let mut staging = Netmap::new();
    let mut working = Netmap::new();
    let mut discovered = false;
    let publisher = Publisher {
        authority: authority.to_owned(),
        secure,
        identity: identity.clone(),
        host_key: host_key.clone(),
        local_endpoint: underlay.endpoint.clone(),
        relay_only: underlay.relay_only,
    };
    std::thread::spawn(move || publish_updates(publisher, underlay.publications));
    loop {
        let event = blocking(stream.next(&mut http2, &mut staging, &mut working)).unwrap();
        if event != transport::MapEvent::Applied {
            continue;
        }
        if !discovered {
            let discovery = network::discover(&underlay.udp, &staging);
            hostinfo.preferred_derp = discovery.region;
            let reflexive = discovery.reflexive.map(|a| a.to_string());
            let mut endpoints = endpoints.clone();
            if !underlay.relay_only
                && let Some(reflexive) = &reflexive
                && !endpoints.contains(&reflexive.as_str())
            {
                endpoints.push(reflexive.as_str());
            }
            let mut body = [0; 2048];
            let body = MapRequest {
                version: control::CAPABILITY_VERSION,
                node_key: &key,
                disco_key: &disco,
                hostinfo,
                stream: false,
                omit_peers: true,
                read_only: false,
                endpoints: &endpoints,
            }
            .write(&mut body)
            .unwrap();
            blocking(transport::send_endpoint_update(
                &mut http2,
                &mut stream,
                &mut staging,
                &mut working,
                authority,
                body,
            ))
            .unwrap();
            staging.home_derp = discovery.region;
            println!(
                "DISCOVERY region={} reflexive={:?} relay_only={}",
                discovery.region, discovery.reflexive, underlay.relay_only
            );
            underlay.initial.send(discovery).unwrap();
            discovered = true;
        }
        if maps.send(staging.clone()).is_err() {
            return;
        }
    }
}

struct Publisher {
    authority: String,
    secure: bool,
    identity: Identity,
    host_key: String,
    local_endpoint: String,
    relay_only: bool,
}

fn publication_error(value: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{value:?}"))
}

fn publication_socket(config: &Publisher) -> std::io::Result<Control> {
    let addresses = if config.secure {
        (config.authority.as_str(), 443).to_socket_addrs()?
    } else {
        config.authority.to_socket_addrs()?
    };
    let mut failure = std::io::Error::other("no control address");
    for address in addresses.filter(SocketAddr::is_ipv4) {
        let stream = match TcpStream::connect_timeout(&address, Duration::from_secs(10)) {
            Ok(stream) => stream,
            Err(error) => {
                failure = error;
                continue;
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_nodelay(true)?;
        println!("PUBLISHER_CONNECTED local={}", stream.local_addr()?);
        return Ok(Control(stream));
    }
    Err(failure)
}

fn publication_tls<'a>(
    config: &Publisher,
    read: &'a mut [u8],
    write: &'a mut [u8],
) -> std::io::Result<tailfeather::embedded_tls::TlsConnection<'a, Control, control::tls::Suite>> {
    use tailfeather::{control::tls::*, embedded_tls::*};
    let tls_config = TlsConfig::new()
        .with_server_name(&config.authority)
        .enable_rsa_signatures();
    let mut connection = TlsConnection::new(publication_socket(config)?, read, write);
    let mut rsa = RsaWorkspace::new();
    blocking(connection.open(TlsContext::new(
        &tls_config,
        VerifyingProvider::<_, SystemClock>::new(Random::new(), None, &mut rsa),
    )))
    .map_err(publication_error)?;
    Ok(connection)
}

fn publication_connection(
    config: &Publisher,
    updates: &mpsc::Receiver<network::Discovery>,
    update: &mut network::Discovery,
) -> std::io::Result<()> {
    if config.secure {
        // Buffers belong to this attempt and are reclaimed on every reconnect.
        let mut read = [0; control::tls::TLS_READ_BUFFER];
        let mut write = [0; control::tls::TLS_WRITE_BUFFER];
        let key = blocking(transport::fetch_server_key(
            &mut publication_tls(config, &mut read, &mut write)?,
            &config.authority,
        ))
        .map_err(publication_error)?;
        publication_session(
            publication_tls(config, &mut read, &mut write)?,
            &key,
            config,
            updates,
            update,
        )
    } else {
        let key = blocking(transport::fetch_server_key(
            &mut publication_socket(config)?,
            &config.authority,
        ))
        .map_err(publication_error)?;
        publication_session(publication_socket(config)?, &key, config, updates, update)
    }
}

fn publish_updates(config: Publisher, updates: mpsc::Receiver<network::Discovery>) {
    // Establish lazily, retain the failed update, and coalesce newer mappings
    // before retrying on a new verified TLS/Noise session.
    let Ok(mut update) = updates.recv() else {
        return;
    };
    let mut backoff = Duration::from_millis(100);
    loop {
        while let Ok(newest) = updates.try_recv() {
            update = newest;
        }
        match publication_connection(&config, &updates, &mut update) {
            Ok(()) => return, // The data-plane sender has shut down.
            Err(error) => eprintln!("PUBLISHER_RETRY {error}"),
        }
        match updates.recv_timeout(backoff) {
            Ok(newest) => update = newest,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

fn publication_session<S>(
    stream: S,
    key: &tailfeather::keys::MachinePublic,
    config: &Publisher,
    updates: &mpsc::Receiver<network::Discovery>,
    update: &mut network::Discovery,
) -> std::io::Result<()>
where
    S: tailfeather::embedded_io_async::Read + tailfeather::embedded_io_async::Write,
{
    let noise = blocking(transport::establish(
        stream,
        &config.authority,
        &config.identity,
        key,
        &mut Random::new(),
    ))
    .map_err(publication_error)?;
    let mut http2 = if config.secure {
        blocking(noise.into_https2())
    } else {
        blocking(noise.into_http2())
    }
    .map_err(publication_error)?;
    let node_key = config.identity.node.public();
    let disco_key = config.identity.disco.public();
    loop {
        // Coalesce queued measurements to the newest mapping.
        while let Ok(newest) = updates.try_recv() {
            *update = newest;
        }
        let mut endpoints = Vec::new();
        if !config.relay_only {
            endpoints.push(config.local_endpoint.clone());
            if let Some(reflexive) = update.reflexive.map(|a| a.to_string())
                && !endpoints.contains(&reflexive)
            {
                endpoints.push(reflexive);
            }
        }
        let refs: Vec<&str> = endpoints.iter().map(String::as_str).collect();
        let keys = [config.host_key.as_str()];
        let mut body = [0; 2048];
        let body = MapRequest {
            version: control::CAPABILITY_VERSION,
            node_key: &node_key,
            disco_key: &disco_key,
            hostinfo: Hostinfo {
                hostname: "tailfeather-ssh-live",
                os: "linux",
                ssh_host_keys: &keys,
                preferred_derp: update.region,
                ..Hostinfo::default()
            },
            stream: false,
            omit_peers: true,
            read_only: false,
            endpoints: &refs,
        }
        .write(&mut body)
        .map_err(publication_error)?;
        let mut response = [0; 65536];
        let (status, _) = blocking(http2.request(
            "POST",
            control::map::PATH,
            &config.authority,
            body,
            &mut response,
        ))
        .map_err(publication_error)?;
        if status != 200 {
            return Err(std::io::Error::other(format!(
                "endpoint update HTTP {status}"
            )));
        }
        println!("PUBLISHED region={} endpoints={endpoints:?}", update.region);
        let Ok(next) = updates.recv() else {
            break;
        };
        *update = next;
    }
    Ok(())
}

fn apply_map(
    node: &mut Node<PEERS>,
    map: &mut Netmap<PEERS>,
    preferred: Option<network::Discovery>,
) -> std::io::Result<()> {
    node.adopt_reconnected_map(map).map_err(publication_error)?;
    if let Some(preferred) = preferred {
        // The map reader runs independently and can still carry our old home.
        // Retain the measured choice while it remains eligible in the new map.
        let _ = node.prefer_derp(preferred.region);
    }
    Ok(())
}

fn queue_discovery(
    node: &mut Node<PEERS>,
    publications: &mpsc::SyncSender<network::Discovery>,
    discovery: network::Discovery,
) -> std::io::Result<()> {
    // A map replacement can remove a region while its STUN scan is in flight.
    // Never advertise that stale choice, or move home if the queue is full.
    if discovery.region == 0
        || node
            .netmap()
            .derp
            .region(discovery.region)
            .is_none_or(|r| !r.can_be_home())
    {
        return Err(std::io::Error::other("discovered home no longer eligible"));
    }
    publications
        .try_send(discovery)
        .map_err(publication_error)?;
    node.prefer_derp(discovery.region)
        .map_err(publication_error)
}

struct Stream {
    tcp: SharedTcp,
    id: StreamId,
}
impl tailfeather_ssh::embedded_io_async::ErrorType for Stream {
    type Error = std::io::Error;
}
fn io_result(result: Result<usize, local_tcp::Error>) -> Poll<std::io::Result<usize>> {
    match result {
        Ok(size) => Poll::Ready(Ok(size)),
        Err(local_tcp::Error::WouldBlock) => Poll::Pending,
        Err(error) => Poll::Ready(Err(std::io::Error::other(error.to_string()))),
    }
}
impl tailfeather_ssh::embedded_io_async::Read for Stream {
    async fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        poll_fn(|_| io_result(self.tcp.borrow_mut().read(self.id, bytes))).await
    }
}
impl tailfeather_ssh::embedded_io_async::Write for Stream {
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        poll_fn(|_| io_result(self.tcp.borrow_mut().write(self.id, bytes))).await
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Echo;
impl Console for Echo {
    fn open(&mut self, output: &mut [u8]) -> Reply {
        let greeting = b"Tailfeather live console\n";
        output[..greeting.len()].copy_from_slice(greeting);
        Reply::output(greeting.len())
    }
    fn input(&mut self, byte: u8, output: &mut [u8]) -> Reply {
        output[0] = byte;
        if byte == b'\n' {
            Reply::exit(1, 0)
        } else {
            Reply::output(1)
        }
    }
}

fn dispatch(
    action: Option<NodeAction>,
    node: &mut Node<PEERS>,
    tcp: &mut Stack<'static, 2>,
    udp: &UdpSocket,
    relays: &mut network::Relays,
    assigned: Ipv4Addr,
    now: u64,
) {
    match action {
        Some(NodeAction::DirectTransmit {
            endpoint, packet, ..
        }) => {
            if std::env::var_os("TF_TEST_NETWORK_DEBUG").is_some() {
                println!("UDP_TX endpoint={endpoint} len={}", packet.as_slice().len());
            }
            if let Err(e) = udp.send_to(packet.as_slice(), endpoint) {
                eprintln!("UDP send: {e}");
            }
        }
        Some(NodeAction::Derp(command)) => {
            if let Some(network::RelayEvent::Disconnected(region)) = relays.command(command) {
                let action = node
                    .handle_derp_event(
                        tailfeather::node::DerpEvent::Disconnected { region },
                        now,
                        &mut Random::new(),
                    )
                    .unwrap();
                dispatch(action, node, tcp, udp, relays, assigned, now);
            }
        }
        Some(NodeAction::DeliveredIpv4 { peer, packet }) => {
            let bytes = packet.as_slice();
            if bytes.len() < 20 {
                return;
            }
            let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let dest = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            let valid = node.netmap().peers.by_node_key(&peer).is_some_and(|p| {
                p.addresses
                    .iter()
                    .any(|a| a.prefix == 32 && a.address == source)
            });
            if !valid
                || dest != assigned
                || !node
                    .netmap()
                    .packet_filter
                    .allows(source, dest, bytes[9], 22)
            {
                return;
            }
            let mut output = [0; local_tcp::MTU];
            let poll = tcp.ingest_ipv4(bytes, &mut output, now).unwrap();
            if poll.transmitted > 0 {
                match node.encapsulate_ipv4(&peer, &output[..poll.transmitted], now) {
                    Ok(action) => dispatch(action, node, tcp, udp, relays, assigned, now),
                    Err(e) => eprintln!("TCP reply: {e}"),
                }
            }
        }
        _ => {}
    }
}

fn timestamp() -> tailfeather::tunnel::Tai64n {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let mut stamp = [0; 12];
    stamp[..8].copy_from_slice(&(0x4000_0000_0000_000au64 + time.as_secs()).to_be_bytes());
    stamp[8..].copy_from_slice(&time.subsec_nanos().to_be_bytes());
    stamp
}

fn main() {
    let control = std::env::args()
        .nth(1)
        .expect("loopback Headscale address or --hosted");
    let hosted = control == "--hosted";
    let address: SocketAddr = if hosted {
        ("controlplane.tailscale.com", 443)
            .to_socket_addrs()
            .unwrap()
            .find(SocketAddr::is_ipv4)
            .unwrap()
    } else {
        let address: SocketAddr = control.parse().unwrap();
        assert!(
            address.ip().is_loopback(),
            "plaintext control must be loopback"
        );
        address
    };
    let endpoint_ip: Ipv4Addr = std::env::args()
        .nth(2)
        .expect("local underlay IPv4")
        .parse()
        .unwrap();
    let udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap());
    let relay_only = std::env::args().any(|arg| arg == "--relay-only");
    udp.set_nonblocking(true).unwrap();
    let endpoint = format!("{endpoint_ip}:{}", udp.local_addr().unwrap().port());
    let local_endpoint: SocketAddr = endpoint.parse().unwrap();
    println!("UDP_BOUND local={local_endpoint}");
    let mut random = Random::new();
    let identity = Identity::generate(&mut random);
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    rand_core::RngCore::fill_bytes(&mut random, &mut *seed);
    let host_key = HostKey::from_seed(&seed);
    let mut public = [0; 80];
    let public = host_key.public_key(&mut public).unwrap().to_owned();
    let (tx, rx) = mpsc::channel();
    let control_identity = identity.clone();
    let mut relays = network::Relays::new(identity.clone());
    let (publications, publication_rx) = mpsc::sync_channel(4);
    let (initial_tx, initial_rx) = mpsc::sync_channel(1);
    let underlay = Underlay {
        udp: udp.clone(),
        endpoint,
        relay_only,
        publications: publication_rx,
        initial: initial_tx,
    };
    std::thread::spawn(move || {
        control_loop(address, hosted, control_identity, public, underlay, tx)
    });
    let node: SharedNode = Rc::new(RefCell::new(Node::factory_reset(identity, 1)));
    let pending = node.borrow_mut().poll(0).unwrap();
    if let Some(NodeAction::PersistState(state)) = pending {
        // This disposable identity lives only as long as the test process.
        node.borrow_mut()
            .persistence_result(state.generation(), true)
            .unwrap();
    }
    node.borrow_mut().set_initiate_on_demand(true);
    node.borrow_mut().set_direct_paths(!relay_only);
    let mut map = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    apply_map(&mut node.borrow_mut(), &mut map, None).unwrap();
    let assigned = node
        .borrow()
        .netmap()
        .addresses
        .iter()
        .find_map(|cidr| match cidr.address {
            std::net::IpAddr::V4(ip) if cidr.prefix == 32 => Some(ip),
            _ => None,
        })
        .unwrap();
    let storage = Box::leak(Box::new(tailfeather_ssh::TcpStorage::new()));
    let tcp = Rc::new(RefCell::new(
        Stack::new(
            storage,
            assigned.octets(),
            rand_core::RngCore::next_u64(&mut random),
            0,
        )
        .unwrap(),
    ));
    tcp.borrow_mut().listen(22).unwrap();
    println!(
        "READY {assigned} policy_supported={}",
        node.borrow().netmap().ssh_policy.is_supported()
    );
    let start = Instant::now();
    let mut datagram = [0; tailfeather::tunnel::MAX_DATAGRAM_LEN];
    let mut output = [0; local_tcp::MTU];
    let mut session: Option<std::pin::Pin<Box<dyn Future<Output = ()>>>> = None;
    let debug_network = std::env::var_os("TF_TEST_NETWORK_DEBUG").is_some();
    let mut active = None;
    let sessions = std::env::args()
        .find_map(|arg| {
            arg.strip_prefix("--sessions=")
                .map(|v| v.parse::<usize>().unwrap())
        })
        .unwrap_or(1);
    let timeout_seconds = std::env::args()
        .find_map(|arg| {
            arg.strip_prefix("--timeout-seconds=")
                .map(|v| v.parse::<u64>().unwrap())
        })
        .unwrap_or(if sessions > 1 { 240 } else { 120 });
    let mut completed = 0usize;
    let mut direct_received = 0usize;
    let mut relay_received = 0usize;
    let mut stun = network::Stun::new();
    let mut published = Some(initial_rx.recv().unwrap());
    let mut active_peers: Vec<(NodePublic, u64)> = Vec::new();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(timeout_seconds),
            "live test deadline"
        );
        let now = start.elapsed().as_millis() as u64;
        while let Ok(mut update) = rx.try_recv() {
            apply_map(&mut node.borrow_mut(), &mut update, published).unwrap();
            if debug_network {
                for peer in node.borrow().netmap().peers.iter() {
                    println!(
                        "PEER_ENDPOINTS peer={} home={} endpoints={:?}",
                        peer.node_key, peer.home_derp, peer.endpoints
                    );
                }
            }
            println!(
                "MAP peers={} policy_supported={}",
                node.borrow().netmap().peers.len(),
                node.borrow().netmap().ssh_policy.is_supported()
            );
        }
        relays.home(node.borrow().netmap().home_derp);
        while let Some(event) = relays.poll() {
            use tailfeather::node::DerpEvent;
            let action = match event {
                network::RelayEvent::Connected(region) => {
                    println!("DERP_CONNECTED region={region}");
                    node.borrow_mut().handle_derp_event(
                        DerpEvent::Connected { region },
                        now,
                        &mut random,
                    )
                }
                network::RelayEvent::Disconnected(region) => {
                    println!("DERP_DISCONNECTED region={region}");
                    node.borrow_mut().handle_derp_event(
                        DerpEvent::Disconnected { region },
                        now,
                        &mut random,
                    )
                }
                network::RelayEvent::Packet {
                    region,
                    peer,
                    packet,
                } => node.borrow_mut().handle_derp_event(
                    DerpEvent::Packet {
                        region,
                        peer,
                        payload: &packet,
                    },
                    now,
                    &mut random,
                ),
                network::RelayEvent::PeerGone { region, peer } => {
                    node.borrow_mut().forget_relay(&peer, region);
                    Ok(None)
                }
            };
            match action {
                Ok(action) => {
                    if let Some(NodeAction::DeliveredIpv4 { peer, packet }) = &action {
                        relay_received += packet.as_slice().len();
                        if !active_peers.iter().any(|(key, _)| key == peer) {
                            active_peers.push((*peer, 0));
                        }
                    }
                    dispatch(
                        action,
                        &mut node.borrow_mut(),
                        &mut tcp.borrow_mut(),
                        &udp,
                        &mut relays,
                        assigned,
                        now,
                    );
                }
                Err(e) => eprintln!("DERP receive: {e}"),
            }
        }
        while let Ok((len, source)) = udp.recv_from(&mut datagram) {
            if debug_network {
                println!("UDP_RX source={source} len={len}");
            }
            if stun.receive(&datagram[..len], source) {
                continue;
            }
            let action =
                node.borrow_mut()
                    .handle_direct_from(&datagram[..len], source, now, &mut random);
            match action {
                Ok(action) => {
                    if let Some(NodeAction::DeliveredIpv4 { packet, .. }) = &action {
                        direct_received += packet.as_slice().len();
                    }
                    dispatch(
                        action,
                        &mut node.borrow_mut(),
                        &mut tcp.borrow_mut(),
                        &udp,
                        &mut relays,
                        assigned,
                        now,
                    );
                }
                Err(e) => eprintln!("UDP receive: {e}"),
            }
        }
        let discovery = {
            let node = node.borrow();
            stun.poll(&udp, node.netmap())
        };
        if let Some(discovery) = discovery
            && published != Some(discovery)
        {
            let queued = queue_discovery(&mut node.borrow_mut(), &publications, discovery);
            match queued {
                Ok(()) => {
                    relays.home(discovery.region);
                    if !relay_only
                        && published
                            .is_some_and(|previous| previous.reflexive != discovery.reflexive)
                    {
                        // A different local NAT mapping invalidates previously
                        // learned direct paths and exhausted discovery rounds.
                        node.borrow_mut().set_direct_paths(false);
                        node.borrow_mut().set_direct_paths(true);
                        for (_, deadline) in &mut active_peers {
                            *deadline = 0;
                        }
                    }
                    published = Some(discovery);
                }
                Err(e) => eprintln!("endpoint publication: {e}"),
            }
        }
        if !relay_only {
            active_peers.retain(|(key, _)| node.borrow().netmap().peers.by_node_key(key).is_some());
            let mut endpoints = vec![local_endpoint];
            if let Some(reflexive) = published.and_then(|p| p.reflexive)
                && !endpoints.contains(&reflexive)
            {
                endpoints.push(reflexive);
            }
            for (peer, deadline) in &mut active_peers {
                if now < *deadline {
                    continue;
                }
                *deadline = now.saturating_add(5000);
                if debug_network {
                    println!("CMM_TX peer={peer} endpoints={endpoints:?}");
                }
                let action = node
                    .borrow_mut()
                    .call_me_maybe(peer, &endpoints, &mut random);
                match action {
                    Ok(action) => dispatch(
                        action,
                        &mut node.borrow_mut(),
                        &mut tcp.borrow_mut(),
                        &udp,
                        &mut relays,
                        assigned,
                        now,
                    ),
                    Err(e) => eprintln!("CallMeMaybe: {e}"),
                }
            }
        }
        if session.is_none() && active.is_none() {
            let accepted = tcp.borrow_mut().accept();
            if let Some(id) = accepted {
                let source = Ipv4Addr::from(tcp.borrow().remote_ipv4(id).unwrap());
                let peer_key: NodePublic = node
                    .borrow()
                    .netmap()
                    .peers
                    .iter()
                    .find(|p| {
                        p.addresses
                            .iter()
                            .any(|a| a.prefix == 32 && a.address == source)
                    })
                    .unwrap()
                    .node_key;
                println!("ACCEPT {source} peer={peer_key}");
                // Count the SSH exchange from this accept onward, excluding
                // late TCP close packets from a previous test session.
                direct_received = 0;
                relay_received = 0;
                active = Some(id);
                let tcp = tcp.clone();
                let node = node.clone();
                let seed = seed.clone();
                session = Some(Box::pin(async move {
                    let access = |username: &str| {
                        TailnetAccess {
                            netmap: node.borrow().netmap(),
                            peer_key,
                            source,
                            destination: assigned,
                            local_user: "console",
                        }
                        .allows(username)
                    };
                    let result = tailfeather_ssh::serve(
                        Stream {
                            tcp: tcp.clone(),
                            id,
                        },
                        &mut Random::new(),
                        &HostKey::from_seed(&seed),
                        &access,
                        &mut Echo,
                        &mut [0; tailfeather_ssh::PACKET_BUFFER],
                        &mut [0; 256],
                    )
                    .await;
                    println!("SESSION {result:?}");
                    tcp.borrow_mut().close(id).unwrap();
                }));
            }
        }
        if let Some(future) = &mut session
            && future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        {
            session = None;
        }
        loop {
            let poll = tcp.borrow_mut().poll_transmit(&mut output, now).unwrap();
            if poll.transmitted == 0 {
                break;
            }
            let destination = Ipv4Addr::new(output[16], output[17], output[18], output[19]);
            let peer = node
                .borrow()
                .netmap()
                .peers
                .iter()
                .find(|p| {
                    p.addresses
                        .iter()
                        .any(|a| a.prefix == 32 && a.address == destination)
                })
                .map(|p| p.node_key);
            if let Some(peer) = peer {
                let action =
                    node.borrow_mut()
                        .encapsulate_ipv4(&peer, &output[..poll.transmitted], now);
                match action {
                    Ok(action) => dispatch(
                        action,
                        &mut node.borrow_mut(),
                        &mut tcp.borrow_mut(),
                        &udp,
                        &mut relays,
                        assigned,
                        now,
                    ),
                    Err(e) => eprintln!("TCP transmit: {e}"),
                }
            }
        }
        for action in [
            {
                let mut node = node.borrow_mut();
                node.poll_disco(now, &mut random)
            },
            {
                let mut node = node.borrow_mut();
                node.poll_derp()
            },
            {
                let mut node = node.borrow_mut();
                node.poll_tunnel(now, &timestamp(), &mut random)
            },
            {
                let mut node = node.borrow_mut();
                node.poll_tunnel_timers(now)
            },
        ] {
            match action {
                Ok(action) => dispatch(
                    action,
                    &mut node.borrow_mut(),
                    &mut tcp.borrow_mut(),
                    &udp,
                    &mut relays,
                    assigned,
                    now,
                ),
                Err(e) => eprintln!("node poll: {e}"),
            }
        }
        if let Some(id) = active
            && session.is_none()
            && !tcp.borrow().is_active(id)
        {
            println!("PATH_BYTES direct={direct_received} relay={relay_received}");
            completed += 1;
            println!("DRAINED {completed}");
            direct_received = 0;
            relay_received = 0;
            active = None;
            if completed >= sessions {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshed_home_is_applied_without_a_control_echo() {
        let mut node = Node::<PEERS>::factory_reset(Identity::generate(&mut Random::new()), 1);
        let generation = match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state.generation(),
            _ => panic!("expected initial persistence"),
        };
        node.persistence_result(generation, true).unwrap();
        let mut map = Netmap::new();
        let mut parser = tailfeather::netmap::Parser::new();
        parser.push(&mut map, br#"{"HomeDERP":999,"DERPMap":{"Regions":{"999":{"Nodes":[{"HostName":"old"}]},"1000":{"Nodes":[{"HostName":"new"}]}}}}"#).unwrap();
        parser.finish(&mut map).unwrap();
        node.handle_control_event(tailfeather::ControlEvent::MapFinished {
            lease: &mut map,
            result: Ok(()),
        })
        .unwrap();
        node.prefer_derp(999).unwrap();
        let mut delayed_map = node.netmap().clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let next = network::Discovery {
            region: 1000,
            reflexive: None,
        };
        queue_discovery(&mut node, &sender, next).unwrap();
        assert_eq!(node.netmap().home_derp, 1000);
        assert!(matches!(
            node.poll_derp().unwrap(),
            Some(NodeAction::Derp(tailfeather::node::DerpCommand::Connect {
                region: 1000,
                ..
            }))
        ));
        assert!(
            queue_discovery(
                &mut node,
                &sender,
                network::Discovery {
                    region: 999,
                    reflexive: None
                }
            )
            .is_err()
        );
        assert_eq!(node.netmap().home_derp, 1000);
        assert_eq!(receiver.recv().unwrap(), next);
        apply_map(&mut node, &mut delayed_map, Some(next)).unwrap();
        assert_eq!(node.netmap().home_derp, 1000);
        assert!(
            queue_discovery(
                &mut node,
                &sender,
                network::Discovery {
                    region: 123,
                    reflexive: None
                }
            )
            .is_err()
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(node.netmap().home_derp, 1000);
    }
}
