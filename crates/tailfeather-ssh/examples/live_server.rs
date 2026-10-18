//! Disposable live interoperability server for loopback Headscale or hosted
//! Tailscale. Hosted control uses the core TLS verifier and system clock.
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    rc::Rc,
    sync::mpsc,
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
    endpoint: String,
    maps: mpsc::Sender<Netmap<PEERS>>,
) {
    let connect = || {
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
        let connect_tls = || {
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
            endpoint,
            maps,
        );
    } else {
        control_session(
            connect,
            &address.to_string(),
            false,
            identity,
            host_key,
            endpoint,
            maps,
        );
    }
}

fn control_session<
    S: tailfeather::embedded_io_async::Read + tailfeather::embedded_io_async::Write,
>(
    connect: impl Fn() -> S,
    authority: &str,
    secure: bool,
    identity: Identity,
    host_key: String,
    endpoint: String,
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
    let hostinfo = Hostinfo {
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
    let endpoints = [endpoint.as_str()];
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
    loop {
        let event = blocking(stream.next(&mut http2, &mut staging)).unwrap();
        if event == transport::MapEvent::Applied && maps.send(staging.clone()).is_err() {
            return;
        }
    }
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

fn send(action: Option<NodeAction>, udp: &UdpSocket) {
    if let Some(NodeAction::DirectTransmit {
        endpoint, packet, ..
    }) = action
    {
        udp.send_to(packet.as_slice(), endpoint).unwrap();
    }
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
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    udp.set_nonblocking(true).unwrap();
    let endpoint = format!("{endpoint_ip}:{}", udp.local_addr().unwrap().port());
    let mut random = Random::new();
    let identity = Identity::generate(&mut random);
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    rand_core::RngCore::fill_bytes(&mut random, &mut *seed);
    let host_key = HostKey::from_seed(&seed);
    let mut public = [0; 80];
    let public = host_key.public_key(&mut public).unwrap().to_owned();
    let (tx, rx) = mpsc::channel();
    let control_identity = identity.clone();
    std::thread::spawn(move || {
        control_loop(address, hosted, control_identity, public, endpoint, tx)
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
    let mut map = rx.recv_timeout(Duration::from_secs(30)).unwrap();
    node.borrow_mut().adopt_reconnected_map(&mut map).unwrap();
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
    let mut active = None;
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "live test deadline"
        );
        let now = start.elapsed().as_millis() as u64;
        while let Ok(mut update) = rx.try_recv() {
            node.borrow_mut()
                .adopt_reconnected_map(&mut update)
                .unwrap();
            println!(
                "MAP peers={} policy_supported={}",
                node.borrow().netmap().peers.len(),
                node.borrow().netmap().ssh_policy.is_supported()
            );
        }
        while let Ok((len, source)) = udp.recv_from(&mut datagram) {
            let action =
                node.borrow_mut()
                    .handle_direct_from(&datagram[..len], source, now, &mut random);
            match action {
                Ok(Some(NodeAction::DeliveredIpv4 { peer, packet })) => {
                    let bytes = packet.as_slice();
                    if bytes.len() < 20 {
                        continue;
                    }
                    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
                    let dest = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
                    let valid = node
                        .borrow()
                        .netmap()
                        .peers
                        .by_node_key(&peer)
                        .is_some_and(|p| {
                            p.addresses
                                .iter()
                                .any(|a| a.prefix == 32 && a.address == source)
                        });
                    if !valid
                        || dest != assigned
                        || !node
                            .borrow()
                            .netmap()
                            .packet_filter
                            .allows(source, dest, bytes[9], 22)
                    {
                        continue;
                    }
                    let poll = tcp
                        .borrow_mut()
                        .ingest_ipv4(bytes, &mut output, now)
                        .unwrap();
                    if poll.transmitted > 0 {
                        send(
                            node.borrow_mut()
                                .encapsulate_ipv4(&peer, &output[..poll.transmitted], now)
                                .unwrap(),
                            &udp,
                        );
                    }
                }
                Ok(other) => send(other, &udp),
                Err(error) => eprintln!("UDP: {error}"),
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
                send(
                    node.borrow_mut()
                        .encapsulate_ipv4(&peer, &output[..poll.transmitted], now)
                        .unwrap(),
                    &udp,
                );
            }
        }
        send(node.borrow_mut().poll_tunnel_timers(now).unwrap(), &udp);
        if let Some(id) = active
            && session.is_none()
            && !tcp.borrow().is_active(id)
        {
            println!("DRAINED");
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
