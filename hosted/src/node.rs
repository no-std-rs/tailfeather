use crate::{
    OsRng,
    exec::{self, Either, Reactor},
    net::{TcpStream, UdpSocket},
};
use core::{cell::RefCell, fmt::Write, net::IpAddr};
use heapless::String;
use std::{cell::Cell, collections::VecDeque};
use tailfeather::control::{
    Hostinfo, MapRequest, RegisterRequest, RegisterResponse,
    authority::Authority,
    transport::{self, MapEvent, MapStream},
};
use tailfeather::{ControlCommand, ControlEvent, Node, NodeAction, PersistState};
pub const PEERS: usize = 256;
const HOST_OS: &str = if cfg!(target_os = "macos") {
    "darwin"
} else {
    std::env::consts::OS
};
pub struct Shared {
    node: RefCell<Node<PEERS>>,
    timestamp: RefCell<crate::time::Timestamp>,
    udp: UdpSocket,
    probe: RefCell<Option<Probe>>,
    endpoints: RefCell<Vec<std::string::String>>,
    candidate_generation: Cell<u64>,
    local_candidate: Cell<Option<core::net::SocketAddrV4>>,
    direct: bool,
    resident: bool,
}
struct Probe {
    transaction: [u8; 12],
    server: core::net::SocketAddrV4,
    reply: tokio::sync::oneshot::Sender<core::net::SocketAddrV4>,
}
impl Shared {
    pub fn borrow(&self) -> std::cell::Ref<'_, Node<PEERS>> {
        self.node.borrow()
    }
    pub fn borrow_mut(&self) -> std::cell::RefMut<'_, Node<PEERS>> {
        self.node.borrow_mut()
    }
    fn candidate(&self, address: core::net::SocketAddrV4) {
        if !self.direct || address.ip().is_unspecified() || address.ip().is_multicast() {
            return;
        }
        let text = address.to_string();
        let mut endpoints = self.endpoints.borrow_mut();
        if endpoints.len() < 8 && !endpoints.contains(&text) {
            endpoints.push(text);
            self.candidate_generation
                .set(self.candidate_generation.get().wrapping_add(1));
        }
    }
    fn reset_candidates(&self) {
        self.endpoints.borrow_mut().clear();
        self.candidate_generation
            .set(self.candidate_generation.get().wrapping_add(1));
    }
    fn receive_stun(&self, bytes: &[u8], from: core::net::SocketAddrV4) -> bool {
        let mapped = self.probe.borrow().as_ref().and_then(|p| {
            (p.server == from)
                .then(|| tailfeather::stun::response(bytes, p.transaction).ok())
                .flatten()
        });
        if let Some((ip, port)) = mapped {
            if let Some(probe) = self.probe.borrow_mut().take() {
                let _ = probe
                    .reply
                    .send(core::net::SocketAddrV4::new(ip.into(), port));
            }
            return true;
        }
        false
    }
}
#[derive(Default)]
pub struct Actions {
    queue: RefCell<tailfeather_reactor::queue::Actions<32>>,
    overflow: Cell<bool>,
    pub ready: tokio::sync::Notify,
    space: tokio::sync::Notify,
}
impl Actions {
    fn borrow_mut(&self) -> std::cell::RefMut<'_, tailfeather_reactor::queue::Actions<32>> {
        self.queue.borrow_mut()
    }
    fn pop(&self) -> Option<NodeAction> {
        let mut queue = self.queue.borrow_mut();
        let action = queue.pop();
        if queue.len() < 16 {
            self.space.notify_waiters();
        }
        action
    }
    pub async fn wait_for_space(&self) {
        loop {
            let full = self.queue.borrow().len() >= 16;
            if !full {
                return;
            }
            self.space.notified().await;
        }
    }
}
pub type Error = &'static str;
fn node_error(_: tailfeather::NodeError) -> Error {
    "node state"
}
pub fn enqueue(actions: &Actions, action: Option<NodeAction>) {
    let Some(action) = action.filter(|a| !matches!(a, NodeAction::StatusChanged(_))) else {
        return;
    };
    if actions.borrow_mut().push(action).is_err() {
        actions.overflow.set(true);
        return;
    }
    actions.ready.notify_one();
}

pub async fn run(
    config: crate::Config,
    mut commands: tokio::sync::mpsc::Receiver<crate::Command>,
    status: tokio::sync::watch::Sender<crate::Status>,
    stopped: tokio::sync::oneshot::Receiver<()>,
    resident: bool,
) -> Result<(), Error> {
    let reactor = Reactor::new();
    let authority = Authority::parse(&config.control_url, false).map_err(|_| "HTTPS authority")?;
    let store = crate::store::FileStore::new(&config.directory);
    let mut saved = [0; PersistState::BLOB_LEN];
    let mut node = match store.load(&mut saved).map_err(|_| "state load")? {
        Some(n) => Node::restore_for_authority(
            &PersistState::from_bytes(&saved[..n]).map_err(node_error)?,
            authority.digest(),
        )
        .map_err(node_error)?,
        None => Node::factory_reset_for_authority(
            tailfeather::keys::Identity::generate(&mut OsRng),
            1,
            authority.digest(),
        ),
    };
    saved.fill(0);
    node.set_initiate_on_demand(true);
    node.set_direct_paths(!config.relay_only);
    node.set_control_endpoint(
        tailfeather::Endpoint::new(authority.host(), authority.port()).map_err(node_error)?,
    );
    let udp = UdpSocket::bind(&reactor, core::net::Ipv4Addr::UNSPECIFIED, 0)
        .await
        .map_err(|_| "UDP bind")?;
    let node = Shared {
        node: RefCell::new(node),
        timestamp: RefCell::new(crate::time::Timestamp::new(&config.directory)?),
        udp,
        probe: RefCell::new(None),
        endpoints: RefCell::new(Vec::new()),
        candidate_generation: Cell::new(0),
        local_candidate: Cell::new(None),
        direct: !config.relay_only,
        resident,
    };
    let actions = Actions::default();
    let slots = [crate::relay::Slot::new(), crate::relay::Slot::new()];
    let result = tokio::select! {
        result=control_loop(&reactor, &node, &actions, &store, &authority, &status, &config)=>result,
        result=packets(&reactor, &node, &actions, &node.udp, &slots, &mut commands, &status)=>result,
        result=crate::relay::worker(&reactor, &node, &actions, &slots[0], &config.control_ca_der)=>result,
        result=crate::relay::worker(&reactor, &node, &actions, &slots[1], &config.control_ca_der)=>result,
        _=stopped=>Ok(()),
    };
    if config.ephemeral && node.borrow().is_enrolled() {
        // Bound shutdown even if DNS or the coordinator is unavailable. A
        // crash/offline exit still relies on the provider's inactive-node GC.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            logout(&reactor, &node, &authority, &config),
        )
        .await;
    }
    result
}

async fn logout(
    reactor: &Reactor,
    node: &Shared,
    authority: &Authority,
    config: &crate::Config,
) -> Result<(), Error> {
    let mut read = [0; tailfeather::control::tls::TLS_READ_BUFFER];
    let mut write = [0; tailfeather::control::tls::TLS_WRITE_BUFFER];
    let host = format!("{}:{}", authority.host(), authority.port());
    let socket = tcp(reactor, authority.host(), authority.port()).await?;
    let mut stream = crate::tls::connect(
        socket,
        authority.host(),
        &config.control_ca_der,
        &mut read,
        &mut write,
    )
    .await
    .map_err(|_| "logout TLS")?;
    let key = transport::fetch_server_key(&mut stream, &host)
        .await
        .map_err(|_| "logout server key")?;
    drop(stream);
    let socket = tcp(reactor, authority.host(), authority.port()).await?;
    let stream = crate::tls::connect(
        socket,
        authority.host(),
        &config.control_ca_der,
        &mut read,
        &mut write,
    )
    .await
    .map_err(|_| "logout TLS")?;
    let identity = node.borrow().identity().clone();
    let noise = transport::establish(stream, &host, &identity, &key, &mut OsRng)
        .await
        .map_err(|_| "logout Noise")?;
    let mut http = noise.into_https2().await.map_err(|_| "logout HTTP/2")?;
    let public = identity.node.public();
    let request = RegisterRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &public,
        old_node_key: None,
        auth_key: "",
        hostinfo: Hostinfo {
            hostname: &config.hostname,
            os: HOST_OS,
            ..Default::default()
        },
        ephemeral: true,
    };
    let mut body = [0; 2048];
    let body = request
        .write_logout(&mut body)
        .map_err(|_| "logout request size")?;
    let mut response = [0; 4096];
    let (status, _) = http
        .request(
            "POST",
            tailfeather::control::register::PATH,
            &host,
            body,
            &mut response,
        )
        .await
        .map_err(|_| "logout request")?;
    if status == 200 {
        Ok(())
    } else {
        Err("logout rejected")
    }
}
fn persist(node: &Shared, store: &crate::store::FileStore, now: u64) -> Result<(), Error> {
    // Registration first requests closing the old control stream, then saving.
    for _ in 0..3 {
        let action = node.borrow_mut().poll(now).map_err(node_error)?;
        match action {
            Some(NodeAction::Control(ControlCommand::Disconnect)) => {
                let _ = node
                    .borrow_mut()
                    .handle_control_event(ControlEvent::Disconnected);
            }
            Some(NodeAction::PersistState(state)) => {
                let result = store.save(state.as_bytes()).is_ok();
                node.borrow_mut()
                    .persistence_result(state.generation(), result)
                    .map_err(node_error)?;
                if !result {
                    return Err("state persistence");
                }
                return Ok(());
            }
            _ => return Err("expected state persistence"),
        }
    }
    Err("state persistence sequence")
}
async fn control_loop(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    store: &crate::store::FileStore,
    authority: &Authority,
    status: &tokio::sync::watch::Sender<crate::Status>,
    config: &crate::Config,
) -> Result<(), Error> {
    let mut retry_delay = 1000u64;
    loop {
        if node.borrow().requires_persistence() {
            persist(node, store, reactor.clock_millis())?;
        }
        let connect = node
            .borrow_mut()
            .poll(reactor.clock_millis())
            .map_err(node_error)?;
        if !matches!(
            connect,
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ) {
            reactor.sleep(100).await;
            continue;
        }
        let started = reactor.clock_millis();
        let session = control_session(reactor, node, actions, authority, status, config);
        if let Err(stage) = session.await {
            let rejected = matches!(stage, "registration rejected" | "netmap rejected");
            if rejected && (!node.resident || stage == "registration rejected") {
                return Err(stage);
            }
            if rejected {
                // A retained owner waits for a fresh accepted map. Never reset
                // persisted enrollment or substitute a new node on rejection.
                // Reject the previous data-plane authority too: retaining an
                // enrollment does not retain permission from a rejected map.
                node.borrow_mut()
                    .adopt_reconnected_map(&mut tailfeather::netmap::Netmap::new())
                    .map_err(node_error)?;
                status.send_replace(crate::Status::default());
                actions.ready.notify_one();
            }
            if reactor.clock_millis().saturating_sub(started) >= 60_000 {
                retry_delay = 1000;
            }
            tracing::debug!("POCKETBOOT TAILNET_CONTROL_RETRY stage={stage}");
            node.borrow_mut().control_failed(reactor.clock_millis(), 0);
            reactor.sleep(retry_delay).await;
            if node.resident {
                retry_delay = (retry_delay * 2).min(60_000);
            }
        }
    }
}
async fn tcp(reactor: &Reactor, host: &str, port: u16) -> Result<TcpStream, Error> {
    TcpStream::connect_host(reactor, host, port)
        .await
        .map_err(|_| "TCP connect")
}
async fn control_session(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    authority: &Authority,
    status: &tokio::sync::watch::Sender<crate::Status>,
    config: &crate::Config,
) -> Result<(), Error> {
    let hostname = config.hostname.as_str();
    let auth = config.auth_key.as_str();
    let ca = config.control_ca_der.as_slice();
    let ephemeral = config.ephemeral;
    let mut read = [0; tailfeather::control::tls::TLS_READ_BUFFER];
    let mut write = [0; tailfeather::control::tls::TLS_WRITE_BUFFER];
    let mut host = String::<160>::new();
    write!(host, "{}:{}", authority.host(), authority.port()).map_err(|_| "host")?;
    let key = {
        let socket = tcp(reactor, authority.host(), authority.port()).await?;
        node.reset_candidates();
        if let Ok(std::net::SocketAddr::V4(local)) = socket.0.local_addr()
            && let Ok(bound) = node.udp.local_addr()
        {
            let candidate = core::net::SocketAddrV4::new(*local.ip(), bound.port());
            node.local_candidate.set(Some(candidate));
            if node.direct {
                for candidate in crate::discovery::local_candidates(Some(candidate)) {
                    node.candidate(candidate);
                }
            }
        }
        let tls = crate::tls::connect(socket, authority.host(), ca, &mut read, &mut write);
        let mut stream = match exec::select(tls, reactor.sleep(20000)).await {
            Either::First(Ok(s)) => s,
            _ => return Err("key TLS"),
        };
        match exec::select(
            transport::fetch_server_key(&mut stream, &host),
            reactor.sleep(20000),
        )
        .await
        {
            Either::First(Ok(key)) => key,
            _ => return Err("key fetch"),
        }
    };
    let socket = tcp(reactor, authority.host(), authority.port()).await?;
    let tls = crate::tls::connect(socket, authority.host(), ca, &mut read, &mut write);
    let stream = match exec::select(tls, reactor.sleep(20000)).await {
        Either::First(Ok(s)) => s,
        _ => return Err("control TLS"),
    };
    let identity = node.borrow().identity().clone();
    let noise = match exec::select(
        transport::establish(stream, &host, &identity, &key, &mut OsRng),
        reactor.sleep(20000),
    )
    .await
    {
        Either::First(Ok(s)) => s,
        _ => return Err("control Noise"),
    };
    let mut http = tokio::time::timeout(std::time::Duration::from_secs(20), noise.into_https2())
        .await
        .map_err(|_| "HTTP/2 initialization deadline")?
        .map_err(|_| "HTTP/2")?;
    let public = identity.node.public();
    let disco = identity.disco.public();
    let mut body = [0u8; 2048];
    let len = {
        let n = node.borrow();
        let request = RegisterRequest {
            version: tailfeather::control::CAPABILITY_VERSION,
            node_key: &public,
            old_node_key: n.rotation_old_node_key(),
            auth_key: n.registration_auth_key(auth),
            hostinfo: Hostinfo {
                hostname,
                os: HOST_OS,
                version: concat!("tailfeather-hosted-", env!("CARGO_PKG_VERSION")),
                ..Default::default()
            },
            ephemeral,
        };
        request
            .write(&mut body)
            .map_err(|_| "registration size")?
            .len()
    };
    node.borrow_mut()
        .set_registration_body(&body[..len])
        .map_err(node_error)?;
    let registration = node
        .borrow_mut()
        .handle_control_event(ControlEvent::Connected)
        .map_err(node_error)?;
    if !matches!(
        registration,
        Some(NodeAction::Control(ControlCommand::Register { .. }))
    ) {
        return Err("registration transition");
    }
    let mut response = [0u8; 4096];
    let (http_status, len) = match exec::select(
        http.request(
            "POST",
            tailfeather::control::register::PATH,
            &host,
            &body[..len],
            &mut response,
        ),
        reactor.sleep(30000),
    )
    .await
    {
        Either::First(Ok(r)) => r,
        _ => return Err("registration request"),
    };
    body.fill(0);
    let result = RegisterResponse::parse(
        core::str::from_utf8(&response[..len]).map_err(|_| "register encoding")?,
    );
    if matches!(http_status, 408 | 429) || http_status >= 500 {
        return Err("registration unavailable");
    }
    if http_status != 200 || !result.is_success() {
        return Err("registration rejected");
    }
    if result.node_key_expired {
        node.borrow_mut()
            .stage_node_key_rotation(&mut OsRng)
            .map_err(node_error)?;
        return Ok(());
    }
    enqueue(
        actions,
        node.borrow_mut()
            .handle_control_event(ControlEvent::Registered)
            .map_err(node_error)?,
    );
    // First registration commits enrolled identity before opening a fresh map.
    if node.borrow().requires_persistence() {
        return Ok(());
    }
    let endpoints = node.endpoints.borrow().clone();
    let endpoint_refs: Vec<_> = endpoints.iter().map(|s| s.as_str()).collect();
    let request = MapRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &public,
        disco_key: &disco,
        hostinfo: Hostinfo {
            hostname,
            os: HOST_OS,
            version: concat!("tailfeather-hosted-", env!("CARGO_PKG_VERSION")),
            ..Default::default()
        },
        stream: true,
        omit_peers: false,
        read_only: false,
        endpoints: &endpoint_refs,
    };
    let request = request.write(&mut body).map_err(|_| "map size")?;
    let mut maps = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        MapStream::<PEERS>::start(&mut http, &host, request),
    )
    .await
    .map_err(|_| "map start deadline")?
    .map_err(|_| "map start")?;
    let mut staging = tailfeather::netmap::Netmap::new();
    // A reconnect may inherit a coordinator-side preference from the previous
    // stream. Unknown is distinct from explicitly advertising no home.
    let mut published_home = None;
    let mut selected_home = 0;
    let mut published_generation = 0;
    let mut next_discovery = tokio::time::Instant::now();
    loop {
        if !maps.has_pending_update() {
            node.borrow().seed_staging(&mut staging);
        }
        let event =
            match exec::select(maps.next(&mut http, &mut staging), reactor.sleep(90000)).await {
                Either::First(Ok(event)) => event,
                Either::First(Err(error)) => return Err(map_failure(error)),
                _ => return Err("map timeout"),
            };
        if matches!(event, MapEvent::Applied) {
            enqueue(
                actions,
                node.borrow_mut()
                    .handle_control_event(ControlEvent::MapFinished {
                        lease: &mut staging,
                        result: Ok(()),
                    })
                    .map_err(node_error)?,
            );
            publish(node, status)?;
        }
        // A control heartbeat is also a safe boundary for bounded rediscovery:
        // no HTTP/2 read is cancelled halfway through consuming a frame.
        let discover = tokio::time::Instant::now() >= next_discovery;
        if matches!(event, MapEvent::Applied) || discover {
            refresh_home(reactor, node, &mut selected_home, discover).await?;
            if discover {
                next_discovery = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            }
            let generation = node.candidate_generation.get();
            if published_home != Some(selected_home) || published_generation != generation {
                let endpoints = node.endpoints.borrow().clone();
                let endpoint_refs: Vec<_> = endpoints.iter().map(|s| s.as_str()).collect();
                let request = MapRequest {
                    version: tailfeather::control::CAPABILITY_VERSION,
                    node_key: &public,
                    disco_key: &disco,
                    hostinfo: Hostinfo {
                        hostname,
                        preferred_derp: selected_home,
                        report_no_derp: selected_home == 0,
                        os: HOST_OS,
                        version: concat!("tailfeather-hosted-", env!("CARGO_PKG_VERSION")),
                        ..Default::default()
                    },
                    stream: false,
                    omit_peers: true,
                    read_only: false,
                    endpoints: &endpoint_refs,
                };
                let request = request.write(&mut body).map_err(|_| "endpoint size")?;
                if !maps.has_pending_update() {
                    node.borrow().seed_staging(&mut staging);
                }
                match exec::select(
                    transport::send_endpoint_update(
                        &mut http,
                        &mut maps,
                        &mut staging,
                        &host,
                        request,
                    ),
                    reactor.sleep(30000),
                )
                .await
                {
                    Either::First(Ok(())) => {}
                    Either::First(Err(error)) => return Err(map_failure(error)),
                    _ => return Err("endpoint update"),
                }
                published_home = Some(selected_home);
                published_generation = generation;
                tracing::debug!("POCKETBOOT TAILNET_HOME_PUBLISHED region={selected_home}");
            }
        }
    }
}
fn map_failure<E>(error: transport::Error<E>) -> Error {
    match error {
        transport::Error::Netmap(error) => {
            eprintln!("Network map rejected: {error}");
            "netmap rejected"
        }
        transport::Error::ResponseTooLong | transport::Error::FrameTooLarge => "netmap rejected",
        _ => "map transport",
    }
}
async fn refresh_home(
    reactor: &Reactor,
    node: &Shared,
    selected: &mut u16,
    discover: bool,
) -> Result<(), Error> {
    if *selected != 0
        && node
            .borrow()
            .netmap()
            .derp
            .region(*selected)
            .is_none_or(|region| !region.can_be_home())
    {
        *selected = 0;
    }
    if *selected == 0 || discover {
        *selected = select_home(reactor, node).await;
    }
    node.borrow_mut()
        .prefer_derp(*selected)
        .map_err(node_error)?;
    Ok(())
}
async fn select_home(reactor: &Reactor, node: &Shared) -> u16 {
    let snapshot = node.borrow().netmap().clone();
    let mut best = tailfeather::stun::Selection::new(&snapshot);
    if !node.direct {
        return best.home();
    }
    let mut candidates: Vec<_> = crate::discovery::local_candidates(node.local_candidate.get())
        .into_iter()
        .map(|a| a.to_string())
        .collect();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    'regions: for region in snapshot.derp.iter() {
        for relay in region.nodes.iter().filter(|n| n.stun_port != 0) {
            let addresses =
                match tokio::time::timeout_at(deadline, crate::net::resolve_v4(&relay.host_name))
                    .await
                {
                    Ok(Ok(addresses)) => addresses,
                    Ok(Err(_)) => continue,
                    Err(_) => break 'regions,
                };
            for ip in addresses {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                let server = core::net::SocketAddrV4::new(ip, relay.stun_port);
                let mut transaction = [0; 12];
                getrandom::fill(&mut transaction).expect("OS random");
                let (reply, received) = tokio::sync::oneshot::channel();
                *node.probe.borrow_mut() = Some(Probe {
                    transaction,
                    server,
                    reply,
                });
                let started = reactor.clock_millis();
                let probe = async {
                    node.udp
                        .send_to(&tailfeather::stun::request(transaction), &server)
                        .await
                        .ok()?;
                    received.await.ok()
                };
                let limit = deadline
                    .min(tokio::time::Instant::now() + std::time::Duration::from_millis(200));
                if let Ok(Some(mapped)) = tokio::time::timeout_at(limit, probe).await {
                    let text = mapped.to_string();
                    if candidates.len() < 8 && !candidates.contains(&text) {
                        candidates.push(text);
                    }
                    best.record(region, reactor.clock_millis() - started, mapped);
                }
                node.probe.borrow_mut().take();
            }
        }
    }
    if *node.endpoints.borrow() != candidates {
        *node.endpoints.borrow_mut() = candidates;
        node.candidate_generation
            .set(node.candidate_generation.get().wrapping_add(1));
    }
    // These reflexive candidates belong to the actual data socket and can be
    // published alongside its local interface address.
    best.home()
}
fn publish(node: &Shared, status: &tokio::sync::watch::Sender<crate::Status>) -> Result<(), Error> {
    let n = node.borrow();
    let address = n
        .netmap()
        .addresses
        .iter()
        .find_map(|a| match a.address {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .ok_or("assigned IPv4")?;
    status.send_replace(crate::Status {
        address: Some(address),
        error: None,
    });
    Ok(())
}
async fn packets(
    reactor: &Reactor,
    node: &Shared,
    actions: &Actions,
    udp: &UdpSocket,
    slots: &[crate::relay::Slot; 2],
    commands: &mut tokio::sync::mpsc::Receiver<crate::Command>,
    status: &tokio::sync::watch::Sender<crate::Status>,
) -> Result<(), Error> {
    let mut datagram = [0; 2048];
    let net = std::rc::Rc::new(RefCell::new(crate::netstack::NetStack::new(1)));
    let tcp_wake = std::rc::Rc::new(tokio::sync::Notify::new());
    let mut local_port = 49152u16;
    let mut outgoing = VecDeque::new();
    let mut drain: Option<tokio::sync::oneshot::Sender<std::io::Result<()>>> = None;
    let mut punches: Vec<(tailfeather::keys::NodePublic, u64, u8)> = Vec::new();
    let mut candidate_generation = node.candidate_generation.get();
    let mut listeners: Vec<(
        crate::netstack::TcpListener,
        tokio::sync::mpsc::Sender<tokio::io::DuplexStream>,
    )> = Vec::new();
    let mut random = [0; 8];
    getrandom::fill(&mut random).map_err(|_| "random")?;
    let seed = u64::from_ne_bytes(random);
    let trace = std::env::var_os("TAILFEATHER_NET_TRACE").is_some();
    let mut trace_at = 0;
    loop {
        if actions.overflow.get() {
            return Err("node action capacity exceeded");
        }
        if let Some(address) = status.borrow().address {
            net.borrow_mut()
                .set_address(address, reactor.clock_millis(), seed);
        } else {
            net.borrow_mut().clear_address();
            outgoing.clear();
            punches.clear();
        }
        let queued = actions.borrow_mut().len();
        for _ in 0..queued {
            let Some(action) = actions.pop() else {
                break;
            };
            match action {
                NodeAction::DirectTransmit {
                    endpoint: core::net::SocketAddr::V4(to),
                    packet,
                    ..
                } => {
                    if status.borrow().address.is_some() {
                        let _ = udp.send_to(packet.as_slice(), &to).await;
                    }
                }
                NodeAction::DeliveredIpv4 { peer, packet } => {
                    let bytes = packet.as_slice();
                    let allowed = {
                        let n = node.borrow();
                        (crate::logic::tcp_continuation(bytes)
                            || n.netmap().packet_filter.allows_ipv4(bytes))
                            && n.netmap().addresses.iter().any(|a| match a.address {
                                IpAddr::V4(own) => crate::logic::inbound_allowed(
                                    bytes,
                                    &peer,
                                    n.netmap().peers.iter(),
                                    own,
                                ),
                                _ => false,
                            })
                    };
                    if allowed {
                        net.borrow_mut().deliver(bytes);
                    }
                }
                NodeAction::Derp(command) => {
                    if status.borrow().address.is_none()
                        && matches!(command, tailfeather::DerpCommand::Send { .. })
                    {
                        continue;
                    }
                    if let Some(command) = crate::relay::dispatch(
                        slots,
                        command,
                        node,
                        actions,
                        reactor.clock_millis(),
                    ) {
                        let _ = actions.borrow_mut().push(NodeAction::Derp(command));
                        continue;
                    }
                }
                _ => {}
            }
        }
        listeners.retain_mut(|(listener, incoming)| {
            if incoming.is_closed() {
                net.borrow_mut().remove_listener(listener);
                false
            } else {
                true
            }
        });
        for (listener, incoming) in &mut listeners {
            let ready = net.borrow_mut().accept_ready(listener);
            for accepted in ready {
                let net = net.clone();
                let incoming = incoming.clone();
                tokio::task::spawn_local(crate::bridge::accepted(
                    net,
                    accepted,
                    tcp_wake.clone(),
                    incoming,
                ));
            }
        }
        let now = reactor.clock_millis();
        if trace && now >= trace_at {
            net.borrow().trace();
            trace_at = now + 2000;
        }
        if outgoing.is_empty() {
            let mut net = net.borrow_mut();
            net.poll_stack(now);
            while let Some(packet) = net.take_transmit() {
                outgoing.push_back(packet);
            }
        }
        // Keep generated TCP packets until the bounded actor queues have room;
        // large windows must not turn into systematic local packet loss.
        while actions.borrow_mut().len() < 16 {
            let Some(packet) = outgoing.pop_front() else {
                break;
            };
            let peer = crate::logic::ipv4_addresses(&packet).and_then(|(_, destination)| {
                crate::logic::route_ipv4(node.borrow().netmap().peers.iter(), destination)
            });
            if let Some(peer) = peer {
                enqueue(
                    actions,
                    node.borrow_mut()
                        .encapsulate_ipv4(&peer, &packet, now)
                        .ok()
                        .flatten(),
                );
            }
        }
        if node.direct {
            if candidate_generation != node.candidate_generation.get() {
                punches.clear();
                candidate_generation = node.candidate_generation.get();
            }
            let active: Vec<_> = net
                .borrow()
                .remote_addresses()
                .into_iter()
                .filter_map(|address| {
                    crate::logic::route_ipv4(node.borrow().netmap().peers.iter(), address)
                })
                .collect();
            punches.retain(|(peer, _, _)| active.contains(peer));
            for peer in &active {
                if !punches.iter().any(|(key, _, _)| key == peer) {
                    punches.push((*peer, 0, 0));
                }
            }
            let candidates: Vec<core::net::SocketAddr> = node
                .endpoints
                .borrow()
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect();
            for (peer, next, attempts) in &mut punches {
                if *attempts < 3 && now >= *next && actions.borrow_mut().len() < 16 {
                    let action = node
                        .borrow_mut()
                        .call_me_maybe(peer, &candidates, &mut OsRng)
                        .ok()
                        .flatten();
                    enqueue(actions, action);
                    *attempts += 1;
                    *next = now + 1000;
                }
            }
            for peer in &active {
                if actions.borrow_mut().len() >= 16 {
                    break;
                }
                enqueue(
                    actions,
                    node.borrow_mut()
                        .poll_disco_for(peer, now, &mut OsRng)
                        .ok()
                        .flatten(),
                );
            }
        }
        enqueue(actions, node.borrow_mut().poll_derp().ok().flatten());
        let timestamp = node.timestamp.borrow().candidate()?;
        let handshake = node
            .borrow_mut()
            .poll_tunnel(now, &timestamp, &mut OsRng)
            .ok()
            .flatten();
        if handshake.is_some() {
            node.timestamp.borrow_mut().commit(timestamp)?;
        }
        enqueue(actions, handshake);
        enqueue(
            actions,
            node.borrow_mut().poll_tunnel_timers(now).ok().flatten(),
        );
        if drain.as_ref().is_some_and(|reply| reply.is_closed()) {
            drain.take();
        }
        if drain.is_some() && net.borrow().drained() {
            let failed = std::mem::take(&mut net.borrow_mut().close_failed);
            let _ = drain.take().unwrap().send(if failed {
                Err(std::io::Error::other("TCP close was not acknowledged"))
            } else {
                Ok(())
            });
        }
        let tcp_deadline = if outgoing.is_empty() {
            net.borrow_mut().deadline(now)
        } else {
            None
        };
        let idle = tcp_deadline
            .map_or(250, |deadline| {
                deadline.saturating_sub(reactor.clock_millis())
            })
            .clamp(1, 250);
        tokio::select! {
            _=actions.ready.notified()=>{},
            _=tcp_wake.notified()=>{},
            received=udp.recv_from(&mut datagram)=>{let (len,from)=received.map_err(|_|"UDP receive")?;if node.receive_stun(&datagram[..len],from){continue;}enqueue(actions,node.borrow_mut().handle_direct_from(&datagram[..len],from.into(),reactor.clock_millis(),&mut OsRng).ok().flatten());}
            command=commands.recv()=>match command {
                Some(crate::Command::Drain { reply }) => {
                    if listeners.iter().any(|(_,incoming)|!incoming.is_closed()) { let _=reply.send(Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"drop listeners before draining"))); }
                    else if drain.as_ref().is_some_and(|reply| !reply.is_closed()) { let _ = reply.send(Err(std::io::Error::other("TCP drain already pending"))); }
                    else { drain=Some(reply); }
                }
                Some(crate::Command::Connect {address,port,reply})=>{
                    if let Some(own)=status.borrow().address {net.borrow_mut().set_address(own,reactor.clock_millis(),seed);}
                    let result=net.borrow_mut().connect(address,port,local_port);
                    local_port=if local_port==65535 {49152} else {local_port+1};
                    match result {
                        Ok(handle)=>{let net=net.clone();let wake=tcp_wake.clone();tokio::task::spawn_local(async move {crate::bridge::connect(net,handle,wake,reply).await;});}
                        Err(error)=>{let _=reply.send(Err(std::io::Error::other(error)));}
                    }
                }
                Some(crate::Command::Listen{port,incoming,reply})=>{
                    if let Some(own)=status.borrow().address {net.borrow_mut().set_address(own,reactor.clock_millis(),seed);}
                    if listeners.len()>=4||listeners.iter().any(|(listener,_)|listener.port==port){let _=reply.send(Err(std::io::Error::other("listener unavailable")));}
                    else {let result=net.borrow_mut().listen_backlog(port);match result {Ok(listener)=>{listeners.push((listener,incoming));let _=reply.send(Ok(()));},Err(error)=>{let _=reply.send(Err(std::io::Error::other(error)));}}}
                }
                None=>return Ok(()),
            },
            _=reactor.sleep(idle)=>{}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture() -> Shared {
        let mut node = Node::factory_reset(tailfeather::keys::Identity::generate(&mut OsRng), 1);
        let Some(NodeAction::PersistState(state)) = node.poll(0).unwrap() else {
            panic!("initial state");
        };
        node.persistence_result(state.generation(), true).unwrap();
        Shared {
            node: RefCell::new(node),
            timestamp: RefCell::new(crate::time::Timestamp::default()),
            udp: UdpSocket::bind(&Reactor::new(), std::net::Ipv4Addr::LOCALHOST, 0)
                .await
                .unwrap(),
            probe: RefCell::new(None),
            endpoints: RefCell::new(Vec::new()),
            candidate_generation: Cell::new(0),
            local_candidate: Cell::new(None),
            direct: true,
            resident: false,
        }
    }
    #[test]
    fn a_queued_disconnect_prevents_any_relay_connection_attempt() {
        crate::on_worker_stack(a_queued_disconnect_prevents_any_relay_connection_attempt_on_worker);
    }
    fn a_queued_disconnect_prevents_any_relay_connection_attempt_on_worker() {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let server=std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).unwrap();server.set_nonblocking(true).unwrap();
            let node=fixture().await;let actions=Actions::default();let slots=[crate::relay::Slot::new(),crate::relay::Slot::new()];
            let connect=tailfeather::DerpCommand::Connect {region:7,endpoint:tailfeather::Endpoint::new("127.0.0.1",server.local_addr().unwrap().port()).unwrap()};
            assert!(crate::relay::dispatch(&slots,connect,&node,&actions,0).is_none());
            assert!(crate::relay::dispatch(&slots,tailfeather::DerpCommand::Disconnect {region:7},&node,&actions,0).is_none());
            let reactor=Reactor::new();
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50),crate::relay::worker(&reactor,&node,&actions,&slots[0],&[])).await.is_err());
            assert!(matches!(server.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
        });
    }
    #[test]
    fn stun_discovery_tries_a_backup_node_using_the_data_socket() {
        crate::on_worker_stack(stun_discovery_tries_a_backup_node_using_the_data_socket_on_worker);
    }
    fn stun_discovery_tries_a_backup_node_using_the_data_socket_on_worker() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use tailfeather::netmap::{DerpNode, DerpRegion, Netmap};
                let node = fixture().await;
                let server = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let port = server.local_addr().unwrap().port();
                let mut nodes = heapless::Vec::new();
                for host in ["127.0.0.2", "127.0.0.1"] {
                    nodes
                        .push(DerpNode {
                            host_name: heapless::String::try_from(host).unwrap(),
                            cert_name: None,
                            port: 443,
                            stun_port: port,
                        })
                        .unwrap();
                }
                let mut map = Netmap::new();
                map.derp
                    .insert(DerpRegion {
                        id: 7,
                        no_measure_no_home: false,
                        code: heapless::String::try_from("fixture").unwrap(),
                        nodes,
                    })
                    .unwrap();
                node.borrow_mut()
                    .handle_control_event(ControlEvent::MapFinished {
                        lease: &mut map,
                        result: Ok(()),
                    })
                    .unwrap();
                let respond = async {
                    for delta in 0..2u16 {
                        let mut request = [0; 512];
                        let (len, source) = server.recv_from(&mut request).await.unwrap();
                        assert!(len >= 20);
                        let std::net::SocketAddr::V4(source) = source else {
                            unreachable!()
                        };
                        let mut response = [0u8; 32];
                        response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
                        response[2..4].copy_from_slice(&12u16.to_be_bytes());
                        response[4..20].copy_from_slice(&request[4..20]);
                        response[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
                        response[22..24].copy_from_slice(&8u16.to_be_bytes());
                        response[25] = 1;
                        response[26..28].copy_from_slice(
                            &(source.port().wrapping_add(delta) ^ 0x2112).to_be_bytes(),
                        );
                        response[28..32]
                            .copy_from_slice(&(u32::from(*source.ip()) ^ 0x2112a442).to_be_bytes());
                        server.send_to(&response, source).await.unwrap();
                        let (len, from) = node.udp.recv_from(&mut request).await.unwrap();
                        assert!(node.receive_stun(&request[..len], from));
                    }
                };
                let reactor = Reactor::new();
                let discover = async {
                    let mut selected = 7;
                    refresh_home(&reactor, &node, &mut selected, true)
                        .await
                        .unwrap();
                    assert_eq!(selected, 7);
                    let first = node.endpoints.borrow().clone();
                    assert_eq!(first, [node.udp.local_addr().unwrap().to_string()]);
                    refresh_home(&reactor, &node, &mut selected, true)
                        .await
                        .unwrap();
                    let mut mapped = node.udp.local_addr().unwrap();
                    mapped.set_port(mapped.port().wrapping_add(1));
                    assert_eq!(node.endpoints.borrow().as_slice(), [mapped.to_string()]);
                    assert_ne!(*node.endpoints.borrow(), first);
                };
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    tokio::join!(discover, respond)
                })
                .await
                .unwrap();
            });
    }
    #[test]
    fn discovery_replaces_old_candidates_even_after_filling_capacity() {
        crate::on_worker_stack(
            discovery_replaces_old_candidates_even_after_filling_capacity_on_worker,
        );
    }
    fn discovery_replaces_old_candidates_even_after_filling_capacity_on_worker() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let node = fixture().await;
                for n in 1..=8 {
                    node.candidate(format!("192.0.2.{n}:1234").parse().unwrap());
                }
                assert_eq!(node.endpoints.borrow().len(), 8);
                let generation = node.candidate_generation.get();
                node.reset_candidates();
                node.candidate("198.51.100.7:5678".parse().unwrap());
                assert_eq!(node.endpoints.borrow().as_slice(), ["198.51.100.7:5678"]);
                assert_ne!(node.candidate_generation.get(), generation);
            });
    }
    #[test]
    fn a_disconnect_bypasses_a_saturated_relay_send() {
        crate::on_worker_stack(a_disconnect_bypasses_a_saturated_relay_send_on_worker);
    }
    fn a_disconnect_bypasses_a_saturated_relay_send_on_worker() {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let server=std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).unwrap();server.set_nonblocking(true).unwrap();
            let node=fixture().await;let actions=Actions::default();let slots=[crate::relay::Slot::new(),crate::relay::Slot::new()];
            let connect=tailfeather::DerpCommand::Connect {region:7,endpoint:tailfeather::Endpoint::new("127.0.0.1",server.local_addr().unwrap().port()).unwrap()};
            assert!(crate::relay::dispatch(&slots,connect,&node,&actions,0).is_none());
            let peer=node.borrow().identity().node.public();
            let send=||tailfeather::DerpCommand::Send{region:7,peer,packet:tailfeather::SecretBuffer::try_from_slice(&[1;20]).unwrap()};
            for _ in 0..15 { assert!(crate::relay::dispatch(&slots,send(),&node,&actions,0).is_none()); }
            enqueue(&actions,Some(NodeAction::Derp(send())));
            enqueue(&actions,Some(NodeAction::Derp(tailfeather::DerpCommand::Disconnect{region:7})));
            let (_keep,mut commands)=tokio::sync::mpsc::channel(1);
            let (status,_watch)=tokio::sync::watch::channel(crate::Status::default());
            let reactor=Reactor::new();
            let actors=async {tokio::join!(packets(&reactor,&node,&actions,&node.udp,&slots,&mut commands,&status),crate::relay::worker(&reactor,&node,&actions,&slots[0],&[]))};
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50),actors).await.is_err());
            assert!(matches!(server.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
        });
    }
    #[test]
    fn streaming_maps_replace_a_removed_or_ineligible_home_region() {
        crate::on_worker_stack(
            streaming_maps_replace_a_removed_or_ineligible_home_region_on_worker,
        );
    }
    fn streaming_maps_replace_a_removed_or_ineligible_home_region_on_worker() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use tailfeather::netmap::{DerpNode, DerpRegion, Netmap};
                let mut node = fixture().await;
                node.direct = false;
                let reactor = Reactor::new();
                let mut selected = 7;
                for (id, excluded, expected) in [(8, false, 8), (8, true, 0), (7, false, 7)] {
                    let mut nodes = heapless::Vec::new();
                    nodes
                        .push(DerpNode {
                            host_name: heapless::String::try_from("127.0.0.1").unwrap(),
                            cert_name: None,
                            port: 443,
                            stun_port: 0,
                        })
                        .unwrap();
                    let mut map = Netmap::new();
                    map.derp
                        .insert(DerpRegion {
                            id,
                            no_measure_no_home: excluded,
                            code: heapless::String::try_from("fixture").unwrap(),
                            nodes,
                        })
                        .unwrap();
                    node.borrow_mut()
                        .handle_control_event(ControlEvent::MapFinished {
                            lease: &mut map,
                            result: Ok(()),
                        })
                        .unwrap();
                    refresh_home(&reactor, &node, &mut selected, false)
                        .await
                        .unwrap();
                    assert_eq!(selected, expected);
                    assert_eq!(node.borrow().netmap().home_derp, expected);
                }
            });
    }
    #[test]
    fn hosted_peer_capacity_keeps_the_last_peer_and_reports_overflow() {
        crate::on_worker_stack(|| {
            for count in [PEERS, PEERS + 1] {
                let peers = (1..=count)
                    .map(|id| {
                        let mut private = [0; 32];
                        private[..8].copy_from_slice(&(id as u64).to_le_bytes());
                        let key = tailfeather::keys::NodePrivate::from_bytes(private).public();
                        let mut encoded = [0; 128];
                        let key = key.encode(&mut encoded).unwrap();
                        format!(
                            r#"{{"ID":{id},"Key":"{key}","Addresses":["100.64.{}.{}/32"]}}"#,
                            id / 256,
                            id % 256
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let json = format!(r#"{{"Peers":[{peers}]}}"#);
                let mut map = tailfeather::netmap::Netmap::<PEERS>::new();
                let mut parser = tailfeather::netmap::Parser::new();
                let result = parser
                    .push(&mut map, json.as_bytes())
                    .and_then(|()| parser.finish(&mut map));
                if count <= PEERS {
                    result.unwrap();
                    assert_eq!(map.peers.len(), PEERS);
                    assert!(map.peers.iter().any(|peer| peer.id == PEERS as u64));
                    assert!(!map.peers_truncated);
                } else {
                    result.unwrap();
                    assert_eq!(map.peers.len(), PEERS);
                    assert!(map.peers_truncated);
                }
            }
        });
    }

    #[test]
    fn expanded_fleet_acl_is_complete_and_still_bounded() {
        std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(|| {
            for count in [40, 512, 513] {
                let sources = (1..=count).map(|n| format!("\"100.64.{}.{}/32\"", n / 256, n % 256)).collect::<Vec<_>>().join(",");
                let destinations = (1..=count).map(|n| format!(r#"{{"IP":"100.65.{}.{}/32","Ports":{{"First":2222,"Last":2222}}}}"#, n / 256, n % 256)).collect::<Vec<_>>().join(",");
                let json = format!(r#"{{"PacketFilter":[{{"SrcIPs":[{sources}],"DstPorts":[{destinations}],"IPProto":[6]}}]}}"#);
                let mut map = tailfeather::netmap::Netmap::<PEERS>::new();
                let mut parser = tailfeather::netmap::Parser::new();
                parser.push(&mut map, json.as_bytes()).unwrap();
                let result = parser.finish(&mut map);
                if count > 512 {
                    assert!(matches!(result, Err(tailfeather::netmap::Error::Full(_))));
                } else {
                    result.unwrap();
                    assert!(map.packet_filter.allows([100,64,(count / 256) as u8,(count % 256) as u8].into(), [100,65,(count / 256) as u8,(count % 256) as u8].into(), 6, 2222));
                    assert!(!map.packet_filter.allows([100,64,2,200].into(), [100,65,0,1].into(), 6, 2222));
                    assert!(!map.packet_filter.allows([100,64,0,1].into(), [100,65,0,1].into(), 6, 22));
                }
            }
        }).unwrap().join().unwrap();
    }
    #[test]
    fn over_capacity_acl_updates_are_terminal() {
        crate::on_worker_stack(over_capacity_acl_updates_are_terminal_on_worker);
    }
    fn over_capacity_acl_updates_are_terminal_on_worker() {
        let rules=(0..100).map(|port|format!(r#"{{"SrcIPs":["*"],"DstPorts":[{{"IP":"*","Ports":{{"First":{port},"Last":{port}}}}}]}}"#)).collect::<Vec<_>>().join(",");
        let json = format!(r#"{{"PacketFilter":[{rules}]}}"#);
        let mut map = tailfeather::netmap::Netmap::<PEERS>::new();
        let mut parser = tailfeather::netmap::Parser::new();
        parser.push(&mut map, json.as_bytes()).unwrap();
        let error = parser.finish(&mut map).unwrap_err();
        assert!(matches!(error, tailfeather::netmap::Error::Full(_)));
        assert_eq!(
            map_failure(transport::Error::<std::io::Error>::Netmap(error)),
            "netmap rejected"
        );
    }
    #[test]
    fn map_status_bursts_cannot_exhaust_the_action_queue() {
        crate::on_worker_stack(map_status_bursts_cannot_exhaust_the_action_queue_on_worker);
    }
    fn map_status_bursts_cannot_exhaust_the_action_queue_on_worker() {
        let actions = Actions::default();
        for _ in 0..100 {
            enqueue(
                &actions,
                Some(NodeAction::StatusChanged(
                    tailfeather::NodeStatus::Registered,
                )),
            );
        }
        assert!(!actions.overflow.get());
        assert!(actions.borrow_mut().is_empty());
    }
    #[test]
    fn saturated_packet_queue_keeps_stateful_relay_commands() {
        crate::on_worker_stack(saturated_packet_queue_keeps_stateful_relay_commands_on_worker);
    }
    fn saturated_packet_queue_keeps_stateful_relay_commands_on_worker() {
        let actions = Actions::default();
        let key = tailfeather::keys::Identity::generate(&mut OsRng)
            .node
            .public();
        for _ in 0..32 {
            enqueue(
                &actions,
                Some(NodeAction::DeliveredIpv4 {
                    peer: key,
                    packet: tailfeather::SecretBuffer::try_from_slice(&[0; 20]).unwrap(),
                }),
            );
        }
        enqueue(
            &actions,
            Some(NodeAction::Derp(tailfeather::DerpCommand::Connect {
                region: 7,
                endpoint: tailfeather::Endpoint::new("relay.invalid", 443).unwrap(),
            })),
        );
        assert_eq!(actions.borrow_mut().len(), 32);
        assert!(matches!(
            actions.pop(),
            Some(NodeAction::Derp(tailfeather::DerpCommand::Connect {
                region: 7,
                ..
            }))
        ));
        assert!(!actions.overflow.get());
        for _ in 0..33 {
            enqueue(
                &actions,
                Some(NodeAction::Derp(tailfeather::DerpCommand::Disconnect {
                    region: 7,
                })),
            );
        }
        assert!(actions.overflow.get());
        assert_eq!(actions.borrow_mut().len(), 32);
    }
}
