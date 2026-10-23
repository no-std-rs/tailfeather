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
pub const PEERS: usize = 32;
const HOST_OS: &str = if cfg!(target_os = "macos") {
    "darwin"
} else {
    std::env::consts::OS
};
pub struct Shared {
    node: RefCell<Node<PEERS>>,
    udp: UdpSocket,
    probe: RefCell<Option<Probe>>,
    endpoints: RefCell<Vec<std::string::String>>,
    direct: bool,
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
        }
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
    queue: RefCell<VecDeque<NodeAction>>,
    overflow: Cell<bool>,
    pub ready: tokio::sync::Notify,
}
impl Actions {
    fn borrow_mut(&self) -> std::cell::RefMut<'_, VecDeque<NodeAction>> {
        self.queue.borrow_mut()
    }
}
fn droppable(action: &NodeAction) -> bool {
    matches!(
        action,
        NodeAction::DirectTransmit { .. }
            | NodeAction::DeliveredIpv4 { .. }
            | NodeAction::Derp(tailfeather::DerpCommand::Send { .. })
    )
}
pub type Error = &'static str;
fn node_error(_: tailfeather::NodeError) -> Error {
    "node state"
}
pub fn enqueue(actions: &Actions, action: Option<NodeAction>) {
    let Some(action) = action else {
        return;
    };
    let mut queue = actions.borrow_mut();
    if queue.len() == 32 {
        if droppable(&action) {
            return;
        }
        if let Some(index) = queue.iter().position(droppable) {
            queue.remove(index);
        } else {
            // Stateful commands cannot be lost while leaving a live node that
            // believes they ran. Surface capacity exhaustion to its caller.
            actions.overflow.set(true);
            return;
        }
    }
    queue.push_back(action);
    actions.ready.notify_one();
}
pub async fn run(
    config: crate::Config,
    mut commands: tokio::sync::mpsc::Receiver<crate::Command>,
    status: tokio::sync::watch::Sender<crate::Status>,
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
        udp,
        probe: RefCell::new(None),
        endpoints: RefCell::new(Vec::new()),
        direct: !config.relay_only,
    };
    let actions = Actions::default();
    let slots = [crate::relay::Slot::new(), crate::relay::Slot::new()];
    tokio::select! {
        result=control_loop(&reactor, &node, &actions, &store, &authority, &status, &config)=>result,
        result=packets(&reactor, &node, &actions, &node.udp, &slots, &mut commands, &status)=>result,
        result=crate::relay::worker(&reactor, &node, &actions, &slots[0], &config.control_ca_der)=>result,
        result=crate::relay::worker(&reactor, &node, &actions, &slots[1], &config.control_ca_der)=>result,
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
        let session = control_session(reactor, node, actions, authority, status, config);
        if let Err(stage) = session.await {
            if stage == "registration rejected" {
                return Err(stage);
            }
            tracing::debug!("POCKETBOOT TAILNET_CONTROL_RETRY stage={stage}");
            node.borrow_mut().control_failed(reactor.clock_millis(), 0);
            reactor.sleep(1000).await;
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
        if let Ok(std::net::SocketAddr::V4(local)) = socket.0.local_addr()
            && let Ok(bound) = node.udp.local_addr()
        {
            node.candidate(core::net::SocketAddrV4::new(*local.ip(), bound.port()));
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
    let mut http = noise.into_https2().await.map_err(|_| "HTTP/2")?;
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
    if http_status == 429 || http_status >= 500 {
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
    let mut maps = MapStream::<PEERS>::start(&mut http, &host, request)
        .await
        .map_err(|_| "map start")?;
    let mut staging = tailfeather::netmap::Netmap::new();
    let mut published_home = 0;
    let mut selected_home = 0;
    loop {
        if !maps.has_pending_update() {
            node.borrow().seed_staging(&mut staging);
        }
        let event =
            match exec::select(maps.next(&mut http, &mut staging), reactor.sleep(90000)).await {
                Either::First(Ok(event)) => event,
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
            if selected_home == 0 {
                selected_home = select_home(reactor, node).await;
            }
            if selected_home != 0 {
                node.borrow_mut()
                    .prefer_derp(selected_home)
                    .map_err(node_error)?;
            }
            publish(node, status)?;
            if selected_home != 0 && published_home != selected_home {
                let endpoints = node.endpoints.borrow().clone();
                let endpoint_refs: Vec<_> = endpoints.iter().map(|s| s.as_str()).collect();
                let request = MapRequest {
                    version: tailfeather::control::CAPABILITY_VERSION,
                    node_key: &public,
                    disco_key: &disco,
                    hostinfo: Hostinfo {
                        hostname,
                        preferred_derp: selected_home,
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
                    _ => return Err("endpoint update"),
                }
                published_home = selected_home;
                tracing::debug!("POCKETBOOT TAILNET_HOME_PUBLISHED region={selected_home}");
            }
        }
    }
}
async fn select_home(reactor: &Reactor, node: &Shared) -> u16 {
    let snapshot = node.borrow().netmap().clone();
    let mut best = tailfeather::stun::Selection::new(&snapshot);
    if !node.direct {
        return best.home();
    }
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
                    node.candidate(mapped);
                    best.record(region, reactor.clock_millis() - started, mapped);
                }
                node.probe.borrow_mut().take();
            }
        }
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
    let mut local_port = 49152u16;
    let mut timestamp = crate::time::Timestamp::default();
    let mut outgoing = VecDeque::new();
    let mut punches: Vec<(tailfeather::keys::NodePublic, u64, u8)> = Vec::new();
    let mut listeners: Vec<(
        u16,
        crate::netstack::TcpHandle,
        tokio::sync::mpsc::Sender<tokio::io::DuplexStream>,
    )> = Vec::new();
    let mut random = [0; 8];
    getrandom::fill(&mut random).map_err(|_| "random")?;
    let seed = u64::from_ne_bytes(random);
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
    loop {
        if actions.overflow.get() {
            return Err("node action capacity exceeded");
        }
        if let Some(address) = status.borrow().address {
            net.borrow_mut()
                .set_address(address, reactor.clock_millis(), seed);
        }
        for _ in 0..64 {
            let Some(action) = actions.borrow_mut().pop_front() else {
                break;
            };
            match action {
                NodeAction::DirectTransmit {
                    endpoint: core::net::SocketAddr::V4(to),
                    packet,
                    ..
                } => {
                    let _ = udp.send_to(packet.as_slice(), &to).await;
                }
                NodeAction::DeliveredIpv4 { peer, packet } => {
                    let bytes = packet.as_slice();
                    let allowed = {
                        let n = node.borrow();
                        n.netmap().packet_filter.allows_ipv4(bytes)
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
                    if let Some(command) = crate::relay::dispatch(
                        slots,
                        command,
                        node,
                        actions,
                        reactor.clock_millis(),
                    ) {
                        actions.borrow_mut().push_front(NodeAction::Derp(command));
                        break;
                    }
                }
                _ => {}
            }
        }
        listeners.retain(|(_, handle, incoming)| {
            if incoming.is_closed() {
                net.borrow_mut().remove(*handle);
                false
            } else {
                true
            }
        });
        for (port, handle, incoming) in &mut listeners {
            if net
                .borrow_mut()
                .tcp(*handle)
                .is_some_and(|s| s.state() == smoltcp::socket::tcp::State::Established)
            {
                let accepted = *handle;
                let replacement = net.borrow_mut().listen(*port);
                match replacement {
                    Ok(next) => {
                        *handle = next;
                        let net = net.clone();
                        let incoming = incoming.clone();
                        tokio::task::spawn_local(crate::bridge::accepted(net, accepted, incoming));
                    }
                    Err(_) => {
                        net.borrow_mut().remove(accepted);
                        *handle = net
                            .borrow_mut()
                            .listen(*port)
                            .map_err(|_| "listener capacity")?;
                    }
                }
            }
        }
        let now = reactor.clock_millis();
        if outgoing.is_empty() {
            outgoing.extend(net.borrow_mut().poll(now));
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
            let active: Vec<_> = net
                .borrow()
                .remote_addresses()
                .into_iter()
                .filter_map(|address| {
                    crate::logic::route_ipv4(node.borrow().netmap().peers.iter(), address)
                })
                .collect();
            punches.retain(|(peer, _, _)| active.contains(peer));
            for peer in active {
                if !punches.iter().any(|(key, _, _)| *key == peer) {
                    punches.push((peer, 0, 0));
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
        }
        enqueue(
            actions,
            node.borrow_mut().poll_disco(now, &mut OsRng).ok().flatten(),
        );
        enqueue(actions, node.borrow_mut().poll_derp().ok().flatten());
        enqueue(
            actions,
            node.borrow_mut()
                .poll_tunnel(now, &timestamp.next(), &mut OsRng)
                .ok()
                .flatten(),
        );
        enqueue(
            actions,
            node.borrow_mut().poll_tunnel_timers(now).ok().flatten(),
        );
        tokio::select! {
            _=actions.ready.notified()=>{},
            received=udp.recv_from(&mut datagram)=>{let (len,from)=received.map_err(|_|"UDP receive")?;if node.receive_stun(&datagram[..len],from){continue;}enqueue(actions,node.borrow_mut().handle_direct_from(&datagram[..len],from.into(),reactor.clock_millis(),&mut OsRng).ok().flatten());}
            command=commands.recv()=>match command {
                Some(crate::Command::Connect {address,port,reply})=>{
                    if let Some(own)=status.borrow().address {net.borrow_mut().set_address(own,reactor.clock_millis(),seed);}
                    let result=net.borrow_mut().connect(address,port,local_port);
                    local_port=if local_port==65535 {49152} else {local_port+1};
                    match result {
                        Ok(handle)=>{let net=net.clone();tokio::task::spawn_local(async move {crate::bridge::connect(net,handle,reply).await;});}
                        Err(error)=>{let _=reply.send(Err(std::io::Error::other(error)));}
                    }
                }
                Some(crate::Command::Listen{port,incoming,reply})=>{
                    if let Some(own)=status.borrow().address {net.borrow_mut().set_address(own,reactor.clock_millis(),seed);}
                    if listeners.len()>=4||listeners.iter().any(|(p,_,_)|*p==port){let _=reply.send(Err(std::io::Error::other("listener unavailable")));}
                    else {let result=net.borrow_mut().listen(port);match result {Ok(handle)=>{listeners.push((port,handle,incoming));let _=reply.send(Ok(()));},Err(error)=>{let _=reply.send(Err(std::io::Error::other(error)));}}}
                }
                None=>return Ok(()),
            },
            _=interval.tick()=>{}
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
            udp: UdpSocket::bind(&Reactor::new(), std::net::Ipv4Addr::LOCALHOST, 0)
                .await
                .unwrap(),
            probe: RefCell::new(None),
            endpoints: RefCell::new(Vec::new()),
            direct: true,
        }
    }
    #[test]
    fn a_queued_disconnect_prevents_any_relay_connection_attempt() {
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
                    response[26..28].copy_from_slice(&(source.port() ^ 0x2112).to_be_bytes());
                    response[28..32]
                        .copy_from_slice(&(u32::from(*source.ip()) ^ 0x2112a442).to_be_bytes());
                    server.send_to(&response, source).await.unwrap();
                    let (len, from) = node.udp.recv_from(&mut request).await.unwrap();
                    assert!(node.receive_stun(&request[..len], from));
                };
                let reactor = Reactor::new();
                let (home, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    tokio::join!(select_home(&reactor, &node), respond)
                })
                .await
                .unwrap();
                assert_eq!(home, 7);
                assert_eq!(
                    node.endpoints.borrow().as_slice(),
                    [node.udp.local_addr().unwrap().to_string()]
                );
            });
    }
    #[test]
    fn saturated_packet_queue_keeps_stateful_relay_commands() {
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
            actions.borrow_mut().back(),
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
