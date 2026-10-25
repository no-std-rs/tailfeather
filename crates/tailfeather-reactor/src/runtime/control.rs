use super::*;
use core::fmt::Write as _;
use heapless::String;
use tailfeather::control::{
    Hostinfo, MapRequest, RegisterRequest, RegisterResponse,
    transport::{self, MapEvent, MapStream},
};

fn map_error<E>(error: transport::Error<E>) -> Error {
    match error {
        transport::Error::Netmap(_)
        | transport::Error::ResponseTooLong
        | transport::Error::FrameTooLarge => "netmap rejected",
        _ => "map transport",
    }
}

fn persist<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
) -> Result<(), Error> {
    for _ in 0..3 {
        let action = runtime
            .node
            .borrow_mut()
            .poll(runtime.network.now_millis())
            .map_err(|_| "node state")?;
        match action {
            Some(NodeAction::Control(ControlCommand::Disconnect)) => {
                let _ = runtime
                    .node
                    .borrow_mut()
                    .handle_control_event(ControlEvent::Disconnected);
            }
            Some(NodeAction::PersistState(state)) => {
                let saved = runtime.state.save(state.as_bytes()).is_ok();
                runtime
                    .node
                    .borrow_mut()
                    .persistence_result(state.generation(), saved)
                    .map_err(|_| "identity persistence")?;
                return if saved {
                    Ok(())
                } else {
                    Err("identity persistence")
                };
            }
            _ => return Err("expected identity persistence"),
        }
    }
    Err("identity persistence sequence")
}

pub(super) async fn run<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
    buffers: &mut LinkBuffers,
    staging: &mut tailfeather::netmap::Netmap<PEERS>,
) -> Result<(), Error> {
    let authority =
        Authority::parse(runtime.config.control_url, false).map_err(|_| "HTTPS authority")?;
    loop {
        if runtime.node.borrow().requires_persistence() {
            persist(runtime)?;
        }
        let action = runtime
            .node
            .borrow_mut()
            .poll(reactor.clock_millis())
            .map_err(|_| "node state")?;
        if !matches!(
            action,
            Some(NodeAction::Control(ControlCommand::Connect { .. }))
        ) {
            reactor.sleep(100).await;
            continue;
        }
        match session(runtime, reactor, &authority, buffers, staging).await {
            Err(error @ ("registration rejected" | "netmap rejected")) => return Err(error),
            Err(_) => {
                runtime
                    .node
                    .borrow_mut()
                    .control_failed(reactor.clock_millis(), 0);
                reactor.sleep(1000).await;
            }
            Ok(()) => {}
        }
    }
}

fn hostinfo<'a>(config: &Config<'a>, preferred_derp: u16, report_no_derp: bool) -> Hostinfo<'a> {
    Hostinfo {
        hostname: config.hostname,
        os: config.os,
        version: concat!("tailfeather-reactor-", env!("CARGO_PKG_VERSION")),
        preferred_derp,
        report_no_derp,
        ..Default::default()
    }
}

fn endpoints<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
) -> Vec<String<32>, 8> {
    runtime
        .candidates
        .borrow()
        .iter()
        .map(|endpoint| {
            let mut text = String::new();
            write!(text, "{endpoint}").expect("IPv4 endpoint fits 32 bytes");
            text
        })
        .collect()
}

async fn session<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
    authority: &Authority,
    buffers: &mut LinkBuffers,
    staging: &mut tailfeather::netmap::Netmap<PEERS>,
) -> Result<(), Error> {
    let config = &runtime.config;
    let mut host = String::<160>::new();
    write!(host, "{}:{}", authority.host(), authority.port())
        .map_err(|_| "control authority length")?;
    let key = {
        let mut stream = reactor
            .timeout(
                35_000,
                runtime.network.connect(
                    authority.host(),
                    authority.port(),
                    authority.host(),
                    config.control_ca_der,
                    buffers,
                ),
            )
            .await
            .map_err(|_| "key TLS deadline")??;
        let mut candidates = Vec::new();
        if !config.relay_only
            && let Some(address) = runtime.network.interface_address()
        {
            let endpoint = runtime.network.local_endpoint()?;
            let _ = candidates.push(SocketAddrV4::new(address, endpoint.port()));
        }
        runtime.candidates(candidates);
        reactor
            .timeout(20_000, transport::fetch_server_key(&mut stream, &host))
            .await
            .map_err(|_| "key fetch deadline")?
            .map_err(|_| "key fetch")?
    };
    let stream = reactor
        .timeout(
            35_000,
            runtime.network.connect(
                authority.host(),
                authority.port(),
                authority.host(),
                config.control_ca_der,
                buffers,
            ),
        )
        .await
        .map_err(|_| "control TLS deadline")??;
    let identity = runtime.node.borrow().identity().clone();
    let noise = reactor
        .timeout(
            20_000,
            transport::establish(stream, &host, &identity, &key, &mut runtime.network.rng()),
        )
        .await
        .map_err(|_| "control Noise deadline")?
        .map_err(|_| "control Noise")?;
    let mut http = reactor
        .timeout(20_000, noise.into_https2())
        .await
        .map_err(|_| "HTTP/2 deadline")?
        .map_err(|_| "HTTP/2")?;
    let public = identity.node.public();
    let disco = identity.disco.public();
    let mut body = zeroize::Zeroizing::new([0; 2048]);
    let len = {
        let node = runtime.node.borrow();
        RegisterRequest {
            version: tailfeather::control::CAPABILITY_VERSION,
            node_key: &public,
            old_node_key: node.rotation_old_node_key(),
            auth_key: node.registration_auth_key(config.auth_key),
            hostinfo: hostinfo(config, 0, false),
            ephemeral: config.ephemeral,
        }
        .write(&mut body[..])
        .map_err(|_| "registration size")?
        .len()
    };
    runtime
        .node
        .borrow_mut()
        .set_registration_body(&body[..len])
        .map_err(|_| "registration body")?;
    if !matches!(
        runtime
            .node
            .borrow_mut()
            .handle_control_event(ControlEvent::Connected)
            .map_err(|_| "control state")?,
        Some(NodeAction::Control(ControlCommand::Register { .. }))
    ) {
        return Err("registration transition");
    }
    let mut response = [0; 4096];
    let (status, len) = reactor
        .timeout(
            30_000,
            http.request(
                "POST",
                tailfeather::control::register::PATH,
                &host,
                &body[..len],
                &mut response,
            ),
        )
        .await
        .map_err(|_| "registration deadline")?
        .map_err(|_| "registration request")?;
    body.fill(0);
    if matches!(status, 408 | 429) || status >= 500 {
        return Err("registration unavailable");
    }
    let result = RegisterResponse::parse(
        core::str::from_utf8(&response[..len]).map_err(|_| "registration encoding")?,
    );
    if status != 200 || !result.is_success() {
        return Err("registration rejected");
    }
    if result.node_key_expired {
        runtime
            .node
            .borrow_mut()
            .stage_node_key_rotation(&mut runtime.network.rng())
            .map_err(|_| "key rotation")?;
        return Ok(());
    }
    runtime.enqueue(
        runtime
            .node
            .borrow_mut()
            .handle_control_event(ControlEvent::Registered)
            .map_err(|_| "registration state")?,
    );
    if runtime.node.borrow().requires_persistence() {
        return Ok(());
    }
    let texts = endpoints(runtime);
    let refs: Vec<&str, 8> = texts.iter().map(|text| text.as_str()).collect();
    let request = MapRequest {
        version: tailfeather::control::CAPABILITY_VERSION,
        node_key: &public,
        disco_key: &disco,
        hostinfo: hostinfo(config, 0, false),
        stream: true,
        omit_peers: false,
        read_only: false,
        endpoints: &refs,
    };
    let request = request
        .write(&mut body[..])
        .map_err(|_| "map request size")?;
    let mut maps = reactor
        .timeout(30_000, MapStream::<PEERS>::start(&mut http, &host, request))
        .await
        .map_err(|_| "map start deadline")?
        .map_err(|_| "map start")?;
    let mut home = 0;
    let mut published_home = None;
    let mut published_generation = 0;
    let mut discovery_at = 0;
    loop {
        if !maps.has_pending_update() {
            runtime.node.borrow().seed_staging(staging);
        }
        let event = reactor
            .timeout(90_000, maps.next(&mut http, staging))
            .await
            .map_err(|_| "map timeout")?
            .map_err(map_error)?;
        if matches!(event, MapEvent::Applied) {
            runtime.enqueue(
                runtime
                    .node
                    .borrow_mut()
                    .handle_control_event(ControlEvent::MapFinished {
                        lease: staging,
                        result: Ok(()),
                    })
                    .map_err(|_| "map state")?,
            );
            let address = runtime
                .node
                .borrow()
                .netmap()
                .addresses
                .iter()
                .find_map(|cidr| match cidr.address {
                    core::net::IpAddr::V4(address) => Some(address),
                    _ => None,
                })
                .ok_or("assigned IPv4")?;
            runtime.status.sender().send(Status {
                address: Some(address),
                error: None,
            });
        }
        let discover = reactor.clock_millis() >= discovery_at;
        if matches!(event, MapEvent::Applied) || discover {
            if home != 0
                && runtime
                    .node
                    .borrow()
                    .netmap()
                    .derp
                    .region(home)
                    .is_none_or(|region| !region.can_be_home())
            {
                home = 0;
            }
            if home == 0 || discover {
                home = discover_home(runtime, reactor).await;
            }
            runtime
                .node
                .borrow_mut()
                .prefer_derp(home)
                .map_err(|_| "home relay")?;
            if discover {
                discovery_at = reactor.clock_millis().saturating_add(30_000);
            }
            let generation = runtime.candidate_generation.get();
            if published_home != Some(home) || published_generation != generation {
                let texts = endpoints(runtime);
                let refs: Vec<&str, 8> = texts.iter().map(|text| text.as_str()).collect();
                let request = MapRequest {
                    version: tailfeather::control::CAPABILITY_VERSION,
                    node_key: &public,
                    disco_key: &disco,
                    hostinfo: hostinfo(config, home, home == 0),
                    stream: false,
                    omit_peers: true,
                    read_only: false,
                    endpoints: &refs,
                };
                let request = request
                    .write(&mut body[..])
                    .map_err(|_| "endpoint request size")?;
                if !maps.has_pending_update() {
                    runtime.node.borrow().seed_staging(staging);
                }
                reactor
                    .timeout(
                        30_000,
                        transport::send_endpoint_update(
                            &mut http, &mut maps, staging, &host, request,
                        ),
                    )
                    .await
                    .map_err(|_| "endpoint update deadline")?
                    .map_err(map_error)?;
                published_home = Some(home);
                published_generation = generation;
            }
        }
        crate::exec::yield_now().await;
    }
}

async fn discover_home<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
) -> u16 {
    let mut selection = tailfeather::stun::Selection::new(runtime.node.borrow().netmap());
    if runtime.config.relay_only {
        return selection.home();
    }
    let deadline = reactor.clock_millis().saturating_add(12_000);
    let mut candidates = Vec::new();
    if let Some(address) = runtime.network.interface_address()
        && let Ok(endpoint) = runtime.network.local_endpoint()
    {
        let _ = candidates.push(SocketAddrV4::new(address, endpoint.port()));
    }
    let mut index = 0;
    'regions: loop {
        let region = runtime
            .node
            .borrow()
            .netmap()
            .derp
            .iter()
            .nth(index)
            .cloned();
        let Some(region) = region else {
            break;
        };
        index += 1;
        for relay in region.nodes.iter().filter(|relay| relay.stun_port != 0) {
            let remaining = deadline.saturating_sub(reactor.clock_millis());
            let addresses = match reactor
                .timeout(remaining, runtime.network.resolve(&relay.host_name))
                .await
            {
                Ok(Ok(addresses)) => addresses,
                Ok(Err(_)) => continue,
                Err(_) => break 'regions,
            };
            for address in addresses {
                let now = reactor.clock_millis();
                if now >= deadline {
                    break 'regions;
                }
                let mut transaction = [0; 12];
                Rng::fill_bytes(&mut runtime.network.rng(), &mut transaction);
                let server = SocketAddrV4::new(address, relay.stun_port);
                runtime.probed.reset();
                *runtime.probe.borrow_mut() = Some(Probe {
                    transaction,
                    server,
                    received: None,
                });
                let probe = async {
                    runtime
                        .network
                        .send(&tailfeather::stun::request(transaction), server)
                        .await?;
                    loop {
                        if let Some(received) = runtime
                            .probe
                            .borrow()
                            .as_ref()
                            .and_then(|probe| probe.received)
                        {
                            return Ok::<_, Error>(received);
                        }
                        runtime.probed.wait().await;
                    }
                };
                if let Ok(Ok(mapped)) = reactor.timeout((deadline - now).min(200), probe).await {
                    if !candidates.contains(&mapped) {
                        let _ = candidates.push(mapped);
                    }
                    selection.record(&region, reactor.clock_millis().saturating_sub(now), mapped);
                }
                runtime.probe.borrow_mut().take();
            }
        }
    }
    runtime.candidates(candidates);
    selection.home()
}
