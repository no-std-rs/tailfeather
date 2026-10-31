use super::*;
use core::fmt::Write as _;
use core::{future::Future, pin::Pin, task::Poll};
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
    working: &mut tailfeather::netmap::Netmap<PEERS>,
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
        match session(runtime, reactor, &authority, buffers, staging, working).await {
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

fn local_candidates<P: Network>(network: &P) -> Vec<SocketAddrV4, 8> {
    let Ok(endpoint) = network.local_endpoint() else {
        return Vec::new();
    };
    candidate_addresses(
        SocketAddrV4::new(
            network.interface_address().unwrap_or(*endpoint.ip()),
            endpoint.port(),
        ),
        |visit| network.visit_local_addresses(visit),
    )
}

fn candidate_addresses(
    fallback: SocketAddrV4,
    addresses: impl FnOnce(&mut dyn FnMut(Ipv4Addr)),
) -> Vec<SocketAddrV4, 8> {
    fn usable(address: Ipv4Addr) -> bool {
        !address.is_unspecified()
            && !address.is_loopback()
            && !address.is_multicast()
            && !address.is_broadcast()
            // Advertising the overlay itself cannot establish a UDP path.
            && (u32::from(address) & 0xffc0_0000) != 0x6440_0000
    }
    let keep_fallback = usable(*fallback.ip());
    // Keep half of the bounded advertisement for STUN-derived endpoints.
    let limit = 4 - usize::from(keep_fallback);
    let mut ips = Vec::<Ipv4Addr, 4>::new();
    addresses(&mut |address| {
        if !usable(address) || address == *fallback.ip() || ips.contains(&address) {
            return;
        }
        if ips.len() < limit {
            let _ = ips.push(address);
        } else if address < ips[limit - 1] {
            ips[limit - 1] = address;
        }
        ips.sort_unstable();
    });
    let mut candidates: Vec<SocketAddrV4, 8> = ips
        .into_iter()
        .map(|address| SocketAddrV4::new(address, fallback.port()))
        .collect();
    if keep_fallback || (candidates.is_empty() && fallback.ip().is_loopback()) {
        let _ = candidates.push(fallback);
    }
    candidates
}

/// Keep the complete HTTP operation alive even when discovery finishes during
/// a partial encrypted write. Only that operation can release its mutable
/// transport/staging borrows; discovery completion is retained for a boundary.
async fn drive_http<F: Future, D: Future>(
    operation: F,
    mut discovery: Pin<&mut D>,
    completed: &mut Option<D::Output>,
    discover: bool,
) -> F::Output {
    let mut operation = core::pin::pin!(operation);
    core::future::poll_fn(|cx| {
        if discover
            && completed.is_none()
            && let Poll::Ready(result) = discovery.as_mut().poll(cx)
        {
            *completed = Some(result);
        }
        operation.as_mut().poll(cx)
    })
    .await
}

fn validated_home<const PEERS: usize>(
    map: &tailfeather::netmap::Netmap<PEERS>,
    preferred: u16,
) -> u16 {
    if preferred != 0
        && map
            .derp
            .region(preferred)
            .is_some_and(|region| region.can_be_home())
    {
        preferred
    } else {
        tailfeather::stun::Selection::new(map).home()
    }
}

struct ClearProbe<'a>(&'a RefCell<Option<Probe>>);

impl Drop for ClearProbe<'_> {
    fn drop(&mut self) {
        self.0.borrow_mut().take();
    }
}

fn apply_map<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    staging: &mut tailfeather::netmap::Netmap<PEERS>,
    event: MapEvent,
) -> Result<(), Error> {
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
        runtime.publish_status(Status {
            address: Some(address),
            error: None,
        });
    }
    Ok(())
}

async fn session<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
    authority: &Authority,
    buffers: &mut LinkBuffers,
    staging: &mut tailfeather::netmap::Netmap<PEERS>,
    working: &mut tailfeather::netmap::Netmap<PEERS>,
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
        let candidates = if config.relay_only {
            Vec::new()
        } else {
            local_candidates(runtime.network)
        };
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
    // Keep the map in the session's persistent storage. Returning the complete
    // bounded map through start's future duplicates it in nested poll frames.
    let mut maps = MapStream::<PEERS>::new();
    reactor
        .timeout(
            30_000,
            MapStream::start_in(&mut maps, &mut http, &host, request),
        )
        .await
        .map_err(|_| "map start deadline")?
        .map_err(|_| "map start")?;
    let mut home = 0;
    let mut published_home = None;
    let mut published_generation = 0;
    let mut bootstrapped = false;
    loop {
        // One sweep remains pinned across both map reads and endpoint writes.
        // Its body is not polled until the initial map's fallback home/local
        // endpoints have been published successfully.
        let mut discovery = core::pin::pin!(async {
            let measured = discover_home(runtime, reactor).await;
            (measured, reactor.clock_millis())
        });
        let mut completed = None;
        loop {
            if !maps.has_pending_update() {
                runtime.node.borrow().seed_staging(staging);
            }
            let event = drive_http(
                reactor.timeout(90_000, maps.next(&mut http, staging, working)),
                discovery.as_mut(),
                &mut completed,
                bootstrapped,
            )
            .await
            .map_err(|_| "map timeout")?
            .map_err(map_error)?;
            apply_map(runtime, staging, event)?;
            if maps.has_pending_update() {
                // A queued keepalive can precede an already parsed Applied
                // event. Consume it before selecting/publishing from the old
                // active map, preserving the uncommitted staging lease.
                crate::exec::yield_now().await;
                continue;
            }
            if !bootstrapped && !matches!(event, MapEvent::Applied) {
                crate::exec::yield_now().await;
                continue;
            }

            loop {
                // A sweep can finish against a map that has since changed. Never
                // select a removed/ineligible home, including a stale fallback.
                let measured = completed.as_ref().map_or(home, |(measured, _)| *measured);
                home = validated_home(runtime.node.borrow().netmap(), measured);
                runtime
                    .node
                    .borrow_mut()
                    .prefer_derp(home)
                    .map_err(|_| "home relay")?;
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
                    let was_complete = completed.is_some();
                    drive_http(
                        reactor.timeout(
                            30_000,
                            transport::send_endpoint_update(
                                &mut http, &mut maps, staging, working, &host, request,
                            ),
                        ),
                        discovery.as_mut(),
                        &mut completed,
                        bootstrapped,
                    )
                    .await
                    .map_err(|_| "endpoint update deadline")?
                    .map_err(map_error)?;
                    // Discovery may have changed candidates while the old snapshot
                    // was being sent. Acknowledge only the generation actually sent.
                    published_home = Some(home);
                    published_generation = generation;
                    // The transport is free here. If discovery finished during this
                    // write, publish its now-known snapshot before parking another
                    // map read, unless the update already queued a newer map.
                    // Only one Pending -> Complete transition exists per sweep, so
                    // at most one additional publication is made at this boundary.
                    if !was_complete && completed.is_some() && !maps.has_pending_update() {
                        bootstrapped = true;
                        continue;
                    }
                }
                bootstrapped = true;
                break;
            }
            if completed
                .as_ref()
                .is_some_and(|(_, at)| reactor.clock_millis() >= at.saturating_add(30_000))
            {
                break;
            }
            // Completion during a quiet pending map read does not cancel that
            // read to publish new endpoints. Publication waits for an HTTP/map
            // boundary (or the existing deadline abandons the whole session).
            crate::exec::yield_now().await;
        }
    }
}

async fn discover_home<P: Network, S: State, const PEERS: usize, const A: usize>(
    runtime: &Runtime<'_, P, S, PEERS, A>,
    reactor: &Reactor<&P>,
) -> u16 {
    let _clear_probe = ClearProbe(&runtime.probe);
    let mut selection = tailfeather::stun::Selection::new(runtime.node.borrow().netmap());
    if runtime.config.relay_only {
        return selection.home();
    }
    let deadline = reactor.clock_millis().saturating_add(12_000);
    let mut candidates = local_candidates(runtime.network);
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::task::{Context, Waker};

    #[test]
    fn bootstrap_http_completes_before_discovery_is_polled() {
        let polls = Cell::new(0);
        let mut discovery = core::pin::pin!(core::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            Poll::Ready(17)
        }));
        let mut completed = None;
        let mut operation = core::pin::pin!(drive_http(
            async { "bootstrap published" },
            discovery.as_mut(),
            &mut completed,
            false,
        ));
        assert_eq!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready("bootstrap published")
        );
        assert_eq!(polls.get(), 0);
    }

    #[test]
    fn a_later_map_completes_while_the_same_discovery_remains_pending() {
        let probes = Cell::new(0);
        let finish = Cell::new(false);
        let mut discovery = core::pin::pin!(core::future::poll_fn(|_| {
            probes.set(probes.get() + 1);
            if finish.get() {
                Poll::Ready(17)
            } else {
                Poll::Pending
            }
        }));
        let mut completed = None;
        let mut context = Context::from_waker(Waker::noop());
        {
            let mut map = core::pin::pin!(drive_http(
                async { MapEvent::Applied },
                discovery.as_mut(),
                &mut completed,
                true,
            ));
            assert_eq!(
                map.as_mut().poll(&mut context),
                Poll::Ready(MapEvent::Applied)
            );
        }
        assert_eq!(probes.get(), 1);
        assert_eq!(completed, None);
        finish.set(true);
        {
            let mut next_map = core::pin::pin!(drive_http(
                async { MapEvent::KeepAlive },
                discovery.as_mut(),
                &mut completed,
                true,
            ));
            assert_eq!(
                next_map.as_mut().poll(&mut context),
                Poll::Ready(MapEvent::KeepAlive)
            );
        }
        assert_eq!(probes.get(), 2);
        assert_eq!(completed, Some(17));
        // Completed futures must never be polled again at later boundaries.
        let mut next_map = core::pin::pin!(drive_http(
            async { MapEvent::Applied },
            discovery.as_mut(),
            &mut completed,
            true,
        ));
        assert_eq!(
            next_map.as_mut().poll(&mut context),
            Poll::Ready(MapEvent::Applied)
        );
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn discovery_completion_does_not_cancel_a_partial_http_operation() {
        struct PartialWriter<'a> {
            allow_tail: &'a Cell<bool>,
            bytes: std::vec::Vec<u8>,
        }
        impl embedded_io_async::ErrorType for PartialWriter<'_> {
            type Error = core::convert::Infallible;
        }
        impl Write for PartialWriter<'_> {
            async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
                core::future::poll_fn(|_| {
                    if !self.bytes.is_empty() && !self.allow_tail.get() {
                        return Poll::Pending;
                    }
                    let amount = bytes.len().min(2);
                    self.bytes.extend_from_slice(&bytes[..amount]);
                    Poll::Ready(Ok(amount))
                })
                .await
            }
            async fn flush(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }
        }
        struct OperationGuard<'a> {
            finished: &'a Cell<bool>,
            abandoned: &'a Cell<bool>,
        }
        impl Drop for OperationGuard<'_> {
            fn drop(&mut self) {
                if !self.finished.get() {
                    self.abandoned.set(true);
                }
            }
        }
        let allow_tail = Cell::new(false);
        let discovery_ready = Cell::new(false);
        let discovery_polls = Cell::new(0);
        let finished = Cell::new(false);
        let abandoned = Cell::new(false);
        let starts = Cell::new(0);
        let mut writer = PartialWriter {
            allow_tail: &allow_tail,
            bytes: std::vec::Vec::new(),
        };
        let mut discovery = core::pin::pin!(core::future::poll_fn(|_| {
            discovery_polls.set(discovery_polls.get() + 1);
            if discovery_ready.get() {
                Poll::Ready(17)
            } else {
                Poll::Pending
            }
        }));
        let mut completed = None;
        let mut context = Context::from_waker(Waker::noop());
        {
            let operation = async {
                starts.set(starts.get() + 1);
                let _guard = OperationGuard {
                    finished: &finished,
                    abandoned: &abandoned,
                };
                writer.write_all(b"one encrypted record").await.unwrap();
                finished.set(true);
                MapEvent::Applied
            };
            let mut operation = core::pin::pin!(drive_http(
                operation,
                discovery.as_mut(),
                &mut completed,
                true
            ));
            assert_eq!(operation.as_mut().poll(&mut context), Poll::Pending);
            discovery_ready.set(true);
            assert_eq!(operation.as_mut().poll(&mut context), Poll::Pending);
            assert!(!abandoned.get());
            assert!(!finished.get());
            allow_tail.set(true);
            assert_eq!(
                operation.as_mut().poll(&mut context),
                Poll::Ready(MapEvent::Applied)
            );
        }
        assert!(!abandoned.get());
        assert_eq!(starts.get(), 1);
        assert_eq!(discovery_polls.get(), 2);
        assert_eq!(completed, Some(17));
        assert_eq!(writer.bytes, b"one encrypted record");
    }

    #[test]
    fn endpoint_ack_keeps_a_newly_discovered_generation_dirty() {
        let generation = Cell::new(0);
        let discovery_ready = Cell::new(false);
        let update_ready = Cell::new(false);
        let discovery_polls = Cell::new(0);
        let mut discovery = core::pin::pin!(core::future::poll_fn(|_| {
            discovery_polls.set(discovery_polls.get() + 1);
            if discovery_ready.get() {
                generation.set(1);
                Poll::Ready(23)
            } else {
                Poll::Pending
            }
        }));
        let sent_generation = generation.get();
        let mut completed = None;
        let mut context = Context::from_waker(Waker::noop());
        {
            let update = core::future::poll_fn(|_| {
                if update_ready.get() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            });
            let mut update =
                core::pin::pin!(drive_http(update, discovery.as_mut(), &mut completed, true));
            assert_eq!(update.as_mut().poll(&mut context), Poll::Pending);
            discovery_ready.set(true);
            assert_eq!(update.as_mut().poll(&mut context), Poll::Pending);
            update_ready.set(true);
            assert_eq!(update.as_mut().poll(&mut context), Poll::Ready(()));
        }
        assert_eq!(completed, Some(23));
        let acknowledged_generation = sent_generation;
        assert_ne!(acknowledged_generation, generation.get());
        // With no pending map operation, the retained completion can drive the
        // second endpoint request immediately, without repolling the sweep or
        // waiting for another map notification.
        {
            let mut update = core::pin::pin!(drive_http(
                async { generation.get() },
                discovery.as_mut(),
                &mut completed,
                true,
            ));
            assert_eq!(update.as_mut().poll(&mut context), Poll::Ready(1));
        }
        assert_eq!(discovery_polls.get(), 2);
    }

    #[test]
    fn a_result_from_an_old_map_cannot_restore_a_removed_or_ineligible_home() {
        use tailfeather::netmap::{DerpNode, DerpRegion, Netmap};
        let mut map = Netmap::<1>::new();
        let relay = DerpNode {
            host_name: String::try_from("relay.invalid").unwrap(),
            cert_name: None,
            port: 443,
            stun_port: 3478,
        };
        let mut region = DerpRegion {
            id: 23,
            code: String::new(),
            no_measure_no_home: false,
            nodes: Vec::new(),
        };
        region.nodes.push(relay).unwrap();
        map.derp.insert(region.clone()).unwrap();
        assert_eq!(validated_home(&map, 17), 23);
        assert_eq!(validated_home(&map, 0), 23);
        region.no_measure_no_home = true;
        map.derp.insert(region).unwrap();
        assert_eq!(validated_home(&map, 23), 0);
        map.derp.clear();
        assert_eq!(validated_home(&map, 17), 0);
    }

    #[test]
    fn abandoning_a_session_clears_its_pending_stun_probe() {
        let probe = RefCell::new(Some(Probe {
            transaction: [17; 12],
            server: "192.0.2.1:3478".parse().unwrap(),
            received: None,
        }));
        {
            let mut sweep = core::pin::pin!(async {
                let _clear = ClearProbe(&probe);
                core::future::pending::<()>().await;
            });
            assert_eq!(
                sweep.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            );
            assert!(probe.borrow().is_some());
        }
        assert!(probe.borrow().is_none());
    }

    #[test]
    fn local_interfaces_share_the_data_port_and_leave_room_for_stun() {
        let candidates = candidate_addresses("192.168.6.3:41641".parse().unwrap(), |visit| {
            for text in [
                "127.0.0.1",
                "0.0.0.0",
                "224.0.0.1",
                "255.255.255.255",
                "100.64.1.1",
                "192.168.6.3",
                "10.203.0.1",
                "10.203.0.1",
                "10.203.1.1",
                "10.88.0.1",
                "172.16.0.1",
            ] {
                visit(text.parse().unwrap());
            }
        });
        assert_eq!(
            candidates.as_slice(),
            &[
                "10.88.0.1:41641",
                "10.203.0.1:41641",
                "10.203.1.1:41641",
                "192.168.6.3:41641"
            ]
            .map(|text| text.parse().unwrap())
        );
    }

    #[test]
    fn a_lan_without_the_control_route_is_advertised_and_refreshes() {
        for address in ["10.203.0.2", "192.168.6.3"] {
            let candidates = candidate_addresses("127.0.0.1:1234".parse().unwrap(), |visit| {
                visit(address.parse().unwrap());
            });
            assert_eq!(
                candidates.as_slice(),
                &[SocketAddrV4::new(address.parse().unwrap(), 1234)]
            );
        }
    }

    #[test]
    fn single_interface_fallback_and_loopback_fixtures_remain_supported() {
        for fallback in ["192.168.6.3:41641", "127.0.0.1:41641"] {
            let fallback = fallback.parse().unwrap();
            assert_eq!(
                candidate_addresses(fallback, |_| {}).as_slice(),
                &[fallback]
            );
        }
        assert!(candidate_addresses("100.64.1.1:41641".parse().unwrap(), |_| {}).is_empty());
    }
}
