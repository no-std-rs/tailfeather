//! Full shared runtime over bounded in-memory datagram rings. The trusted map,
//! deterministic RNG and volatile state are fixtures, never production adapters.
use super::*;
use core::net::{Ipv4Addr, SocketAddrV4};
use tailfeather::{
    ControlEvent, Node, NodeAction,
    control::authority::Authority,
    keys::Identity,
    netmap::{Cidr, Cidr4, Netmap, Peer},
};
use tailfeather_reactor::runtime::{Buffers, Config, Error, LinkBuffers, Network, Runtime, State};

struct Counter(u64);
impl Counter {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (self.0 >> 33) as u8;
        }
    }
}
macro_rules! rng {
    ($trait:path) => {
        impl $trait for Counter {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                self.fill(out);
            }
        }
    };
}
rng!(tailfeather::keys::Rng);
rng!(tailfeather::tunnel::Rng);
rng!(tailfeather::disco::packet::Rng);
rng!(tailfeather::derp::client::Rng);

struct PendingStream;
impl embedded_io_async::ErrorType for PendingStream {
    type Error = core::convert::Infallible;
}
impl Read for PendingStream {
    async fn read(&mut self, _: &mut [u8]) -> Result<usize, Self::Error> {
        core::future::pending().await
    }
}
impl Write for PendingStream {
    async fn write(&mut self, _: &[u8]) -> Result<usize, Self::Error> {
        core::future::pending().await
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

type Ring = Channel<NoopRawMutex, (Datagram, SocketAddrV4), 128>;
struct MemoryNetwork<'a, C> {
    clock: &'a C,
    endpoint: SocketAddrV4,
    incoming: &'a Ring,
    outgoing: &'a Ring,
    seed: Cell<u64>,
    packets: Cell<u64>,
    packet_bytes: Cell<u64>,
}
impl<C: Clock> Clock for MemoryNetwork<'_, C> {
    fn now_millis(&self) -> u64 {
        self.clock.now_millis()
    }
    async fn sleep_until(&self, deadline: u64) {
        self.clock.sleep_until(deadline).await;
    }
}
impl<C: Clock> Network for MemoryNetwork<'_, C> {
    type Stream<'a>
        = PendingStream
    where
        Self: 'a;
    type Rng = Counter;
    fn rng(&self) -> Counter {
        self.seed.set(self.seed.get().wrapping_add(1));
        Counter(self.seed.get())
    }
    fn unix_millis(&self) -> Result<u64, Error> {
        Ok(1_700_000_000_000 + self.now_millis())
    }
    fn local_endpoint(&self) -> Result<SocketAddrV4, Error> {
        Ok(self.endpoint)
    }
    fn interface_address(&self) -> Option<Ipv4Addr> {
        Some(*self.endpoint.ip())
    }
    fn validate_ca(&self, ca: &[u8]) -> Result<(), Error> {
        assert!(ca.is_empty());
        Ok(())
    }
    async fn resolve(&self, _: &str) -> Result<heapless::Vec<Ipv4Addr, 16>, Error> {
        Ok(heapless::Vec::new())
    }
    async fn connect<'a>(
        &'a self,
        _: &str,
        _: u16,
        _: &str,
        _: &[u8],
        _: &'a mut LinkBuffers,
    ) -> Result<PendingStream, Error> {
        core::future::pending().await
    }
    async fn receive(&self, output: &mut [u8]) -> Result<(usize, SocketAddrV4), Error> {
        let (packet, from) = self.incoming.receive().await;
        output[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), from))
    }
    async fn send(&self, packet: &[u8], _: SocketAddrV4) -> Result<(), Error> {
        let packet = Datagram::from_slice(packet).unwrap();
        self.packets.set(self.packets.get() + 1);
        self.packet_bytes
            .set(self.packet_bytes.get() + packet.len() as u64);
        self.outgoing.send((packet, self.endpoint)).await;
        Ok(())
    }
}
struct VolatileState;
impl State for VolatileState {
    fn load(&self, _: &mut [u8]) -> Result<Option<usize>, Error> {
        Ok(None)
    }
    fn save(&self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn load_timestamp(&self, _: &mut [u8; 12]) -> Result<bool, Error> {
        Ok(false)
    }
    fn save_timestamp(&self, _: &[u8; 12]) -> Result<(), Error> {
        Ok(())
    }
}
fn config() -> Config<'static> {
    Config {
        control_url: "https://benchmark.invalid",
        hostname: "benchmark",
        auth_key: "",
        control_ca_der: &[],
        relay_only: false,
        ephemeral: true,
        os: "fixture",
    }
}
fn map(own: &str, other: &Node<2>, address: &str, endpoint: SocketAddrV4) -> Netmap<2> {
    let mut map = Netmap::new();
    map.addresses.push(Cidr::parse(own).unwrap()).unwrap();
    let mut rule = tailfeather::netmap::policy::FilterRule::new();
    rule.sources
        .push(tailfeather::netmap::policy::Network::parse(address).unwrap())
        .unwrap();
    rule.destinations
        .push(tailfeather::netmap::policy::Destination {
            network: tailfeather::netmap::policy::Network::parse(own).unwrap(),
            first_port: 2222,
            last_port: 2222,
        })
        .unwrap();
    rule.protocols.push(6).unwrap();
    map.packet_filter.replace_set("benchmark").unwrap();
    map.packet_filter.push_rule("benchmark", rule).unwrap();
    let mut peer = Peer::new(1, other.identity().node.public());
    peer.disco_key = Some(other.identity().disco.public());
    let cidr = Cidr4::from_cidr(Cidr::parse(address).unwrap()).unwrap();
    peer.addresses.push(cidr).unwrap();
    peer.allowed_ips.push(cidr).unwrap();
    peer.endpoints.push(endpoint).unwrap();
    map.peers.upsert(peer).unwrap();
    map
}
pub(super) async fn measure<'a, C: Clock, B: PacketQueue<64>>(
    clock: C,
    local: NetStack<'a, 8, 64, B>,
    remote: NetStack<'a, 8, 64, B>,
    bytes: usize,
) -> (f64, u64, u64) {
    let reactor = Reactor::with_clock(&clock);
    let local = Tcp::new(local);
    let remote = Tcp::new(remote);
    let a = Ring::new();
    let b = Ring::new();
    let make = |endpoint, incoming, outgoing, seed| MemoryNetwork {
        clock: &clock,
        endpoint,
        incoming,
        outgoing,
        seed: Cell::new(seed),
        packets: Cell::new(0),
        packet_bytes: Cell::new(0),
    };
    let net_a = make("192.0.2.1:51820".parse().unwrap(), &a, &b, 1);
    let net_b = make("192.0.2.2:51820".parse().unwrap(), &b, &a, 1000);
    let authority = Authority::parse(config().control_url, false)
        .unwrap()
        .digest();
    let mut node_a = Box::new(Node::<2>::factory_reset_for_authority(
        Identity::generate(&mut Counter(1)),
        1,
        authority,
    ));
    let mut node_b = Box::new(Node::<2>::factory_reset_for_authority(
        Identity::generate(&mut Counter(2)),
        1,
        authority,
    ));
    let mut map_a = map("100.64.0.1/32", &node_b, "100.64.0.2/32", net_b.endpoint);
    let mut map_b = map("100.64.0.2/32", &node_a, "100.64.0.1/32", net_a.endpoint);
    for (node, map) in [(&mut *node_a, &mut map_a), (&mut *node_b, &mut map_b)] {
        node.set_initiate_on_demand(true);
        let Some(NodeAction::PersistState(saved)) = node.poll(0).unwrap() else {
            panic!("initial persistence");
        };
        node.persistence_result(saved.generation(), true).unwrap();
        node.handle_control_event(ControlEvent::MapFinished {
            lease: map,
            result: Ok(()),
        })
        .unwrap();
    }
    let runtime_a =
        Runtime::<_, _, 2, 16>::new(config(), &mut node_a, &net_a, &VolatileState).unwrap();
    let runtime_b =
        Runtime::<_, _, 2, 16>::new(config(), &mut node_b, &net_b, &VolatileState).unwrap();
    let mut buffers_a = Buffers::new();
    let mut buffers_b = Buffers::new();
    let traffic = async {
        runtime_a.ready().await.unwrap();
        runtime_b.ready().await.unwrap();
        local.set_address("100.64.0.1".parse().unwrap(), clock.now_millis(), 1);
        remote.set_address("100.64.0.2".parse().unwrap(), clock.now_millis(), 2);
        let seconds = super::transfer(&reactor, &local, &remote, bytes, || {
            net_a.packets.set(0);
            net_b.packets.set(0);
            net_a.packet_bytes.set(0);
            net_b.packet_bytes.set(0);
        })
        .await;
        (
            seconds,
            net_a.packets.get() + net_b.packets.get(),
            net_a.packet_bytes.get() + net_b.packet_bytes.get(),
        )
    };
    tokio::select! {
        result = traffic => result,
        result = runtime_a.run(&local, &mut buffers_a) => panic!("runtime A: {result:?}"),
        result = runtime_b.run(&remote, &mut buffers_b) => panic!("runtime B: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => panic!("mesh deadline"),
    }
}
