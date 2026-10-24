//! Host test of the browser data plane without a browser: two relay-only,
//! on-demand tailfeather nodes joined by an in-memory DERP relay, each with
//! the same smoltcp stack, routing, and cryptokey checks the page uses. A TCP
//! connection is opened from one to a listener on the other and carries data
//! both ways, starting from no WireGuard session at all.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use tailfeather::keys::{Identity, NodePublic, Rng};
use tailfeather::netmap::{Cidr, Cidr4, DerpNode, DerpRegion, Netmap, Peer};
use tailfeather::{ControlEvent, DerpCommand, DerpEvent, Node, NodeAction};

use crate::logic;
use crate::netstack::NetStack;

const REGION: u16 = 7;

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

impl Rng for Counter {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.fill(out);
    }
}

impl tailfeather::tunnel::Rng for Counter {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.fill(out);
    }
}

impl tailfeather::disco::packet::Rng for Counter {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.fill(out);
    }
}

struct Side {
    node: Box<Node<4>>,
    net: NetStack,
    key: NodePublic,
    tai64n: [u8; 12],
    derp_connected: bool,
}

/// A packet in flight through the relay: (destination, source, bytes).
type Relay = VecDeque<(NodePublic, NodePublic, Vec<u8>)>;

fn cidr4(text: &str) -> Cidr4 {
    Cidr4::from_cidr(Cidr::parse(text).unwrap()).unwrap()
}

fn netmap(own: &str, peer_key: NodePublic, peer_address: &str) -> Netmap<4> {
    let mut map = Netmap::new();
    map.addresses.push(Cidr::parse(own).unwrap()).unwrap();
    map.home_derp = REGION;
    let mut peer = Peer::new(1, peer_key);
    peer.home_derp = REGION;
    peer.addresses.push(cidr4(peer_address)).unwrap();
    peer.allowed_ips.push(cidr4(peer_address)).unwrap();
    // Advertised endpoints are ignored by a relay-only node.
    peer.endpoints
        .push("192.0.2.1:41641".parse().unwrap())
        .unwrap();
    map.peers.upsert(peer).unwrap();
    let mut nodes = heapless::Vec::new();
    nodes
        .push(DerpNode {
            host_name: heapless::String::try_from("derp.example").unwrap(),
            cert_name: None,
            port: 443,
            stun_port: 0,
        })
        .unwrap();
    map.derp
        .insert(DerpRegion {
            id: REGION,
            no_measure_no_home: false,
            code: heapless::String::try_from("tst").unwrap(),
            nodes,
        })
        .unwrap();
    map
}

impl Side {
    fn new(seed: u64, rng: &mut Counter) -> Self {
        let mut node = Box::new(Node::<4>::factory_reset(Identity::generate(rng), 1));
        let Some(NodeAction::PersistState(state)) = node.poll(0).unwrap() else {
            panic!("a new node persists first");
        };
        node.persistence_result(state.generation(), true).unwrap();
        node.set_direct_paths(false);
        node.set_initiate_on_demand(true);
        let key = node.identity().node.public();
        Self {
            node,
            net: NetStack::new(seed),
            key,
            tai64n: [0; 12],
            derp_connected: false,
        }
    }

    fn apply(&mut self, mut map: Netmap<4>, now: u64, seed: u64) {
        self.node
            .handle_control_event(ControlEvent::MapFinished {
                lease: &mut map,
                result: Ok(()),
            })
            .unwrap();
        let address = self
            .node
            .netmap()
            .addresses
            .iter()
            .find_map(|cidr| match cidr.address {
                std::net::IpAddr::V4(address) => Some(address),
                std::net::IpAddr::V6(_) => None,
            })
            .unwrap();
        self.net.set_address(address, now, seed);
    }

    fn dispatch(&mut self, action: NodeAction, relay: &mut Relay) {
        match action {
            NodeAction::DirectTransmit { .. } => panic!("a relay-only node transmitted directly"),
            NodeAction::Derp(DerpCommand::Connect { region, .. }) => {
                assert_eq!(region, REGION);
                self.derp_connected = true;
                // Connected immediately; the node may hand back a queued packet.
                let action = self
                    .node
                    .handle_derp_event(DerpEvent::Connected { region }, 0, &mut Counter(1))
                    .unwrap();
                if let Some(action) = action {
                    self.dispatch(action, relay);
                }
            }
            NodeAction::Derp(DerpCommand::Send { peer, packet, .. }) => {
                assert!(self.derp_connected, "sent before the region connected");
                relay.push_back((peer, self.key, packet.as_slice().to_vec()));
            }
            NodeAction::DeliveredIpv4 { peer, packet } => {
                let own = self.net.address().unwrap();
                assert!(logic::inbound_allowed(
                    packet.as_slice(),
                    &peer,
                    self.node.netmap().peers.iter(),
                    own
                ));
                if self
                    .node
                    .netmap()
                    .packet_filter
                    .allows_ipv4(packet.as_slice())
                    || logic::tcp_continuation(packet.as_slice())
                {
                    self.net.deliver(packet.as_slice());
                }
            }
            NodeAction::Derp(DerpCommand::Disconnect { .. })
            | NodeAction::Control(_)
            | NodeAction::PersistState(_)
            | NodeAction::StatusChanged(_) => {}
        }
    }

    /// One turn of the page's driver loop.
    fn pump(&mut self, now: u64, relay: &mut Relay) {
        for _ in 0..64 {
            let mut progressed = false;
            if let Ok(Some(action)) = self.node.poll_derp() {
                self.dispatch(action, relay);
                progressed = true;
            }
            let tai64n = logic::next_tai64n(&mut self.tai64n, now);
            if let Ok(Some(action)) = self.node.poll_tunnel(now, &tai64n, &mut Counter(now)) {
                self.dispatch(action, relay);
                progressed = true;
            }
            if let Ok(Some(action)) = self.node.poll_tunnel_timers(now) {
                self.dispatch(action, relay);
                progressed = true;
            }
            assert!(
                self.node
                    .poll_disco(now, &mut Counter(now))
                    .unwrap()
                    .is_none()
            );
            for packet in self.net.poll(now) {
                progressed = true;
                let (_, destination) = logic::ipv4_addresses(&packet).unwrap();
                let peer = logic::route_ipv4(self.node.netmap().peers.iter(), destination).unwrap();
                match self.node.encapsulate_ipv4(&peer, &packet, now) {
                    Ok(Some(action)) => self.dispatch(action, relay),
                    Ok(None) => {}
                    // The on-demand handshake starts; TCP retransmits.
                    Err(tailfeather::NodeError::Tunnel(tailfeather::tunnel::Error::NoSession)) => {}
                    Err(error) => panic!("encapsulate: {error}"),
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn receive(&mut self, from: NodePublic, packet: &[u8], now: u64, relay: &mut Relay) {
        let action = self
            .node
            .handle_derp_event(
                DerpEvent::Packet {
                    region: REGION,
                    peer: from,
                    payload: packet,
                },
                now,
                &mut Counter(now ^ 0x55),
            )
            .unwrap();
        if let Some(action) = action {
            self.dispatch(action, relay);
        }
    }
}

#[test]
fn tcp_crosses_relay_only_wireguard_from_a_cold_start() {
    crate::on_worker_stack(tcp_crosses_relay_only_wireguard_from_a_cold_start_on_worker);
}
fn tcp_crosses_relay_only_wireguard_from_a_cold_start_on_worker() {
    let mut rng = Counter(42);
    let mut browser = Side::new(1, &mut rng);
    let mut server = Side::new(2, &mut rng);
    let mut client_map = netmap("100.64.0.1/32", server.key, "100.64.0.2/32");
    let mut server_map = netmap("100.64.0.2/32", browser.key, "100.64.0.1/32");
    tailfeather::netmap::Parser::new()
        .push(&mut client_map, br#"{"PacketFilter":[]}"#)
        .unwrap();
    tailfeather::netmap::Parser::new().push(&mut server_map, br#"{"PacketFilter":[{"SrcIPs":["100.64.0.1"],"DstPorts":[{"IP":"100.64.0.2","Ports":{"First":22,"Last":22}}]}]}"#).unwrap();
    browser.apply(client_map, 0, 11);
    server.apply(server_map, 0, 12);

    let listener = server.net.listen(22).unwrap();
    let client = browser
        .net
        .connect(Ipv4Addr::new(100, 64, 0, 2), 22, 50_000)
        .unwrap();

    let mut relay = Relay::new();
    let mut sent = false;
    let mut echoed = false;
    let mut received = Vec::new();
    let mut now = 1_000;
    while now < 30_000 && received != b"HELLO" {
        browser.pump(now, &mut relay);
        server.pump(now, &mut relay);
        while let Some((to, from, packet)) = relay.pop_front() {
            if to == server.key {
                server.receive(from, &packet, now, &mut relay);
            } else {
                assert_eq!(to, browser.key);
                browser.receive(from, &packet, now, &mut relay);
            }
        }
        {
            let socket = browser.net.tcp(client).unwrap();
            if !sent && socket.may_send() {
                socket.send_slice(b"hello").unwrap();
                sent = true;
            }
            if socket.can_recv() {
                let mut buffer = [0u8; 16];
                let len = socket.recv_slice(&mut buffer).unwrap();
                received.extend_from_slice(&buffer[..len]);
            }
        }
        {
            let socket = server.net.tcp(listener).unwrap();
            if !echoed && socket.can_recv() {
                let mut buffer = [0u8; 16];
                let len = socket.recv_slice(&mut buffer).unwrap();
                assert_eq!(&buffer[..len], b"hello");
                socket.send_slice(b"HELLO").unwrap();
                echoed = true;
            }
        }
        now += 10;
    }
    assert_eq!(received, b"HELLO", "no round trip by t={now}ms");
    // The first SYN was refused for want of a session; the handshake and the
    // retransmitted SYN follow within a couple of TCP retransmission timeouts.
    assert!(now < 5_000, "round trip took until t={now}ms");
}
