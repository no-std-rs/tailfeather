//! Peers, and the table that survives deltas.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::str::FromStr;

use crate::keys::{DiscoPublic, NodePublic};

use crate::netmap::{Error, MAX_ADDRESSES, MAX_ALLOWED_IPS, MAX_ENDPOINTS, MAX_PEERS};

/// An address with a prefix length, as the server writes them: `100.64.0.1/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let (address, prefix) = text.split_once('/').ok_or(Error::Malformed)?;
        let address = IpAddr::from_str(address).map_err(|_| Error::Malformed)?;
        let prefix: u8 = prefix.parse().map_err(|_| Error::Malformed)?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return Err(Error::Malformed);
        }
        Ok(Self { address, prefix })
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }
}

/// One node on the tailnet.
#[derive(Debug, Clone)]
pub struct Peer {
    /// The server's identifier, which is what deltas refer to. Stable across a
    /// node key rotation, unlike the key.
    pub id: u64,
    pub node_key: NodePublic,
    pub disco_key: Option<DiscoPublic>,
    pub online: bool,
    /// The DERP region this peer is reachable through when no direct path
    /// exists. Zero means none advertised.
    pub home_derp: u16,
    pub addresses: heapless::Vec<Cidr, MAX_ADDRESSES>,
    pub allowed_ips: heapless::Vec<Cidr, MAX_ALLOWED_IPS>,
    pub endpoints: heapless::Vec<SocketAddr, MAX_ENDPOINTS>,
}

impl Peer {
    pub fn new(id: u64, node_key: NodePublic) -> Self {
        Self {
            id,
            node_key,
            disco_key: None,
            online: false,
            home_derp: 0,
            addresses: heapless::Vec::new(),
            allowed_ips: heapless::Vec::new(),
            endpoints: heapless::Vec::new(),
        }
    }

    /// This peer's tailnet IPv4 address, which is what traffic to it is
    /// addressed to.
    pub fn tailscale_ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|cidr| match cidr.address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
    }

    /// The first endpoint that can be used directly.
    ///
    /// IPv4 only, because the data plane below is: `wirefeather` reads IPv4 headers
    /// and the harness binds `AF_INET` sockets. A peer reachable only over IPv6
    /// has no direct path as far as this node is concerned, and must be reached
    /// through DERP.
    pub fn direct_endpoint(&self) -> Option<core::net::SocketAddrV4> {
        self.endpoints.iter().find_map(|endpoint| match endpoint {
            SocketAddr::V4(address) => Some(*address),
            SocketAddr::V6(_) => None,
        })
    }
}

/// The peers a node knows about, updated in place by deltas.
///
/// Keyed by node id rather than by key: a peer that rotates its node key is the
/// same peer, and a table keyed by key would grow a duplicate every rotation.
#[derive(Clone)]
pub struct PeerTable<const N: usize = MAX_PEERS> {
    peers: heapless::Vec<Peer, N>,
}

impl<const N: usize> Default for PeerTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerTable<N> {
    pub const fn new() -> Self {
        Self {
            peers: heapless::Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }

    pub fn get(&self, id: u64) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.id == id)
    }

    pub fn by_node_key(&self, key: &NodePublic) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.node_key == key)
    }

    /// Insert or replace a peer.
    ///
    /// `PeersChanged` carries whole records, so an existing entry is replaced
    /// rather than merged — merging would keep endpoints the server has just
    /// told us are gone.
    pub fn upsert(&mut self, peer: Peer) -> Result<(), Error> {
        if let Some(existing) = self.get_mut(peer.id) {
            *existing = peer;
            return Ok(());
        }
        self.peers.push(peer).map_err(|_| Error::Full)
    }

    pub fn remove(&mut self, id: u64) -> bool {
        match self.peers.iter().position(|p| p.id == id) {
            Some(index) => {
                self.peers.swap_remove(index);
                true
            }
            None => false,
        }
    }

    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodePrivate;

    fn key(byte: u8) -> NodePublic {
        NodePrivate::from_bytes([byte; 32]).public()
    }

    #[test]
    fn parses_the_cidr_forms_the_server_sends() {
        let v4 = Cidr::parse("100.64.0.1/32").unwrap();
        assert!(v4.is_ipv4());
        assert_eq!(v4.prefix, 32);
        assert_eq!(v4.address, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));

        let v6 = Cidr::parse("fd7a:115c:a1e0::1/128").unwrap();
        assert!(!v6.is_ipv4());
        assert_eq!(v6.prefix, 128);

        // An exit node's advertisement.
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().prefix, 0);
    }

    #[test]
    fn rejects_addresses_that_are_not_addresses() {
        assert_eq!(Cidr::parse("100.64.0.1"), Err(Error::Malformed));
        assert_eq!(Cidr::parse("not-an-address/32"), Err(Error::Malformed));
        // A prefix wider than the family allows would silently match traffic it
        // should not.
        assert_eq!(Cidr::parse("100.64.0.1/33"), Err(Error::Malformed));
        assert!(Cidr::parse("fd7a::1/129").is_err());
    }

    #[test]
    fn a_peer_reports_its_tailnet_address_and_a_usable_endpoint() {
        let mut peer = Peer::new(1, key(1));
        peer.addresses
            .push(Cidr::parse("fd7a:115c:a1e0::1/128").unwrap())
            .unwrap();
        peer.addresses
            .push(Cidr::parse("100.64.0.1/32").unwrap())
            .unwrap();
        // The v4 address must be found even when it is not first.
        assert_eq!(peer.tailscale_ipv4(), Some(Ipv4Addr::new(100, 64, 0, 1)));

        peer.endpoints
            .push("[fd7a::1]:41641".parse().unwrap())
            .unwrap();
        assert_eq!(
            peer.direct_endpoint(),
            None,
            "an IPv6-only peer has no direct path for an IPv4 data plane"
        );
        peer.endpoints
            .push("192.168.6.167:37907".parse().unwrap())
            .unwrap();
        assert_eq!(peer.direct_endpoint().unwrap().port(), 37907);
    }

    #[test]
    fn upserting_replaces_rather_than_merges() {
        // `PeersChanged` carries whole records. Merging would keep endpoints the
        // server has just said are gone, and the node would keep trying them.
        let mut table = PeerTable::<4>::new();
        let mut first = Peer::new(1, key(1));
        first.endpoints.push("10.0.0.1:1".parse().unwrap()).unwrap();
        table.upsert(first).unwrap();

        let second = Peer::new(1, key(2));
        table.upsert(second).unwrap();

        assert_eq!(table.len(), 1, "the same id must not appear twice");
        assert!(table.get(1).unwrap().endpoints.is_empty());
        assert_eq!(table.get(1).unwrap().node_key, key(2));
    }

    #[test]
    fn a_peer_is_keyed_by_id_so_a_rotation_does_not_duplicate_it() {
        let mut table = PeerTable::<4>::new();
        table.upsert(Peer::new(7, key(1))).unwrap();
        table.upsert(Peer::new(7, key(9))).unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.by_node_key(&key(9)).is_some());
        assert!(table.by_node_key(&key(1)).is_none());
    }

    #[test]
    fn a_full_table_reports_rather_than_dropping_a_peer() {
        // A silently missing peer looks exactly like one that is offline, and
        // would be diagnosed as a network fault.
        let mut table = PeerTable::<2>::new();
        table.upsert(Peer::new(1, key(1))).unwrap();
        table.upsert(Peer::new(2, key(2))).unwrap();
        assert_eq!(table.upsert(Peer::new(3, key(3))), Err(Error::Full));
    }

    #[test]
    fn removing_reports_whether_anything_went() {
        let mut table = PeerTable::<4>::new();
        table.upsert(Peer::new(1, key(1))).unwrap();
        assert!(table.remove(1));
        assert!(!table.remove(1));
        assert!(table.is_empty());
    }
}
