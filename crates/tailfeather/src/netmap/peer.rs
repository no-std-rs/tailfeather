//! Peers, and the table that survives deltas.

use core::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use core::str::FromStr;

use crate::keys::{DiscoPublic, NodePublic};

use crate::netmap::{
    CapacityError, Error, MAX_ADDRESSES, MAX_ALLOWED_IPS, MAX_ENDPOINTS, MAX_PEERS,
};

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

/// A peer's subnet, stored IPv4-only.
///
/// Peers are the one part of the staged map that scales with the tailnet, and
/// the staged map lives in the C6's 16 KiB RTC-fast bank, which is silicon and
/// cannot be grown. A [`Cidr`] spends 24 bytes to hold an address family this
/// device's data plane does not have: `wirefeather` reads IPv4 headers, the
/// harness binds `AF_INET`, and [`Peer::endpoints`] is already `SocketAddrV4`
/// for exactly that reason. Eight bytes here instead saves 192 bytes per peer
/// across [`MAX_ADDRESSES`] and [`MAX_ALLOWED_IPS`] — the difference between a
/// 3-peer and a 9-peer table, which is the difference between reaching the
/// device from your laptop and not.
///
/// Self addresses and routes keep the full [`Cidr`]: `default_routes_approved`
/// must still see the `::/0` the control plane sends, and there is one such
/// record rather than one per peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr4 {
    pub address: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr4 {
    /// The IPv4 half of a parsed CIDR. `None` for IPv6, which this node cannot
    /// route and therefore does not retain.
    pub fn from_cidr(cidr: Cidr) -> Option<Self> {
        match cidr.address {
            IpAddr::V4(address) => Some(Self {
                address,
                prefix: cidr.prefix,
            }),
            IpAddr::V6(_) => None,
        }
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
    /// Bit zero is online; bit one retains delayed-self IPv4 approval.
    state_flags: u8,
    /// IPv6 default-route approval retained until a delayed self record is
    /// distinguished from an ordinary peer. IPv4 fits in allowed-IP storage.
    pub(crate) approved_ipv6_default: bool,
    /// The DERP region this peer is reachable through when no direct path
    /// exists. Zero means none advertised.
    pub home_derp: u16,
    pub addresses: heapless::Vec<Cidr4, MAX_ADDRESSES>,
    pub allowed_ips: heapless::Vec<Cidr4, MAX_ALLOWED_IPS>,
    /// Usable direct paths for this IPv4-only node. IPv6 endpoints from a map
    /// are valid but intentionally not retained, just as IPv6 payloads are
    /// counted and rejected by the data plane.
    pub endpoints: heapless::Vec<SocketAddrV4, MAX_ENDPOINTS>,
    /// What to call this peer on a screen: the first label of its MagicDNS
    /// name, or its self-reported host name when it has none. Empty when the
    /// map named neither. Display only; never used to route or authorize.
    #[cfg(feature = "peer-names")]
    pub name: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
}

impl Peer {
    pub fn new(id: u64, node_key: NodePublic) -> Self {
        Self {
            id,
            node_key,
            disco_key: None,
            state_flags: 0,
            approved_ipv6_default: false,
            home_derp: 0,
            addresses: heapless::Vec::new(),
            allowed_ips: heapless::Vec::new(),
            endpoints: heapless::Vec::new(),
            #[cfg(feature = "peer-names")]
            name: heapless::String::new(),
        }
    }

    pub fn online(&self) -> bool {
        self.state_flags & 1 != 0
    }

    pub(crate) fn set_online(&mut self, online: bool) {
        self.state_flags = (self.state_flags & !1) | u8::from(online);
    }

    pub(crate) fn set_approved_ipv4_default(&mut self, approved: bool) {
        self.state_flags = (self.state_flags & !2) | (u8::from(approved) << 1);
    }

    pub(crate) fn approved_ipv4_default(&self) -> bool {
        self.state_flags & 2 != 0
    }

    /// This peer's tailnet IPv4 address, which is what traffic to it is
    /// addressed to.
    pub fn tailscale_ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.first().map(|cidr| cidr.address)
    }

    /// The first endpoint that can be used directly.
    ///
    /// IPv4 only, because the data plane below is: `wirefeather` reads IPv4 headers
    /// and the harness binds `AF_INET` sockets. A peer reachable only over IPv6
    /// has no direct path as far as this node is concerned, and must be reached
    /// through DERP.
    pub fn direct_endpoint(&self) -> Option<core::net::SocketAddrV4> {
        self.endpoints.first().copied()
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

    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.peers.clear();
        for peer in source.iter() {
            self.peers
                .push(peer.clone())
                .expect("equal peer capacities");
        }
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
        self.peers
            .push(peer)
            .map_err(|_| Error::Full(CapacityError::Peers))
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
        // A peer's IPv6 subnet is not representable: it is dropped as the map
        // is parsed, because this node has no way to route it.
        assert_eq!(
            Cidr4::from_cidr(Cidr::parse("fd7a:115c:a1e0::1/128").unwrap()),
            None
        );
        peer.addresses
            .push(Cidr4::from_cidr(Cidr::parse("100.64.0.1/32").unwrap()).unwrap())
            .unwrap();
        assert_eq!(peer.tailscale_ipv4(), Some(Ipv4Addr::new(100, 64, 0, 1)));

        // The parser discards IPv6 endpoints before constructing a Peer.
        assert_eq!(peer.direct_endpoint(), None);
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
        assert_eq!(
            table.upsert(Peer::new(3, key(3))),
            Err(Error::Full(CapacityError::Peers))
        );
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
