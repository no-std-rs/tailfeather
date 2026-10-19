//! Turning a stream of JSON tokens into netmap updates.
//!
//! # How it knows where it is
//!
//! A SAX parser reports tokens with no context, so the meaning of a string
//! depends entirely on where it appeared. Rather than track a general JSON path
//! — which would need an unbounded key stack — this keeps a stack of *contexts*:
//! a small enum saying what the container currently being read is, computed from
//! the container it is nested in and the key that opened it.
//!
//! That makes the unknown case trivial and total. Anything not recognised
//! becomes `Context::Ignored`, and every container inside it is ignored too,
//! so whole subtrees — `Hostinfo`, `UserProfiles`, and `DNSConfig`'s
//! sixty-five-entry `Routes` map — are skipped for the cost of a push and a
//! pop. A server that adds a field costs nothing, which matters for a protocol
//! that gains them regularly.
//!
//! # What a delta means
//!
//! `PeersChanged` and `Peers` are read identically — both are whole records —
//! but `PeersChangedPatch` is not: it names an existing peer and a few fields,
//! and everything it does not mention must be left alone. Applying a patch as if
//! it were a record would blank every peer's endpoints on every heartbeat.

use crate::keys::{DiscoPublic, NodePublic};

use crate::netmap::derp::{DEFAULT_DERP_PORT, DEFAULT_STUN_PORT, DerpMap, DerpNode, DerpRegion};
use crate::netmap::dns::DnsConfig;
use crate::netmap::peer::{Cidr, Cidr4, Peer, PeerTable};
use crate::netmap::policy::{Destination, FilterRule, Network};
use crate::netmap::scanner::{Scanner, Token};
use crate::netmap::{CapacityError, Error, MAX_PEERS, MalformedField};

/// Where in the document the parser currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// The outermost object of one MapResponse.
    Root,
    /// `Node`: this node's own record.
    SelfNode,
    /// The array of `Peers` or `PeersChanged`; both carry whole records.
    /// A full `Peers` snapshot replaces the prior peer table.
    PeerArray,
    /// `PeersChanged` merges whole records into the prior peer table.
    PeerChangedArray,
    PeerObject,
    /// An array of strings inside a peer: `Addresses`, `AllowedIPs`,
    /// `Endpoints`.
    PeerAddresses,
    PeerAllowedIps,
    PeerPrimaryRoutes,
    PeerEndpoints,
    /// A peer's `Hostinfo`, read only for its `Hostname`.
    #[cfg(feature = "peer-names")]
    PeerHostinfo,
    /// The self node's address arrays.
    SelfAddresses,
    SelfPrimaryRoutes,
    /// `PeersChangedPatch`: named fields of peers that already exist.
    PatchArray,
    PatchObject,
    PatchEndpoints,
    /// `PeersRemoved`: node ids to forget.
    RemovedArray,
    DerpMapObject,
    DerpRegions,
    DerpRegion,
    DerpNodes,
    DerpNode,
    /// `DNSConfig`. Its `Routes` map is deliberately not a context of its own:
    /// it has one member per claimed reverse zone and no bound at all, so it
    /// falls through to `Ignored` and costs a push and a pop.
    DnsConfigObject,
    DnsDomains,
    DnsResolvers,
    DnsResolverObject,
    /// Legacy singular policy and incremental named policy updates.
    PacketFilterArray,
    PacketFiltersObject,
    FilterSetArray,
    FilterRuleObject,
    FilterSources,
    FilterDestinations,
    FilterDestinationObject,
    FilterPortsObject,
    FilterProtocols,
    /// Anything this parser does not read. Nested containers inherit it, so a
    /// whole subtree costs one push and one pop.
    Ignored,
}

/// The state a netmap is accumulated into.
#[derive(Default, Clone)]
pub struct Netmap<const PEERS: usize = MAX_PEERS> {
    pub peers: PeerTable<PEERS>,
    /// The control map named more peers than this target retains.
    ///
    /// Selection is deterministic: a full snapshot keeps the first `PEERS`
    /// non-self records in server order. This lets memory-constrained targets
    /// remain connected to control instead of rejecting the entire map.
    pub peers_truncated: bool,
    pub derp: DerpMap,
    /// The tailnet's DNS configuration, minus the unbounded `Routes` map.
    pub dns: DnsConfig,
    /// This node's own record, once the server has sent one.
    pub node_key: Option<NodePublic>,
    pub disco_key: Option<DiscoPublic>,
    pub addresses: heapless::Vec<Cidr, { crate::netmap::MAX_ADDRESSES }>,
    /// Routes this control plane has approved for this node.
    pub primary_routes: heapless::Vec<Cidr, { crate::netmap::MAX_PRIMARY_ROUTES }>,
    /// Preferred relay for this node.
    pub home_derp: u16,
    /// Staged packet-filter policy. No packet is forwarded until at least one
    /// syntactically valid policy update has been received.
    pub packet_filter: crate::netmap::PacketPolicy,
    /// Bounded SSH authorization, separate from the network packet filter.
    #[cfg(feature = "ssh-policy")]
    pub ssh_policy: crate::netmap::ssh::Policy,
    /// How many complete MapResponses have been applied.
    pub responses: usize,
    /// This node's display name: the first label of its MagicDNS name.
    #[cfg(feature = "peer-names")]
    pub name: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
}

impl<const PEERS: usize> Netmap<PEERS> {
    pub const fn new() -> Self {
        Self {
            peers: PeerTable::new(),
            peers_truncated: false,
            derp: DerpMap::new(),
            dns: DnsConfig::new(),
            node_key: None,
            disco_key: None,
            addresses: heapless::Vec::new(),
            primary_routes: heapless::Vec::new(),
            home_derp: 0,
            packet_filter: crate::netmap::PacketPolicy::new(),
            #[cfg(feature = "ssh-policy")]
            ssh_policy: crate::netmap::ssh::Policy::new(),
            responses: 0,
            #[cfg(feature = "peer-names")]
            name: heapless::String::new(),
        }
    }

    /// Copy a complete map without materializing another map-sized temporary
    /// on the caller's stack. This is used to reseed the one streaming-delta
    /// lease after swapping it into the active node.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.peers.copy_from(&source.peers);
        self.peers_truncated = source.peers_truncated;
        self.derp.copy_from(&source.derp);
        self.dns.copy_from(&source.dns);
        self.node_key = source.node_key;
        self.disco_key = source.disco_key;
        self.addresses.clear();
        for address in &source.addresses {
            self.addresses
                .push(*address)
                .expect("equal address capacities");
        }
        self.primary_routes.clear();
        for route in &source.primary_routes {
            self.primary_routes
                .push(*route)
                .expect("equal route capacities");
        }
        self.home_derp = source.home_derp;
        self.packet_filter.copy_from(&source.packet_filter);
        #[cfg(feature = "ssh-policy")]
        self.ssh_policy.clone_from(&source.ssh_policy);
        self.responses = source.responses;
        #[cfg(feature = "peer-names")]
        {
            self.name = source.name.clone();
        }
    }

    pub fn has_assigned_ipv4(&self) -> bool {
        self.addresses
            .iter()
            .any(|route| matches!(route.address, core::net::IpAddr::V4(_)))
    }

    pub fn default_routes_approved(&self) -> bool {
        let mut ipv4 = false;
        let mut ipv6 = false;
        for route in &self.primary_routes {
            match route.address {
                core::net::IpAddr::V4(address) if address.is_unspecified() && route.prefix == 0 => {
                    ipv4 = true;
                }
                core::net::IpAddr::V6(address) if address.is_unspecified() && route.prefix == 0 => {
                    ipv6 = true;
                }
                _ => {}
            }
        }
        ipv4 && ipv6
    }
}

/// A peer being built, or a patch being collected.
#[derive(Default)]
struct Pending {
    id: u64,
    node_key: Option<NodePublic>,
    disco_key: Option<DiscoPublic>,
    online: Option<bool>,
    #[cfg(feature = "ssh-policy")]
    expired: Option<bool>,
    #[cfg(feature = "ssh-policy")]
    key_expiry_restricted: Option<bool>,
    home_derp: Option<u16>,
    addresses: heapless::Vec<Cidr4, { crate::netmap::MAX_ADDRESSES }>,
    allowed_ips: heapless::Vec<Cidr4, { crate::netmap::MAX_ALLOWED_IPS }>,
    approved_ipv4_default: bool,
    approved_ipv6_default: bool,
    endpoints: heapless::Vec<core::net::SocketAddrV4, { crate::netmap::MAX_ENDPOINTS }>,
    /// Set when a patch mentioned `Endpoints`, so an empty list can be told
    /// apart from an absent one.
    endpoints_present: bool,
    #[cfg(feature = "peer-names")]
    name: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
    #[cfg(feature = "peer-names")]
    hostname: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
}

impl Pending {
    const fn new() -> Self {
        Self {
            id: 0,
            node_key: None,
            disco_key: None,
            online: None,
            #[cfg(feature = "ssh-policy")]
            expired: None,
            #[cfg(feature = "ssh-policy")]
            key_expiry_restricted: None,
            home_derp: None,
            addresses: heapless::Vec::new(),
            allowed_ips: heapless::Vec::new(),
            approved_ipv4_default: false,
            approved_ipv6_default: false,
            endpoints: heapless::Vec::new(),
            endpoints_present: false,
            #[cfg(feature = "peer-names")]
            name: heapless::String::new(),
            #[cfg(feature = "peer-names")]
            hostname: heapless::String::new(),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// A DERP region being built.
#[derive(Default)]
struct PendingRegion {
    id: u16,
    code: heapless::String<16>,
    nodes: heapless::Vec<DerpNode, { crate::netmap::MAX_DERP_NODES }>,
    stun_fallback: Option<DerpNode>,
    node_host: heapless::String<{ crate::netmap::MAX_DERP_HOSTNAME }>,
    node_cert: heapless::String<{ crate::netmap::MAX_DERP_HOSTNAME }>,
    node_port: u16,
    node_stun: u16,
    /// Bit zero is STUNOnly; bit one is InsecureForTests.
    node_flags: u8,
}

struct PendingFilter {
    set: heapless::String<{ crate::netmap::policy::MAX_FILTER_SET_NAME }>,
    rule: FilterRule,
    destination_network: Option<Network>,
    first_port: Option<u16>,
    last_port: Option<u16>,
}

impl PendingFilter {
    const fn new() -> Self {
        Self {
            set: heapless::String::new(),
            rule: FilterRule::new(),
            destination_network: None,
            first_port: None,
            last_port: None,
        }
    }

    fn reset_rule(&mut self) {
        self.rule = FilterRule::new();
    }

    fn reset_destination(&mut self) {
        self.destination_network = None;
        self.first_port = None;
        self.last_port = None;
    }
}

impl Default for PendingFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRegion {
    const fn new() -> Self {
        Self {
            id: 0,
            code: heapless::String::new(),
            nodes: heapless::Vec::new(),
            stun_fallback: None,
            node_host: heapless::String::new(),
            node_cert: heapless::String::new(),
            node_port: 0,
            node_stun: 0,
            node_flags: 0,
        }
    }
}

/// The parser's own state: where it is in the document and what it is building.
/// The netmap is passed in per call rather than borrowed for the parser's life,
/// so a caller can read it between chunks — which is the whole point of
/// streaming.
#[derive(Default)]
struct State {
    stack: heapless::Vec<Context, 16>,
    /// The key most recently seen, which names whatever comes next.
    key: heapless::String<64>,
    /// The current member name exceeded the bounded key buffer. Unknown
    /// members can still be skipped without making a forward-compatible map
    /// fatal; dynamic namespaces reject these names explicitly.
    key_oversized: bool,
    /// `AllowedIPs` and `PrimaryRoutes` both contribute approved self routes.
    /// Clear the prior response only once so JSON field order cannot decide
    /// which of the two arrays survives.
    self_routes_seen: bool,
    /// The self record in progress named its home region numerically, which
    /// outranks the legacy `DERP` string whatever the member order.
    self_numeric_derp: bool,
    pending: Pending,
    /// The first peer that overflowed before a snapshot identified its self
    /// key. It can fill the slot released when that delayed self record is
    /// removed.
    deferred_peer: Option<Peer>,
    region: PendingRegion,
    filter: PendingFilter,
    #[cfg(feature = "ssh-policy")]
    ssh: crate::netmap::ssh::Builder,
    /// The first error, kept so parsing stops reporting the same thing.
    failed: Option<Error>,
}

impl State {
    fn context(&self) -> Context {
        self.stack.last().copied().unwrap_or(Context::Ignored)
    }

    fn fail(&mut self, error: Error) {
        self.failed.get_or_insert(error);
    }

    /// What a container opened by the current key, inside the current context,
    /// should be read as.
    fn child_context(&self) -> Context {
        if self.key_oversized {
            return Context::Ignored;
        }
        let key = self.key.as_str();
        match self.context() {
            // The outermost object of a response has no enclosing container.
            Context::Ignored if self.stack.is_empty() => Context::Root,
            Context::Root => match key {
                "Node" => Context::SelfNode,
                "Peers" => Context::PeerArray,
                "PeersChanged" => Context::PeerChangedArray,
                "PeersChangedPatch" => Context::PatchArray,
                "PeersRemoved" => Context::RemovedArray,
                "DERPMap" => Context::DerpMapObject,
                "DNSConfig" => Context::DnsConfigObject,
                "PacketFilter" => Context::PacketFilterArray,
                "PacketFilters" => Context::PacketFiltersObject,
                _ => Context::Ignored,
            },
            Context::SelfNode => match key {
                "Addresses" => Context::SelfAddresses,
                // Hosted control places approved exit defaults in AllowedIPs;
                // PrimaryRoutes is the HA-primary subnet-router subset. Treat
                // either as approved self routes, and default-route readiness
                // below still requires both exact /0 entries.
                "AllowedIPs" | "PrimaryRoutes" => Context::SelfPrimaryRoutes,
                _ => Context::Ignored,
            },
            Context::PeerArray | Context::PeerChangedArray => Context::PeerObject,
            Context::PeerObject => match key {
                "Addresses" => Context::PeerAddresses,
                "AllowedIPs" => Context::PeerAllowedIps,
                "PrimaryRoutes" => Context::PeerPrimaryRoutes,
                "Endpoints" => Context::PeerEndpoints,
                #[cfg(feature = "peer-names")]
                "Hostinfo" => Context::PeerHostinfo,
                _ => Context::Ignored,
            },
            Context::PatchArray => Context::PatchObject,
            Context::PatchObject => match key {
                "Endpoints" => Context::PatchEndpoints,
                _ => Context::Ignored,
            },
            Context::DerpMapObject => match key {
                "Regions" => Context::DerpRegions,
                _ => Context::Ignored,
            },
            // Every member of `Regions` is a region, keyed by its id as a string.
            Context::DerpRegions => Context::DerpRegion,
            Context::DerpRegion => match key {
                "Nodes" => Context::DerpNodes,
                _ => Context::Ignored,
            },
            Context::DerpNodes => Context::DerpNode,
            Context::DnsConfigObject => match key {
                "Domains" => Context::DnsDomains,
                "Resolvers" => Context::DnsResolvers,
                // `Routes`, `FallbackResolvers`, and anything else the server
                // adds.
                _ => Context::Ignored,
            },
            Context::DnsResolvers => Context::DnsResolverObject,
            Context::PacketFiltersObject => Context::FilterSetArray,
            Context::PacketFilterArray | Context::FilterSetArray => Context::FilterRuleObject,
            Context::FilterRuleObject => match key {
                "SrcIPs" => Context::FilterSources,
                "DstPorts" => Context::FilterDestinations,
                "IPProto" => Context::FilterProtocols,
                _ => Context::Ignored,
            },
            Context::FilterDestinations => Context::FilterDestinationObject,
            Context::FilterDestinationObject if key == "Ports" => Context::FilterPortsObject,
            // Anything inside something ignored is ignored.
            _ => Context::Ignored,
        }
    }

    fn on_start<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let context = self.child_context();
        match context {
            Context::Root => self.self_routes_seen = false,
            Context::SelfNode => self.self_numeric_derp = false,
            Context::PeerObject | Context::PatchObject => self.pending.reset(),
            Context::PeerArray => {
                netmap.peers.clear();
                netmap.peers_truncated = false;
            }
            Context::SelfAddresses => netmap.addresses.clear(),
            Context::SelfPrimaryRoutes if !self.self_routes_seen => {
                netmap.primary_routes.clear();
                self.self_routes_seen = true;
            }
            Context::SelfPrimaryRoutes => {}
            Context::DerpRegions => netmap.derp.clear(),
            // A response that carries DNSConfig carries all of it, so the
            // prior one is replaced rather than merged into.
            Context::DnsConfigObject => netmap.dns.clear(),
            Context::DerpRegion => {
                self.region = PendingRegion::default();
                // The member name is the region id, and is the only place it is
                // guaranteed to appear.
                match self.key.parse() {
                    Ok(id) if id != 0 => self.region.id = id,
                    _ => self.fail(Error::MalformedField(MalformedField::DerpRegionId)),
                }
            }
            Context::DerpNode => {
                self.region.node_host.clear();
                self.region.node_cert.clear();
                self.region.node_port = DEFAULT_DERP_PORT;
                self.region.node_stun = DEFAULT_STUN_PORT;
                self.region.node_flags = 0;
            }
            Context::PacketFilterArray => {
                if let Err(error) = netmap.packet_filter.replace_set("base") {
                    self.fail(error);
                }
                self.filter.set = heapless::String::try_from("base").unwrap();
            }
            Context::PacketFiltersObject => netmap.packet_filter.mark_present(),
            Context::FilterSetArray => match heapless::String::try_from(self.key.as_str()) {
                Ok(name) => {
                    self.filter.set = name;
                    if let Err(error) = netmap.packet_filter.replace_set(self.filter.set.as_str()) {
                        self.fail(error);
                    }
                }
                Err(_) => self.fail(Error::Full(CapacityError::PacketPolicy)),
            },
            Context::FilterRuleObject => self.filter.reset_rule(),
            Context::FilterDestinationObject => self.filter.reset_destination(),
            _ => {}
        }
        if self.stack.push(context).is_err() {
            self.fail(Error::Full(CapacityError::ParserDepth));
        }
        self.key.clear();
        self.key_oversized = false;
    }

    fn on_end<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let context = self.stack.pop().unwrap_or(Context::Ignored);
        match context {
            Context::SelfNode => self.reconcile_self_peer(netmap),
            Context::PeerObject => {
                self.commit_peer(netmap);
            }
            Context::PatchObject => self.apply_patch(netmap),
            Context::DerpNode => {
                let mut node = DerpNode {
                    host_name: self.region.node_host.clone(),
                    cert_name: None,
                    port: self.region.node_port,
                    stun_port: self.region.node_stun,
                };
                if self.region.node_flags & 1 != 0 {
                    if !node.host_name.is_empty()
                        && node.stun_port != 0
                        && self.region.stun_fallback.is_none()
                    {
                        self.region.stun_fallback = Some(node);
                    }
                } else if !node.host_name.is_empty()
                    && node.port != 0
                    && self.region.nodes.len() < crate::netmap::MAX_DERP_NODES
                {
                    if !self.region.node_cert.is_empty()
                        && self.region.node_cert != self.region.node_host
                    {
                        match netmap.derp.intern_cert_name(self.region.node_cert.as_str()) {
                            Ok(name) => node.cert_name = Some(name),
                            Err(error) => self.fail(error),
                        }
                    }
                    if self.region.node_flags & 2 != 0 {
                        node.mark_insecure_for_tests();
                    }
                    let _ = self.region.nodes.push(node);
                }
            }
            Context::DerpRegion => {
                // If the retained relays expose no STUN endpoint, keep one
                // dedicated STUN-only host in the second bounded slot. Its
                // zero DERP port prevents relay selection from using it.
                if self.region.nodes.iter().all(|node| node.stun_port == 0)
                    && let Some(mut stun) = self.region.stun_fallback.take()
                {
                    stun.port = 0;
                    if self.region.nodes.len() == crate::netmap::MAX_DERP_NODES {
                        self.region.nodes.pop();
                    }
                    let _ = self.region.nodes.push(stun);
                }
                let region = DerpRegion {
                    id: self.region.id,
                    code: self.region.code.clone(),
                    nodes: core::mem::take(&mut self.region.nodes),
                };
                if let Err(e) = netmap.derp.insert(region) {
                    self.fail(e);
                }
            }
            Context::FilterDestinationObject => {
                let destination = match (
                    self.filter.destination_network,
                    self.filter.first_port,
                    self.filter.last_port,
                ) {
                    (Some(network), Some(first_port), Some(last_port))
                        if first_port <= last_port =>
                    {
                        Destination {
                            network,
                            first_port,
                            last_port,
                        }
                    }
                    _ => {
                        self.fail(Error::MalformedField(MalformedField::PacketDestination));
                        self.key.clear();
                        return;
                    }
                };
                if self.filter.rule.destinations.push(destination).is_err() {
                    self.fail(Error::Full(CapacityError::PacketPolicy));
                }
            }
            Context::FilterRuleObject => {
                if !self.filter.rule.is_well_formed() {
                    self.fail(Error::MalformedField(MalformedField::PacketRule));
                } else if let Err(error) = netmap.packet_filter.push_rule(
                    self.filter.set.as_str(),
                    core::mem::take(&mut self.filter.rule),
                ) {
                    self.fail(error);
                }
            }
            Context::Root => netmap.responses += 1,
            _ => {}
        }
        self.key.clear();
    }

    fn commit_peer<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let Some(node_key) = self.pending.node_key else {
            // A record with no key names nothing and cannot be routed to.
            return;
        };
        // The server sends a node its own record in `PeersChanged` — the
        // captured session does exactly this. Adding it would make the node a
        // peer of itself: a handshake with its own key, which cannot complete,
        // retried forever.
        if netmap.node_key == Some(node_key) {
            if !self.self_routes_seen {
                Self::replace_self_routes(
                    netmap,
                    &self.pending.allowed_ips,
                    self.pending.approved_ipv4_default,
                    self.pending.approved_ipv6_default,
                );
            }
            return;
        }
        let mut peer = Peer::new(self.pending.id, node_key);
        peer.disco_key = self.pending.disco_key;
        peer.set_online(self.pending.online.unwrap_or(false));
        #[cfg(feature = "ssh-policy")]
        peer.set_expired(self.pending.expired.unwrap_or(false));
        #[cfg(feature = "ssh-policy")]
        peer.set_key_expiry_restricted(self.pending.key_expiry_restricted.unwrap_or(false));
        peer.set_approved_ipv4_default(self.pending.approved_ipv4_default);
        peer.approved_ipv6_default = self.pending.approved_ipv6_default;
        peer.home_derp = self.pending.home_derp.unwrap_or(0);
        peer.addresses = self.pending.addresses.clone();
        peer.allowed_ips = self.pending.allowed_ips.clone();
        peer.endpoints = self.pending.endpoints.clone();
        #[cfg(feature = "peer-names")]
        {
            peer.name = if self.pending.name.is_empty() {
                self.pending.hostname.clone()
            } else {
                self.pending.name.clone()
            };
        }
        if let Err(error) = netmap.peers.upsert(peer.clone()) {
            if error == Error::Full(CapacityError::Peers) {
                if netmap.node_key.is_none() && self.deferred_peer.is_none() {
                    self.deferred_peer = Some(peer);
                } else {
                    netmap.peers_truncated = true;
                }
            } else {
                self.fail(error);
            }
        }
    }

    fn reconcile_self_peer<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        // A prior PeersChanged record can be recognized only after Node.Key is
        // known. Reconcile at the end of Node so its routes win regardless of
        // whether Key precedes or follows the route arrays in JSON.
        let Some(own) = netmap.node_key else { return };
        if !self.self_routes_seen {
            let own_routes = netmap.peers.by_node_key(&own).map(|peer| {
                (
                    peer.allowed_ips.clone(),
                    peer.approved_ipv4_default(),
                    peer.approved_ipv6_default,
                )
            });
            if let Some((routes, approved_ipv4_default, approved_ipv6_default)) =
                own_routes.as_ref()
            {
                Self::replace_self_routes(
                    netmap,
                    routes,
                    *approved_ipv4_default,
                    *approved_ipv6_default,
                );
            }
        }
        let ours: heapless::Vec<u64, 4> = netmap
            .peers
            .iter()
            .filter(|p| p.node_key == own)
            .map(|p| p.id)
            .collect();
        for id in ours {
            netmap.peers.remove(id);
        }
        if netmap.peers.len() < PEERS
            && let Some(peer) = self.deferred_peer.take()
            && netmap.peers.upsert(peer).is_err()
        {
            netmap.peers_truncated = true;
        }
    }

    fn replace_self_routes<const PEERS: usize>(
        netmap: &mut Netmap<PEERS>,
        allowed: &heapless::Vec<Cidr4, { crate::netmap::MAX_ALLOWED_IPS }>,
        approved_ipv4_default: bool,
        approved_ipv6_default: bool,
    ) {
        netmap.primary_routes.clear();
        if approved_ipv4_default {
            let route = Cidr {
                address: core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            };
            if !netmap.primary_routes.contains(&route) {
                let _ = netmap.primary_routes.push(route);
            }
        }
        if approved_ipv6_default {
            let route = Cidr {
                address: core::net::IpAddr::V6(core::net::Ipv6Addr::UNSPECIFIED),
                prefix: 0,
            };
            if !netmap.primary_routes.contains(&route) {
                let _ = netmap.primary_routes.push(route);
            }
        }
        // Defaults are the route-approval facts required to enable an exit
        // node, so reserve their bounded slots before copying unrelated
        // AllowedIPs from a delayed self record.
        for route in allowed {
            let route = Cidr {
                address: core::net::IpAddr::V4(route.address),
                prefix: route.prefix,
            };
            if !netmap.primary_routes.contains(&route) && netmap.primary_routes.push(route).is_err()
            {
                break;
            }
        }
    }

    /// Apply only the fields the patch mentioned.
    ///
    /// The difference from `commit_peer` is the whole point of the type: a patch
    /// that blanked unmentioned fields would clear every peer's endpoints on
    /// every heartbeat, and the tunnel would keep falling back to a relay.
    fn apply_patch<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let id = self.pending.id;
        let Some(peer) = netmap.peers.get_mut(id) else {
            // A patch for a peer we never saw. Nothing to merge it into, and
            // inventing one would produce a peer with no key.
            return;
        };
        if let Some(key) = self.pending.node_key {
            peer.node_key = key;
        }
        if let Some(online) = self.pending.online {
            peer.set_online(online);
        }
        #[cfg(feature = "ssh-policy")]
        if let Some(expired) = self.pending.expired {
            peer.set_expired(expired);
        }
        #[cfg(feature = "ssh-policy")]
        if let Some(restricted) = self.pending.key_expiry_restricted {
            peer.set_key_expiry_restricted(restricted);
        }
        if let Some(derp) = self.pending.home_derp {
            peer.home_derp = derp;
        }
        if let Some(key) = self.pending.disco_key {
            peer.disco_key = Some(key);
        }
        if self.pending.endpoints_present {
            peer.endpoints = self.pending.endpoints.clone();
        }
    }

    fn on_string<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>, value: &str) {
        let key = self.key.as_str();
        match self.context() {
            Context::SelfNode => match key {
                "Key" => netmap.node_key = NodePublic::parse(value).ok(),
                "DiscoKey" => netmap.disco_key = DiscoPublic::parse(value).ok(),
                // The numeric `HomeDERP` wins when both are present, in any order.
                "DERP" if !self.self_numeric_derp => {
                    if let Some(region) = legacy_derp_region(value) {
                        netmap.home_derp = region;
                    }
                }
                #[cfg(feature = "peer-names")]
                "Name" => netmap.name = display_name(first_label(value)),
                _ => {}
            },
            Context::SelfAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    if netmap.addresses.push(cidr).is_err() {
                        self.fail(Error::Full(CapacityError::Addresses));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::Address)),
            },
            Context::SelfPrimaryRoutes => match Cidr::parse(value) {
                Ok(cidr) => {
                    if self.primary_route(netmap, cidr).is_err() {
                        self.fail(Error::Full(CapacityError::Routes));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::Address)),
            },
            Context::PeerObject | Context::PatchObject => match key {
                "Key" => match NodePublic::parse(value) {
                    Ok(parsed) => self.pending.node_key = Some(parsed),
                    Err(_) => self.fail(Error::MalformedField(MalformedField::NodeKey)),
                },
                "DiscoKey" => match DiscoPublic::parse(value) {
                    Ok(parsed) => self.pending.disco_key = Some(parsed),
                    Err(_) => self.fail(Error::MalformedField(MalformedField::DiscoKey)),
                },
                // The numeric `HomeDERP` wins when both are present.
                "DERP" => {
                    if let Some(region) = legacy_derp_region(value) {
                        self.pending.home_derp.get_or_insert(region);
                    }
                }
                #[cfg(feature = "peer-names")]
                "Name" => self.pending.name = display_name(first_label(value)),
                _ => {}
            },
            #[cfg(feature = "peer-names")]
            Context::PeerHostinfo if key == "Hostname" => {
                self.pending.hostname = display_name(value);
            }
            // A peer's IPv6 subnets are dropped rather than stored: this node
            // routes IPv4 only, so they are bytes the RTC-fast bank spends on
            // something the data plane will never act on. Malformed input is
            // still a malformed netmap.
            Context::PeerAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    if let Some(cidr) = Cidr4::from_cidr(cidr)
                        && self.pending.addresses.push(cidr).is_err()
                    {
                        self.fail(Error::Full(CapacityError::Addresses));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::Address)),
            },
            Context::PeerAllowedIps => match Cidr::parse(value) {
                Ok(cidr) => {
                    self.pending.approved_ipv4_default |= matches!(
                        cidr,
                        Cidr {
                            address: core::net::IpAddr::V4(address),
                            prefix: 0,
                        } if address.is_unspecified()
                    );
                    self.pending.approved_ipv6_default |= matches!(
                        cidr,
                        Cidr {
                            address: core::net::IpAddr::V6(address),
                            prefix: 0,
                        } if address.is_unspecified()
                    );
                    if let Some(cidr) = Cidr4::from_cidr(cidr)
                        && self.pending.allowed_ips.push(cidr).is_err()
                    {
                        self.fail(Error::Full(CapacityError::AllowedIps));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::AllowedIp)),
            },
            Context::PeerPrimaryRoutes => match Cidr::parse(value) {
                Ok(cidr) => {
                    // A peer record only proves to be this node after its key
                    // has been parsed. Retain the two route facts used by exit
                    // readiness without putting a full route vector in every
                    // streaming parser's static state.
                    self.pending.approved_ipv4_default |= matches!(
                        cidr,
                        Cidr {
                            address: core::net::IpAddr::V4(address),
                            prefix: 0,
                        } if address.is_unspecified()
                    );
                    self.pending.approved_ipv6_default |= matches!(
                        cidr,
                        Cidr {
                            address: core::net::IpAddr::V6(address),
                            prefix: 0,
                        } if address.is_unspecified()
                    );
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::AllowedIp)),
            },
            Context::PeerEndpoints | Context::PatchEndpoints => {
                self.pending.endpoints_present = true;
                // An endpoint that does not parse is one path lost, not a
                // broken netmap: the server is entitled to advertise address
                // families this node cannot use.
                if let Ok(core::net::SocketAddr::V4(endpoint)) = value.parse()
                    && self.pending.endpoints.push(endpoint).is_err()
                {
                    self.fail(Error::Full(CapacityError::Endpoints));
                }
            }
            Context::FilterSources => match Network::parse(value) {
                Ok(network) => {
                    if self.filter.rule.sources.push(network).is_err() {
                        self.fail(Error::Full(CapacityError::PacketPolicy));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::PolicySource)),
            },
            Context::FilterDestinationObject if key == "IP" => match Network::parse(value) {
                Ok(network) => self.filter.destination_network = Some(network),
                Err(_) => self.fail(Error::MalformedField(MalformedField::PolicyDestination)),
            },
            Context::DerpRegion if key == "RegionCode" => match heapless::String::try_from(value) {
                Ok(code) => self.region.code = code,
                Err(_) => self.fail(Error::Full(CapacityError::String)),
            },
            Context::DerpNode if key == "HostName" => match heapless::String::try_from(value) {
                Ok(host) => self.region.node_host = host,
                Err(_) => self.fail(Error::Full(CapacityError::String)),
            },
            Context::DerpNode if key == "CertName" => match heapless::String::try_from(value) {
                Ok(host) => self.region.node_cert = host,
                Err(_) => self.fail(Error::Full(CapacityError::String)),
            },
            Context::DnsDomains => netmap.dns.push_domain(value),
            Context::DnsResolverObject if key == "Addr" => netmap.dns.push_resolver(value),
            _ => {}
        }
        self.key.clear();
    }

    fn on_number<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>, value: i64) {
        let key = self.key.as_str();
        match self.context() {
            Context::SelfNode if matches!(key, "HomeDERP" | "DERPRegion") => {
                match u16::try_from(value) {
                    Ok(region) => {
                        netmap.home_derp = region;
                        self.self_numeric_derp = true;
                    }
                    Err(_) => self.fail(Error::MalformedField(MalformedField::HomeDerp)),
                }
            }
            Context::PeerObject | Context::PatchObject => match key {
                "ID" | "NodeID" => match u64::try_from(value) {
                    Ok(id) => self.pending.id = id,
                    Err(_) => self.fail(Error::MalformedField(MalformedField::PeerId)),
                },
                "HomeDERP" | "DERPRegion" => match u16::try_from(value) {
                    Ok(region) => self.pending.home_derp = Some(region),
                    Err(_) => self.fail(Error::MalformedField(MalformedField::HomeDerp)),
                },
                _ => {}
            },
            Context::RemovedArray => match u64::try_from(value) {
                Ok(id) => {
                    netmap.peers.remove(id);
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::RemovedPeerId)),
            },
            Context::DerpRegion if key == "RegionID" => match u16::try_from(value) {
                Ok(id) if id != 0 => self.region.id = id,
                _ => self.fail(Error::MalformedField(MalformedField::DerpRegionId)),
            },
            Context::DerpNode => match key {
                "DERPPort" => match u16::try_from(value) {
                    Ok(0) => self.region.node_port = DEFAULT_DERP_PORT,
                    Ok(port) => self.region.node_port = port,
                    _ => self.fail(Error::MalformedField(MalformedField::DerpPort)),
                },
                // Normalize upstream's default and disabled representations.
                // The retained map uses zero only for a disabled endpoint.
                "STUNPort" if value == -1 => self.region.node_stun = 0,
                "STUNPort" => match u16::try_from(value) {
                    Ok(0) => self.region.node_stun = DEFAULT_STUN_PORT,
                    Ok(port) => self.region.node_stun = port,
                    Err(_) => self.fail(Error::MalformedField(MalformedField::StunPort)),
                },
                _ => {}
            },
            Context::FilterPortsObject => match key {
                "First" => match u16::try_from(value) {
                    Ok(port) => self.filter.first_port = Some(port),
                    Err(_) => self.fail(Error::MalformedField(MalformedField::PolicyPort)),
                },
                "Last" => match u16::try_from(value) {
                    Ok(port) => self.filter.last_port = Some(port),
                    Err(_) => self.fail(Error::MalformedField(MalformedField::PolicyPort)),
                },
                _ => {}
            },
            Context::FilterProtocols => match u8::try_from(value) {
                Ok(protocol) => {
                    if self.filter.rule.protocols.push(protocol).is_err() {
                        self.fail(Error::Full(CapacityError::PacketPolicy));
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::PolicyProtocol)),
            },
            _ => {}
        }
        self.key.clear();
    }

    fn on_bool<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>, value: bool) {
        match self.context() {
            Context::PeerObject | Context::PatchObject if self.key == "Online" => {
                self.pending.online = Some(value);
            }
            #[cfg(feature = "ssh-policy")]
            Context::PeerObject | Context::PatchObject if self.key == "Expired" => {
                self.pending.expired = Some(value);
            }
            Context::DerpNode => match self.key.as_str() {
                "STUNOnly" => {
                    self.region.node_flags = (self.region.node_flags & !1) | u8::from(value);
                }
                "InsecureForTests" => {
                    self.region.node_flags = (self.region.node_flags & !2) | (u8::from(value) << 1);
                }
                _ => {}
            },
            Context::DnsConfigObject if self.key == "Proxied" => netmap.dns.proxied = value,
            _ => {}
        }
        self.key.clear();
    }

    fn on_null<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        if self.context() == Context::PacketFiltersObject {
            if self.key == "*" {
                netmap.packet_filter.clear();
            } else if !self.key.is_empty() {
                netmap.packet_filter.delete_set(self.key.as_str());
            }
        } else if self.context() == Context::Root && self.key == "PacketFilter" {
            netmap.packet_filter.delete_set("base");
        }
        self.key.clear();
    }

    fn primary_route<const PEERS: usize>(
        &self,
        netmap: &mut Netmap<PEERS>,
        cidr: Cidr,
    ) -> Result<(), ()> {
        if netmap.primary_routes.contains(&cidr) {
            Ok(())
        } else {
            netmap.primary_routes.push(cidr).map_err(|_| ())
        }
    }
}

impl State {
    fn on_token<const PEERS: usize>(
        &mut self,
        netmap: &mut Netmap<PEERS>,
        token: Token<'_>,
    ) -> Result<(), Error> {
        #[cfg(feature = "ssh-policy")]
        {
            let field = self.context() == Context::Root && self.key == "SSHPolicy";
            self.ssh.token(&mut netmap.ssh_policy, &token, field);
            if matches!(self.context(), Context::PeerObject | Context::PatchObject)
                && self.key == "KeyExpiry"
            {
                match &token {
                    Token::Str(value) => {
                        // Go's zero time means no expiry. Supporting finite
                        // deadlines needs an advancing trusted clock; deny
                        // them rather than retaining an unchecked timestamp.
                        self.pending.key_expiry_restricted = Some(*value != "0001-01-01T00:00:00Z");
                    }
                    Token::StartObject
                    | Token::StartArray
                    | Token::Int(_)
                    | Token::OtherNumber
                    | Token::Bool(_) => {
                        self.pending.key_expiry_restricted = Some(true);
                    }
                    // A null optional patch field leaves the old value alone.
                    _ => {}
                }
            }
        }
        match token {
            Token::StartObject | Token::StartArray => self.on_start(netmap),
            Token::EndObject | Token::EndArray => self.on_end(netmap),
            Token::Key(key) => {
                self.key_oversized = false;
                match heapless::String::try_from(key) {
                    Ok(key) => self.key = key,
                    Err(_) => {
                        self.key.clear();
                        if matches!(
                            self.context(),
                            Context::DerpRegions | Context::PacketFiltersObject
                        ) {
                            self.fail(Error::Full(CapacityError::String));
                        } else {
                            self.key_oversized = true;
                        }
                    }
                }
            }
            Token::Str(value) => self.on_string(netmap, value),
            Token::Int(value) => self.on_number(netmap, value),
            Token::OtherNumber => {
                // Hosted DERP regions include fractional coordinates. They
                // are unused metadata; do not reject the map for their shape.
                // All other retained contexts keep rejecting non-integers.
                let coordinate = self.context() == Context::DerpRegion
                    && matches!(self.key.as_str(), "Latitude" | "Longitude");
                if self.context() != Context::Ignored && !coordinate {
                    self.fail(Error::Malformed);
                }
                self.key.clear();
            }
            Token::Bool(value) => self.on_bool(netmap, value),
            Token::Null => self.on_null(netmap),
        }
        Ok(())
    }
}

/// The region in the legacy `DERP` field, `"127.3.3.40:<region>"`, which some
/// control servers still send instead of `HomeDERP`. The address spells DERP
/// on a keyboard; the port is the region. Anything else is ignored rather than
/// failing the map, because the field is deprecated and purely advisory.
fn legacy_derp_region(value: &str) -> Option<u16> {
    value
        .strip_prefix("127.3.3.40:")?
        .parse::<u16>()
        .ok()
        .filter(|region| *region != 0)
}

/// The first DNS label of a MagicDNS name: `host` of `host.tailnet.ts.net.`.
#[cfg(feature = "peer-names")]
fn first_label(name: &str) -> &str {
    name.split('.').next().unwrap_or_default()
}

/// A display name cut to the retained bound at a character boundary.
#[cfg(feature = "peer-names")]
fn display_name(value: &str) -> heapless::String<{ crate::netmap::MAX_PEER_NAME }> {
    let mut name = heapless::String::new();
    for character in value.chars() {
        if name.push(character).is_err() {
            break;
        }
    }
    name
}

/// Feeds bytes in and updates a [`Netmap`].
///
/// The only memory whose size depends on the document is the scanner's string
/// buffer, and it scales with the longest single string rather than with the
/// number of peers or the total length.
///
/// The netmap is a parameter of [`Parser::push`] rather than of
/// [`Parser::new`], so it is not borrowed between chunks and the caller can read
/// it as it fills.
#[derive(Default)]
pub struct Parser<const PEERS: usize = MAX_PEERS> {
    scanner: Scanner,
    state: State,
}

impl<const PEERS: usize> Parser<PEERS> {
    pub const fn new() -> Self {
        Self {
            scanner: Scanner::new(),
            state: State {
                stack: heapless::Vec::new(),
                key: heapless::String::new(),
                key_oversized: false,
                self_routes_seen: false,
                self_numeric_derp: false,
                pending: Pending::new(),
                deferred_peer: None,
                region: PendingRegion::new(),
                filter: PendingFilter::new(),
                #[cfg(feature = "ssh-policy")]
                ssh: crate::netmap::ssh::Builder::new(),
                failed: None,
            },
        }
    }

    pub(crate) fn reset(&mut self) {
        self.scanner.reset();
        self.state.stack.clear();
        self.state.key.clear();
        self.state.key_oversized = false;
        self.state.self_routes_seen = false;
        self.state.self_numeric_derp = false;
        self.state.pending.reset();
        self.state.deferred_peer = None;
        self.state.region = PendingRegion::new();
        self.state.filter = PendingFilter::new();
        #[cfg(feature = "ssh-policy")]
        {
            self.state.ssh = crate::netmap::ssh::Builder::new();
        }
        self.state.failed = None;
    }

    /// Feed the next bytes of one MapResponse.
    ///
    /// Chunks may split anywhere, including the middle of a string: that is the
    /// point, and the reason the caller never has to buffer a document.
    pub fn push(&mut self, netmap: &mut Netmap<PEERS>, bytes: &[u8]) -> Result<(), Error> {
        let Self { scanner, state } = self;
        scanner.push(bytes, |token| state.on_token(netmap, token))
    }

    /// Whether the document has been closed.
    pub fn is_done(&self) -> bool {
        self.scanner.is_done()
    }

    /// Finish one response, reporting the first error if there was one.
    pub fn finish(mut self, netmap: &mut Netmap<PEERS>) -> Result<(), Error> {
        let Self { scanner, state } = &mut self;
        scanner.finish(|token| state.on_token(netmap, token))?;
        if self.state.deferred_peer.is_some() {
            netmap.peers_truncated = true;
        }
        match self.state.failed {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(all(test, feature = "peer-names"))]
mod peer_name_tests {
    use super::*;
    use crate::keys::NodePrivate;

    fn key(byte: u8) -> std::string::String {
        let mut text = [0u8; 128];
        std::string::String::from(
            NodePrivate::from_bytes([byte; 32])
                .public()
                .encode(&mut text)
                .unwrap(),
        )
    }

    fn apply(netmap: &mut Netmap<4>, document: &str) {
        let mut parser = Parser::<4>::new();
        parser.push(netmap, document.as_bytes()).unwrap();
        parser.finish(netmap).unwrap();
    }

    #[test]
    fn names_prefer_the_magicdns_label_and_fall_back_to_the_hostname() {
        let long = "x".repeat(80);
        let document = std::format!(
            r#"{{"Node":{{"Key":"{own}","Name":"browser.tail1234.ts.net."}},
               "Peers":[
                 {{"ID":1,"Key":"{a}","Name":"bazzite.tail1234.ts.net.","Hostinfo":{{"Hostname":"Bazzite PC"}}}},
                 {{"ID":2,"Key":"{b}","Hostinfo":{{"Hostname":"laptop","OS":"linux"}}}},
                 {{"ID":3,"Key":"{c}","Name":"{long}.tail1234.ts.net."}}
               ]}}"#,
            own = key(1),
            a = key(2),
            b = key(3),
            c = key(4),
        );
        let mut netmap = Netmap::<4>::new();
        apply(&mut netmap, &document);

        assert_eq!(netmap.name.as_str(), "browser");
        assert_eq!(netmap.peers.get(1).unwrap().name.as_str(), "bazzite");
        assert_eq!(netmap.peers.get(2).unwrap().name.as_str(), "laptop");
        assert_eq!(
            netmap.peers.get(3).unwrap().name.len(),
            crate::netmap::MAX_PEER_NAME
        );
    }

    #[test]
    fn a_patch_keeps_the_name() {
        let mut netmap = Netmap::<4>::new();
        apply(
            &mut netmap,
            &std::format!(
                r#"{{"Peers":[{{"ID":1,"Key":"{a}","Name":"bazzite.example."}}]}}"#,
                a = key(2)
            ),
        );
        apply(
            &mut netmap,
            r#"{"PeersChangedPatch":[{"NodeID":1,"Online":true}]}"#,
        );
        let peer = netmap.peers.get(1).unwrap();
        assert!(peer.online());
        assert_eq!(peer.name.as_str(), "bazzite");
    }
}
