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
#[cfg(feature = "peer-api")]
use crate::netmap::peer::PeerServices;
use crate::netmap::peer::{Cidr, Cidr4, Peer, PeerTable};
use crate::netmap::policy::{Destination, FilterRule, Network};
#[cfg(feature = "peer-api")]
use crate::netmap::policy::{MAX_CAP_DESTINATIONS, PeerCapability};
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
    /// A peer's `Hostinfo`, read for its `Hostname` and `Services`.
    #[cfg(any(feature = "peer-names", feature = "peer-api"))]
    PeerHostinfo,
    /// A peer's `Tags`, and its `Hostinfo.Services` entries.
    #[cfg(feature = "peer-api")]
    PeerTags,
    #[cfg(feature = "peer-api")]
    PeerServices,
    #[cfg(feature = "peer-api")]
    PeerServiceObject,
    /// The self node's `Tags`, `Capabilities` and `CapMap` (whose member
    /// names are the capabilities).
    #[cfg(feature = "peer-api")]
    SelfTags,
    #[cfg(feature = "peer-api")]
    SelfCapabilities,
    #[cfg(feature = "peer-api")]
    SelfCapMap,
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
    /// A rule's `CapGrant`: capabilities rather than network access. Always
    /// recognized, so a grant-only rule is accepted instead of malformed.
    FilterCapGrants,
    FilterCapGrantObject,
    #[cfg(feature = "peer-api")]
    FilterCapDestinations,
    #[cfg(feature = "peer-api")]
    FilterCapMap,
    #[cfg(feature = "peer-api")]
    FilterCapList,
    /// Anything this parser does not read. Nested containers inherit it, so a
    /// whole subtree costs one push and one pop.
    Ignored,
}

/// The state a netmap is accumulated into.
#[derive(Default, Clone)]
pub struct Netmap<const PEERS: usize = MAX_PEERS> {
    pub peers: PeerTable<PEERS>,
    /// The control map named more peers than this target retains, or named a
    /// peer whose addresses or allowed IPs exceed the per-peer bounds.
    ///
    /// Selection is deterministic and independent of server order: a full
    /// table keeps the highest-ranked non-self records (online first, then the
    /// lowest node id), skipping oversized records. With the `alloc` feature
    /// the table is full only at `PEERS` or when the allocator refuses to
    /// grow it. This lets memory-constrained targets remain connected to
    /// control instead of rejecting the entire map.
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
    /// This node's owner, tags and the capabilities peer API endpoints use.
    #[cfg(feature = "peer-api")]
    pub services: crate::netmap::peer_api::SelfServices,
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
            #[cfg(feature = "peer-api")]
            services: crate::netmap::peer_api::SelfServices::new(),
        }
    }

    /// Copy a complete map without materializing another map-sized temporary
    /// on the caller's stack. This is used to reseed the one streaming-delta
    /// lease after swapping it into the active node.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        let complete = self.peers.copy_from(&source.peers);
        self.peers_truncated = source.peers_truncated || !complete;
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
        #[cfg(feature = "peer-api")]
        {
            self.services = source.services;
        }
    }

    pub fn has_assigned_ipv4(&self) -> bool {
        self.addresses
            .iter()
            .any(|route| matches!(route.address, core::net::IpAddr::V4(_)))
    }

    /// Approval of `0.0.0.0/0` is independent of IPv6 uplink capability.
    pub fn ipv4_default_route_approved(&self) -> bool {
        self.primary_routes.iter().any(|route| {
            route.prefix == 0
                && route.address == core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED)
        })
    }

    /// Only an explicitly approved `::/0` authorizes IPv6 exit forwarding.
    pub fn ipv6_default_route_approved(&self) -> bool {
        self.primary_routes.iter().any(|route| {
            route.prefix == 0
                && route.address == core::net::IpAddr::V6(core::net::Ipv6Addr::UNSPECIFIED)
        })
    }

    /// Whether both exit-route families are approved. Family-specific packet
    /// paths must use the corresponding approval query instead.
    pub fn default_routes_approved(&self) -> bool {
        self.ipv4_default_route_approved() && self.ipv6_default_route_approved()
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
    ipv6_address: Option<core::net::Ipv6Addr>,
    addresses: heapless::Vec<Cidr4, { crate::netmap::MAX_ADDRESSES }>,
    allowed_ips: heapless::Vec<Cidr4, { crate::netmap::MAX_ALLOWED_IPS }>,
    approved_ipv4_default: bool,
    approved_ipv6_default: bool,
    endpoints: heapless::Vec<core::net::SocketAddrV4, { crate::netmap::MAX_ENDPOINTS }>,
    /// Set when a patch mentioned `Endpoints`, so an empty list can be told
    /// apart from an absent one.
    endpoints_present: bool,
    /// The record named more addresses or allowed IPs than a peer retains.
    /// Those lists decide routing and source checks, so a partial copy is not
    /// kept: the peer is omitted instead of failing the whole map.
    oversized: Option<CapacityError>,
    /// The record's `Key` was too large to read. Whatever this node knew of
    /// the peer is stale, so the record removes it rather than being ignored.
    key_unreadable: bool,
    /// The record's `DiscoKey` was too large to read; a patch clears the old
    /// one rather than keep probing with a retired key.
    disco_unreadable: bool,
    #[cfg(feature = "peer-names")]
    name: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
    #[cfg(feature = "peer-names")]
    hostname: heapless::String<{ crate::netmap::MAX_PEER_NAME }>,
    #[cfg(feature = "peer-api")]
    services: PeerServices,
    /// The `Hostinfo.Services` entry being read: 4 or 6 for `peerapi4`/
    /// `peerapi6`, zero for any other protocol.
    #[cfg(feature = "peer-api")]
    service_proto: u8,
    #[cfg(feature = "peer-api")]
    service_port: u16,
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
            ipv6_address: None,
            addresses: heapless::Vec::new(),
            allowed_ips: heapless::Vec::new(),
            approved_ipv4_default: false,
            approved_ipv6_default: false,
            endpoints: heapless::Vec::new(),
            endpoints_present: false,
            oversized: None,
            key_unreadable: false,
            disco_unreadable: false,
            #[cfg(feature = "peer-names")]
            name: heapless::String::new(),
            #[cfg(feature = "peer-names")]
            hostname: heapless::String::new(),
            #[cfg(feature = "peer-api")]
            services: PeerServices {
                user_id: 0,
                tagged: false,
                unsigned_peer_api_only: false,
                peer_api4: 0,
                peer_api6: 0,
            },
            #[cfg(feature = "peer-api")]
            service_proto: 0,
            #[cfg(feature = "peer-api")]
            service_port: 0,
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
    code: heapless::String<{ crate::netmap::MAX_DERP_REGION_CODE }>,
    no_measure_no_home: bool,
    nodes: crate::BoundedVec<DerpNode, { crate::netmap::MAX_DERP_NODES }>,
    stun_fallback: Option<DerpNode>,
    node_host: heapless::String<{ crate::netmap::MAX_DERP_HOSTNAME }>,
    node_cert: heapless::String<{ crate::netmap::MAX_DERP_HOSTNAME }>,
    node_port: u16,
    node_stun: u16,
    /// Bit zero is STUNOnly; bit one is InsecureForTests; bit two marks a
    /// relay whose host or certificate name did not fit, which is skipped.
    node_flags: u8,
}

struct PendingFilter {
    set: heapless::String<{ crate::netmap::policy::MAX_FILTER_SET_NAME }>,
    /// The current set could not be stored, so its rules are dropped.
    skip_set: bool,
    /// The current rule outgrew a bound and is dropped whole: rules only
    /// allow traffic, so dropping one can only deny.
    rule_overflow: bool,
    rule: FilterRule,
    destination_network: Option<Network>,
    first_port: Option<u16>,
    last_port: Option<u16>,
    /// The rule carried a `CapGrant`, so it may lack `DstPorts`.
    cap_grant: bool,
    #[cfg(feature = "peer-api")]
    grants: heapless::Vec<PendingCapGrant, MAX_PENDING_CAP_GRANTS>,
    #[cfg(feature = "peer-api")]
    grant: PendingCapGrant,
}

/// One `CapGrant` entry of the rule being read.
#[cfg(feature = "peer-api")]
#[derive(Clone, Default)]
struct PendingCapGrant {
    destinations: crate::BoundedVec<Network, MAX_CAP_DESTINATIONS>,
    caps: PeerCapability,
}

/// `CapGrant` entries one rule may carry.
#[cfg(feature = "peer-api")]
const MAX_PENDING_CAP_GRANTS: usize = 4;

impl PendingFilter {
    const fn new() -> Self {
        Self {
            set: heapless::String::new(),
            skip_set: false,
            rule_overflow: false,
            rule: FilterRule::new(),
            destination_network: None,
            first_port: None,
            last_port: None,
            cap_grant: false,
            #[cfg(feature = "peer-api")]
            grants: heapless::Vec::new(),
            #[cfg(feature = "peer-api")]
            grant: PendingCapGrant {
                destinations: crate::BoundedVec::new(),
                caps: PeerCapability::NONE,
            },
        }
    }

    fn reset_rule(&mut self) {
        self.rule = FilterRule::new();
        self.rule_overflow = false;
        self.cap_grant = false;
        #[cfg(feature = "peer-api")]
        self.grants.clear();
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
            no_measure_no_home: false,
            nodes: crate::BoundedVec::new(),
            stun_fallback: None,
            node_host: heapless::String::new(),
            node_cert: heapless::String::new(),
            node_port: 0,
            node_stun: 0,
            node_flags: 0,
        }
    }
}

/// Records dropped before the self key is known whose routes are kept.
const MAX_DROPPED_ROUTES: usize = 4;

/// The route-approval facts of a record ranked out of a full peer table.
#[derive(Clone)]
struct DroppedRoutes {
    node_key: NodePublic,
    allowed_ips: heapless::Vec<Cidr4, { crate::netmap::MAX_ALLOWED_IPS }>,
    approved_ipv4_default: bool,
    approved_ipv6_default: bool,
}

/// The parser's own state: where it is in the document and what it is building.
/// The netmap is passed in per call rather than borrowed for the parser's life,
/// so a caller can read it between chunks — which is the whole point of
/// streaming.
#[derive(Default)]
struct State {
    /// One entry per container the scanner reported open, so it can never be
    /// shallower than the scanner's own stack.
    stack: heapless::Vec<Context, { crate::netmap::scanner::MAX_DEPTH }>,
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
    /// This response explicitly replaced the self home, including legacy DERP.
    self_home_derp_set: bool,
    pending: Pending,
    /// The best-ranked peer that overflowed before a snapshot identified its
    /// self key. It fills the slot released when that delayed self record is
    /// removed, so the retained set is the same ranked subset whether `Node`
    /// precedes or follows the peer list.
    deferred_peer: Option<Peer>,
    /// Route facts of records ranked out entirely before the self key was
    /// known. A lower-ranked self record can be among them, and its route
    /// approval must still reach reconciliation.
    dropped_routes: heapless::Vec<DroppedRoutes, MAX_DROPPED_ROUTES>,
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
                #[cfg(feature = "peer-api")]
                "Tags" => Context::SelfTags,
                #[cfg(feature = "peer-api")]
                "Capabilities" => Context::SelfCapabilities,
                #[cfg(feature = "peer-api")]
                "CapMap" => Context::SelfCapMap,
                _ => Context::Ignored,
            },
            Context::PeerArray | Context::PeerChangedArray => Context::PeerObject,
            Context::PeerObject => match key {
                "Addresses" => Context::PeerAddresses,
                "AllowedIPs" => Context::PeerAllowedIps,
                "PrimaryRoutes" => Context::PeerPrimaryRoutes,
                "Endpoints" => Context::PeerEndpoints,
                #[cfg(any(feature = "peer-names", feature = "peer-api"))]
                "Hostinfo" => Context::PeerHostinfo,
                #[cfg(feature = "peer-api")]
                "Tags" => Context::PeerTags,
                _ => Context::Ignored,
            },
            #[cfg(feature = "peer-api")]
            Context::PeerHostinfo if key == "Services" => Context::PeerServices,
            #[cfg(feature = "peer-api")]
            Context::PeerServices => Context::PeerServiceObject,
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
                "CapGrant" => Context::FilterCapGrants,
                _ => Context::Ignored,
            },
            Context::FilterCapGrants => Context::FilterCapGrantObject,
            #[cfg(feature = "peer-api")]
            Context::FilterCapGrantObject => match key {
                "Dsts" => Context::FilterCapDestinations,
                "CapMap" => Context::FilterCapMap,
                // The legacy form: capability names without values.
                "Caps" => Context::FilterCapList,
                _ => Context::Ignored,
            },
            Context::FilterDestinations => Context::FilterDestinationObject,
            Context::FilterDestinationObject if key == "Ports" => Context::FilterPortsObject,
            // Anything inside something ignored is ignored.
            _ => Context::Ignored,
        }
    }

    fn on_start<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        // A capability map's member names are the capabilities; its values
        // (arrays of parameters) are not read.
        #[cfg(feature = "peer-api")]
        self.note_cap_member(netmap);
        let context = self.child_context();
        match context {
            Context::Root => {
                self.self_routes_seen = false;
                self.self_home_derp_set = false;
            }
            Context::SelfNode => {
                self.self_numeric_derp = false;
                // A self record is whole: what it omits no longer applies.
                #[cfg(feature = "peer-api")]
                {
                    netmap.services = crate::netmap::peer_api::SelfServices::new();
                }
            }
            Context::PeerObject | Context::PatchObject => self.pending.reset(),
            #[cfg(feature = "peer-api")]
            Context::PeerServiceObject => {
                self.pending.service_proto = 0;
                self.pending.service_port = 0;
            }
            Context::FilterCapGrants => self.filter.cap_grant = true,
            #[cfg(feature = "peer-api")]
            Context::FilterCapGrantObject => self.filter.grant = PendingCapGrant::default(),
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
                self.filter.skip_set = false;
                match netmap.packet_filter.replace_set("base") {
                    Ok(()) => {}
                    Err(Error::Full(_)) => {
                        netmap.packet_filter.mark_truncated("base");
                        self.filter.skip_set = true;
                    }
                    Err(error) => self.fail(error),
                }
                self.filter.set = heapless::String::try_from("base").unwrap();
            }
            Context::PacketFiltersObject => netmap.packet_filter.mark_present(),
            Context::FilterSetArray => {
                self.filter.skip_set = false;
                match heapless::String::try_from(self.key.as_str()) {
                    Ok(name) => {
                        self.filter.set = name;
                        match netmap.packet_filter.replace_set(self.filter.set.as_str()) {
                            Ok(()) => {}
                            // The set's earlier rules are already gone; its
                            // new ones are dropped, which only denies.
                            Err(Error::Full(_)) => {
                                netmap
                                    .packet_filter
                                    .mark_truncated(self.filter.set.as_str());
                                self.filter.skip_set = true;
                            }
                            Err(error) => self.fail(error),
                        }
                    }
                    Err(_) => {
                        netmap.packet_filter.mark_truncated_unnamed();
                        self.filter.skip_set = true;
                    }
                }
            }
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
                if self.region.node_flags & 4 != 0 {
                    // Unusable relay: dropped, regardless of field order.
                } else if self.region.node_flags & 1 != 0 {
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
                        match netmap.derp.intern_cert_name(
                            self.region.node_cert.as_str(),
                            &mut self.region.nodes,
                        ) {
                            Ok(name) => node.cert_name = Some(name),
                            // Without its certificate name the relay cannot be
                            // verified; skip it rather than the whole map.
                            Err(_) => {
                                netmap.derp.mark_truncated();
                                node.host_name.clear();
                            }
                        }
                    }
                    if self.region.node_flags & 2 != 0 {
                        node.mark_insecure_for_tests();
                    }
                    if !node.host_name.is_empty() && self.region.nodes.push(node).is_err() {
                        netmap.derp.mark_truncated();
                    }
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
                    if self.region.nodes.is_full() {
                        self.region.nodes.pop();
                    }
                    if let Err(stun) = self.region.nodes.push(stun) {
                        // Out of memory: a relay with no STUN port still
                        // relays, so give its slot to the STUN host.
                        if self.region.nodes.pop().is_some() {
                            let _ = self.region.nodes.push(stun);
                        }
                        netmap.derp.mark_truncated();
                    }
                }
                let region = DerpRegion {
                    id: self.region.id,
                    code: self.region.code.clone(),
                    no_measure_no_home: self.region.no_measure_no_home,
                    nodes: core::mem::take(&mut self.region.nodes),
                };
                netmap.derp.insert_bounded(region);
            }
            // The rule is already being dropped; a destination missing the
            // field that overflowed is not a reason to reject the map.
            Context::FilterDestinationObject
                if self.filter.rule_overflow || self.filter.skip_set => {}
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
                    self.filter.rule_overflow = true;
                }
            }
            #[cfg(feature = "peer-api")]
            Context::PeerServiceObject => match self.pending.service_proto {
                4 => self.pending.services.peer_api4 = self.pending.service_port,
                6 => self.pending.services.peer_api6 = self.pending.service_port,
                _ => {}
            },
            #[cfg(feature = "peer-api")]
            Context::FilterCapGrantObject => {
                let grant = core::mem::take(&mut self.filter.grant);
                if !grant.caps.is_empty() && self.filter.grants.push(grant).is_err() {
                    self.filter.rule_overflow = true;
                }
            }
            Context::FilterRuleObject => self.commit_rule(netmap),
            Context::Root => netmap.responses += 1,
            _ => {}
        }
        self.key.clear();
    }

    fn commit_rule<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let set = self.filter.set.clone();
        if self.filter.skip_set || self.filter.rule_overflow {
            netmap.packet_filter.mark_truncated(set.as_str());
            return;
        }
        // Capability grants (`CapGrant`) grant no network access, and such a
        // rule carries no `DstPorts`. It is not malformed; only its grants of
        // capabilities this crate acts on are kept.
        #[cfg(feature = "peer-api")]
        for grant in core::mem::take(&mut self.filter.grants) {
            match netmap.packet_filter.push_cap_rule(
                set.as_str(),
                self.filter.rule.sources.iter().copied(),
                grant.destinations.iter().copied(),
                grant.caps,
            ) {
                Ok(()) => {}
                Err(Error::Full(_)) => netmap.packet_filter.mark_truncated(set.as_str()),
                Err(error) => self.fail(error),
            }
        }
        if self.filter.cap_grant && self.filter.rule.destinations.is_empty() {
            return;
        }
        if !self.filter.rule.is_well_formed() {
            self.fail(Error::MalformedField(MalformedField::PacketRule));
            return;
        }
        match netmap
            .packet_filter
            .push_rule(set.as_str(), core::mem::take(&mut self.filter.rule))
        {
            Ok(()) => {}
            Err(Error::Full(_)) => netmap.packet_filter.mark_truncated(set.as_str()),
            Err(error) => self.fail(error),
        }
    }

    /// Record a capability named by a member of a capability map.
    #[cfg(feature = "peer-api")]
    fn note_cap_member<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        if self.key_oversized {
            return;
        }
        match self.context() {
            Context::SelfCapMap if self.key == crate::netmap::peer_api::CAP_FILE_SHARING => {
                netmap.services.file_sharing = true;
            }
            Context::FilterCapMap => {
                let cap = PeerCapability::from_name(self.key.as_str());
                self.filter.grant.caps = self.filter.grant.caps.union(cap);
            }
            _ => {}
        }
    }

    fn commit_peer<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let Some(node_key) = self.pending.node_key else {
            // A record with no key names nothing and cannot be routed to. One
            // whose key could not be read replaces whatever was known.
            if self.pending.key_unreadable {
                netmap.peers.remove(self.pending.id);
                netmap.peers_truncated = true;
            }
            return;
        };
        // The server sends a node its own record in `PeersChanged` — the
        // captured session does exactly this. Adding it would make the node a
        // peer of itself: a handshake with its own key, which cannot complete,
        // retried forever.
        if netmap.node_key == Some(node_key) {
            // This node's own routes are not one peer among many: keep the
            // strict bound rather than act on a partial self record.
            if let Some(category) = self.pending.oversized {
                self.fail(Error::Full(category));
                return;
            }
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
        if let Some(category) = self.pending.oversized {
            if netmap.node_key.is_none() {
                // Without our own key this record may be a delayed self record
                // carrying route approval, which must not be silently lost.
                self.fail(Error::Full(category));
            } else {
                // Partial address or allowed-IP lists would misstate what the
                // peer may send and receive. Forget any older record for the
                // same id too, since control has just said it is stale.
                netmap.peers.remove(self.pending.id);
                netmap.peers_truncated = true;
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
        peer.ipv6_address = self.pending.ipv6_address;
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
        #[cfg(feature = "peer-api")]
        {
            peer.services = self.pending.services;
        }
        if let Err(error) = netmap.peers.upsert(peer.clone()) {
            if error == Error::Full(CapacityError::Peers) {
                let dropped = Self::insert_ranked(netmap, peer);
                if netmap.node_key.is_none() {
                    // One retained record may be the self record, which
                    // reconciliation removes. Keep the best overflow as the
                    // runner-up for that slot; anything below it is lost.
                    let runner_up = match self.deferred_peer.take() {
                        None => dropped,
                        Some(previous) => {
                            netmap.peers_truncated = true;
                            let (kept, lost) = if Self::rank(&dropped) > Self::rank(&previous) {
                                (dropped, previous)
                            } else {
                                (previous, dropped)
                            };
                            // Best effort beyond the bound: a self record this
                            // far down the ranking loses only its routes.
                            let _ = self.dropped_routes.push(DroppedRoutes {
                                node_key: lost.node_key,
                                approved_ipv4_default: lost.approved_ipv4_default(),
                                approved_ipv6_default: lost.approved_ipv6_default,
                                allowed_ips: lost.allowed_ips,
                            });
                            kept
                        }
                    };
                    self.deferred_peer = Some(runner_up);
                } else {
                    netmap.peers_truncated = true;
                }
            } else {
                self.fail(error);
            }
        }
    }

    /// Insert into a full peer table, keeping the highest-ranked peers.
    ///
    /// Control does not promise a stable peer order, so keeping whichever
    /// peers arrived first would retain a different subset after each full
    /// map and tear down tunnels to the peers that fell out. Ranking makes the
    /// retained set independent of arrival order: online peers first, then
    /// the lowest node id.
    ///
    /// Returns the peer left out: the new one, or the retained peer it
    /// displaced.
    fn insert_ranked<const PEERS: usize>(netmap: &mut Netmap<PEERS>, peer: Peer) -> Peer {
        let Some(worst) = netmap.peers.iter().min_by_key(|peer| Self::rank(peer)) else {
            return peer;
        };
        if Self::rank(&peer) <= Self::rank(worst) {
            return peer;
        }
        let worst = worst.clone();
        // Overwrite the displaced peer in place: reusing its slot needs no
        // allocation, so a heap-backed table that is out of memory cannot
        // lose both peers.
        match netmap.peers.get_mut(worst.id) {
            Some(slot) => {
                *slot = peer;
                worst
            }
            None => peer,
        }
    }

    fn rank(peer: &Peer) -> (bool, core::cmp::Reverse<u64>) {
        peer.retention_rank()
    }

    fn reconcile_self_peer<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        // A prior PeersChanged record can be recognized only after Node.Key is
        // known. Reconcile at the end of Node so its routes win regardless of
        // whether Key precedes or follows the route arrays in JSON.
        let Some(own) = netmap.node_key else { return };
        if !self.self_routes_seen {
            // Ranking may have left the self record in the deferred slot.
            let deferred_self = self
                .deferred_peer
                .as_ref()
                .filter(|peer| peer.node_key == own);
            let own_routes = netmap
                .peers
                .by_node_key(&own)
                .or(deferred_self)
                .map(|peer| {
                    (
                        peer.allowed_ips.clone(),
                        peer.approved_ipv4_default(),
                        peer.approved_ipv6_default,
                    )
                })
                .or_else(|| {
                    self.dropped_routes
                        .iter()
                        .find(|dropped| dropped.node_key == own)
                        .map(|dropped| {
                            (
                                dropped.allowed_ips.clone(),
                                dropped.approved_ipv4_default,
                                dropped.approved_ipv6_default,
                            )
                        })
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
        if let Some(peer) = self.deferred_peer.take()
            && peer.node_key != own
            && netmap.peers.upsert(peer.clone()).is_err()
        {
            Self::insert_ranked(netmap, peer);
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
        if self.pending.key_unreadable {
            // A rotated key that could not be read: the old one is stale.
            netmap.peers.remove(id);
            netmap.peers_truncated = true;
            return;
        }
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
        if self.pending.disco_unreadable {
            peer.disco_key = None;
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
                        self.self_home_derp_set = true;
                    }
                }
                #[cfg(feature = "peer-names")]
                "Name" => netmap.name = display_name(first_label(value)),
                _ => {}
            },
            Context::SelfAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    // More addresses than fit: keep the first ones, but never
                    // lose the IPv4 address this node is reached and routed by.
                    if let Err(cidr) = netmap.addresses.push(cidr)
                        && cidr.address.is_ipv4()
                        && !netmap.addresses.iter().any(|kept| kept.address.is_ipv4())
                        && let Some(last) = netmap.addresses.last_mut()
                    {
                        *last = cidr;
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::Address)),
            },
            Context::SelfPrimaryRoutes => match Cidr::parse(value) {
                // Extra routes beyond the bound are not served. Default
                // routes, which make this node an exit, take a subnet's slot.
                Ok(cidr) => {
                    if self.primary_route(netmap, cidr).is_err()
                        && cidr.prefix == 0
                        && let Some(subnet) = netmap
                            .primary_routes
                            .iter_mut()
                            .rev()
                            .find(|route| route.prefix != 0)
                    {
                        *subnet = cidr;
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
            #[cfg(feature = "peer-api")]
            Context::PeerTags => self.pending.services.tagged = true,
            #[cfg(feature = "peer-api")]
            Context::PeerServiceObject if key == "Proto" => {
                self.pending.service_proto = match value {
                    "peerapi4" => 4,
                    "peerapi6" => 6,
                    _ => 0,
                };
            }
            #[cfg(feature = "peer-api")]
            Context::SelfTags => netmap.services.tagged = true,
            #[cfg(feature = "peer-api")]
            Context::SelfCapabilities if value == crate::netmap::peer_api::CAP_FILE_SHARING => {
                netmap.services.file_sharing = true;
            }
            #[cfg(feature = "peer-api")]
            Context::FilterCapDestinations => match Network::parse(value) {
                Ok(network) => {
                    if self.filter.grant.destinations.push(network).is_err() {
                        self.filter.rule_overflow = true;
                    }
                }
                // An unreadable grant destination drops the rule: grants
                // only allow, so dropping one only denies.
                Err(_) => self.filter.rule_overflow = true,
            },
            #[cfg(feature = "peer-api")]
            Context::FilterCapList => {
                let cap = PeerCapability::from_name(value);
                self.filter.grant.caps = self.filter.grant.caps.union(cap);
            }
            // Retain the exact IPv6 host assignment separately from compact
            // IPv4 route lists, so exit forwarding can bind it to the node key.
            Context::PeerAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    if let core::net::IpAddr::V6(address) = cidr.address {
                        if cidr.prefix != 128
                            || self
                                .pending
                                .ipv6_address
                                .is_some_and(|previous| previous != address)
                        {
                            self.fail(Error::MalformedField(MalformedField::Address));
                        } else {
                            self.pending.ipv6_address = Some(address);
                        }
                    }
                    if let Some(cidr) = Cidr4::from_cidr(cidr)
                        && self.pending.addresses.push(cidr).is_err()
                    {
                        self.pending
                            .oversized
                            .get_or_insert(CapacityError::Addresses);
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
                        self.pending
                            .oversized
                            .get_or_insert(CapacityError::AllowedIps);
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
                if let Ok(core::net::SocketAddr::V4(endpoint)) = value.parse() {
                    retain_endpoint(&mut self.pending.endpoints, endpoint);
                }
            }
            Context::FilterSources => match Network::parse(value) {
                Ok(network) => {
                    if self.filter.rule.sources.push(network).is_err() {
                        self.filter.rule_overflow = true;
                    }
                }
                Err(_) => self.fail(Error::MalformedField(MalformedField::PolicySource)),
            },
            Context::FilterDestinationObject if key == "IP" => match Network::parse(value) {
                Ok(network) => self.filter.destination_network = Some(network),
                Err(_) => self.fail(Error::MalformedField(MalformedField::PolicyDestination)),
            },
            // A display code: keep what fits at a character boundary.
            Context::DerpRegion if key == "RegionCode" => {
                self.region.code.clear();
                for character in value.chars() {
                    if self.region.code.push(character).is_err() {
                        break;
                    }
                }
            }
            // A relay whose name does not fit cannot be dialled or verified:
            // skip that relay (an empty host is never retained), not the map.
            Context::DerpNode if key == "HostName" => match heapless::String::try_from(value) {
                Ok(host) => self.region.node_host = host,
                Err(_) => {
                    self.region.node_flags |= 4;
                    netmap.derp.mark_truncated();
                }
            },
            Context::DerpNode if key == "CertName" => match heapless::String::try_from(value) {
                Ok(host) => self.region.node_cert = host,
                Err(_) => {
                    // Verifying against the host name instead would accept a
                    // certificate control did not name, so drop the relay.
                    self.region.node_flags |= 4;
                    netmap.derp.mark_truncated();
                }
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
                        self.self_home_derp_set = true;
                    }
                    Err(_) => self.fail(Error::MalformedField(MalformedField::HomeDerp)),
                }
            }
            #[cfg(feature = "peer-api")]
            Context::SelfNode if key == "User" => {
                netmap.services.user_id = u64::try_from(value).unwrap_or(0);
            }
            #[cfg(feature = "peer-api")]
            Context::PeerObject if key == "User" => {
                self.pending.services.user_id = u64::try_from(value).unwrap_or(0);
            }
            #[cfg(feature = "peer-api")]
            Context::PeerServiceObject if key == "Port" => {
                self.pending.service_port = u16::try_from(value).unwrap_or(0);
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
                        self.filter.rule_overflow = true;
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
            Context::DerpRegion if self.key == "NoMeasureNoHome" => {
                self.region.no_measure_no_home = value;
            }
            Context::PeerObject | Context::PatchObject if self.key == "Online" => {
                self.pending.online = Some(value);
            }
            #[cfg(feature = "peer-api")]
            Context::PeerObject if self.key == "UnsignedPeerAPIOnly" => {
                self.pending.services.unsigned_peer_api_only = value;
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
        #[cfg(feature = "peer-api")]
        self.note_cap_member(netmap);
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
    /// A value too large to retain: a string past [`crate::netmap::MAX_STRING`]
    /// or a container nested past the scanner's depth.
    ///
    /// Control sends such values in fields this crate never reads (tailnet-lock
    /// signatures, capability maps, Hostinfo), and rejecting the whole map for
    /// them would cut the node off. Where the value would have been retained,
    /// the narrowest safe loss applies instead.
    fn on_oversized<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        match self.context() {
            // A partial rule could widen it (an empty protocol list means
            // every protocol), so the whole rule is dropped. Rules only allow
            // traffic, so a dropped rule can only deny.
            // Unknown, forward-compatible members are ignored at any size, as
            // they are when short.
            Context::FilterRuleObject
                if matches!(self.key.as_str(), "SrcIPs" | "DstPorts" | "IPProto") =>
            {
                self.filter.rule_overflow = true;
            }
            Context::FilterDestinationObject if matches!(self.key.as_str(), "IP" | "Ports") => {
                self.filter.rule_overflow = true;
            }
            Context::FilterPortsObject if matches!(self.key.as_str(), "First" | "Last") => {
                self.filter.rule_overflow = true;
            }
            Context::FilterSources | Context::FilterDestinations | Context::FilterProtocols => {
                self.filter.rule_overflow = true;
            }
            // An endpoint that cannot be read is one path lost, as for any
            // unparseable endpoint; the list was still sent and replaces the
            // old one.
            Context::PeerEndpoints | Context::PatchEndpoints => {
                self.pending.endpoints_present = true;
            }
            // A rule too large to read at all.
            Context::PacketFilterArray | Context::FilterSetArray => {
                netmap
                    .packet_filter
                    .mark_truncated(self.filter.set.as_str());
            }
            // A named set that cannot be read cannot replace the set's
            // earlier rules, which would then linger; and this node's own
            // addresses and routes are not optional.
            Context::PacketFiltersObject | Context::SelfAddresses | Context::SelfPrimaryRoutes => {
                self.fail(Error::Full(CapacityError::String));
            }
            // A partial address or allowed-IP list would misstate what the
            // peer may send; omit the peer, as for any oversized list.
            Context::PeerAddresses => {
                self.pending
                    .oversized
                    .get_or_insert(CapacityError::Addresses);
            }
            Context::PeerObject | Context::PatchObject if self.key == "Key" => {
                self.pending.key_unreadable = true;
            }
            Context::PeerObject | Context::PatchObject if self.key == "DiscoKey" => {
                self.pending.disco_unreadable = true;
            }
            // As for a short key that does not parse: this node's identity is
            // replaced by none, never left at a stale one.
            Context::SelfNode if self.key == "Key" => netmap.node_key = None,
            Context::SelfNode if self.key == "DiscoKey" => netmap.disco_key = None,
            // Retained DNS entries that do not fit are reported as dropped.
            Context::DnsDomains | Context::DnsResolvers => netmap.dns.truncated = true,
            Context::DnsResolverObject if self.key == "Addr" => netmap.dns.truncated = true,
            Context::PeerAllowedIps | Context::PeerPrimaryRoutes => {
                self.pending
                    .oversized
                    .get_or_insert(CapacityError::AllowedIps);
            }
            // A relay name that did not fit cannot be replaced by a guess
            // (verifying against the host name instead of the certificate
            // name would accept a certificate control did not name); drop
            // that relay. Unknown relay fields stay ignored.
            Context::DerpNode if matches!(self.key.as_str(), "HostName" | "CertName") => {
                self.region.node_flags |= 4;
                netmap.derp.mark_truncated();
            }
            // Anything else is unread, advisory, or only shortens what the
            // node knows (a peer without a parseable key is not retained).
            _ => {}
        }
        self.key.clear();
    }

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
                    | Token::Oversized
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
            Token::OversizedKey => {
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
            Token::Oversized => self.on_oversized(netmap),
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

/// Keep a bounded set of a peer's candidate paths rather than reject the map.
///
/// Tailscale clients list port-mapped and STUN-derived addresses before local
/// interface addresses, so server order is kept, duplicates are collapsed, and
/// later candidates are dropped once the list is full. The one exception is
/// IPv4 link-local, which is reachable only on the same segment: a later
/// routable candidate takes the place of the last retained link-local one.
/// A dropped candidate costs at most a direct path; the peer stays reachable
/// through DERP.
fn retain_endpoint(
    endpoints: &mut heapless::Vec<core::net::SocketAddrV4, { crate::netmap::MAX_ENDPOINTS }>,
    endpoint: core::net::SocketAddrV4,
) {
    if endpoints.contains(&endpoint) {
        return;
    }
    if endpoints.push(endpoint).is_ok() || endpoint.ip().is_link_local() {
        return;
    }
    if let Some(index) = endpoints.iter().rposition(|kept| kept.ip().is_link_local()) {
        endpoints.remove(index);
        let _ = endpoints.push(endpoint);
    }
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
                self_home_derp_set: false,
                pending: Pending::new(),
                deferred_peer: None,
                dropped_routes: heapless::Vec::new(),
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
        self.state.self_home_derp_set = false;
        self.state.pending.reset();
        self.state.deferred_peer = None;
        self.state.dropped_routes.clear();
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

    /// Whether this response supplied a valid explicit self home. Transport
    /// staging can otherwise inherit a newer local choice made mid-document.
    pub(crate) fn sets_home_derp(&self) -> bool {
        self.state.self_home_derp_set
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

#[cfg(test)]
mod cap_grant_tests {
    use super::*;

    /// Grants with app capabilities arrive as rules with `CapGrant` and no
    /// `DstPorts`. They grant no network access and must not fail the map.
    #[test]
    fn a_grant_only_rule_is_accepted_and_grants_no_traffic() {
        let document = r#"{"PacketFilter":[
            {"SrcIPs":["100.64.0.2"],"CapGrant":[{"Dsts":["100.64.0.9/32"],
              "CapMap":{"https://tailscale.com/cap/file-send":[]}}]},
            {"SrcIPs":["100.64.0.3"],"DstPorts":[{"IP":"100.64.0.9","Ports":{"First":22,"Last":22}}]}
        ]}"#;
        let mut netmap = Netmap::<4>::new();
        let mut parser = Parser::<4>::new();
        parser.push(&mut netmap, document.as_bytes()).unwrap();
        parser.finish(&mut netmap).unwrap();
        let policy = &netmap.packet_filter;
        assert_eq!(policy.rule_count(), 1);
        let to_self = core::net::Ipv4Addr::new(100, 64, 0, 9);
        assert!(!policy.allows(core::net::Ipv4Addr::new(100, 64, 0, 2), to_self, 6, 22));
        assert!(policy.allows(core::net::Ipv4Addr::new(100, 64, 0, 3), to_self, 6, 22));
    }
}
