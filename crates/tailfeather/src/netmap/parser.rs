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
//! so whole subtrees — `Hostinfo`, `UserProfiles`, `PacketFilters`, `DNSConfig`
//! — are skipped for the cost of a push and a pop. A server that adds a field
//! costs nothing, which matters for a protocol that gains them regularly.
//!
//! # What a delta means
//!
//! `PeersChanged` and `Peers` are read identically — both are whole records —
//! but `PeersChangedPatch` is not: it names an existing peer and a few fields,
//! and everything it does not mention must be left alone. Applying a patch as if
//! it were a record would blank every peer's endpoints on every heartbeat.

use crate::keys::{DiscoPublic, NodePublic};

use crate::netmap::derp::{DEFAULT_DERP_PORT, DerpMap, DerpNode, DerpRegion};
use crate::netmap::peer::{Cidr, Peer, PeerTable};
use crate::netmap::scanner::{Scanner, Token};
use crate::netmap::{Error, MAX_PEERS};

/// Where in the document the parser currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// The outermost object of one MapResponse.
    Root,
    /// `Node`: this node's own record.
    SelfNode,
    /// The array of `Peers` or `PeersChanged`; both carry whole records.
    PeerArray,
    PeerObject,
    /// An array of strings inside a peer: `Addresses`, `AllowedIPs`,
    /// `Endpoints`.
    PeerAddresses,
    PeerAllowedIps,
    PeerEndpoints,
    /// The self node's address arrays.
    SelfAddresses,
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
    /// Anything this parser does not read. Nested containers inherit it, so a
    /// whole subtree costs one push and one pop.
    Ignored,
}

/// The state a netmap is accumulated into.
#[derive(Default, Clone)]
pub struct Netmap<const PEERS: usize = MAX_PEERS> {
    pub peers: PeerTable<PEERS>,
    pub derp: DerpMap,
    /// This node's own record, once the server has sent one.
    pub node_key: Option<NodePublic>,
    pub disco_key: Option<DiscoPublic>,
    pub addresses: heapless::Vec<Cidr, { crate::netmap::MAX_ADDRESSES }>,
    /// How many complete MapResponses have been applied.
    pub responses: usize,
}

impl<const PEERS: usize> Netmap<PEERS> {
    pub const fn new() -> Self {
        Self {
            peers: PeerTable::new(),
            derp: DerpMap::new(),
            node_key: None,
            disco_key: None,
            addresses: heapless::Vec::new(),
            responses: 0,
        }
    }
}

/// A peer being built, or a patch being collected.
#[derive(Default)]
struct Pending {
    id: u64,
    node_key: Option<NodePublic>,
    disco_key: Option<DiscoPublic>,
    online: Option<bool>,
    home_derp: Option<u16>,
    addresses: heapless::Vec<Cidr, { crate::netmap::MAX_ADDRESSES }>,
    allowed_ips: heapless::Vec<Cidr, { crate::netmap::MAX_ALLOWED_IPS }>,
    endpoints: heapless::Vec<core::net::SocketAddr, { crate::netmap::MAX_ENDPOINTS }>,
    /// Set when a patch mentioned `Endpoints`, so an empty list can be told
    /// apart from an absent one.
    endpoints_present: bool,
}

impl Pending {
    const fn new() -> Self {
        Self {
            id: 0,
            node_key: None,
            disco_key: None,
            online: None,
            home_derp: None,
            addresses: heapless::Vec::new(),
            allowed_ips: heapless::Vec::new(),
            endpoints: heapless::Vec::new(),
            endpoints_present: false,
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
    node_host: heapless::String<64>,
    node_port: u16,
    node_stun: u16,
}

impl PendingRegion {
    const fn new() -> Self {
        Self {
            id: 0,
            code: heapless::String::new(),
            nodes: heapless::Vec::new(),
            node_host: heapless::String::new(),
            node_port: 0,
            node_stun: 0,
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
    pending: Pending,
    region: PendingRegion,
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
        let key = self.key.as_str();
        match self.context() {
            // The outermost object of a response has no enclosing container.
            Context::Ignored if self.stack.is_empty() => Context::Root,
            Context::Root => match key {
                "Node" => Context::SelfNode,
                "Peers" | "PeersChanged" => Context::PeerArray,
                "PeersChangedPatch" => Context::PatchArray,
                "PeersRemoved" => Context::RemovedArray,
                "DERPMap" => Context::DerpMapObject,
                _ => Context::Ignored,
            },
            Context::SelfNode => match key {
                "Addresses" => Context::SelfAddresses,
                _ => Context::Ignored,
            },
            Context::PeerArray => Context::PeerObject,
            Context::PeerObject => match key {
                "Addresses" => Context::PeerAddresses,
                "AllowedIPs" => Context::PeerAllowedIps,
                "Endpoints" => Context::PeerEndpoints,
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
            // Anything inside something ignored is ignored.
            _ => Context::Ignored,
        }
    }

    fn on_start<const PEERS: usize>(&mut self, _netmap: &mut Netmap<PEERS>) {
        let context = self.child_context();
        match context {
            Context::PeerObject | Context::PatchObject => self.pending.reset(),
            Context::DerpRegion => {
                self.region = PendingRegion::default();
                // The member name is the region id, and is the only place it is
                // guaranteed to appear.
                self.region.id = self.key.parse().unwrap_or(0);
            }
            Context::DerpNode => {
                self.region.node_host.clear();
                self.region.node_port = DEFAULT_DERP_PORT;
                self.region.node_stun = 0;
            }
            _ => {}
        }
        if self.stack.push(context).is_err() {
            self.fail(Error::Full);
        }
        self.key.clear();
    }

    fn on_end<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>) {
        let context = self.stack.pop().unwrap_or(Context::Ignored);
        match context {
            Context::PeerObject => self.commit_peer(netmap),
            Context::PatchObject => self.apply_patch(netmap),
            Context::DerpNode => {
                let node = DerpNode {
                    host_name: self.region.node_host.clone(),
                    port: self.region.node_port,
                    stun_port: self.region.node_stun,
                };
                let _ = self.region.nodes.push(node);
            }
            Context::DerpRegion => {
                let region = DerpRegion {
                    id: self.region.id,
                    code: self.region.code.clone(),
                    nodes: core::mem::take(&mut self.region.nodes),
                };
                if let Err(e) = netmap.derp.insert(region) {
                    self.fail(e);
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
            return;
        }
        let mut peer = Peer::new(self.pending.id, node_key);
        peer.disco_key = self.pending.disco_key;
        peer.online = self.pending.online.unwrap_or(false);
        peer.home_derp = self.pending.home_derp.unwrap_or(0);
        peer.addresses = self.pending.addresses.clone();
        peer.allowed_ips = self.pending.allowed_ips.clone();
        peer.endpoints = self.pending.endpoints.clone();
        if let Err(e) = netmap.peers.upsert(peer) {
            self.fail(e);
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
        if let Some(online) = self.pending.online {
            peer.online = online;
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
                "Key" => {
                    netmap.node_key = NodePublic::parse(value).ok();
                    // A response is not obliged to describe this node before it
                    // lists peers, so a record for ourselves may already be in
                    // the table.
                    if let Some(own) = netmap.node_key {
                        let ours: heapless::Vec<u64, 4> = netmap
                            .peers
                            .iter()
                            .filter(|p| p.node_key == own)
                            .map(|p| p.id)
                            .collect();
                        for id in ours {
                            netmap.peers.remove(id);
                        }
                    }
                }
                "DiscoKey" => netmap.disco_key = DiscoPublic::parse(value).ok(),
                _ => {}
            },
            Context::SelfAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    let _ = netmap.addresses.push(cidr);
                }
                Err(e) => self.fail(e),
            },
            Context::PeerObject | Context::PatchObject => match key {
                "Key" => match NodePublic::parse(value) {
                    Ok(parsed) => self.pending.node_key = Some(parsed),
                    Err(_) => self.fail(Error::Malformed),
                },
                "DiscoKey" => match DiscoPublic::parse(value) {
                    Ok(parsed) => self.pending.disco_key = Some(parsed),
                    Err(_) => self.fail(Error::Malformed),
                },
                _ => {}
            },
            Context::PeerAddresses => match Cidr::parse(value) {
                Ok(cidr) => {
                    let _ = self.pending.addresses.push(cidr);
                }
                Err(e) => self.fail(e),
            },
            Context::PeerAllowedIps => match Cidr::parse(value) {
                Ok(cidr) => {
                    let _ = self.pending.allowed_ips.push(cidr);
                }
                Err(e) => self.fail(e),
            },
            Context::PeerEndpoints | Context::PatchEndpoints => {
                self.pending.endpoints_present = true;
                // An endpoint that does not parse is one path lost, not a
                // broken netmap: the server is entitled to advertise address
                // families this node cannot use.
                if let Ok(endpoint) = value.parse() {
                    let _ = self.pending.endpoints.push(endpoint);
                }
            }
            Context::DerpRegion if key == "RegionCode" => {
                self.region.code = heapless::String::try_from(value).unwrap_or_default();
            }
            Context::DerpNode if key == "HostName" => {
                self.region.node_host = heapless::String::try_from(value).unwrap_or_default();
            }
            _ => {}
        }
        self.key.clear();
    }

    fn on_number<const PEERS: usize>(&mut self, netmap: &mut Netmap<PEERS>, value: i64) {
        let key = self.key.as_str();
        match self.context() {
            Context::PeerObject | Context::PatchObject => match key {
                "ID" | "NodeID" => self.pending.id = value as u64,
                "HomeDERP" | "DERPRegion" => self.pending.home_derp = Some(value as u16),
                _ => {}
            },
            Context::RemovedArray => {
                netmap.peers.remove(value as u64);
            }
            Context::DerpRegion if key == "RegionID" => self.region.id = value as u16,
            Context::DerpNode => match key {
                "DERPPort" => self.region.node_port = value as u16,
                "STUNPort" => self.region.node_stun = value as u16,
                _ => {}
            },
            _ => {}
        }
        self.key.clear();
    }

    fn on_bool(&mut self, value: bool) {
        if matches!(self.context(), Context::PeerObject | Context::PatchObject)
            && self.key == "Online"
        {
            self.pending.online = Some(value);
        }
        self.key.clear();
    }
}

impl State {
    fn on_token<const PEERS: usize>(
        &mut self,
        netmap: &mut Netmap<PEERS>,
        token: Token<'_>,
    ) -> Result<(), Error> {
        match token {
            Token::StartObject | Token::StartArray => self.on_start(netmap),
            Token::EndObject | Token::EndArray => self.on_end(netmap),
            Token::Key(key) => {
                self.key = heapless::String::try_from(key).unwrap_or_default();
            }
            Token::Str(value) => self.on_string(netmap, value),
            Token::Int(value) => self.on_number(netmap, value),
            Token::Bool(value) => self.on_bool(value),
            Token::Null => self.key.clear(),
        }
        Ok(())
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
                pending: Pending::new(),
                region: PendingRegion::new(),
                failed: None,
            },
        }
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
        match self.state.failed {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
