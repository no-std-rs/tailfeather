//! The network map: who else is on the tailnet, and how to reach them.
//!
//! # Streaming, not buffering
//!
//! A `MapResponse` for a two-node lab is 27 KB. A real tailnet's is megabytes,
//! and the connection carrying it is a long poll that never ends — so there is
//! no "the document" to hold, only a stream of them. Nothing here ever has more
//! than one JSON token and one peer under construction in hand, whatever the
//! size of what is arriving.
//!
//! That is the whole reason this is a push parser rather than a `serde` model:
//! the shape of the API is what enforces the property. A parser that returned a
//! `MapResponse` would have had to build one.
//!
//! # Deltas
//!
//! The first response is a full map; almost everything after it is a delta, and
//! the capture bears that out — five of eleven captured responses carry only
//! changes. Deltas *omit* fields rather than repeating them, so treating each
//! response as a full map silently discards every peer it did not mention. The
//! three forms are handled separately:
//!
//! - `PeersChanged` — whole peer records to insert or replace
//! - `PeersChangedPatch` — named fields of an existing peer, and nothing else
//! - `PeersRemoved` — node ids to forget
//!
//! # Scope
//!
//! Fields a headless node acts on: identity, addresses, endpoints, packet
//! filters, the DERP map, and the bounded part of `DNSConfig`. `Hostinfo` and
//! `UserProfiles` are skipped wholesale rather than parsed into something
//! nothing reads, as is `DNSConfig`'s unbounded `Routes` map — see
//! [`crate::netmap::dns`].

#![forbid(unsafe_code)]

pub mod derp;
pub mod dns;
pub mod frame;
pub mod parser;
pub mod peer;
pub mod policy;
pub mod scanner;

pub use derp::{DerpMap, DerpNode, DerpRegion};
pub use dns::DnsConfig;
pub use frame::FrameReader;
pub use parser::{Netmap, Parser};
pub use peer::{Cidr, Cidr4, Peer, PeerTable};
pub use policy::{Destination, FilterRule, Network, PacketPolicy};
pub use scanner::{Scanner, Token};

/// How many peers a netmap may name. A small tailnet, sized for a device with
/// tens of kilobytes of RAM rather than a laptop.
pub const MAX_PEERS: usize = 32;

/// Addresses assigned to one node: normally one IPv4 and one IPv6.
pub const MAX_ADDRESSES: usize = 4;
pub const MAX_PRIMARY_ROUTES: usize = 8;

/// Subnets a peer will accept traffic for. More than its own addresses, because
/// a subnet router or exit node advertises others.
pub const MAX_ALLOWED_IPS: usize = 8;

/// Candidate paths to one peer.
pub const MAX_ENDPOINTS: usize = 8;

/// Hosted publishes several dozen regions. The map retains two usable relays
/// per region, while [`crate::Node`] limits live sessions separately.
pub const MAX_DERP_REGIONS: usize = 40;
/// A primary and one failover relay are retained for each region.
pub const MAX_DERP_NODES: usize = 2;
/// DERP DNS names retained by the embedded map. This keeps the capacity that
/// previous releases accepted, including custom relay hostnames.
pub const MAX_DERP_HOSTNAME: usize = 64;

/// The longest retained display name, in bytes: a DNS label's limit. Longer
/// names are cut at a character boundary.
#[cfg(feature = "peer-names")]
pub const MAX_PEER_NAME: usize = 63;

/// Search domains retained from `DNSConfig`. Headscale publishes one; a
/// tailnet with split DNS publishes a handful.
pub const MAX_DNS_DOMAINS: usize = 4;
/// Upstream resolvers retained from `DNSConfig`, matching the three the
/// gateway will actually query plus one spare.
pub const MAX_DNS_RESOLVERS: usize = 4;
/// The longest domain or resolver address retained. A DoH URL longer than this
/// is dropped rather than stored cut in half.
pub const MAX_DNS_NAME: usize = 64;

/// The longest single JSON string the parser will materialise.
///
/// This bounds the parser's scratch buffer, and it is the *only* thing about
/// the document whose size matters — not the number of peers, not the total
/// length. The longest string in the captured map is a 73-character node name.
/// Maximum decoded JSON string in a streamed netmap. Hosted policy payloads
/// can exceed one KiB even when the retained peer/DERP fields are short.
pub const MAX_STRING: usize = 2 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityError {
    Peers,
    DerpRegions,
    Routes,
    Addresses,
    AllowedIps,
    Endpoints,
    PacketPolicy,
    String,
    ParserDepth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedField {
    DerpRegionId,
    PacketDestination,
    PacketRule,
    NodeKey,
    DiscoKey,
    Address,
    AllowedIp,
    PolicySource,
    PolicyDestination,
    HomeDerp,
    PeerId,
    RemovedPeerId,
    DerpPort,
    StunPort,
    PolicyPort,
    PolicyProtocol,
}

impl core::fmt::Display for CapacityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Peers => "peer table",
            Self::DerpRegions => "DERP region table",
            Self::Routes => "route table",
            Self::Addresses => "address table",
            Self::AllowedIps => "allowed-IP table",
            Self::Endpoints => "endpoint table",
            Self::PacketPolicy => "packet policy",
            Self::String => "JSON string",
            Self::ParserDepth => "JSON nesting depth",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not valid JSON.
    Json,
    /// One specific bounded category exceeded its configured capacity.
    ///
    /// Deliberately not silent. A netmap missing a peer because the table was
    /// full would look like that peer being offline, and would be diagnosed as
    /// a network problem.
    Full(CapacityError),
    /// A key or address the server sent could not be parsed.
    Malformed,
    /// A retained field failed to parse. Only its category, never its value,
    /// is retained for diagnostics.
    MalformedField(MalformedField),
    /// The frame length prefix announced more than the reader can hold.
    FrameTooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json => f.write_str("malformed JSON"),
            Self::Full(category) => {
                write!(f, "netmap {category} exceeds its configured bound")
            }
            Self::Malformed => f.write_str("a field could not be parsed"),
            Self::MalformedField(field) => write!(f, "malformed {field:?}"),
            Self::FrameTooLarge => f.write_str("map frame larger than the reader can hold"),
        }
    }
}

impl core::error::Error for Error {}
