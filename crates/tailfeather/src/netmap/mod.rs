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
//! Fields a headless node acts on: identity, addresses, endpoints, and the DERP
//! map. `Hostinfo`, `UserProfiles`, `PacketFilters` and `DNSConfig` are skipped
//! wholesale rather than parsed into something nothing reads.

#![forbid(unsafe_code)]

pub mod derp;
pub mod frame;
pub mod parser;
pub mod peer;
pub mod scanner;

pub use derp::{DerpMap, DerpNode, DerpRegion};
pub use frame::FrameReader;
pub use parser::{Netmap, Parser};
pub use peer::{Cidr, Peer, PeerTable};
pub use scanner::{Scanner, Token};

/// How many peers a netmap may name. A small tailnet, sized for a device with
/// tens of kilobytes of RAM rather than a laptop.
pub const MAX_PEERS: usize = 32;

/// Addresses assigned to one node: normally one IPv4 and one IPv6.
pub const MAX_ADDRESSES: usize = 4;

/// Subnets a peer will accept traffic for. More than its own addresses, because
/// a subnet router or exit node advertises others.
pub const MAX_ALLOWED_IPS: usize = 8;

/// Candidate paths to one peer.
pub const MAX_ENDPOINTS: usize = 8;

pub const MAX_DERP_REGIONS: usize = 8;
pub const MAX_DERP_NODES: usize = 4;

/// The longest single JSON string the parser will materialise.
///
/// This bounds the parser's scratch buffer, and it is the *only* thing about
/// the document whose size matters — not the number of peers, not the total
/// length. The longest string in the captured map is a 73-character node name.
pub const MAX_STRING: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not valid JSON.
    Json,
    /// A string longer than [`MAX_STRING`], or more peers than [`MAX_PEERS`].
    ///
    /// Deliberately not silent. A netmap missing a peer because the table was
    /// full would look like that peer being offline, and would be diagnosed as
    /// a network problem.
    Full,
    /// A key or address the server sent could not be parsed.
    Malformed,
    /// The frame length prefix announced more than the reader can hold.
    FrameTooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Json => "malformed JSON",
            Self::Full => "the netmap does not fit the configured bounds",
            Self::Malformed => "a field could not be parsed",
            Self::FrameTooLarge => "map frame larger than the reader can hold",
        })
    }
}

impl core::error::Error for Error {}
