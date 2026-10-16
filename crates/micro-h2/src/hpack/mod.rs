//! HPACK (RFC 7541): header compression for HTTP/2.
//!
//! Asymmetric on purpose. Decoding must be complete, because the *server*
//! decides how to encode and Go's HTTP/2 server uses the dynamic table and
//! Huffman freely. Encoding can be as simple as we like, because a literal,
//! unindexed, uncompressed header is always legal — so this crate emits those
//! and keeps no encoder-side table at all.
//!
//! That asymmetry removes the hardest failure mode. An encoder dynamic table has
//! to stay in step with the peer's decoder copy, and a divergence corrupts every
//! subsequent header rather than failing outright. Not having one cannot
//! diverge.

pub mod decode;
pub mod dynamic;
pub mod encode;
pub mod huffman;
pub mod static_table;

pub use decode::{Decoder, Header};
pub use dynamic::DynamicTable;

/// The dynamic table size an endpoint assumes before any `SETTINGS` says
/// otherwise (RFC 7540 section 6.5.2).
/// The receive-side table size advertised by this constrained client. HTTP/2
/// peers must honor it, so the fixed decoder never needs the desktop default.
pub const DEFAULT_TABLE_SIZE: usize = 256;
