//! A minimal HTTP/2 client: `no_std`, allocation-free, sans-io.
//!
//! # Scope
//!
//! Enough HTTP/2 to be a client and no more. No server, no push, no priority,
//! no trailers, and a small fixed number of concurrent streams. That is not
//! laziness — HTTP/2's full surface is large, and every feature carried is
//! another piece of state that has to be right. What this omits, it omits
//! explicitly, and refuses rather than half-implements.
//!
//! # What is genuinely hard here
//!
//! Two things, and both fail silently rather than loudly:
//!
//! **HPACK's dynamic table is connection state built from the peer's stream.**
//! Skipping an insertion does not lose a header; it shifts every subsequent
//! index, so later headers decode as *different headers*. See [`hpack::dynamic`].
//!
//! **Flow control is not optional.** A receiver starts with a 65535-byte window
//! per stream and per connection, and a sender that has exhausted it simply
//! stops. A long-poll streaming a netmap will deliver exactly 65535 bytes and
//! then hang, which looks like a server fault and is not. See [`conn`].
//!
//! # Sans-io
//!
//! [`conn::Connection`] never touches a socket. It is fed the bytes that arrived
//! and writes the bytes to send, so the same code runs over TCP, over a ts2021
//! Noise channel, and over a captured session in a test.
//!
//! ```
//! let mut connection = micro_h2::Connection::new();
//! let mut out = [0u8; 256];
//! let written = connection.start(&mut out).unwrap();
//! assert!(written > 24); // client preface plus SETTINGS and WINDOW_UPDATE
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod conn;
pub mod frame;
pub mod hpack;

pub use conn::{Connection, Event};
pub use frame::{FrameHeader, FrameType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// More bytes are needed before this can be decoded.
    Incomplete,
    /// The peer sent something that is not valid HTTP/2.
    Protocol,
    /// A header block could not be decoded. Fatal for the connection: HPACK
    /// state cannot be resynchronised.
    Hpack,
    /// A fixed buffer was too small.
    BufferTooSmall,
    /// A frame larger than the negotiated maximum.
    FrameTooLarge,
    /// The peer closed the connection with GOAWAY.
    GoAway,
    /// The peer reset the stream.
    StreamReset,
    /// More concurrent streams than this client supports.
    TooManyStreams,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "incomplete",
            Self::Protocol => "http/2 protocol error",
            Self::Hpack => "header decoding failed",
            Self::BufferTooSmall => "buffer too small",
            Self::FrameTooLarge => "frame too large",
            Self::GoAway => "the server sent GOAWAY",
            Self::StreamReset => "the stream was reset",
            Self::TooManyStreams => "too many concurrent streams",
        })
    }
}

impl core::error::Error for Error {}
