//! DERP: relaying for peers with no direct path.
//!
//! # What it is for
//!
//! Disco finds a direct path when one exists. Often none does — symmetric NATs,
//! restrictive firewalls, networks that drop UDP entirely — and then traffic has
//! to go through a server that both sides can reach. DERP is that server, and it
//! is deliberately dumb: it forwards WireGuard packets by destination *node key*
//! without being able to read any of them.
//!
//! It is also how two nodes bootstrap a direct path. `CallMeMaybe` travels over
//! the relay to tell a peer where to probe, which is a step that needs a working
//! path in order to establish a better one.
//!
//! # Shape
//!
//! An HTTP upgrade to `/derp`, then frames: `1B type ‖ 4B length BE ‖ payload`.
//! The server opens with its public key; the client answers with its own and a
//! sealed hello; after that, packets are addressed by node key.
//!
//! Note the length is **big-endian and four bytes**, where controlbase records
//! use two and map responses use four *little*-endian. Three framings in one
//! protocol, no two alike.

#![forbid(unsafe_code)]

pub mod client;
pub mod frame;

pub use client::{Client, MAX_PACKET};
pub use frame::{Frame, FrameType};

/// `DERP🔑` — four ASCII letters and the four UTF-8 bytes of U+1F511.
pub const MAGIC: [u8; 8] = [b'D', b'E', b'R', b'P', 0xf0, 0x9f, 0x94, 0x91];

/// The protocol version this client speaks. Version 2 is what makes
/// `RecvPacket` carry the sender's key; version 1 left the receiver guessing.
pub const VERSION: u32 = 2;

/// Where the upgrade request goes.
pub const PATH: &str = "/derp";

/// The token both ends name the protocol with.
pub const UPGRADE_TOKEN: &str = "DERP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// More bytes are needed.
    Incomplete,
    /// Not a DERP frame, or not the one expected here.
    Malformed,
    /// The server's hello did not open, or ours was refused.
    Decryption,
    /// A frame larger than this client will hold.
    TooLarge,
    /// The output buffer was too small.
    BufferTooSmall,
    /// The server named a protocol version this client does not speak.
    Unsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "incomplete",
            Self::Malformed => "malformed DERP frame",
            Self::Decryption => "the DERP handshake did not open",
            Self::TooLarge => "frame larger than the client will hold",
            Self::BufferTooSmall => "output buffer too small",
            Self::Unsupported => "unsupported DERP version",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_is_what_a_real_server_sends() {
        // Read off the wire from Headscale's embedded DERP:
        // 01 00000028 44455250 f09f9491 <32-byte key>
        assert_eq!(MAGIC.len(), 8);
        assert_eq!(&MAGIC, "DERP\u{1f511}".as_bytes());
        assert_eq!(&MAGIC[..4], b"DERP");
    }
}
