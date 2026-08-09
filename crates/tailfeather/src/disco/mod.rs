//! Disco: finding a direct path to a peer.
//!
//! # What it is for
//!
//! WireGuard needs to know where to send a packet, and on the internet that
//! answer changes: peers move, NATs rewrite ports, and neither side can be
//! told its own public address by anything except the other side. Disco is the
//! probe that discovers it — pings and pongs sent to every candidate address a
//! peer might be at, with the winner becoming the endpoint the tunnel uses.
//!
//! # It shares the WireGuard socket
//!
//! Disco messages travel on the same UDP socket as the tunnel, alongside
//! WireGuard's own packets, and are told apart by a six-byte magic prefix. That
//! is not an accident of implementation: a probe that arrived on a different
//! port would prove a path that the tunnel cannot use, because a NAT maps ports
//! independently.
//!
//! WireGuard's first byte is a message type in 1..=4, and disco's is `'T'`
//! (0x54), so the two cannot be confused. [`is_disco`] is the demultiplexer.
//!
//! # Different cryptography from everything else
//!
//! Disco uses NaCl's `crypto_box` — X25519 with HSalsa20 key derivation and
//! XSalsa20-Poly1305 — where the rest of the protocol uses ChaCha20-Poly1305.
//! It also uses the *disco* keypair, not the node key, so a disco message
//! cannot be replayed as anything else and a compromised disco key cannot
//! impersonate the node.

#![forbid(unsafe_code)]

pub mod message;
pub mod packet;

pub use message::{CallMeMaybe, Message, Ping, Pong, TxId};
pub use packet::{MAX_PACKET, open, seal};

/// `TS💬` — the two ASCII letters followed by UTF-8 for U+1F4AC.
///
/// Six bytes, not five: the emoji is four. Getting the length wrong shifts the
/// sender's key by a byte and every message fails to open, with nothing to say
/// why.
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];

/// The nonce NaCl boxes carry, prepended to the ciphertext.
pub const NONCE_LEN: usize = 24;

/// Poly1305's tag.
pub const TAG_LEN: usize = 16;

/// `magic ‖ sender disco public key ‖ nonce`.
pub const HEADER_LEN: usize = MAGIC.len() + 32 + NONCE_LEN;

/// Whether a datagram on the shared socket is a disco message.
///
/// The alternative — assuming anything that fails to parse as WireGuard is
/// disco — would hand malformed tunnel packets to the wrong parser and report
/// the wrong error.
pub fn is_disco(datagram: &[u8]) -> bool {
    datagram.starts_with(&MAGIC)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a disco packet, or too short to be one.
    Malformed,
    /// The box did not open: the wrong key, or a forgery.
    Decryption,
    /// A message type or version this implementation does not handle.
    Unsupported,
    /// The output buffer was too small.
    BufferTooSmall,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed disco packet",
            Self::Decryption => "the disco box did not open",
            Self::Unsupported => "unsupported disco message",
            Self::BufferTooSmall => "output buffer too small",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_is_the_bytes_of_ts_and_a_speech_bubble() {
        assert_eq!(MAGIC.len(), 6);
        assert_eq!(&MAGIC, "TS\u{1f4ac}".as_bytes());
        assert_eq!(&MAGIC[..2], b"TS");
    }

    #[test]
    fn disco_is_told_from_wireguard_by_its_first_byte() {
        // WireGuard message types are 1..=4 and disco starts with 'T' = 0x54,
        // so nothing on the shared socket is ambiguous.
        assert!(is_disco(&MAGIC));
        for wireguard_type in 1u8..=4 {
            let datagram = [wireguard_type, 0, 0, 0, 0, 0, 0, 0];
            assert!(!is_disco(&datagram), "type {wireguard_type} read as disco");
        }
        assert!(!is_disco(b"TS"), "a prefix of the magic is not the magic");
        assert!(!is_disco(&[]));
    }
}
