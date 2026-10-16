//! The Tailscale control-plane transport, known upstream as ts2021.
//!
//! A TCP connection carrying a Noise IK handshake, then a record layer, and
//! HTTP/2 inside that. This crate covers everything below the HTTP/2: the
//! bootstrap over HTTP/1.1, the handshake, the framing, and the early payload
//! the server sends before its HTTP/2 preface.
//!
//! # Sans-io
//!
//! Nothing here touches a socket. Functions take the bytes that arrived and
//! write the bytes to send, so the same code runs under Bazel tests on the
//! host, on the harness's reactor, and later on embassy-net. It also means the
//! whole protocol can be replayed against a captured session.
//!
//! # Where the constants come from
//!
//! Every byte-level constant in this crate was read out of
//! `tests/vectors/ts2021-session.pcap` — a real tailscaled 1.94.2 registering
//! with a real Headscale v0.29.3 — not from documentation. Each is commented
//! with what the capture showed. The one that matters most is in [`record`]:
//! the record nonce counter is **big-endian**, where WireGuard's is
//! little-endian, and the two agree at counter zero. An implementation that
//! gets this wrong completes the handshake, exchanges one correct record, and
//! then fails.

#![forbid(unsafe_code)]

pub mod early;
pub mod ik;
pub mod record;
pub mod upgrade;

pub use early::{EarlyReader, MAGIC as EARLY_MAGIC, PROBE_LEN};
pub use ik::{Handshake, INITIATION_LEN, RESPONSE_LEN, initiate};
pub use record::{HEADER_LEN, MAX_MESSAGE, MAX_PLAINTEXT, Session, TAG_LEN};

/// The capability version this client advertises.
///
/// It appears in three places that must agree: the `?v=` on `/key`, the
/// big-endian version field at the front of the initiation, and — critically —
/// the Noise prologue, which binds it into the handshake so it cannot be
/// downgraded by an attacker rewriting the header.
///
/// 131 is what tailscaled 1.94.2 sent in the captured session. The lab's
/// Headscale rejects anything below 113, recorded in
/// `tests/vectors/server_key.json`; that floor rises as servers are upgraded,
/// which is why it is probed rather than assumed.
pub const CAPABILITY_VERSION: u16 = 131;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A message was the wrong length, or had the wrong type byte.
    Malformed,
    /// AEAD tag verification failed. On the handshake this usually means the
    /// server's key or the prologue disagreed; on a record it means the nonce
    /// counters have diverged.
    Decryption,
    /// A public key with no contributory Diffie-Hellman output.
    InvalidPublicKey,
    /// The output buffer was shorter than the message to be written.
    BufferTooSmall,
    /// A record claimed a length past what the protocol permits.
    RecordTooLong,
    /// The session has sent or received its last usable message.
    Exhausted,
    /// The server's HTTP response was not the upgrade we asked for.
    UpgradeRefused,
    /// The bytes so far are a valid prefix; more are needed.
    Incomplete,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed message",
            Self::Decryption => "decryption failed",
            Self::InvalidPublicKey => "invalid public key",
            Self::BufferTooSmall => "output buffer too small",
            Self::RecordTooLong => "record longer than the protocol allows",
            Self::Exhausted => "session exhausted",
            Self::UpgradeRefused => "the server refused the protocol upgrade",
            Self::Incomplete => "incomplete",
        })
    }
}

impl core::error::Error for Error {}
