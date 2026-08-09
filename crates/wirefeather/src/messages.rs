//! WireGuard's four wire formats, as byte offsets.
//!
//! All multi-byte integers are little-endian. Every message begins with a
//! one-byte type followed by three reserved zero bytes.

use crate::Error;

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;
pub const TYPE_COOKIE_REPLY: u8 = 3;
pub const TYPE_DATA: u8 = 4;

/// `msg = type ‖ reserved[3] ‖ sender ‖ ephemeral ‖ static ‖ timestamp ‖ mac1 ‖ mac2`
pub mod initiation {
    pub const LEN: usize = 148;
    pub const SENDER: core::ops::Range<usize> = 4..8;
    pub const EPHEMERAL: core::ops::Range<usize> = 8..40;
    /// 32-byte static public key plus a 16-byte tag.
    pub const STATIC: core::ops::Range<usize> = 40..88;
    /// 12-byte TAI64N timestamp plus a 16-byte tag.
    pub const TIMESTAMP: core::ops::Range<usize> = 88..116;
    pub const MAC1: core::ops::Range<usize> = 116..132;
    pub const MAC2: core::ops::Range<usize> = 132..148;
    /// The prefix mac1 is computed over.
    pub const MAC1_INPUT: core::ops::Range<usize> = 0..116;
}

/// `msg = type ‖ reserved[3] ‖ sender ‖ receiver ‖ ephemeral ‖ empty ‖ mac1 ‖ mac2`
pub mod response {
    pub const LEN: usize = 92;
    pub const SENDER: core::ops::Range<usize> = 4..8;
    pub const RECEIVER: core::ops::Range<usize> = 8..12;
    pub const EPHEMERAL: core::ops::Range<usize> = 12..44;
    /// Sealed empty plaintext: the 16-byte tag alone.
    pub const EMPTY: core::ops::Range<usize> = 44..60;
    pub const MAC1: core::ops::Range<usize> = 60..76;
    pub const MAC2: core::ops::Range<usize> = 76..92;
    pub const MAC1_INPUT: core::ops::Range<usize> = 0..60;
}

/// `msg = type ‖ reserved[3] ‖ receiver ‖ counter ‖ sealed packet`
pub mod data {
    pub const HEADER_LEN: usize = 16;
    pub const RECEIVER: core::ops::Range<usize> = 4..8;
    pub const COUNTER: core::ops::Range<usize> = 8..16;
}

/// Cookie replies are parsed only far enough to recognise and drop them: this
/// implementation does not participate in the cookie/`mac2` DoS mechanism.
pub mod cookie_reply {
    pub const LEN: usize = 64;
}

/// The message type byte, if `datagram` is long enough to have one.
pub fn message_type(datagram: &[u8]) -> Result<u8, Error> {
    datagram.first().copied().ok_or(Error::Malformed)
}

/// Write a message type and its three reserved zero bytes.
pub fn put_header(out: &mut [u8], ty: u8) {
    out[0] = ty;
    out[1..4].fill(0);
}

pub fn get_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("caller passes a 4-byte range"))
}

pub fn get_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("caller passes an 8-byte range"))
}
