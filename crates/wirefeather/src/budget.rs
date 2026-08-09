//! Every buffer size in this crate, in one place.
//!
//! The x86 test harness links the same constants as the ESP32-C6 firmware, so a
//! change that quietly grows RAM use shows up in host tests instead of only
//! appearing as a link failure or a stack overflow on the chip.

/// Largest inner (tunnelled) IP packet we accept. WireGuard's conventional
/// client MTU; keeping it here means the outer datagram never fragments on a
/// 1500-byte Ethernet uplink.
pub const INNER_MTU: usize = 1280;

/// Transport header: type + 3 reserved + receiver index + 64-bit counter.
pub const TRANSPORT_HEADER_LEN: usize = 16;

/// ChaCha20-Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Plaintext is padded up to a multiple of this before sealing, so that packet
/// lengths leak less about their contents.
pub const PAD_TO: usize = 16;

/// Worst-case outer datagram: a full-MTU inner packet, padded, plus header and
/// tag. Callers should size their UDP buffers to at least this.
pub const MAX_DATAGRAM_LEN: usize =
    TRANSPORT_HEADER_LEN + INNER_MTU.next_multiple_of(PAD_TO) + TAG_LEN;

/// Replay window width in packets. WireGuard's specification requires at least
/// 2000; 1024 bits costs 128 bytes per session and two sessions live per peer.
pub const REPLAY_WINDOW_BITS: u64 = 1024;

/// `u64` words backing the replay bitmap.
pub const REPLAY_WINDOW_WORDS: usize = (REPLAY_WINDOW_BITS as usize) / 64;

const _: () = assert!(MAX_DATAGRAM_LEN == 1312);
