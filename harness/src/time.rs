//! Clocks, in the two shapes the protocol needs them.
//!
//! `wirefeather` wants a monotonic millisecond counter for its timers and a TAI64N
//! stamp for handshake initiations. Those are different clocks for a reason: the
//! first must never jump, and the second must survive a reboot and be comparable
//! against what the peer last saw from us.

use rustix::time::{ClockId, clock_gettime};
use wirefeather::{Instant, Tai64n};

fn millis(clock: ClockId) -> u64 {
    let ts = clock_gettime(clock);
    (ts.tv_sec as u64) * 1_000 + (ts.tv_nsec as u64) / 1_000_000
}

/// Milliseconds from the monotonic clock, on the kernel's own origin.
pub fn monotonic_millis() -> u64 {
    millis(ClockId::Monotonic)
}

/// A monotonic clock zeroed at process start, so `Instant` values stay small
/// and readable in logs.
#[derive(Clone, Copy)]
pub struct Clock {
    origin_millis: u64,
}

impl Clock {
    pub fn start() -> Self {
        Self {
            origin_millis: monotonic_millis(),
        }
    }

    pub fn now(&self) -> Instant {
        Instant(monotonic_millis().saturating_sub(self.origin_millis))
    }

    /// Milliseconds on the same scale as [`Clock::now`], for computing a
    /// reactor deadline.
    pub fn millis(&self) -> u64 {
        self.now().0
    }
}

/// TAI64N's origin: 2^62, with the label second at 1970-01-01 sitting at
/// `2^62 + 10` because TAI was already ten seconds ahead of UTC when the Unix
/// epoch was defined.
const TAI64_UNIX_EPOCH: u64 = (1u64 << 62) + 10;

/// The current time as TAI64N: 8 bytes of big-endian seconds followed by 4
/// bytes of big-endian nanoseconds.
///
/// Leap seconds since 1972 are ignored, which puts us 27 seconds behind true
/// TAI. Every WireGuard implementation does the same — the Linux kernel feeds
/// the same UTC-derived value straight in — and it does not matter, because the
/// responder only ever compares our timestamps against our own previous ones.
/// Being consistently offset is harmless; being non-monotonic is not.
pub fn tai64n() -> Tai64n {
    let ts = clock_gettime(ClockId::Realtime);
    let seconds = TAI64_UNIX_EPOCH.wrapping_add(ts.tv_sec as u64);
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&(ts.tv_nsec as u32).to_be_bytes());
    out
}
