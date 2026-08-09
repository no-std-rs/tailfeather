//! WireGuard's protocol constants and the timer rules a responder needs.
//!
//! Everything here is a pure function of an injected `now`, so the same logic
//! runs against a monotonic clock on the chip and against a fabricated one in
//! tests.

/// Milliseconds since an arbitrary fixed origin, from a monotonic clock.
///
/// The core never interprets the origin, only differences, so callers are free
/// to use time-since-boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub u64);

impl Instant {
    /// Milliseconds elapsed from `earlier` to `self`, saturating at zero if the
    /// caller's clock went backwards.
    pub fn saturating_since(self, earlier: Instant) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A session older than this must not be used, in either direction.
pub const REJECT_AFTER_TIME_MS: u64 = 180_000;

/// After this long, a session should be rekeyed. A device that only responds
/// cannot act on this and instead lets the session expire at
/// [`REJECT_AFTER_TIME_MS`], leaving the peer to start a new handshake; one that
/// initiates begins a fresh handshake here, while the old session is still
/// usable, so there is no gap in connectivity.
pub const REKEY_AFTER_TIME_MS: u64 = 120_000;

/// How long to wait for a response before repeating an initiation.
pub const REKEY_TIMEOUT_MS: u64 = 5_000;

/// How long to keep repeating initiations before abandoning the attempt.
///
/// Giving up matters on a mesh: a netmap can name peers that are offline or
/// unreachable, and retrying all of them forever would spend the handshake
/// budget that reachable peers need.
pub const REKEY_ATTEMPT_TIME_MS: u64 = 90_000;

/// Having received a data packet, send something back within this long so the
/// peer's NAT mapping and its own timers stay alive.
pub const KEEPALIVE_TIMEOUT_MS: u64 = 10_000;

/// Counter value at which a session must stop being used: `2^64 - 2^13 - 1`.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Counter value at which a rekey becomes due.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// The sustained interval between handshakes the device will do the
/// Diffie-Hellman work for.
///
/// Each handshake costs two X25519 operations, which take milliseconds on a
/// 160 MHz RISC-V core, so an unthrottled flood is a cheap denial of service.
/// This implementation omits the cookie/`mac2` machinery, and [`HandshakeBudget`]
/// is what stands in for it.
pub const HANDSHAKE_RATE_LIMIT_MS: u64 = 50;

/// How many handshakes may be done back to back before the sustained rate
/// applies.
///
/// A mesh legitimately produces bursts: one netmap can name a dozen new peers,
/// and every one of them wants a handshake at the same instant. A limiter with
/// no burst allowance would serialise those at one per
/// [`HANDSHAKE_RATE_LIMIT_MS`] and make a fresh tailnet take visibly long to
/// come up, so the bucket is sized to absorb a whole netmap's worth.
pub const HANDSHAKE_BURST: u32 = 8;

/// A token bucket over handshake work, replacing what the cookie mechanism
/// would otherwise provide.
///
/// It is deliberately device-wide rather than per-peer. Per-peer limiting alone
/// does not bound the total cost: an attacker who knows our public key can forge
/// initiations claiming to be from any peer we have configured, and `PEERS`
/// peers' worth of X25519 is still more than a small core can absorb. Per-peer
/// state exists too — see the timestamp check — but for replay, not for load.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeBudget {
    /// Tokens available, scaled by [`HANDSHAKE_RATE_LIMIT_MS`] so that refill is
    /// integer arithmetic with no lost remainder.
    tokens: u32,
    last_refill: Option<Instant>,
}

impl HandshakeBudget {
    pub const fn new() -> Self {
        Self {
            tokens: HANDSHAKE_BURST,
            last_refill: None,
        }
    }

    /// Take one token if any is available, refilling first.
    pub fn take(&mut self, now: Instant) -> bool {
        match self.last_refill {
            None => self.last_refill = Some(now),
            Some(last) => {
                let elapsed = now.saturating_since(last);
                let earned = elapsed / HANDSHAKE_RATE_LIMIT_MS;
                if earned > 0 {
                    self.tokens = self
                        .tokens
                        .saturating_add(earned.min(u32::MAX as u64) as u32)
                        .min(HANDSHAKE_BURST);
                    // Carry the remainder forward rather than discarding it, so
                    // a caller polling faster than the refill interval still
                    // accrues tokens at the intended rate.
                    self.last_refill = Some(Instant(last.0 + earned * HANDSHAKE_RATE_LIMIT_MS));
                }
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

impl Default for HandshakeBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether an initiation should be sent now for a handshake that was last
/// attempted at `last_attempt`.
pub fn handshake_retry_is_due(last_attempt: Option<Instant>, now: Instant) -> bool {
    match last_attempt {
        None => true,
        Some(last) => now.saturating_since(last) >= REKEY_TIMEOUT_MS,
    }
}

/// Whether a handshake begun at `started` has been retried for long enough that
/// the peer should be treated as unreachable.
pub fn handshake_has_expired(started: Instant, now: Instant) -> bool {
    now.saturating_since(started) >= REKEY_ATTEMPT_TIME_MS
}

/// Whether a session established at `established` is old enough to rekey.
pub fn rekey_is_due(established: Instant, now: Instant) -> bool {
    now.saturating_since(established) >= REKEY_AFTER_TIME_MS
}

/// Whether a session established at `established` may still be used at `now`.
pub fn session_is_alive(established: Instant, now: Instant) -> bool {
    now.saturating_since(established) < REJECT_AFTER_TIME_MS
}

/// Whether a passive keepalive is due.
///
/// `armed_since` is the moment data arrived with nothing sent back since. It is
/// deliberately a single piece of state rather than a comparison of "last
/// received" against "last sent": those can carry the same timestamp when a
/// send and a receive land in the same millisecond, and then neither ordering
/// is recoverable. Arming on receipt and disarming on send has no such tie.
pub fn keepalive_is_due(armed_since: Option<Instant>, now: Instant) -> bool {
    armed_since.is_some_and(|armed| now.saturating_since(armed) >= KEEPALIVE_TIMEOUT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_at_the_reject_boundary() {
        let start = Instant(1_000);
        assert!(session_is_alive(start, Instant(1_000)));
        assert!(session_is_alive(
            start,
            Instant(1_000 + REJECT_AFTER_TIME_MS - 1)
        ));
        assert!(!session_is_alive(
            start,
            Instant(1_000 + REJECT_AFTER_TIME_MS)
        ));
    }

    #[test]
    fn a_backwards_clock_does_not_expire_a_session() {
        assert!(session_is_alive(Instant(5_000), Instant(1_000)));
    }

    #[test]
    fn keepalive_waits_for_received_data() {
        // Disarmed: nothing to keep alive.
        assert!(!keepalive_is_due(None, Instant(1_000_000)));

        let armed = Instant(1_000);
        assert!(!keepalive_is_due(Some(armed), Instant(1_000)));
        assert!(!keepalive_is_due(
            Some(armed),
            Instant(1_000 + KEEPALIVE_TIMEOUT_MS - 1)
        ));
        assert!(keepalive_is_due(
            Some(armed),
            Instant(1_000 + KEEPALIVE_TIMEOUT_MS)
        ));
    }

    #[test]
    fn the_budget_absorbs_a_burst_then_throttles() {
        let mut budget = HandshakeBudget::new();
        // A whole netmap's worth of peers may handshake at once.
        for _ in 0..HANDSHAKE_BURST {
            assert!(budget.take(Instant(0)));
        }
        assert!(!budget.take(Instant(0)));
        assert!(!budget.take(Instant(HANDSHAKE_RATE_LIMIT_MS - 1)));
        assert!(budget.take(Instant(HANDSHAKE_RATE_LIMIT_MS)));
        assert!(!budget.take(Instant(HANDSHAKE_RATE_LIMIT_MS)));
    }

    #[test]
    fn polling_faster_than_the_refill_interval_still_accrues_tokens() {
        // The remainder is carried rather than discarded: without that, a caller
        // polling every millisecond would earn zero tokens forever, because each
        // call would see less than one interval elapsed since the last.
        let mut budget = HandshakeBudget::new();
        for _ in 0..HANDSHAKE_BURST {
            assert!(budget.take(Instant(0)));
        }
        for ms in 1..HANDSHAKE_RATE_LIMIT_MS {
            assert!(!budget.take(Instant(ms)));
        }
        assert!(budget.take(Instant(HANDSHAKE_RATE_LIMIT_MS)));
    }

    #[test]
    fn the_budget_never_exceeds_its_burst_after_a_long_idle() {
        let mut budget = HandshakeBudget::new();
        assert!(budget.take(Instant(0)));
        let long_idle = Instant(3_600_000);
        for _ in 0..HANDSHAKE_BURST {
            assert!(budget.take(long_idle));
        }
        assert!(!budget.take(long_idle));
    }

    #[test]
    fn handshakes_retry_then_give_up() {
        assert!(handshake_retry_is_due(None, Instant(0)));
        let sent = Instant(1_000);
        assert!(!handshake_retry_is_due(Some(sent), Instant(1_000)));
        assert!(!handshake_retry_is_due(
            Some(sent),
            Instant(1_000 + REKEY_TIMEOUT_MS - 1)
        ));
        assert!(handshake_retry_is_due(
            Some(sent),
            Instant(1_000 + REKEY_TIMEOUT_MS)
        ));

        assert!(!handshake_has_expired(
            sent,
            Instant(1_000 + REKEY_ATTEMPT_TIME_MS - 1)
        ));
        assert!(handshake_has_expired(
            sent,
            Instant(1_000 + REKEY_ATTEMPT_TIME_MS)
        ));
    }

    #[test]
    fn a_rekey_becomes_due_before_the_session_is_rejected() {
        // The ordering is what keeps connectivity unbroken: the new handshake
        // starts while the old session can still carry traffic.
        const { assert!(REKEY_AFTER_TIME_MS < REJECT_AFTER_TIME_MS) };
        let start = Instant(0);
        assert!(!rekey_is_due(start, Instant(REKEY_AFTER_TIME_MS - 1)));
        assert!(rekey_is_due(start, Instant(REKEY_AFTER_TIME_MS)));
        assert!(session_is_alive(start, Instant(REKEY_AFTER_TIME_MS)));
    }

    #[test]
    fn a_send_in_the_same_millisecond_still_disarms_the_keepalive() {
        // Disarming is a state change, not a timestamp comparison, so a send
        // that shares a millisecond with the receipt still cancels it.
        assert!(!keepalive_is_due(
            None,
            Instant(1_000 + KEEPALIVE_TIMEOUT_MS)
        ));
    }
}
