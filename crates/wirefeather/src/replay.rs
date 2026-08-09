//! Sliding-window replay protection over the 64-bit transport counter.

use crate::budget::{REPLAY_WINDOW_BITS, REPLAY_WINDOW_WORDS};
use crate::timers::REJECT_AFTER_MESSAGES;

/// Tracks which of the most recent [`REPLAY_WINDOW_BITS`] counter values have
/// already been seen.
///
/// Bit `n % REPLAY_WINDOW_BITS` records counter `n`; `highest` disambiguates
/// which window that bit currently belongs to. Counters may arrive out of
/// order, but each is accepted exactly once.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Largest counter accepted so far. `None` until the first packet.
    highest: Option<u64>,
    seen: [u64; REPLAY_WINDOW_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self {
            highest: None,
            seen: [0; REPLAY_WINDOW_WORDS],
        }
    }

    /// Accept `counter` if it is fresh, recording it. Returns `false` for a
    /// replay, a counter that has fallen out of the window, or one past the
    /// point where the session must be rekeyed.
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }

        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.set(counter);
            return true;
        };

        if counter > highest {
            // Everything strictly between the old and new high water marks is
            // now unseen, so clear those bits before they are reinterpreted as
            // belonging to the new window.
            let advance = counter - highest;
            if advance >= REPLAY_WINDOW_BITS {
                self.seen = [0; REPLAY_WINDOW_WORDS];
            } else {
                for c in (highest + 1)..counter {
                    self.clear(c);
                }
            }
            self.highest = Some(counter);
            self.set(counter);
            return true;
        }

        if highest - counter >= REPLAY_WINDOW_BITS || self.is_set(counter) {
            return false;
        }
        self.set(counter);
        true
    }

    fn index(counter: u64) -> (usize, u64) {
        let bit = counter % REPLAY_WINDOW_BITS;
        ((bit / 64) as usize, 1u64 << (bit % 64))
    }

    fn set(&mut self, counter: u64) {
        let (word, mask) = Self::index(counter);
        self.seen[word] |= mask;
    }

    fn clear(&mut self, counter: u64) {
        let (word, mask) = Self::index(counter);
        self.seen[word] &= !mask;
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, mask) = Self::index(counter);
        self.seen[word] & mask != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_counter_once_in_order() {
        let mut w = ReplayWindow::new();
        for c in 0..5000 {
            assert!(w.accept(c), "fresh counter {c} rejected");
            assert!(!w.accept(c), "counter {c} accepted twice");
        }
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(50));
        assert!(w.accept(99));
        assert!(!w.accept(50));
        assert!(w.accept(101));
    }

    #[test]
    fn rejects_counters_that_fell_out_of_the_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(REPLAY_WINDOW_BITS * 2));
        assert!(!w.accept(REPLAY_WINDOW_BITS * 2 - REPLAY_WINDOW_BITS));
        assert!(!w.accept(0));
        // The oldest counter still inside the window is accepted.
        assert!(w.accept(REPLAY_WINDOW_BITS * 2 - REPLAY_WINDOW_BITS + 1));
    }

    #[test]
    fn a_large_jump_clears_stale_bits() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(7));
        assert!(w.accept(1_000_000));
        // 7 is far outside the window now, and must not appear pre-seen at the
        // aliasing position 1_000_000 - 7 wraps to.
        assert!(!w.accept(7));
        assert!(w.accept(999_999));
    }

    #[test]
    fn rejects_counters_past_the_rekey_limit() {
        let mut w = ReplayWindow::new();
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
        assert!(!w.accept(u64::MAX));
        assert!(w.accept(REJECT_AFTER_MESSAGES - 1));
    }

    #[test]
    fn does_not_alias_across_a_full_window_gap() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1));
        // Exactly one window later maps to the same bit as counter 1.
        assert!(w.accept(1 + REPLAY_WINDOW_BITS));
        assert!(!w.accept(1));
    }
}
