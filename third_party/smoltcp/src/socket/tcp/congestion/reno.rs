use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

/// Reno (RFC 5681). Tailfeather patch: upstream grew the window by one
/// segment per ACK above `ssthresh` too (slow start that never ends) and only
/// halved it, so after every loss it regrew straight into the next overflow.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    min_cwnd: usize,
    ssthresh: usize,
    rwnd: usize,
    /// Bytes acknowledged since the window last grew in congestion avoidance.
    acked: usize,
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            ssthresh: usize::MAX,
            rwnd: 64 * 1024,
            acked: 0,
        }
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _rtt: &RttEstimator) {
        if self.cwnd < self.ssthresh {
            // Slow start, counting every acknowledged byte as Linux does:
            // receivers that coalesce segments send stretch ACKs, and RFC
            // 3465's two-segment cap would make the ramp additive.
            self.cwnd = self.cwnd.saturating_add(len).min(self.ssthresh);
        } else {
            // Congestion avoidance: one segment per window of acknowledged data.
            self.acked = self.acked.saturating_add(len);
            if self.acked >= self.cwnd {
                self.acked -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.min_cwnd);
            }
        }
        self.cwnd = self.cwnd.min(self.rwnd).max(self.min_cwnd);
    }

    fn on_retransmit(&mut self, _now: Instant) {
        // Called once per loss event: on entering fast recovery and on a
        // retransmission timeout.
        self.ssthresh = (self.cwnd >> 1).max(2 * self.min_cwnd);
        self.cwnd = self.ssthresh;
        self.acked = 0;
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
        // RFC 6928 initial window, before any loss has been seen.
        if self.ssthresh == usize::MAX {
            self.cwnd = (10 * mss).min((2 * mss).max(14600)).max(self.cwnd);
        }
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time::Instant;

    use super::*;

    #[test]
    fn test_reno() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut reno = Reno::new();
                reno.set_mss(1480);

                // Set remote window.
                reno.set_remote_window(remote_window);

                reno.on_ack(now, 4096, &RttEstimator::default());

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                if i & 1 == 0 {
                    reno.on_retransmit(now);
                } else {
                    reno.on_duplicate_ack(now);
                }

                let elapsed = Instant::from_millis(1000);
                reno.on_ack(elapsed, n, &RttEstimator::default());

                let cwnd = reno.window();
                println!("Reno: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= reno.min_cwnd);
                assert!(reno.window() <= remote_window);
            }
        }
    }

    #[test]
    fn reno_min_cwnd() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        let mut reno = Reno::new();
        reno.set_remote_window(remote_window);

        for _ in 0..100 {
            reno.on_retransmit(now);
            assert!(reno.window() >= reno.min_cwnd);
        }
    }

    #[test]
    fn reno_set_rwnd() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 * 1024 * 1024);

        println!("{reno:?}");
    }
}
