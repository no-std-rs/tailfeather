//! Allocation-free SNTP request validation and trusted-time consensus.

const PACKET_LEN: usize = 48;
const NTP_UNIX_EPOCH: u64 = 2_208_988_800;
const ERA_SECONDS: u64 = 1u64 << 32;
const MAX_SKEW_SECONDS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    LeapAlarm,
    Version,
    Mode,
    Stratum,
    Nonce,
    Timestamp,
    Rollback,
    DuplicateServer,
    Inconsistent,
    Full,
}

/// Build an SNTPv4 client request. The random nonce occupies the transmit
/// timestamp and must be copied into the response's originate timestamp.
pub fn request(nonce: [u8; 8]) -> [u8; PACKET_LEN] {
    let mut packet = [0; PACKET_LEN];
    packet[0] = (4 << 3) | 3;
    packet[40..48].copy_from_slice(&nonce);
    packet
}

/// Validate one server response and return its Unix transmit time.
pub fn response(packet: &[u8], nonce: [u8; 8], floor: u64) -> Result<u64, Error> {
    if packet.len() < PACKET_LEN {
        return Err(Error::Length);
    }
    let leap = packet[0] >> 6;
    let version = (packet[0] >> 3) & 0x07;
    let mode = packet[0] & 0x07;
    if leap == 3 {
        return Err(Error::LeapAlarm);
    }
    if !(3..=4).contains(&version) {
        return Err(Error::Version);
    }
    if mode != 4 {
        return Err(Error::Mode);
    }
    if !(1..=15).contains(&packet[1]) {
        return Err(Error::Stratum);
    }
    if packet[24..32] != nonce {
        return Err(Error::Nonce);
    }

    let receive = u64::from(u32::from_be_bytes(packet[32..36].try_into().unwrap()));
    let transmit = u64::from(u32::from_be_bytes(packet[40..44].try_into().unwrap()));
    if receive == 0 || transmit == 0 {
        return Err(Error::Timestamp);
    }

    let unix_seconds = unfold_era(transmit, floor).ok_or(Error::Rollback)?;
    let receive_seconds =
        unfold_era(receive, floor.saturating_sub(MAX_SKEW_SECONDS)).ok_or(Error::Timestamp)?;
    if receive_seconds > unix_seconds.saturating_add(MAX_SKEW_SECONDS) {
        return Err(Error::Timestamp);
    }
    if unix_seconds < floor {
        return Err(Error::Rollback);
    }
    Ok(unix_seconds)
}

fn unfold_era(seconds: u64, floor: u64) -> Option<u64> {
    // Era zero covers 1900..2036; era one covers 2036..2172. The embedded
    // build floor makes the otherwise ambiguous 32-bit seconds field safe.
    let era_zero = seconds.checked_sub(NTP_UNIX_EPOCH);
    let era_one = seconds
        .checked_add(ERA_SECONDS)?
        .checked_sub(NTP_UNIX_EPOCH)?;
    match era_zero {
        Some(era_zero) if era_zero.abs_diff(floor) <= era_one.abs_diff(floor) => Some(era_zero),
        _ => Some(era_one),
    }
}

/// Collect replies from distinct IPv4 servers and require two close clocks.
#[derive(Debug, Clone)]
pub struct Consensus {
    samples: heapless::Vec<([u8; 4], u64), 4>,
}

impl Consensus {
    pub const fn new() -> Self {
        Self {
            samples: heapless::Vec::new(),
        }
    }

    pub fn push(&mut self, server: [u8; 4], unix_seconds: u64) -> Result<(), Error> {
        if self.samples.iter().any(|(seen, _)| *seen == server) {
            return Err(Error::DuplicateServer);
        }
        self.samples
            .push((server, unix_seconds))
            .map_err(|_| Error::Full)
    }

    /// Median of the accepted clocks once at least two independent servers
    /// agree. For an even count the midpoint of the middle pair is used.
    pub fn provisional(&self) -> Option<u64> {
        if self.samples.len() < 2 {
            return None;
        }
        let mut values = heapless::Vec::<u64, 4>::new();
        for (_, value) in &self.samples {
            values.push(*value).ok()?;
        }
        values.as_mut_slice().sort_unstable();
        let mut best_start = 0;
        let mut best_len = 0;
        let mut best_count = 0;
        for start in 0..values.len() {
            let mut end = start + 1;
            while end < values.len()
                && values[end].saturating_sub(values[start]) <= MAX_SKEW_SECONDS
            {
                end += 1;
            }
            let len = end - start;
            if len > best_len {
                best_start = start;
                best_len = len;
                best_count = 1;
            } else if len == best_len {
                best_count += 1;
            }
        }
        if best_len < 2 || best_count != 1 {
            return None;
        }
        let middle = best_start + best_len / 2;
        if best_len % 2 == 1 {
            Some(values[middle])
        } else {
            Some(values[middle - 1] + (values[middle] - values[middle - 1]) / 2)
        }
    }
}

impl Default for Consensus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(nonce: [u8; 8], unix_seconds: u64) -> [u8; PACKET_LEN] {
        let ntp = u32::try_from(unix_seconds + NTP_UNIX_EPOCH).unwrap();
        let mut packet = [0; PACKET_LEN];
        packet[0] = (4 << 3) | 4;
        packet[1] = 2;
        packet[24..32].copy_from_slice(&nonce);
        packet[32..36].copy_from_slice(&ntp.to_be_bytes());
        packet[40..44].copy_from_slice(&ntp.to_be_bytes());
        packet
    }

    #[test]
    fn request_and_two_server_median_are_bound_to_the_nonce() {
        let nonce = [9; 8];
        assert_eq!(request(nonce)[40..], nonce);
        let floor = 1_700_000_000;
        let a = response(&reply(nonce, floor + 2), nonce, floor).unwrap();
        let b = response(&reply(nonce, floor + 4), nonce, floor).unwrap();
        let mut consensus = Consensus::new();
        consensus.push([192, 0, 2, 1], a).unwrap();
        assert_eq!(consensus.provisional(), None);
        consensus.push([192, 0, 2, 2], b).unwrap();
        assert_eq!(consensus.provisional(), Some(floor + 3));
    }

    #[test]
    fn malformed_and_rollback_responses_fail_closed() {
        let nonce = [7; 8];
        let floor = 1_700_000_000;
        let valid = reply(nonce, floor);
        for (offset, value, expected) in [
            (0, (3 << 6) | (4 << 3) | 4, Error::LeapAlarm),
            (0, (2 << 3) | 4, Error::Version),
            (0, (4 << 3) | 3, Error::Mode),
            (1, 0, Error::Stratum),
        ] {
            let mut malformed = valid;
            malformed[offset] = value;
            assert_eq!(response(&malformed, nonce, floor), Err(expected));
        }
        assert_eq!(response(&valid, [8; 8], floor), Err(Error::Nonce));
        assert_eq!(
            response(&reply(nonce, floor - 1), nonce, floor),
            Err(Error::Rollback)
        );
    }

    #[test]
    fn consensus_requires_distinct_consistent_servers() {
        let mut consensus = Consensus::new();
        consensus.push([1, 1, 1, 1], 100).unwrap();
        assert_eq!(
            consensus.push([1, 1, 1, 1], 101),
            Err(Error::DuplicateServer)
        );
        consensus.push([1, 0, 0, 1], 106).unwrap();
        assert_eq!(consensus.provisional(), None);

        let mut recovered = Consensus::new();
        recovered.push([1, 0, 0, 1], 1_000).unwrap();
        recovered.push([1, 0, 0, 2], 100).unwrap();
        assert_eq!(recovered.provisional(), None);
        recovered.push([1, 0, 0, 3], 103).unwrap();
        assert_eq!(recovered.provisional(), Some(101));

        let mut ambiguous = Consensus::new();
        ambiguous.push([1, 0, 0, 1], 100).unwrap();
        ambiguous.push([1, 0, 0, 2], 102).unwrap();
        ambiguous.push([1, 0, 0, 3], 200).unwrap();
        ambiguous.push([1, 0, 0, 4], 202).unwrap();
        assert_eq!(ambiguous.provisional(), None);
    }
}
