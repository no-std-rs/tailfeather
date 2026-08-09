//! Just enough IP header parsing to undo WireGuard's padding.
//!
//! A sealed data message carries its plaintext padded up to a 16-byte boundary,
//! and the padding is not length-prefixed. The only way to recover the real
//! packet is to read the length out of the inner IP header, which is why a
//! protocol crate that otherwise knows nothing about IP has to peek at it.

const IPV4: u8 = 4;
const IPV6: u8 = 6;
const IPV6_HEADER_LEN: usize = 40;

/// The true length of the inner IP packet at the front of `padded`, or `None`
/// if it is not a plausible IPv4 or IPv6 packet that fits within the buffer.
pub fn packet_len(padded: &[u8]) -> Option<usize> {
    let version = padded.first()? >> 4;
    let len = match version {
        IPV4 => {
            let total = padded.get(2..4)?;
            u16::from_be_bytes([total[0], total[1]]) as usize
        }
        IPV6 => {
            let payload = padded.get(4..6)?;
            u16::from_be_bytes([payload[0], payload[1]]) as usize + IPV6_HEADER_LEN
        }
        _ => return None,
    };
    // A declared length longer than what we actually decrypted means a
    // malformed or truncated packet, not padding.
    (len <= padded.len()).then_some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ipv4_total_length() {
        let mut packet = [0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(packet_len(&packet), Some(20));
    }

    #[test]
    fn reads_ipv6_payload_length_plus_header() {
        let mut packet = [0u8; 64];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(packet_len(&packet), Some(48));
    }

    #[test]
    fn rejects_a_length_that_overruns_the_buffer() {
        let mut packet = [0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes());
        assert_eq!(packet_len(&packet), None);
    }

    #[test]
    fn rejects_junk_and_empty_input() {
        assert_eq!(packet_len(&[]), None);
        assert_eq!(packet_len(&[0x00; 32]), None);
        assert_eq!(packet_len(&[0xf0; 32]), None);
    }
}
