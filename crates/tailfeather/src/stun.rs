//! Minimal allocation-free STUN binding requests and IPv4 responses.

pub const TRANSACTION_ID_LEN: usize = 12;
pub const REQUEST_LEN: usize = 40;
const HEADER_LEN: usize = 20;
const COOKIE: u32 = 0x2112_a442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const SOFTWARE: u16 = 0x8022;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Type,
    Cookie,
    Transaction,
    Attribute,
    Fingerprint,
    MissingAddress,
    AddressFamily,
}

/// Independently select a reflexive endpoint and an eligible home relay.
/// Standalone STUN servers can discover a mapping without becoming a home.
#[derive(Debug, Default)]
pub struct Selection {
    home: u16,
    home_latency: Option<u64>,
    reflexive: Option<(u64, core::net::SocketAddrV4)>,
}
impl Selection {
    /// Use the first eligible relay when no relay answers STUN.
    pub fn new<const N: usize>(map: &crate::netmap::Netmap<N>) -> Self {
        Self {
            home: map
                .derp
                .iter()
                .find(|r| r.can_be_home())
                .map_or(0, |r| r.id),
            ..Self::default()
        }
    }

    /// Record an source- and transaction-matched STUN response.
    pub fn record(
        &mut self,
        region: &crate::netmap::DerpRegion,
        latency: u64,
        endpoint: core::net::SocketAddrV4,
    ) {
        if region.no_measure_no_home {
            return;
        }
        if self.reflexive.is_none_or(|best| latency < best.0) {
            self.reflexive = Some((latency, endpoint));
        }
        if region.can_be_home() && self.home_latency.is_none_or(|best| latency < best) {
            self.home = region.id;
            self.home_latency = Some(latency);
        }
    }

    pub fn home(&self) -> u16 {
        self.home
    }

    pub fn reflexive(&self) -> Option<core::net::SocketAddrV4> {
        self.reflexive.map(|(_, endpoint)| endpoint)
    }
}

/// Encode a binding request with Tailscale's `tailnode` software marker.
pub fn request(transaction: [u8; TRANSACTION_ID_LEN]) -> [u8; REQUEST_LEN] {
    let mut packet = [0; REQUEST_LEN];
    packet[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[4..8].copy_from_slice(&COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(&transaction);
    packet[20..22].copy_from_slice(&SOFTWARE.to_be_bytes());
    packet[22..24].copy_from_slice(&8u16.to_be_bytes());
    packet[24..32].copy_from_slice(b"tailnode");
    packet[32..34].copy_from_slice(&FINGERPRINT.to_be_bytes());
    packet[34..36].copy_from_slice(&4u16.to_be_bytes());
    let fingerprint = crc32(&packet[..32]) ^ FINGERPRINT_XOR;
    packet[36..40].copy_from_slice(&fingerprint.to_be_bytes());
    packet
}

/// Validate a binding-success response and return the reflexive IPv4 endpoint.
pub fn response(
    packet: &[u8],
    transaction: [u8; TRANSACTION_ID_LEN],
) -> Result<([u8; 4], u16), Error> {
    if packet.len() < HEADER_LEN {
        return Err(Error::Length);
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS {
        return Err(Error::Type);
    }
    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if declared % 4 != 0 || HEADER_LEN + declared != packet.len() {
        return Err(Error::Length);
    }
    if u32::from_be_bytes(packet[4..8].try_into().unwrap()) != COOKIE {
        return Err(Error::Cookie);
    }
    if packet[8..20] != transaction {
        return Err(Error::Transaction);
    }

    let cookie = COOKIE.to_be_bytes();
    let mut mapped = None;
    let mut offset = HEADER_LEN;
    while offset < packet.len() {
        if packet.len() - offset < 4 {
            return Err(Error::Attribute);
        }
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        let value_start = offset + 4;
        let value_end = value_start.checked_add(len).ok_or(Error::Attribute)?;
        let padded_end = value_start
            .checked_add(len.div_ceil(4) * 4)
            .ok_or(Error::Attribute)?;
        if value_end > packet.len() || padded_end > packet.len() {
            return Err(Error::Attribute);
        }
        match kind {
            XOR_MAPPED_ADDRESS => {
                let family = *packet.get(value_start + 1).ok_or(Error::Attribute)?;
                let address_len = match family {
                    1 if len == 8 => 4,
                    2 if len == 20 => 16,
                    1 | 2 => return Err(Error::Attribute),
                    _ => return Err(Error::AddressFamily),
                };
                let port = u16::from_be_bytes([
                    packet[value_start + 2] ^ cookie[0],
                    packet[value_start + 3] ^ cookie[1],
                ]);
                let mut decoded = [0; 16];
                for index in 0..address_len {
                    let mask = if index < 4 {
                        cookie[index]
                    } else {
                        transaction[index - 4]
                    };
                    decoded[index] = packet[value_start + 4 + index] ^ mask;
                }
                let address = if address_len == 4 {
                    decoded[..4].try_into().unwrap()
                } else if decoded[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255] {
                    // A dual-stack STUN listener can encode an IPv4 sender as
                    // ::ffff:a.b.c.d. Upstream Unmap()s it before publication.
                    decoded[12..].try_into().unwrap()
                } else {
                    return Err(Error::AddressFamily);
                };
                mapped = Some((address, port));
            }
            FINGERPRINT => {
                if len != 4 || padded_end != packet.len() {
                    return Err(Error::Fingerprint);
                }
                let actual = u32::from_be_bytes(packet[value_start..value_end].try_into().unwrap());
                let expected = crc32(&packet[..offset]) ^ FINGERPRINT_XOR;
                if actual != expected {
                    return Err(Error::Fingerprint);
                }
            }
            _ => {}
        }
        offset = padded_end;
    }
    mapped.ok_or(Error::MissingAddress)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_stun_mapping_and_home_latency_are_independent() {
        let mut map = crate::netmap::Netmap::<1>::new();
        let mut parser = crate::netmap::Parser::new();
        parser.push(&mut map, br#"{"DERPMap":{"Regions":{"900":{"Nodes":[{"HostName":"stun","STUNOnly":true}]},"998":{"NoMeasureNoHome":true,"Nodes":[{"HostName":"excluded"}]},"999":{"Nodes":[{"HostName":"relay","STUNPort":-1}]},"1000":{"Nodes":[{"HostName":"backup"}]}}}}"#).unwrap();
        parser.finish(&mut map).unwrap();
        let endpoint = core::net::SocketAddrV4::new([203, 0, 113, 7].into(), 41641);
        let slower = core::net::SocketAddrV4::new([203, 0, 113, 8].into(), 41642);
        let mut selection = Selection::new(&map);
        assert_eq!(selection.home(), 999);
        assert_eq!(selection.reflexive(), None);
        let region = |id| map.derp.iter().find(|r| r.id == id).unwrap();
        selection.record(region(998), 0, slower);
        assert_eq!(selection.reflexive(), None);
        selection.record(region(900), 1, endpoint);
        assert_eq!(selection.home(), 999);
        assert_eq!(selection.reflexive(), Some(endpoint));
        selection.record(region(999), 10, slower);
        selection.record(region(1000), 5, slower);
        assert_eq!(selection.home(), 1000);
        assert_eq!(selection.reflexive(), Some(endpoint));
    }

    fn success(transaction: [u8; 12], address: [u8; 4], port: u16) -> [u8; 40] {
        let cookie = COOKIE.to_be_bytes();
        let mut packet = [0; 40];
        packet[..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[4..8].copy_from_slice(&cookie);
        packet[8..20].copy_from_slice(&transaction);
        packet[20..22].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        packet[22..24].copy_from_slice(&8u16.to_be_bytes());
        packet[25] = 1;
        let encoded_port = port ^ (COOKIE >> 16) as u16;
        packet[26..28].copy_from_slice(&encoded_port.to_be_bytes());
        for index in 0..4 {
            packet[28 + index] = address[index] ^ cookie[index];
        }
        packet[32..34].copy_from_slice(&FINGERPRINT.to_be_bytes());
        packet[34..36].copy_from_slice(&4u16.to_be_bytes());
        let fingerprint = crc32(&packet[..32]) ^ FINGERPRINT_XOR;
        packet[36..40].copy_from_slice(&fingerprint.to_be_bytes());
        packet
    }

    #[test]
    fn request_has_tailnode_marker_and_a_valid_fingerprint() {
        let packet = request([3; 12]);
        assert_eq!(&packet[24..32], b"tailnode");
        assert_eq!(
            u32::from_be_bytes(packet[36..40].try_into().unwrap()),
            crc32(&packet[..32]) ^ FINGERPRINT_XOR
        );
    }

    #[test]
    fn xor_mapped_ipv4_round_trips() {
        let transaction = [9; 12];
        assert_eq!(
            response(&success(transaction, [203, 0, 113, 7], 41_641), transaction),
            Ok(([203, 0, 113, 7], 41_641))
        );
    }

    #[test]
    fn response_without_optional_fingerprint_is_accepted() {
        let transaction = [9; 12];
        let mut packet = success(transaction, [203, 0, 113, 7], 41_641);
        packet[2..4].copy_from_slice(&12u16.to_be_bytes());
        assert_eq!(
            response(&packet[..32], transaction),
            Ok(([203, 0, 113, 7], 41_641))
        );
    }

    #[test]
    fn upstream_dual_stack_listener_response_unmaps_ipv4() {
        // tailscale/net/stun.Response with a dual-stack UDP sender address.
        let packet = [
            0x01, 0x01, 0x00, 0x18, 0x21, 0x12, 0xa4, 0x42, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0x83, 0xbb,
            0x21, 0x12, 0xa4, 0x42, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0xf6, 0xf6, 0xc2, 0x09,
            0x78, 0x0e,
        ];
        assert_eq!(response(&packet, [9; 12]), Ok(([203, 0, 113, 7], 41641)));
        assert_eq!(response(&packet, [8; 12]), Err(Error::Transaction));
        let mut native_v6 = packet;
        native_v6[28] ^= 1;
        assert_eq!(response(&native_v6, [9; 12]), Err(Error::AddressFamily));
    }

    #[test]
    fn wrong_transaction_and_fingerprint_are_rejected() {
        let transaction = [9; 12];
        let mut packet = success(transaction, [203, 0, 113, 7], 41_641);
        assert_eq!(response(&packet, [8; 12]), Err(Error::Transaction));
        packet[39] ^= 1;
        assert_eq!(response(&packet, transaction), Err(Error::Fingerprint));
    }
}
