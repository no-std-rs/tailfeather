//! Fail-closed checks applied before packets enter the uplink NAT.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    ForwardIpv4,
    RejectIpv6,
    Malformed,
    SpoofedSource,
    IsolatedDestination,
}

/// Check family, source ownership, and destinations that must never be routed.
/// Ordinary LAN unicasts deliberately pass this layer and are decided by the
/// hosted packet filter just like internet destinations.
pub fn classify(
    packet: &[u8],
    peer_ip: [u8; 4],
    uplink_ip: [u8; 4],
    uplink_prefix: u8,
) -> Decision {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        return Decision::Malformed;
    };
    if version == 6 {
        return Decision::RejectIpv6;
    }
    if version != 4 || packet.len() < 20 || uplink_prefix > 32 {
        return Decision::Malformed;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len || total_len > packet.len() {
        return Decision::Malformed;
    }
    let source: [u8; 4] = packet[12..16].try_into().unwrap();
    if source != peer_ip {
        return Decision::SpoofedSource;
    }
    let destination: [u8; 4] = packet[16..20].try_into().unwrap();
    if isolated(destination, uplink_ip, uplink_prefix) {
        return Decision::IsolatedDestination;
    }
    Decision::ForwardIpv4
}

fn isolated(destination: [u8; 4], uplink: [u8; 4], prefix: u8) -> bool {
    let destination = u32::from_be_bytes(destination);
    let uplink = u32::from_be_bytes(uplink);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let on_link = prefix != 0 && destination & mask == uplink & mask;
    let loopback = destination & 0xff00_0000 == 0x7f00_0000;
    let host_mask = !mask;
    let subnet_network_or_broadcast = on_link
        && prefix <= 30
        && (destination & host_mask == 0 || destination & host_mask == host_mask);
    let link_local = destination & 0xffff_0000 == 0xa9fe_0000;
    let multicast = destination & 0xf000_0000 == 0xe000_0000;
    let unspecified_or_broadcast = destination == 0 || destination == u32::MAX;
    destination == uplink
        || subnet_network_or_broadcast
        || loopback
        || link_local
        || multicast
        || unspecified_or_broadcast
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(source: [u8; 4], destination: [u8; 4]) -> [u8; 20] {
        let mut packet = [0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn internet_v4_from_the_authenticated_peer_is_forwarded() {
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [1, 1, 1, 1]),
                [100, 64, 0, 2],
                [192, 168, 4, 20],
                24
            ),
            Decision::ForwardIpv4
        );
    }

    #[test]
    fn point_to_point_prefixes_do_not_invent_network_or_broadcast_hosts() {
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [192, 0, 2, 1]),
                [100, 64, 0, 2],
                [192, 0, 2, 0],
                31,
            ),
            Decision::ForwardIpv4
        );
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [192, 0, 2, 1]),
                [100, 64, 0, 2],
                [192, 0, 2, 0],
                32,
            ),
            Decision::ForwardIpv4
        );
    }

    #[test]
    fn loopback_is_isolated_from_exit_traffic() {
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [127, 0, 0, 1]),
                [100, 64, 0, 2],
                [192, 168, 4, 20],
                24
            ),
            Decision::IsolatedDestination
        );
    }

    #[test]
    fn spoofing_and_unsafe_lan_destinations_are_refused() {
        assert_eq!(
            classify(
                &packet([100, 64, 0, 3], [8, 8, 8, 8]),
                [100, 64, 0, 2],
                [10, 0, 0, 9],
                24
            ),
            Decision::SpoofedSource
        );
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [10, 0, 0, 9]),
                [100, 64, 0, 2],
                [10, 0, 0, 9],
                24
            ),
            Decision::IsolatedDestination
        );
        for destination in [[10, 0, 0, 0], [10, 0, 0, 255]] {
            assert_eq!(
                classify(
                    &packet([100, 64, 0, 2], destination),
                    [100, 64, 0, 2],
                    [10, 0, 0, 9],
                    24
                ),
                Decision::IsolatedDestination
            );
        }
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [169, 254, 2, 3]),
                [100, 64, 0, 2],
                [10, 0, 0, 9],
                24
            ),
            Decision::IsolatedDestination
        );
    }

    #[test]
    fn lan_unicast_reaches_the_hosted_acl_layer() {
        assert_eq!(
            classify(
                &packet([100, 64, 0, 2], [192, 168, 6, 170]),
                [100, 64, 0, 2],
                [192, 168, 6, 20],
                24
            ),
            Decision::ForwardIpv4
        );
    }

    #[test]
    fn ipv6_is_countable_and_explicitly_rejected() {
        let mut packet = [0u8; 40];
        packet[0] = 0x60;
        assert_eq!(classify(&packet, [0; 4], [0; 4], 24), Decision::RejectIpv6);
    }
}
