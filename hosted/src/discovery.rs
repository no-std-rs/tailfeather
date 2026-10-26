//! Advertise LAN interfaces independently of the route to the coordinator.
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

pub(crate) fn local_candidates(fallback: Option<SocketAddrV4>) -> Vec<SocketAddrV4> {
    let Some(fallback) = fallback else {
        return Vec::new();
    };
    let addresses = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|interface| interface.is_oper_up() && !interface.is_p2p())
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        });
    let candidates = candidate_addresses(fallback, addresses);
    tracing::debug!(?candidates, "TAILNET_LOCAL_ENDPOINTS");
    candidates
}

fn candidate_addresses(
    fallback: SocketAddrV4,
    addresses: impl Iterator<Item = Ipv4Addr>,
) -> Vec<SocketAddrV4> {
    fn usable(ip: Ipv4Addr) -> bool {
        !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
            // Never advertise the overlay back into itself.
            && (u32::from(ip) & 0xffc0_0000) != 0x6440_0000
    }
    let mut ips: Vec<_> = addresses.filter(|ip| usable(*ip)).collect();
    ips.sort_unstable();
    ips.dedup();
    let mut candidates = Vec::new();
    let keep_fallback = usable(*fallback.ip());
    for ip in ips {
        // Reserve half of the eight-endpoint budget for reflexive candidates.
        if candidates.len() == 4 - usize::from(keep_fallback) {
            break;
        }
        if ip == *fallback.ip() {
            continue;
        }
        let address = SocketAddrV4::new(ip, fallback.port());
        candidates.push(address);
    }
    // Try other LANs before the coordinator's route: a working route through
    // NAT must not prevent discovery of a directly attached private link.
    if keep_fallback || (candidates.is_empty() && fallback.ip().is_loopback()) {
        candidates.push(fallback);
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_lan_interfaces_use_the_data_port_and_leave_room_for_stun() {
        let addresses = [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "100.64.1.1",
            "192.168.6.3",
            "10.203.0.1",
            "10.203.0.1",
            "10.203.1.1",
            "10.88.0.1",
            "172.16.0.1",
        ];
        let candidates = candidate_addresses(
            "192.168.6.3:41641".parse().unwrap(),
            addresses.into_iter().map(|a| a.parse().unwrap()),
        );
        assert_eq!(
            candidates,
            [
                "10.88.0.1:41641",
                "10.203.0.1:41641",
                "10.203.1.1:41641",
                "192.168.6.3:41641"
            ]
            .map(|s| s.parse().unwrap())
        );
    }
    #[test]
    fn a_lan_without_the_internet_route_is_still_advertised() {
        let candidates = candidate_addresses(
            "127.0.0.1:1234".parse().unwrap(),
            ["10.203.0.2".parse().unwrap()].into_iter(),
        );
        assert_eq!(candidates, ["10.203.0.2:1234".parse().unwrap()]);
    }
}
