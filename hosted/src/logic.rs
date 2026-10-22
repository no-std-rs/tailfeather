use std::net::Ipv4Addr;
use tailfeather::{
    keys::NodePublic,
    netmap::{Cidr4, Peer},
};
fn contains(cidr: &Cidr4, address: Ipv4Addr) -> bool {
    let prefix = u32::from(cidr.prefix.min(32));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(cidr.address) & mask == u32::from(address) & mask
}

/// The peer an outbound IPv4 packet belongs to: the peer whose own address it
/// is, otherwise the most specific `AllowedIPs` match.
pub fn route_ipv4<'a>(
    peers: impl IntoIterator<Item = &'a Peer>,
    destination: Ipv4Addr,
) -> Option<NodePublic> {
    let mut best: Option<(u8, NodePublic)> = None;
    for peer in peers {
        if peer
            .addresses
            .iter()
            .any(|cidr| cidr.address == destination)
        {
            return Some(peer.node_key);
        }
        for cidr in peer
            .allowed_ips
            .iter()
            .filter(|cidr| contains(cidr, destination))
        {
            if best.is_none_or(|(prefix, _)| cidr.prefix > prefix) {
                best = Some((cidr.prefix, peer.node_key));
            }
        }
    }
    best.map(|(_, key)| key)
}

/// The source and destination of an IPv4 header, when `packet` is one.
pub fn ipv4_addresses(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((source, destination))
}

/// WireGuard's cryptokey routing on receive: a decrypted packet is accepted
/// only if it is addressed to this node and its source routes back to the peer
/// that sent it.
///
/// The source is resolved across every peer with the same most-specific rule as
/// [`route_ipv4`], not just against the sender's own list. Otherwise a peer
/// with a broad route, such as an exit node's `0.0.0.0/0`, could send packets
/// that claim another peer's address.
pub fn inbound_allowed<'a>(
    packet: &[u8],
    sender: &NodePublic,
    peers: impl IntoIterator<Item = &'a Peer>,
    own: Ipv4Addr,
) -> bool {
    let Some((source, destination)) = ipv4_addresses(packet) else {
        return false;
    };
    destination == own && route_ipv4(peers, source) == Some(*sender)
}

/// The next TAI64N timestamp for a WireGuard initiation.
///
/// Responders reject an initiation whose timestamp is not strictly newer than
/// the last one they accepted from this key, so the value is derived from the
/// wall clock (to survive reloads) and forced strictly increasing within a
/// session.
pub fn next_tai64n(last: &mut [u8; 12], unix_ms: u64) -> [u8; 12] {
    const TAI_OFFSET: u64 = (1 << 62) + 10;
    let mut next = [0u8; 12];
    next[..8].copy_from_slice(&(unix_ms / 1000 + TAI_OFFSET).to_be_bytes());
    next[8..].copy_from_slice(&(((unix_ms % 1000) * 1_000_000) as u32).to_be_bytes());
    if next <= *last {
        next = *last;
        let nanos = u32::from_be_bytes(next[8..].try_into().expect("four bytes")) + 1;
        if nanos >= 1_000_000_000 {
            let seconds = u64::from_be_bytes(next[..8].try_into().expect("eight bytes")) + 1;
            next[..8].copy_from_slice(&seconds.to_be_bytes());
            next[8..].copy_from_slice(&0u32.to_be_bytes());
        } else {
            next[8..].copy_from_slice(&nanos.to_be_bytes());
        }
    }
    *last = next;
    next
}
