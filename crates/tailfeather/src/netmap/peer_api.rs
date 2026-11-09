//! What peer API endpoints decide with, from the netmap.
//!
//! The decisions mirror Tailscale's own (`feature/taildrop` in tailscale.com,
//! v1.94): who may drop files on this node, and which peers this node may
//! drop files on. Both need the owners, tags and capabilities the parser
//! retains with the `peer-api` feature, plus the packet filter's capability
//! grants.

use core::net::{IpAddr, SocketAddr};

use super::Netmap;
use super::peer::Peer;
use super::policy::PeerCapability;

/// The node capability that enables Taildrop on a node.
pub const CAP_FILE_SHARING: &str = "https://tailscale.com/cap/file-sharing";

/// This node's ownership and capabilities from its own control record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelfServices {
    pub user_id: u64,
    pub tagged: bool,
    /// Control enabled Taildrop for this node ([`CAP_FILE_SHARING`]).
    pub file_sharing: bool,
}

impl SelfServices {
    pub const fn new() -> Self {
        Self {
            user_id: 0,
            tagged: false,
            file_sharing: false,
        }
    }
}

impl<const PEERS: usize> Netmap<PEERS> {
    /// The peer that owns tailnet address `address`.
    pub fn peer_by_address(&self, address: IpAddr) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.has_address(address))
    }

    /// This node's own tailnet address in `address`'s family.
    fn own_address(&self, family: IpAddr) -> Option<IpAddr> {
        self.addresses
            .iter()
            .map(|cidr| cidr.address)
            .find(|address| address.is_ipv4() == family.is_ipv4())
    }

    /// Whether the filter grants `peer`'s address `cap` toward this node.
    fn peer_has_cap(&self, source: IpAddr, cap: PeerCapability) -> bool {
        self.own_address(source)
            .is_some_and(|own| self.packet_filter.has_peer_cap(source, own, cap))
    }

    /// Whether the node at tailnet address `source` may send this node files.
    ///
    /// As stock Tailscale decides it (`canPutFile`, `hasCapFileSharing`):
    /// control must have enabled Taildrop here, the sender must be a signed
    /// node, and either both nodes are untagged and owned by the same user,
    /// or a grant gives the sender `https://tailscale.com/cap/file-send`.
    pub fn taildrop_allows_from(&self, source: IpAddr) -> bool {
        let Some(peer) = self.peer_by_address(source) else {
            return false;
        };
        let own = self.services;
        let same_untagged_user = !own.tagged
            && !peer.services.tagged
            && own.user_id != 0
            && own.user_id == peer.services.user_id;
        own.file_sharing
            && !peer.services.unsigned_peer_api_only
            && (same_untagged_user || self.peer_has_cap(source, PeerCapability::FILE_SEND))
    }

    /// Where to send `peer` files, when this node may: its peer API.
    ///
    /// As stock Tailscale decides it (`taildropTargetStatus`): Taildrop is
    /// enabled here, the peer is online, it is owned by the same user or a
    /// grant gives it `https://tailscale.com/cap/file-sharing-target`, and it
    /// advertises a peer API. IPv4 is preferred, as this crate's TCP stacks
    /// are IPv4.
    pub fn taildrop_target(&self, peer: &Peer) -> Option<SocketAddr> {
        if !self.services.file_sharing || !peer.online() {
            return None;
        }
        let address = peer
            .tailscale_ipv4()
            .map(IpAddr::V4)
            .or(peer.tailscale_ipv6().map(IpAddr::V6))?;
        let same_user =
            self.services.user_id != 0 && self.services.user_id == peer.services.user_id;
        if !same_user && !self.peer_has_cap(address, PeerCapability::FILE_SHARING_TARGET) {
            return None;
        }
        peer.peer_api4()
            .map(SocketAddr::V4)
            .or(peer.peer_api6().map(SocketAddr::V6))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{format, string::String};

    use super::*;
    use crate::keys::NodePrivate;
    use crate::netmap::Parser;

    fn key(byte: u8) -> String {
        let mut text = [0u8; 128];
        String::from(
            NodePrivate::from_bytes([byte; 32])
                .public()
                .encode(&mut text)
                .unwrap(),
        )
    }

    fn apply(netmap: &mut Netmap<8>, document: &str) {
        let mut parser = Parser::<8>::new();
        parser.push(netmap, document.as_bytes()).unwrap();
        parser.finish(netmap).unwrap();
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// This node (user 1) and four peers, shaped like Headscale's map.
    fn tailnet(self_caps: &str) -> String {
        format!(
            r#"{{"Node":{{"ID":9,"Key":"{own}","User":1,"Addresses":["100.64.0.9/32"],{self_caps}}},
               "Peers":[
                 {{"ID":1,"Key":"{a}","User":1,"Online":true,"Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],
                   "Hostinfo":{{"Hostname":"laptop","Services":[
                     {{"Proto":"peerapi4","Port":58436}},{{"Proto":"peerapi6","Port":58436}},
                     {{"Proto":"peerapi-dns-proxy","Port":1}}]}}}},
                 {{"ID":2,"Key":"{b}","User":2,"Online":true,"Addresses":["100.64.0.2/32"],
                   "Hostinfo":{{"Services":[{{"Port":41000,"Proto":"peerapi4"}}]}}}},
                 {{"ID":3,"Key":"{c}","User":1,"Online":true,"Tags":["tag:server"],"Addresses":["100.64.0.3/32"]}},
                 {{"ID":4,"Key":"{d}","User":1,"Online":true,"UnsignedPeerAPIOnly":true,"Addresses":["100.64.0.4/32"]}}
               ],
               "PacketFilter":[
                 {{"SrcIPs":["*"],"DstPorts":[{{"IP":"*","Ports":{{"First":0,"Last":65535}}}}]}},
                 {{"SrcIPs":["100.64.0.2/32"],"CapGrant":[{{"Dsts":["100.64.0.9/32"],
                   "CapMap":{{"https://tailscale.com/cap/file-send":[],"https://example.com/cap/other":null}}}}]}}
               ]}}"#,
            own = key(9),
            a = key(1),
            b = key(2),
            c = key(3),
            d = key(4),
        )
    }

    #[test]
    fn retains_owners_tags_and_peer_api_ports() {
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(r#""Capabilities":["https://tailscale.com/cap/file-sharing"]"#),
        );
        assert_eq!(
            netmap.services,
            SelfServices {
                user_id: 1,
                tagged: false,
                file_sharing: true
            }
        );
        let laptop = netmap.peers.get(1).unwrap();
        assert_eq!(laptop.services.user_id, 1);
        assert_eq!(
            laptop.peer_api4(),
            Some("100.64.0.1:58436".parse().unwrap())
        );
        assert_eq!(
            laptop.peer_api6(),
            Some("[fd7a:115c:a1e0::1]:58436".parse().unwrap())
        );
        assert_eq!(netmap.peers.get(2).unwrap().services.peer_api4, 41000);
        assert!(netmap.peers.get(3).unwrap().services.tagged);
        assert!(netmap.peers.get(4).unwrap().services.unsigned_peer_api_only);
        assert_eq!(netmap.peers.get(4).unwrap().peer_api4(), None);
    }

    #[test]
    fn decides_who_may_send_files_like_stock_tailscale() {
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(r#""Capabilities":["https://tailscale.com/cap/file-sharing"]"#),
        );
        // Same untagged user.
        assert!(netmap.taildrop_allows_from(ip("100.64.0.1")));
        assert!(netmap.taildrop_allows_from(ip("fd7a:115c:a1e0::1")));
        // Another user, granted file-send toward this node.
        assert!(netmap.taildrop_allows_from(ip("100.64.0.2")));
        // Tagged, and unsigned, peers of the same user.
        assert!(!netmap.taildrop_allows_from(ip("100.64.0.3")));
        assert!(!netmap.taildrop_allows_from(ip("100.64.0.4")));
        // No such peer.
        assert!(!netmap.taildrop_allows_from(ip("100.64.0.77")));

        // Without the node capability nothing may.
        let mut disabled = Netmap::<8>::new();
        apply(&mut disabled, &tailnet(r#""Capabilities":[]"#));
        assert!(!disabled.taildrop_allows_from(ip("100.64.0.1")));
    }

    #[test]
    fn reads_the_node_capability_from_cap_map_too() {
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(
                r#""CapMap":{"https://tailscale.com/cap/file-sharing":null,"other":[{"x":1}]}"#,
            ),
        );
        assert!(netmap.services.file_sharing);
        // A later self record without it withdraws it.
        apply(
            &mut netmap,
            &format!(
                r#"{{"Node":{{"Key":"{own}","User":1,"Addresses":["100.64.0.9/32"]}}}}"#,
                own = key(9)
            ),
        );
        assert!(!netmap.services.file_sharing);
        assert!(!netmap.taildrop_allows_from(ip("100.64.0.1")));
    }

    #[test]
    fn finds_send_targets_like_stock_tailscale() {
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(r#""Capabilities":["https://tailscale.com/cap/file-sharing"]"#),
        );
        let target = |netmap: &Netmap<8>, id| netmap.taildrop_target(netmap.peers.get(id).unwrap());
        assert_eq!(
            target(&netmap, 1),
            Some("100.64.0.1:58436".parse().unwrap())
        );
        // Another user without file-sharing-target.
        assert_eq!(target(&netmap, 2), None);
        // Same user but no peer API advertised.
        assert_eq!(target(&netmap, 3), None);

        // An offline peer is no target; a patch changes only that.
        apply(
            &mut netmap,
            r#"{"PeersChangedPatch":[{"NodeID":1,"Online":false}]}"#,
        );
        assert_eq!(target(&netmap, 1), None);
        assert_eq!(netmap.peers.get(1).unwrap().services.peer_api4, 58436);
        apply(
            &mut netmap,
            r#"{"PeersChangedPatch":[{"NodeID":1,"Online":true}]}"#,
        );
        assert_eq!(
            target(&netmap, 1),
            Some("100.64.0.1:58436".parse().unwrap())
        );
    }

    #[test]
    fn a_staged_copy_keeps_the_capability_grants() {
        // Staging copies the policy rule by rule; grants must come along.
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(r#""Capabilities":["https://tailscale.com/cap/file-sharing"]"#),
        );
        let mut staged = Netmap::<8>::new();
        staged.copy_from(&netmap);
        assert!(!staged.packet_filter.truncated());
        // Peer 2 may send only through its file-send grant.
        assert!(staged.taildrop_allows_from(ip("100.64.0.2")));
        assert!(staged.taildrop_allows_from(ip("100.64.0.1")));
        assert!(!staged.taildrop_allows_from(ip("100.64.0.3")));
    }

    #[test]
    fn grants_follow_their_named_filter_set() {
        let mut netmap = Netmap::<8>::new();
        apply(
            &mut netmap,
            &tailnet(r#""Capabilities":["https://tailscale.com/cap/file-sharing"]"#),
        );
        let target = r#"{"PacketFilters":{"grants":[{"SrcIPs":["100.64.0.2"],"CapGrant":[
                 {"Dsts":["100.64.0.9/32"],"Caps":["https://tailscale.com/cap/file-sharing-target"]}]}]}}"#;
        apply(&mut netmap, target);
        let peer = netmap.peers.get(2).unwrap();
        assert_eq!(
            netmap.taildrop_target(peer),
            Some("100.64.0.2:41000".parse().unwrap())
        );
        apply(&mut netmap, r#"{"PacketFilters":{"grants":null}}"#);
        let peer = netmap.peers.get(2).unwrap();
        assert_eq!(netmap.taildrop_target(peer), None);
    }
}
