//! The parser against a real server's output.
//!
//! `tests/vectors/map_response.json` is the sequence of MapResponses a real
//! tailscaled 1.94.2 received from a real Headscale v0.29.3, recorded by
//! `tests/lab/capture.sh`. Eleven responses: one full map and ten deltas, which
//! is the ratio that makes delta handling load-bearing rather than an
//! optimisation.
//!
//! These tests are in `tests/` rather than beside the code because they need
//! `std` to read the file. The crate they exercise does not.

use std::path::PathBuf;

use tailfeather::netmap::parser::{Netmap, Parser};

fn vectors() -> PathBuf {
    std::env::var_os("TS_CONFORMANCE_VECTORS")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_file() {
                path.parent().unwrap().to_path_buf()
            } else {
                path
            }
        })
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors"))
}

/// The captured responses, as raw JSON documents.
fn captured() -> Vec<String> {
    let text = std::fs::read_to_string(vectors().join("map_response.json"))
        .expect("run tests/lab/capture.sh to record the vectors");
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    parsed
        .as_array()
        .expect("the capture is an array of responses")
        .iter()
        .map(|response| serde_json::to_string(response).unwrap())
        .collect()
}

/// Feed one document through in `chunk` byte pieces.
fn apply(netmap: &mut Netmap<32>, document: &str, chunk: usize) {
    let bytes = document.as_bytes();
    let mut parser = Parser::<32>::new();
    for piece in bytes.chunks(chunk) {
        parser
            .push(netmap, piece)
            .expect("the capture is valid JSON");
    }
    parser.finish(netmap).expect("the capture parses cleanly");
}

#[test]
fn parses_the_full_map_a_real_server_sent() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, &documents[0], 4096);

    // Our own record.
    assert_eq!(
        netmap.node_key.unwrap().to_string(),
        "nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79"
    );
    assert!(netmap.disco_key.is_some());
    assert_eq!(netmap.addresses.len(), 2, "one IPv4 and one IPv6");

    // The peer, with everything needed to reach it.
    assert_eq!(netmap.peers.len(), 1);
    let peer = netmap.peers.iter().next().unwrap();
    assert_eq!(peer.id, 1);
    assert_eq!(
        peer.node_key.to_string(),
        "nodekey:f4dfaca7341906ffa704d7e529ad63aba59b6616ebea8c9ebbc6c84bb814ed4d"
    );
    assert!(peer.disco_key.is_some());
    assert!(peer.online());
    assert_eq!(peer.home_derp, 999);
    assert_eq!(peer.tailscale_ipv4().unwrap().to_string(), "100.64.0.1");
    // IPv4 route lists remain compact; the IPv6 host address is retained
    // separately for cryptokey ownership checks on IPv6 exit traffic.
    assert!(peer.tailscale_ipv6().is_some());
    assert_eq!(peer.allowed_ips.len(), 1);
    assert_eq!(
        peer.allowed_ips[0].address,
        core::net::Ipv4Addr::new(100, 64, 0, 1)
    );
    assert_eq!(peer.endpoints.len(), 2);
    assert_eq!(
        peer.direct_endpoint().unwrap().to_string(),
        "192.168.6.167:37907"
    );

    // The DERP map the lab advertises.
    assert_eq!(netmap.derp.len(), 1);
    let region = netmap.derp.region(999).unwrap();
    assert_eq!(region.code.as_str(), "lab");
    assert_eq!(region.nodes.len(), 1);
    assert_eq!(region.nodes[0].host_name.as_str(), "127.0.0.1");
    assert_eq!(region.nodes[0].port, 8080);
    assert_eq!(region.nodes[0].stun_port, 3478);

    assert!(netmap.packet_filter.is_valid());
    assert_eq!(netmap.packet_filter.set_count(), 1);
    assert_eq!(netmap.packet_filter.rule_count(), 1);
    assert!(netmap.packet_filter.allows(
        "100.64.0.1".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        6,
        443,
    ));
}

#[test]
fn packet_filter_sets_replace_delete_and_clear_incrementally() {
    let any = r#"{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]}"#;
    let dns = r#"{"PacketFilters":{"dns":[{"SrcIPs":["100.64.0.0/10"],"DstPorts":[{"IP":"1.1.1.1/32","Ports":{"First":53,"Last":53}}],"IPProto":[17]}]}}"#;
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, any, 1);
    apply(&mut netmap, dns, 3);
    assert_eq!(netmap.packet_filter.set_count(), 2);
    assert_eq!(netmap.packet_filter.rule_count(), 2);
    assert!(netmap.packet_filter.allows(
        "100.64.0.9".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        17,
        53,
    ));

    apply(&mut netmap, r#"{"PacketFilters":{"dns":null}}"#, 2);
    assert_eq!(netmap.packet_filter.set_count(), 1);
    apply(&mut netmap, r#"{"PacketFilters":{"*":null}}"#, 2);
    assert!(netmap.packet_filter.is_valid());
    assert_eq!(netmap.packet_filter.rule_count(), 0);
    assert!(!netmap.packet_filter.allows(
        "100.64.0.9".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        17,
        53,
    ));
}

#[test]
fn malformed_or_overflowing_packet_filter_rejects_the_staged_map() {
    fn parse(document: &str) -> Result<(), tailfeather::netmap::Error> {
        let mut netmap = Netmap::<32>::new();
        let mut parser = Parser::<32>::new();
        parser.push(&mut netmap, document.as_bytes())?;
        parser.finish(&mut netmap)
    }

    let reversed = r#"{"PacketFilters":{"base":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":54,"Last":53}}]}]}}"#;
    assert_eq!(
        parse(reversed),
        Err(tailfeather::netmap::Error::MalformedField(
            tailfeather::netmap::MalformedField::PacketDestination
        ))
    );
    let protocols = r#"{"PacketFilters":{"base":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}],"IPProto":[1,2,3,4,5,6,7,8,9]}]}}"#;
    assert_eq!(
        parse(protocols),
        Err(tailfeather::netmap::Error::Full(
            tailfeather::netmap::CapacityError::PacketPolicy
        ))
    );
}

#[test]
fn both_approved_default_routes_are_required() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"Node":{"Addresses":["100.64.0.7/32"],"PrimaryRoutes":["0.0.0.0/0"]}}"#,
        1,
    );
    assert!(netmap.has_assigned_ipv4());
    assert!(!netmap.default_routes_approved());
    apply(
        &mut netmap,
        r#"{"Node":{"PrimaryRoutes":["0.0.0.0/0","::/0"]}}"#,
        2,
    );
    assert!(netmap.default_routes_approved());
}

#[test]
fn default_route_approval_is_independent_and_revocable_per_family() {
    for field in ["PrimaryRoutes", "AllowedIPs"] {
        let mut netmap = Netmap::<32>::new();
        for (routes, ipv4, ipv6) in [
            (r#"["0.0.0.0/0"]"#, true, false),
            (r#"["::/0"]"#, false, true),
            (r#"["0.0.0.0/0","::/0"]"#, true, true),
            (r#"["0.0.0.0/32","::/128"]"#, false, false),
            (r#"["0.0.0.0/0"]"#, true, false),
            ("[]", false, false),
        ] {
            let document = format!(r#"{{"Node":{{"{field}":{routes}}}}}"#);
            apply(&mut netmap, &document, 1);
            assert_eq!(netmap.ipv4_default_route_approved(), ipv4, "{document}");
            assert_eq!(netmap.ipv6_default_route_approved(), ipv6, "{document}");
            assert_eq!(netmap.default_routes_approved(), ipv4 && ipv6, "{document}");
        }
    }
}

#[test]
fn hosted_allowed_ips_carry_approved_exit_routes() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"Node":{"Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"AllowedIPs":["100.64.0.1/32","fd7a:115c:a1e0::1/128","0.0.0.0/0","::/0"]}}"#,
        7,
    );
    assert!(netmap.default_routes_approved());
}

#[test]
fn self_route_fields_are_unioned_independent_of_json_order() {
    for document in [
        r#"{"Node":{"AllowedIPs":["0.0.0.0/0"],"PrimaryRoutes":["::/0"]}}"#,
        r#"{"Node":{"PrimaryRoutes":["::/0"],"AllowedIPs":["0.0.0.0/0"]}}"#,
    ] {
        let mut netmap = Netmap::<32>::new();
        apply(&mut netmap, document, 1);
        assert!(netmap.default_routes_approved(), "document: {document}");
    }
}

/// Hosted control may describe a home region only through the deprecated
/// `"DERP": "127.3.3.40:<region>"` string. Losing it leaves a relay-only node
/// with no way to reach the peer at all.
#[test]
fn the_legacy_derp_string_carries_the_home_region() {
    let key = |byte: u8| format!("nodekey:{}", format!("{byte:02x}").repeat(32));
    let document = format!(
        r#"{{"Node":{{"DERP":"127.3.3.40:1"}},"Peers":[
            {{"ID":1,"Key":"{}","DERP":"127.3.3.40:22"}},
            {{"ID":2,"Key":"{}","HomeDERP":4}},
            {{"ID":3,"Key":"{}","HomeDERP":9,"DERP":"127.3.3.40:5"}},
            {{"ID":4,"Key":"{}","DERP":"not-a-derp-address"}},
            {{"ID":5,"Key":"{}","DERP":"127.3.3.40:5","HomeDERP":9}}]}}"#,
        key(0x11),
        key(0x22),
        key(0x33),
        key(0x44),
        key(0x55),
    );
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, &document, 5);
    assert_eq!(netmap.home_derp, 1);
    let region = |id| netmap.peers.get(id).unwrap().home_derp;
    assert_eq!(region(1), 22, "legacy string only");
    assert_eq!(region(2), 4, "numeric only");
    assert_eq!(region(3), 9, "numeric wins over a later legacy string");
    assert_eq!(region(4), 0, "an unrecognised string is ignored");
    assert_eq!(region(5), 9, "numeric wins over an earlier legacy string");

    // The self record follows the same precedence in either member order, and
    // a later record that carries only the legacy string still updates it.
    for self_record in [
        r#"{"Node":{"HomeDERP":9,"DERP":"127.3.3.40:5"}}"#,
        r#"{"Node":{"DERP":"127.3.3.40:5","HomeDERP":9}}"#,
    ] {
        let mut netmap = Netmap::<32>::new();
        apply(&mut netmap, self_record, 3);
        assert_eq!(netmap.home_derp, 9, "{self_record}");
        apply(&mut netmap, r#"{"Node":{"DERP":"127.3.3.40:22"}}"#, 3);
        assert_eq!(netmap.home_derp, 22, "{self_record}");
    }
}

#[test]
fn oversized_unknown_keys_are_ignored_with_their_subtrees() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"this-is-an-unknown-forward-compatible-key-that-is-deliberately-longer-than-sixty-four-bytes":{"nested":[1,2,3]},"Node":{"Addresses":["100.64.0.7/32"]}}"#,
        3,
    );
    assert!(netmap.has_assigned_ipv4());
}

/// The property the whole design rests on: the result must not depend on where
/// the bytes were split, because HTTP/2 frame boundaries have nothing to do
/// with JSON structure.
#[test]
fn the_result_is_the_same_however_the_stream_is_chunked() {
    let documents = captured();
    let reference = {
        let mut netmap = Netmap::<32>::new();
        apply(&mut netmap, &documents[0], usize::MAX);
        netmap
    };

    for chunk in [1, 2, 7, 13, 64, 512, 4096] {
        let mut netmap = Netmap::<32>::new();
        apply(&mut netmap, &documents[0], chunk);
        assert_eq!(
            netmap.peers.len(),
            reference.peers.len(),
            "chunked at {chunk}"
        );
        assert_eq!(netmap.node_key, reference.node_key, "chunked at {chunk}");
        let peer = netmap.peers.iter().next().unwrap();
        let expected = reference.peers.iter().next().unwrap();
        assert_eq!(peer.node_key, expected.node_key, "chunked at {chunk}");
        assert_eq!(peer.endpoints, expected.endpoints, "chunked at {chunk}");
        assert_eq!(peer.addresses, expected.addresses, "chunked at {chunk}");
    }
}

/// Every captured response applied in order, which is what a live session does.
#[test]
fn applies_the_whole_captured_session_including_deltas() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    for document in &documents {
        apply(&mut netmap, document, 97);
    }
    assert_eq!(netmap.responses, documents.len());
    assert_eq!(
        netmap.home_derp, 999,
        "a self-node delta selects the home DERP"
    );

    // The peer survives ten deltas, and is still reachable. There is exactly
    // one: the captured session's `PeersChanged` also carries this node's *own*
    // record, which must not become a peer of itself.
    assert_eq!(netmap.peers.len(), 1);
    let peer = netmap.peers.iter().next().unwrap();
    assert_eq!(peer.id, 1);
    assert!(
        !peer.endpoints.is_empty(),
        "the deltas must not have blanked the endpoints"
    );
}

/// A patch names a peer and a few fields. Applying it as if it were a whole
/// record would clear everything it did not mention — on a live tailnet that
/// means every peer losing its endpoints on every heartbeat, and the tunnel
/// silently falling back to a relay.
#[test]
fn a_patch_changes_only_what_it_names() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, &documents[0], 4096);

    let before = netmap.peers.get(1).unwrap().clone();
    assert!(!before.endpoints.is_empty());

    // The captured patch is `[{"NodeID": 2, "Online": true}]` — for a node we
    // do not have — so use one naming the peer we do.
    apply(
        &mut netmap,
        r#"{"PeersChangedPatch":[{"NodeID":1,"Online":false}]}"#,
        4096,
    );

    let after = netmap.peers.get(1).unwrap();
    assert!(!after.online(), "the field the patch named must change");
    assert_eq!(
        after.endpoints, before.endpoints,
        "a field the patch did not name must be left alone"
    );
    assert_eq!(after.node_key, before.node_key);
    assert_eq!(after.addresses, before.addresses);
    assert_eq!(after.home_derp, before.home_derp);
}

#[test]
fn a_patch_for_an_unknown_peer_does_not_invent_one() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"PeersChangedPatch":[{"NodeID":42,"Online":true}]}"#,
        4096,
    );
    assert!(
        netmap.peers.is_empty(),
        "a patch carries no key, so a peer built from one could never be reached"
    );
}

#[test]
fn peers_changed_replaces_a_record_and_peers_removed_forgets_it() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, &documents[0], 4096);
    assert_eq!(netmap.peers.len(), 1);

    // A whole record for the same id: the endpoints it omits are gone, because
    // the server has said this is the peer now.
    apply(
        &mut netmap,
        r#"{"PeersChanged":[{"ID":1,"Key":"nodekey:f4dfaca7341906ffa704d7e529ad63aba59b6616ebea8c9ebbc6c84bb814ed4d","Online":true,"Addresses":["100.64.0.1/32"]}]}"#,
        4096,
    );
    assert_eq!(netmap.peers.len(), 1);
    assert!(netmap.peers.get(1).unwrap().endpoints.is_empty());

    apply(&mut netmap, r#"{"PeersRemoved":[1]}"#, 4096);
    assert!(netmap.peers.is_empty());
}

#[test]
fn full_peer_and_derp_snapshots_remove_entries_the_server_omits() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    apply(&mut netmap, &documents[0], 4096);
    assert_eq!(netmap.peers.len(), 1);
    assert_eq!(netmap.derp.len(), 1);

    apply(&mut netmap, r#"{"Peers":[]}"#, 1);
    assert!(netmap.peers.is_empty());

    apply(&mut netmap, r#"{"DERPMap":{"Regions":{}}}"#, 1);
    assert!(netmap.derp.is_empty());
}

#[test]
fn derp_regions_keep_two_relay_capable_nodes_and_skip_stun_only_entries() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"9":{"RegionID":9,"RegionCode":"test","Nodes":[{"HostName":"stun.example","DERPPort":443,"STUNOnly":true},{"HostName":"primary.example","DERPPort":443,"InsecureForTests":true},{"HostName":"backup.example","DERPPort":444},{"HostName":"extra.example","DERPPort":445}]}}}}"#,
        4096,
    );
    let region = netmap.derp.region(9).unwrap();
    assert_eq!(region.nodes.len(), 2);
    assert_eq!(region.nodes[0].host_name.as_str(), "primary.example");
    assert!(region.nodes[0].insecure_for_tests());
    assert_eq!(region.nodes[1].host_name.as_str(), "backup.example");
    assert!(!region.nodes[1].insecure_for_tests());
}

#[test]
fn derp_no_measure_no_home_is_retained_and_resets_between_regions() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"1":{"NoMeasureNoHome":true,"Nodes":[{"HostName":"peer-only.example"}]},"2":{"Nodes":[{"HostName":"home.example"}]},"3":{"NoMeasureNoHome":false,"Nodes":[]}}}}"#,
        1,
    );
    assert!(netmap.derp.region(1).unwrap().no_measure_no_home);
    assert!(!netmap.derp.region(2).unwrap().no_measure_no_home);
    assert!(!netmap.derp.region(3).unwrap().no_measure_no_home);
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"1":{"Nodes":[{"HostName":"home-now.example"}]}}}}"#,
        1,
    );
    assert!(!netmap.derp.region(1).unwrap().no_measure_no_home);
}

#[test]
fn derp_and_stun_ports_follow_upstream_defaults() {
    for ports in ["", ",\"DERPPort\":0,\"STUNPort\":0"] {
        let mut netmap = Netmap::<32>::new();
        apply(
            &mut netmap,
            &format!(
                r#"{{"DERPMap":{{"Regions":{{"9":{{"Nodes":[{{"HostName":"relay.example"{ports}}}]}}}}}}}}"#
            ),
            1,
        );
        let node = &netmap.derp.region(9).unwrap().nodes[0];
        assert_eq!(node.port, 443);
        assert_eq!(node.stun_port, 3478);
    }
}

#[test]
fn derp_hostnames_keep_the_previously_supported_capacity() {
    let mut netmap = Netmap::<32>::new();
    let hostname = "relay-with-a-custom-deployment-name.example.test";
    assert!(hostname.len() > 32 && hostname.len() <= 64);
    apply(
        &mut netmap,
        &format!(
            r#"{{"DERPMap":{{"Regions":{{"9":{{"RegionID":9,"RegionCode":"test","Nodes":[{{"HostName":"{hostname}","DERPPort":443}}]}}}}}}}}"#
        ),
        4096,
    );
    assert_eq!(
        netmap.derp.region(9).unwrap().nodes[0].host_name.as_str(),
        hostname
    );
}

#[test]
fn derp_certificate_names_are_retained_separately_from_connection_hosts() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"9":{"RegionID":9,"RegionCode":"test","Nodes":[{"HostName":"connect.example","CertName":"certificate.example","DERPPort":443}]}}}}"#,
        7,
    );
    let relay = &netmap.derp.region(9).unwrap().nodes[0];
    assert_eq!(relay.host_name.as_str(), "connect.example");
    assert_eq!(netmap.derp.cert_name(relay), "certificate.example");
}

#[test]
fn discarded_derp_backups_do_not_consume_certificate_name_capacity() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"9":{"RegionID":9,"RegionCode":"test","Nodes":[{"HostName":"one.example","CertName":"cert-one.example","DERPPort":443},{"HostName":"two.example","CertName":"cert-two.example","DERPPort":443},{"HostName":"three.example","CertName":"cert-three.example","DERPPort":443},{"HostName":"four.example","CertName":"cert-four.example","DERPPort":443},{"HostName":"five.example","CertName":"cert-five.example","DERPPort":443}]}}}}"#,
        11,
    );
    let region = netmap.derp.region(9).unwrap();
    assert_eq!(region.nodes.len(), 2);
    assert_eq!(netmap.derp.cert_name(&region.nodes[0]), "cert-one.example");
    assert_eq!(netmap.derp.cert_name(&region.nodes[1]), "cert-two.example");
}

#[test]
fn a_stun_only_node_is_retained_when_relays_offer_no_stun_endpoint() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"DERPMap":{"Regions":{"9":{"RegionID":9,"RegionCode":"test","Nodes":[{"HostName":"relay.example","DERPPort":443,"STUNPort":-1},{"HostName":"backup.example","DERPPort":444,"STUNPort":-1},{"HostName":"stun.example","STUNPort":3478,"STUNOnly":true}]}}}}"#,
        32,
    );
    let region = netmap.derp.region(9).unwrap();
    assert_eq!(region.nodes.len(), 2);
    assert_eq!(region.nodes[0].host_name.as_str(), "relay.example");
    assert_eq!(region.nodes[1].host_name.as_str(), "stun.example");
    assert_eq!(region.nodes[1].port, 0);
    assert_eq!(region.nodes[1].stun_port, 3478);
}

/// The scratch buffer is the only memory that scales with the document, and it
/// scales with the longest *string*, not the length or the peer count.
#[test]
fn the_scratch_buffer_bounds_strings_not_documents() {
    let documents = captured();
    let total: usize = documents.iter().map(|d| d.len()).sum();
    assert!(
        total > 15_000,
        "the capture ({total} bytes) should be large enough for this to mean something"
    );

    let longest = documents
        .iter()
        .flat_map(|d| d.split('"').skip(1).step_by(2))
        .map(str::len)
        .max()
        .unwrap();
    assert!(
        longest < tailfeather::netmap::MAX_STRING,
        "longest captured string is {longest} bytes"
    );

    // A scratch buffer sized for the longest string parses all of it, however
    // much there is in total.
    let mut netmap = Netmap::<32>::new();
    for document in &documents {
        apply(&mut netmap, document, 64);
    }
    assert_eq!(netmap.responses, documents.len());
}

/// The server sends a node its own record in `PeersChanged`, and the captured
/// session does it four times. A node that took itself as a peer would try to
/// complete a WireGuard handshake with its own key, which never can.
#[test]
fn this_node_never_becomes_its_own_peer() {
    let documents = captured();
    let mut netmap = Netmap::<32>::new();
    for document in &documents {
        apply(&mut netmap, document, 512);
    }
    let own = netmap.node_key.unwrap();
    assert!(
        netmap.peers.by_node_key(&own).is_none(),
        "the node's own key is in its peer table"
    );

    // And the same holds when its own record arrives *before* it learns who it
    // is, which the response ordering does not guarantee.
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"PeersChanged":[{"ID":9,"Key":"nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79"}]}"#,
        512,
    );
    assert_eq!(netmap.peers.len(), 1, "not yet known to be ourselves");
    apply(
        &mut netmap,
        r#"{"Node":{"ID":2,"Key":"nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79"}}"#,
        512,
    );
    assert!(
        netmap.peers.is_empty(),
        "learning our own key must retire it"
    );
}

#[test]
fn a_changed_self_record_carries_route_approval_without_becoming_a_peer() {
    const KEY: &str = "nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79";
    for documents in [
        [
            format!(r#"{{"Node":{{"Key":"{KEY}"}}}}"#),
            format!(
                r#"{{"PeersChanged":[{{"ID":9,"Key":"{KEY}","AllowedIPs":["100.64.0.7/32","fd7a:115c:a1e0::7/128"],"PrimaryRoutes":["0.0.0.0/0","::/0"]}}]}}"#
            ),
        ],
        [
            format!(
                r#"{{"PeersChanged":[{{"ID":9,"Key":"{KEY}","AllowedIPs":["100.64.0.7/32","fd7a:115c:a1e0::7/128"],"PrimaryRoutes":["0.0.0.0/0","::/0"]}}]}}"#
            ),
            format!(r#"{{"Node":{{"Key":"{KEY}"}}}}"#),
        ],
    ] {
        let mut netmap = Netmap::<32>::new();
        for document in documents {
            apply(&mut netmap, &document, 7);
        }
        assert!(netmap.default_routes_approved());
        assert!(netmap.peers.is_empty(), "the self record became a peer");
    }
}

#[test]
fn delayed_self_defaults_survive_a_full_allowed_ip_list() {
    const KEY: &str = "nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79";
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        &format!(
            r#"{{"PeersChanged":[{{"ID":9,"Key":"{KEY}","AllowedIPs":["100.64.0.1/32","100.64.0.2/32","100.64.0.3/32","100.64.0.4/32","100.64.0.5/32","100.64.0.6/32","100.64.0.7/32","100.64.0.8/32"],"PrimaryRoutes":["0.0.0.0/0","::/0"]}}]}}"#
        ),
        11,
    );
    apply(&mut netmap, &format!(r#"{{"Node":{{"Key":"{KEY}"}}}}"#), 7);

    assert!(netmap.default_routes_approved());
    assert!(netmap.peers.is_empty());
}

#[test]
fn current_self_routes_override_delayed_record_in_any_field_order() {
    const KEY: &str = "nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79";
    for node in [
        format!(r#"{{"Key":"{KEY}","AllowedIPs":["0.0.0.0/0","::/0"]}}"#),
        format!(r#"{{"AllowedIPs":["0.0.0.0/0","::/0"],"Key":"{KEY}"}}"#),
    ] {
        let old_record = format!(r#"{{"ID":9,"Key":"{KEY}","AllowedIPs":["100.64.0.7/32"]}}"#);
        for document in [
            format!(r#"{{"PeersChanged":[{old_record}],"Node":{node}}}"#),
            format!(r#"{{"Node":{node},"PeersChanged":[{old_record}]}}"#),
        ] {
            let mut netmap = Netmap::<32>::new();
            apply(&mut netmap, &document, 2);
            assert!(netmap.default_routes_approved(), "document: {document}");
            assert!(netmap.peers.is_empty());
        }
    }
}

#[test]
fn a_bounded_target_keeps_a_deterministic_prefix_of_a_large_tailnet() {
    let document = r#"{"Peers":[
        {"ID":1,"Key":"nodekey:f4dfaca7341906ffa704d7e529ad63aba59b6616ebea8c9ebbc6c84bb814ed4d"},
        {"ID":2,"Key":"nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79"},
        {"ID":3,"Key":"nodekey:1552a65976f79439979be043fd4707a4626379a87b59d69123e6416a1a678a4d"}
    ]}"#;
    let mut netmap = Netmap::<2>::new();
    let mut parser = Parser::<2>::new();
    parser.push(&mut netmap, document.as_bytes()).unwrap();
    parser.finish(&mut netmap).unwrap();

    assert_eq!(
        netmap.peers.iter().map(|peer| peer.id).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(netmap.peers_truncated);
}

#[test]
fn peers_changed_does_not_evict_a_retained_peer_when_full() {
    let mut netmap = Netmap::<2>::new();
    for document in [
        r#"{"Peers":[
            {"ID":1,"Key":"nodekey:f4dfaca7341906ffa704d7e529ad63aba59b6616ebea8c9ebbc6c84bb814ed4d"},
            {"ID":2,"Key":"nodekey:8e07760a26199478b22a13636eeca585330878b24f673b0a25d658e0bbfb7c79"}
        ]}"#,
        r#"{"PeersChanged":[
            {"ID":3,"Key":"nodekey:1552a65976f79439979be043fd4707a4626379a87b59d69123e6416a1a678a4d"}
        ]}"#,
    ] {
        let mut parser = Parser::<2>::new();
        parser.push(&mut netmap, document.as_bytes()).unwrap();
        parser.finish(&mut netmap).unwrap();
    }

    assert_eq!(
        netmap.peers.iter().map(|peer| peer.id).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(netmap.peers_truncated);
}

/// A peer's IPv6 subnets are parsed and then dropped, while the self record
/// keeps both families. The device routes IPv4 only, and peer storage is the
/// part of the staged map that scales with the tailnet. IPv6 host ownership
/// has a separate field; subnet vectors remain compact IPv4-only storage.
#[test]
fn peer_subnets_are_retained_ipv4_only_while_self_routes_keep_both_families() {
    let mut netmap = Netmap::<32>::new();
    apply(
        &mut netmap,
        r#"{"Node":{"Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"PrimaryRoutes":["0.0.0.0/0","::/0"]},"Peers":[{"ID":7,"Key":"nodekey:f4dfaca7341906ffa704d7e529ad63aba59b6616ebea8c9ebbc6c84bb814ed4d","Addresses":["100.64.0.9/32","fd7a:115c:a1e0::9/128"],"AllowedIPs":["100.64.0.9/32","fd7a:115c:a1e0::9/128","0.0.0.0/0","::/0"]}]}"#,
        4096,
    );

    let peer = netmap.peers.get(7).expect("the peer is retained");
    assert_eq!(
        peer.tailscale_ipv6(),
        Some("fd7a:115c:a1e0::9".parse().unwrap())
    );
    assert_eq!(peer.addresses.len(), 1);
    assert_eq!(peer.allowed_ips.len(), 2, "100.64.0.9/32 and 0.0.0.0/0");
    // The type itself now rules IPv6 out, so what is worth pinning is which
    // entries survived: the peer's own address and its exit-node default route.
    assert_eq!(
        peer.allowed_ips[0].address,
        core::net::Ipv4Addr::new(100, 64, 0, 9)
    );
    assert_eq!(
        peer.allowed_ips[1].address,
        core::net::Ipv4Addr::UNSPECIFIED
    );
    assert_eq!(peer.allowed_ips[1].prefix, 0);
    assert_eq!(
        peer.tailscale_ipv4(),
        Some(core::net::Ipv4Addr::new(100, 64, 0, 9))
    );

    // The self record is unchanged: both families, and the v6 default route is
    // still visible to the approval check.
    assert_eq!(netmap.addresses.len(), 2);
    assert!(netmap.default_routes_approved());
}

#[test]
fn hosted_derp_coordinates_do_not_reject_the_network_map() {
    let document = r#"{
        "DERPMap":{"Regions":{"22":{
            "RegionID":22,"RegionCode":"waw","Latitude":52.23,"Longitude":21.011111,
            "Nodes":[{"HostName":"derp22.tailscale.com","DERPPort":443,"STUNPort":3478}]
        }}},
        "ControlDialPlan":{"Candidates":[{"DialStartDelaySec":0.3}]}
    }"#;
    for chunk in [1, 7, 4096] {
        let mut map = Netmap::<32>::new();
        apply(&mut map, document, chunk);
        let region = map.derp.region(22).unwrap();
        assert_eq!(region.code.as_str(), "waw");
        assert_eq!(region.nodes[0].port, 443);
        assert_eq!(region.nodes[0].stun_port, 3478);
    }
}

#[test]
fn non_integer_forms_in_retained_numeric_fields_still_fail() {
    for number in ["1.5", "1e2", "18446744073709551616"] {
        for document in [
            format!(r#"{{"Node":{{"HomeDERP":{number}}}}}"#),
            format!(r#"{{"PeersRemoved":[{number}]}}"#),
            format!(r#"{{"PeersChangedPatch":[{{"Expired":{number}}}]}}"#),
            format!(r#"{{"PeersChangedPatch":[{{"KeyExpiry":{number}}}]}}"#),
            format!(r#"{{"PeersChangedPatch":[{{"ID":{number}}}]}}"#),
            format!(r#"{{"DERPMap":{{"Regions":{{"22":{{"RegionID":{number}}}}}}}}}"#),
            format!(
                r#"{{"DERPMap":{{"Regions":{{"22":{{"Nodes":[{{"DERPPort":{number}}}]}}}}}}}}"#
            ),
            format!(
                r#"{{"DERPMap":{{"Regions":{{"22":{{"Nodes":[{{"STUNPort":{number}}}]}}}}}}}}"#
            ),
            format!(r#"{{"PacketFilter":[{{"IPProto":[{number}]}}]}}"#),
            format!(
                r#"{{"PacketFilter":[{{"DstPorts":[{{"IP":"*","Ports":{{"First":{number},"Last":65535}}}}]}}]}}"#
            ),
        ] {
            let mut map = Netmap::<32>::new();
            let mut parser = Parser::<32>::new();
            parser.push(&mut map, document.as_bytes()).unwrap();
            assert!(parser.finish(&mut map).is_err(), "accepted {document}");
        }
    }
}
