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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
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
    assert!(peer.online);
    assert_eq!(peer.home_derp, 999);
    assert_eq!(peer.tailscale_ipv4().unwrap().to_string(), "100.64.0.1");
    assert_eq!(peer.allowed_ips.len(), 2);
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
    assert!(!after.online, "the field the patch named must change");
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
