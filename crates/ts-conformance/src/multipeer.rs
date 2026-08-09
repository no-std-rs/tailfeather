//! Drives a real `wirefeather` device through several concurrent sessions.
//!
//! # What this does and does not prove
//!
//! It links the `no_std` crate the firmware runs and puts it through the
//! scenario a mesh actually produces: many peers, all handshaking at once, each
//! then carrying traffic on its own keys. It catches the failures a single-peer
//! test cannot see — sessions attributed to the wrong peer, a device-wide rate
//! limit starving every peer but the first, one peer's rekey tearing down
//! another's session.
//!
//! What it cannot prove is protocol compatibility, because both sides of the
//! conversation are our code. That part is established separately and does
//! carry over: every message exchanged here is built by the same functions the
//! Linux kernel accepted in `scripts/interop-wireguard.sh`, in both roles. So
//! the construction is kernel-verified and the *multiplicity* is verified here.
//! The check reports it that way rather than claiming more.

use wirefeather::{Action, Device, Instant, PeerId, Rng, Tai64n};

use crate::Status;

/// Enough peers that the handshake burst allowance is exercised rather than
/// trivially satisfied, and more than one full mesh's worth for a small tailnet.
const PEERS: usize = 8;

const MAX: usize = wirefeather::MAX_DATAGRAM_LEN;

/// Deterministic, so a failure is reproducible, but not constant, so distinct
/// session indices and ephemeral keys are exercised.
struct TestRng(u64);

impl Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = (z ^ (z >> 31)) as u8;
        }
    }
}

/// A syntactically valid IPv4 packet, since the core reads the header to strip
/// WireGuard's padding.
fn ipv4_packet(payload_len: usize) -> Vec<u8> {
    let total = 20 + payload_len;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 99, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 99, 0, 2]);
    for (i, b) in packet[20..].iter_mut().enumerate() {
        *b = i as u8;
    }
    packet
}

fn timestamp(nth: usize) -> Tai64n {
    let mut stamp = [0u8; 12];
    stamp[..8].copy_from_slice(&((1u64 << 62) + 1_700_000_000).to_be_bytes());
    stamp[8..].copy_from_slice(&(nth as u32).to_be_bytes());
    stamp
}

pub fn run() -> Status {
    match exercise() {
        Ok(detail) => Status::Pass(detail),
        Err(reason) => Status::Fail(reason),
    }
}

fn exercise() -> Result<String, String> {
    let now = Instant(1_000);

    let mut hub: Device<PEERS> = Device::new([0x42; 32]);
    let mut spokes: Vec<Device<1>> = (0..PEERS)
        .map(|i| Device::new([0x20 + i as u8; 32]))
        .collect();

    let mut hub_peers = Vec::new();
    for spoke in &mut spokes {
        hub_peers.push(
            hub.add_peer(spoke.public_key(), None)
                .map_err(|e| format!("the hub could not hold {PEERS} peers: {e}"))?,
        );
        let p = spoke
            .add_peer(hub.public_key(), None)
            .map_err(|e| format!("a spoke could not add the hub: {e}"))?;
        spoke
            .set_initiating(p, true)
            .map_err(|e| format!("a spoke could not be set to initiate: {e}"))?;
    }

    // Every spoke initiates in the same millisecond, which is what a netmap
    // naming a dozen new peers produces. A device-wide "one handshake per
    // interval" limiter fails here.
    let mut connected = 0;
    for (i, spoke) in spokes.iter_mut().enumerate() {
        handshake(&mut hub, spoke, hub_peers[i], i, now).map_err(|e| format!("peer {i}: {e}"))?;
        connected += 1;
    }
    if connected != PEERS {
        return Err(format!("only {connected} of {PEERS} peers connected"));
    }

    // All sessions are live at once.
    for (i, peer) in hub_peers.iter().enumerate() {
        if !hub.is_connected(*peer, now) {
            return Err(format!(
                "peer {i} has no usable session after all handshakes"
            ));
        }
    }

    // And traffic on each is attributed to the peer that sent it, with the
    // right plaintext. Getting this wrong on a mesh means packets delivered
    // under another node's identity.
    let packet = ipv4_packet(i_payload());
    for (i, spoke) in spokes.iter_mut().enumerate() {
        let hub_side = spoke
            .peer_by_public_key(&hub.public_key())
            .ok_or_else(|| format!("peer {i} lost track of the hub"))?;

        let mut datagram = vec![0u8; MAX];
        let len = match spoke.encapsulate(hub_side, &packet, now, &mut datagram) {
            Ok(Action::Send { data, .. }) => data.len(),
            Ok(_) => return Err(format!("peer {i}: encapsulate produced nothing to send")),
            Err(e) => return Err(format!("peer {i}: encapsulate failed: {e}")),
        };

        let mut plain = vec![0u8; MAX];
        match hub.handle_udp(&datagram[..len], now, &mut TestRng(1), &mut plain) {
            Ok(Action::Receive { peer, packet: got }) => {
                if peer != hub_peers[i] {
                    return Err(format!(
                        "traffic from peer {i} was attributed to peer {}",
                        peer.0
                    ));
                }
                if got != packet.as_slice() {
                    return Err(format!("peer {i}: plaintext did not survive the tunnel"));
                }
            }
            Ok(other) => return Err(format!("peer {i}: unexpected action {other:?}")),
            Err(e) => return Err(format!("peer {i}: the hub could not open the packet: {e}")),
        }
    }

    // One peer rekeying must not disturb the others. This is the failure mode a
    // single-peer test structurally cannot see.
    let later = Instant(now.0 + wirefeather::timers::REKEY_AFTER_TIME_MS);
    handshake(&mut hub, &mut spokes[0], hub_peers[0], PEERS, later)
        .map_err(|e| format!("peer 0 could not rekey: {e}"))?;
    for (i, peer) in hub_peers.iter().enumerate() {
        if !hub.is_connected(*peer, later) {
            return Err(format!("peer 0's rekey dropped peer {i}'s session"));
        }
    }

    Ok(format!(
        "{PEERS} concurrent sessions through wirefeather: all handshaked in one millisecond, \
         each peer's traffic attributed correctly, and one peer's rekey left the other \
         {} untouched. The messages are built by the same functions kernel WireGuard \
         accepted in scripts/interop-wireguard.sh, in both roles.",
        PEERS - 1
    ))
}

/// Payload size, kept small enough to be quick and large enough to span more
/// than one padding block.
fn i_payload() -> usize {
    40
}

/// Run one full handshake from `spoke` to `hub`, including the confirming
/// keepalive the initiator owes.
fn handshake(
    hub: &mut Device<PEERS>,
    spoke: &mut Device<1>,
    expected: PeerId,
    nth: usize,
    now: Instant,
) -> Result<(), String> {
    let hub_side = spoke
        .peer_by_public_key(&hub.public_key())
        .ok_or("the spoke does not know the hub")?;

    let mut initiation = vec![0u8; MAX];
    let len = spoke
        .start_handshake(
            hub_side,
            now,
            &timestamp(nth),
            &mut TestRng(nth as u64),
            &mut initiation,
        )
        .map_err(|e| format!("start_handshake: {e}"))?;

    let mut response = vec![0u8; MAX];
    let response_len = match hub.handle_udp(
        &initiation[..len],
        now,
        &mut TestRng(100 + nth as u64),
        &mut response,
    ) {
        Ok(Action::Send { peer, data }) => {
            if peer != expected {
                return Err(format!(
                    "the response was routed to peer {} rather than {}",
                    peer.0, expected.0
                ));
            }
            data.len()
        }
        Ok(other) => return Err(format!("the hub answered an initiation with {other:?}")),
        Err(e) => return Err(format!("the hub rejected the initiation: {e}")),
    };

    let mut keepalive = vec![0u8; MAX];
    let keepalive_len = match spoke.handle_udp(
        &response[..response_len],
        now,
        &mut TestRng(200),
        &mut keepalive,
    ) {
        Ok(Action::Send { data, .. }) => data.len(),
        Ok(other) => return Err(format!("the response produced {other:?}, not a keepalive")),
        Err(e) => return Err(format!("the spoke rejected the response: {e}")),
    };

    let mut sink = vec![0u8; MAX];
    match hub.handle_udp(
        &keepalive[..keepalive_len],
        now,
        &mut TestRng(201),
        &mut sink,
    ) {
        Ok(Action::Authenticated { .. }) => Ok(()),
        Ok(other) => Err(format!("the confirming keepalive produced {other:?}")),
        Err(e) => Err(format!("the hub rejected the confirming keepalive: {e}")),
    }
}
