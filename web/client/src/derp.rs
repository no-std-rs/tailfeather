//! DERP over WebSocket.
//!
//! Hosted DERP servers accept `wss://<host>/derp` with subprotocol `derp` and
//! start the ordinary frame protocol immediately — the server-key frame is the
//! first thing on the socket, with no `Upgrade: DERP` exchange. The frame
//! logic itself is tailfeather's sans-io [`Client`].

use tailfeather::derp::frame::{self, Frame, FrameType};
use tailfeather::derp::{Client, MAX_PACKET};
use tailfeather::keys::{NodePrivate, NodePublic};

use crate::js::JsRng;
use crate::ws::{WsError, WsStream};

/// Read one whole frame into `payload`. Frames too large to be relayed
/// packets (a long health message, say) are drained and skipped.
pub async fn read_frame(ws: &WsStream, payload: &mut Vec<u8>) -> Result<Frame, WsError> {
    loop {
        let mut header = [0u8; frame::HEADER_LEN];
        ws.read_exact(&mut header).await?;
        let parsed = Frame::parse(&header).map_err(|error| WsError(format!("DERP: {error}")))?;
        if !parsed.fits() {
            let mut remaining = parsed.length;
            let mut scratch = [0u8; 4096];
            while remaining > 0 {
                let take = remaining.min(scratch.len());
                ws.read_exact(&mut scratch[..take]).await?;
                remaining -= take;
            }
            continue;
        }
        payload.clear();
        payload.resize(parsed.length, 0);
        ws.read_exact(payload).await?;
        return Ok(parsed);
    }
}

/// The DERP handshake: server key, then our sealed client info, then the
/// server's sealed info. Returns the established client and the server key.
pub async fn handshake(
    ws: &WsStream,
    identity: &NodePrivate,
    preferred: bool,
) -> Result<Client, WsError> {
    let mut payload = Vec::new();
    let server_frame = read_frame(ws, &mut payload).await?;
    let server = Client::read_server_key(server_frame, &payload)
        .map_err(|error| WsError(format!("DERP server key: {error}")))?;
    let mut out = [0u8; 256];
    let len =
        Client::write_client_info(identity, &identity.public(), &server, &mut JsRng, &mut out)
            .map_err(|error| WsError(format!("DERP client info: {error}")))?;
    ws.send(&out[..len])?;
    let info_frame = read_frame(ws, &mut payload).await?;
    let mut info = [0u8; 512];
    let client = Client::read_server_info(identity, &server, info_frame, &payload, &mut info)
        .map_err(|error| WsError(format!("DERP server info: {error}")))?;
    let len = Client::write_note_preferred(preferred, &mut out)
        .map_err(|error| WsError(format!("DERP preferred: {error}")))?;
    ws.send(&out[..len])?;
    Ok(client)
}

/// What one post-handshake frame means to the runtime.
pub enum Inbound {
    Packet(NodePublic),
    PeerGone(NodePublic),
    Restarting,
    Health,
    Other,
}

/// Classify a frame, answering pings on the spot. For a packet, its bytes are
/// moved to the front of `payload`.
pub fn classify(ws: &WsStream, frame: Frame, payload: &mut Vec<u8>) -> Result<Inbound, WsError> {
    Ok(match frame.kind {
        FrameType::RecvPacket => {
            let (peer, packet) = Client::read_packet(frame, payload)
                .map_err(|error| WsError(format!("DERP packet: {error}")))?;
            let len = packet.len();
            let start = payload.len() - len;
            payload.copy_within(start.., 0);
            payload.truncate(len);
            Inbound::Packet(peer)
        }
        FrameType::Ping => {
            let mut pong = [0u8; frame::HEADER_LEN + frame::PING_LEN];
            let len = Client::write_pong(frame, payload, &mut pong)
                .map_err(|error| WsError(format!("DERP ping: {error}")))?;
            ws.send(&pong[..len])?;
            Inbound::Other
        }
        FrameType::PeerGone => Inbound::PeerGone(
            Client::read_peer_gone(frame, payload)
                .map_err(|error| WsError(format!("DERP peer gone: {error}")))?,
        ),
        FrameType::Restarting => Inbound::Restarting,
        FrameType::Health => Inbound::Health,
        _ => Inbound::Other,
    })
}

/// A `NotePreferred` frame for a link that is already up, so the server learns
/// when the home region changes after the handshake.
pub fn note_preferred(preferred: bool) -> Option<Vec<u8>> {
    let mut out = [0u8; 16];
    let len = Client::write_note_preferred(preferred, &mut out).ok()?;
    Some(out[..len].to_vec())
}

/// Frame one packet for `peer`.
pub fn frame_packet(client: &Client, peer: &NodePublic, packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() > MAX_PACKET {
        return None;
    }
    let mut out = vec![0u8; frame::HEADER_LEN + frame::MAX_FRAME];
    let len = client.send_packet(peer, packet, &mut out).ok()?;
    out.truncate(len);
    Some(out)
}
