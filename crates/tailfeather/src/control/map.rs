//! `MapRequest`: asking the server for the network map.
//!
//! # Compression, and why this crate omits the field
//!
//! Tailscale's map responses are normally zstd-compressed, and every zstd
//! decoder in Rust needs an allocator — `ruzstd` requires `alloc`
//! unconditionally — which would end the no-allocation property for the whole
//! project.
//!
//! Reading Headscale's `writeMap` shows it compresses only when the request
//! asked for it (`if m.req.Compress == util.ZstdCompression`), and writes the
//! four-byte length prefix either way. So a request that simply omits the field
//! should get plain JSON.
//!
//! "Should" is doing work in that sentence, which is why [`PATH`] has a
//! subcommand behind it in the harness: the question is answered by looking at
//! the bytes a real server sends, not by reading its source. The hosted service
//! also honours the omission: the SSH `live_server --hosted` acceptance test
//! received and applied its uncompressed map stream.
//!
//! # Framing
//!
//! Each response is `[4-byte length][JSON]`, and the length is **little-endian**
//! — unlike every other length in this protocol, which is big-endian. A
//! long-polling stream is many of these back to back.

use crate::keys::{DiscoPublic, NodePublic};

use crate::control::hostinfo::Hostinfo;
use crate::control::json::{JsonError, Writer};

/// Where the request goes.
pub const PATH: &str = "/machine/map";

/// The length prefix on every response frame.
pub const FRAME_HEADER_LEN: usize = 4;

/// What a node asks for.
pub struct MapRequest<'a> {
    pub version: u16,
    pub node_key: &'a NodePublic,
    pub disco_key: &'a DiscoPublic,
    pub hostinfo: Hostinfo<'a>,
    /// Long-poll: keep the response open and send updates as they happen. A
    /// node that wants to stay current sets this; a one-shot probe does not.
    pub stream: bool,
    /// Ask for the map without the peer list, which is enough to learn our own
    /// address and the DERP map.
    pub omit_peers: bool,
    /// Do not update anything server-side — no endpoints, no hostinfo.
    pub read_only: bool,
    /// Endpoints this node can be reached at, for path discovery.
    pub endpoints: &'a [&'a str],
}

impl MapRequest<'_> {
    pub fn write<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], JsonError> {
        let mut node_text = [0u8; 128];
        let node_key = self
            .node_key
            .encode(&mut node_text)
            .map_err(|_| JsonError::Overflow)?;
        let mut disco_text = [0u8; 128];
        let disco_key = self
            .disco_key
            .encode(&mut disco_text)
            .map_err(|_| JsonError::Overflow)?;

        let mut writer = Writer::new(out);
        writer
            .begin_object()
            .field_u64("Version", self.version as u64)
            .field_str("NodeKey", node_key)
            .field_str("DiscoKey", disco_key)
            .field_bool("Stream", self.stream)
            .field_bool("OmitPeers", self.omit_peers)
            .field_bool("ReadOnly", self.read_only);

        // `Compress` is deliberately absent. Sending "" would be equivalent, but
        // saying nothing is what makes the intent obvious to anyone reading the
        // bytes on the wire: we cannot decompress, so we must not be sent
        // anything compressed.

        writer.key("Endpoints").begin_array();
        for endpoint in self.endpoints {
            writer.str(endpoint);
        }
        writer.end_array();

        writer.key("Hostinfo");
        self.hostinfo.write(&mut writer);
        writer.end_object();
        writer.finish()
    }
}

/// How long the response frame beginning with `header` is.
///
/// Little-endian, unlike the big-endian lengths everywhere else in this
/// protocol. Reading it the other way yields a wildly wrong length that looks
/// like a corrupt stream.
pub fn frame_len(header: &[u8]) -> Option<usize> {
    let bytes: [u8; FRAME_HEADER_LEN] = header.get(..FRAME_HEADER_LEN)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DiscoPrivate, NodePrivate};

    #[test]
    fn the_request_does_not_ask_for_compression() {
        let node = NodePrivate::from_bytes([0x11; 32]).public();
        let disco = DiscoPrivate::from_bytes([0x22; 32]).public();
        let mut buffer = [0u8; 1024];
        let request = MapRequest {
            version: 131,
            node_key: &node,
            disco_key: &disco,
            hostinfo: Hostinfo::default(),
            stream: false,
            omit_peers: false,
            read_only: false,
            endpoints: &[],
        };
        let text = core::str::from_utf8(request.write(&mut buffer).unwrap()).unwrap();

        // The whole no-allocation property rests on this field being absent:
        // every zstd decoder in Rust needs a heap.
        assert!(!text.contains("Compress"), "{text}");
        assert!(text.contains(r#""NodeKey":"nodekey:"#));
        assert!(text.contains(r#""DiscoKey":"discokey:"#));
        assert!(text.contains(r#""Stream":false"#));
        assert!(text.contains(r#""Endpoints":[]"#));
    }

    #[test]
    fn the_frame_length_is_little_endian() {
        // Every other length in this protocol is big-endian, so this is exactly
        // the kind of detail that gets carried over wrongly.
        assert_eq!(frame_len(&[0x2c, 0x01, 0x00, 0x00]), Some(300));
        assert_ne!(frame_len(&[0x00, 0x00, 0x01, 0x2c]), Some(300));
        assert_eq!(frame_len(&[0x01, 0x02]), None);
    }
}
