//! DERP framing: `1B type ‖ 4B length BE ‖ payload`.

use crate::derp::Error;

pub const HEADER_LEN: usize = 5;

/// The largest frame this client will accept.
///
/// A relayed WireGuard packet is at most an MTU plus its header, so this is
/// generous. It exists because the length is attacker-controlled and a fixed
/// buffer has to refuse rather than truncate.
pub const MAX_FRAME: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// `magic ‖ 32-byte server public key`.
    ServerKey,
    /// `32-byte client public key ‖ 24-byte nonce ‖ sealed hello`.
    ClientInfo,
    /// `24-byte nonce ‖ sealed hello`.
    ServerInfo,
    /// `32-byte destination key ‖ packet`.
    SendPacket,
    /// `32-byte source key ‖ packet`. The source is what version 2 added; a
    /// version 1 receiver had to guess who a packet was from.
    RecvPacket,
    KeepAlive,
    NotePreferred,
    PeerGone,
    /// Anything else. Discarded rather than refused, so the server can gain
    /// frame types without breaking older clients.
    Other(u8),
}

impl FrameType {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::ServerKey,
            0x02 => Self::ClientInfo,
            0x03 => Self::ServerInfo,
            0x04 => Self::SendPacket,
            0x05 => Self::RecvPacket,
            0x06 => Self::KeepAlive,
            0x07 => Self::NotePreferred,
            0x08 => Self::PeerGone,
            other => Self::Other(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::ServerKey => 0x01,
            Self::ClientInfo => 0x02,
            Self::ServerInfo => 0x03,
            Self::SendPacket => 0x04,
            Self::RecvPacket => 0x05,
            Self::KeepAlive => 0x06,
            Self::NotePreferred => 0x07,
            Self::PeerGone => 0x08,
            Self::Other(other) => other,
        }
    }
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameType,
    pub length: usize,
}

impl Frame {
    /// Read a header. The payload follows and is the caller's to read.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.get(..HEADER_LEN).ok_or(Error::Incomplete)?;
        let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if length > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            kind: FrameType::from_byte(bytes[0]),
            length,
        })
    }
}

/// Write a complete frame.
pub fn write(kind: FrameType, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let total = HEADER_LEN + payload.len();
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    out[0] = kind.to_byte();
    out[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out[HEADER_LEN..].copy_from_slice(payload);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_server_key_frame_a_real_server_sends() {
        // Copied from Headscale's embedded DERP: type 1, length 40, magic, key.
        let bytes = [
            0x01, 0x00, 0x00, 0x00, 0x28, 0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91,
        ];
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(frame.kind, FrameType::ServerKey);
        assert_eq!(frame.length, 40, "8 bytes of magic and a 32-byte key");
        assert_eq!(&bytes[HEADER_LEN..HEADER_LEN + 8], &crate::derp::MAGIC);
    }

    #[test]
    fn the_length_is_big_endian_and_four_bytes() {
        // Two other framings in this protocol use different widths and orders,
        // so this is exactly the kind of detail carried over wrongly.
        let frame = Frame::parse(&[0x04, 0x00, 0x00, 0x01, 0x2c]).unwrap();
        assert_eq!(frame.length, 300);
        // Little-endian would read this as 738 197 504, which is refused
        // outright rather than becoming a wild read.
        assert_eq!(
            Frame::parse(&[0x04, 0x2c, 0x01, 0x00, 0x00]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn a_frame_round_trips() {
        let mut out = [0u8; 64];
        let len = write(FrameType::SendPacket, b"payload", &mut out).unwrap();
        assert_eq!(len, HEADER_LEN + 7);
        let frame = Frame::parse(&out).unwrap();
        assert_eq!(frame.kind, FrameType::SendPacket);
        assert_eq!(frame.length, 7);
        assert_eq!(&out[HEADER_LEN..len], b"payload");
    }

    #[test]
    fn an_unknown_frame_type_is_carried_rather_than_refused() {
        let frame = Frame::parse(&[0x63, 0, 0, 0, 0]).unwrap();
        assert_eq!(frame.kind, FrameType::Other(0x63));
    }

    #[test]
    fn a_short_header_is_incomplete_and_an_over_long_frame_is_refused() {
        assert_eq!(Frame::parse(&[0x01, 0x00]), Err(Error::Incomplete));
        assert_eq!(
            Frame::parse(&[0x01, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::TooLarge)
        );
        let mut tiny = [0u8; 4];
        assert_eq!(
            write(FrameType::KeepAlive, b"x", &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }
}
