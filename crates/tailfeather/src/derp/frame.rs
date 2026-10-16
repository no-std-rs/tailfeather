//! DERP framing: `1B type ‖ 4B length BE ‖ payload`.

use crate::derp::Error;

pub const HEADER_LEN: usize = 5;

/// The largest frame this client will accept.
///
/// A relayed WireGuard packet is at most an MTU plus its header, so this is
/// generous. It exists because the length is attacker-controlled and a fixed
/// buffer has to refuse rather than truncate.
pub const MAX_FRAME: usize = 32 + wirefeather::MAX_DATAGRAM_LEN;

/// The largest frame the *protocol* permits, which is not the same as the
/// largest one this client stores.
///
/// A length between [`MAX_FRAME`] and this is well-formed but too big to keep:
/// the payload is drained and the frame skipped. Only a length beyond this is a
/// protocol error, because a 64 KiB ceiling is what the wire format itself
/// implies and anything past it means the stream has lost sync. Treating a
/// merely-large frame as fatal used to tear the session down and take the
/// relay's health record with it.
///
/// It is the full 64 KiB, not `u16::MAX`: a frame of exactly 65,536 bytes is
/// still well-formed under a four-byte length, and rejecting it would drop the
/// session instead of taking the discard path.
pub const MAX_WIRE_FRAME: usize = 64 * 1024;

/// The payload length of a `Ping`/`Pong` frame.
pub const PING_LEN: usize = 8;

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
    /// `32-byte peer key [‖ 1-byte reason]`. The relay no longer has that peer,
    /// so relaying to it is pointless until it comes back.
    PeerGone,
    /// `32-byte peer key`. Sent only to a client that asked to watch.
    PeerPresent,
    /// Mesh-only; a device never sends or expects one.
    ForwardPacket,
    WatchConns,
    ClosePeer,
    /// `8 opaque bytes` that must come back in a `Pong`. A server that gets no
    /// answer concludes the connection is dead and drops it.
    Ping,
    /// `8 bytes` echoed from the `Ping` that prompted it.
    Pong,
    /// A human-readable problem with this client's connection.
    Health,
    /// The server is going away and will accept a reconnect.
    Restarting,
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
            0x09 => Self::PeerPresent,
            0x0a => Self::ForwardPacket,
            0x10 => Self::WatchConns,
            0x11 => Self::ClosePeer,
            0x12 => Self::Ping,
            0x13 => Self::Pong,
            0x14 => Self::Health,
            0x15 => Self::Restarting,
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
            Self::PeerPresent => 0x09,
            Self::ForwardPacket => 0x0a,
            Self::WatchConns => 0x10,
            Self::ClosePeer => 0x11,
            Self::Ping => 0x12,
            Self::Pong => 0x13,
            Self::Health => 0x14,
            Self::Restarting => 0x15,
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
        if length > MAX_WIRE_FRAME {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            kind: FrameType::from_byte(bytes[0]),
            length,
        })
    }

    /// Whether the payload fits in the fixed buffer this client reads into.
    ///
    /// A frame that does not fit is still a valid frame: drain `length` bytes
    /// and carry on. Only [`Error::TooLarge`] from [`Frame::parse`] means the
    /// stream is unusable.
    pub fn fits(&self) -> bool {
        self.length <= MAX_FRAME
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

    /// A frame bigger than the read buffer but within the protocol's ceiling is
    /// skipped, not fatal. Tearing the session down for one large `Health`
    /// message used to cost a reconnect and a black mark against the region.
    #[test]
    fn a_large_but_legal_frame_is_skipped_rather_than_fatal() {
        let mut header = [0u8; HEADER_LEN];
        header[0] = FrameType::Health.to_byte();
        header[1..].copy_from_slice(&(4096u32).to_be_bytes());
        let frame = Frame::parse(&header).unwrap();
        assert_eq!(frame.length, 4096);
        assert!(!frame.fits(), "too big to keep, still readable");

        // Past the wire ceiling the stream has lost sync and there is nothing
        // to resynchronise to.
        let mut absurd = [0u8; HEADER_LEN];
        absurd[1..].copy_from_slice(&((MAX_WIRE_FRAME + 1) as u32).to_be_bytes());
        assert_eq!(Frame::parse(&absurd), Err(Error::TooLarge));
    }

    /// The numbering is not contiguous: `ForwardPacket` sits at `0x0a` after
    /// `PeerPresent`, and the second block restarts at `0x10`. Getting this
    /// wrong turns a `Ping` into a `Health` and the connection dies quietly.
    #[test]
    fn the_frame_alphabet_matches_the_wire_numbering() {
        for (byte, kind) in [
            (0x09, FrameType::PeerPresent),
            (0x0a, FrameType::ForwardPacket),
            (0x10, FrameType::WatchConns),
            (0x11, FrameType::ClosePeer),
            (0x12, FrameType::Ping),
            (0x13, FrameType::Pong),
            (0x14, FrameType::Health),
            (0x15, FrameType::Restarting),
        ] {
            assert_eq!(FrameType::from_byte(byte), kind);
            assert_eq!(kind.to_byte(), byte);
        }
        // The gap is real, not an oversight.
        assert_eq!(FrameType::from_byte(0x0f), FrameType::Other(0x0f));
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
