//! HTTP/2 framing (RFC 7540 section 4).
//!
//! ```text
//! 3B length (24-bit BE) ‖ 1B type ‖ 1B flags ‖ 4B stream id (31-bit BE)
//! ```
//!
//! The stream identifier's top bit is reserved and must be ignored on receipt,
//! not treated as part of the number — a detail that only bites when a peer
//! happens to set it.

use crate::Error;

/// Every frame begins with nine bytes. That this is also the length of the
/// ts2021 early-payload probe is what makes the two distinguishable; see
/// `tailfeather::noise::early`.
pub const HEADER_LEN: usize = 9;

/// The largest frame every endpoint must accept, and the default until
/// `SETTINGS` raises it.
pub const DEFAULT_MAX_FRAME: usize = 16_384;

/// The connection preface a client sends before anything else (RFC 7540
/// section 3.5). Exact bytes, including the deliberately odd `PRI` method — its
/// purpose is to make an HTTP/1.1 server fail immediately rather than
/// misinterpret what follows.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    /// A type this client does not know. RFC 7540 requires unknown frame types
    /// to be discarded, not treated as an error — that is what lets the protocol
    /// be extended without breaking older peers.
    Unknown(u8),
}

impl FrameType {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(other) => other,
        }
    }
}

pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

pub mod settings {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: usize,
    pub kind: FrameType,
    pub flags: u8,
    pub stream: u32,
}

impl FrameHeader {
    /// Parse the nine-byte header, without the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.get(..HEADER_LEN).ok_or(Error::Incomplete)?;
        Ok(Self {
            length: u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize,
            kind: FrameType::from_byte(bytes[3]),
            flags: bytes[4],
            // The top bit is reserved and must be ignored, not read as part of
            // the identifier.
            stream: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & 0x7fff_ffff,
        })
    }

    pub fn write(&self, out: &mut [u8]) -> Result<usize, Error> {
        let out = out.get_mut(..HEADER_LEN).ok_or(Error::BufferTooSmall)?;
        let length = (self.length as u32).to_be_bytes();
        out[0..3].copy_from_slice(&length[1..4]);
        out[3] = self.kind.to_byte();
        out[4] = self.flags;
        out[5..9].copy_from_slice(&(self.stream & 0x7fff_ffff).to_be_bytes());
        Ok(HEADER_LEN)
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Write a complete frame: header then payload.
pub fn write_frame(
    kind: FrameType,
    flags: u8,
    stream: u32,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let header = FrameHeader {
        length: payload.len(),
        kind,
        flags,
        stream,
    };
    header.write(out)?;
    let end = HEADER_LEN + payload.len();
    out.get_mut(HEADER_LEN..end)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(payload);
    Ok(end)
}

/// Strip the padding a DATA or HEADERS frame may carry.
///
/// The pad length is one byte at the front, and the padding itself is at the
/// back. Forgetting it feeds padding bytes to the HPACK decoder, which then
/// fails on a frame that was perfectly valid.
pub fn strip_padding(payload: &[u8], flags: u8) -> Result<&[u8], Error> {
    if flags & flags::PADDED == 0 {
        return Ok(payload);
    }
    let pad_length = *payload.first().ok_or(Error::Protocol)? as usize;
    let body = payload.get(1..).ok_or(Error::Protocol)?;
    let end = body.len().checked_sub(pad_length).ok_or(Error::Protocol)?;
    Ok(&body[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_settings_frame_a_server_opens_with() {
        // Length 18, type SETTINGS, no flags, stream 0.
        let bytes = [0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(header.length, 18);
        assert_eq!(header.kind, FrameType::Settings);
        assert_eq!(header.stream, 0);
        assert!(!header.has(flags::ACK));
    }

    #[test]
    fn the_reserved_bit_of_a_stream_id_is_ignored() {
        // A peer that sets it must not make us read stream 1 as 2147483649.
        let bytes = [0x00, 0x00, 0x00, 0x01, 0x04, 0x80, 0x00, 0x00, 0x01];
        assert_eq!(FrameHeader::parse(&bytes).unwrap().stream, 1);
    }

    #[test]
    fn a_header_round_trips() {
        let header = FrameHeader {
            length: 16_383,
            kind: FrameType::Data,
            flags: flags::END_STREAM,
            stream: 3,
        };
        let mut out = [0u8; HEADER_LEN];
        header.write(&mut out).unwrap();
        assert_eq!(FrameHeader::parse(&out).unwrap(), header);
    }

    #[test]
    fn an_unknown_frame_type_is_carried_rather_than_rejected() {
        // RFC 7540 requires discarding, not failing: that is what lets the
        // protocol gain frame types without breaking older clients.
        let bytes = [0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            FrameHeader::parse(&bytes).unwrap().kind,
            FrameType::Unknown(0x63)
        );
    }

    #[test]
    fn a_short_buffer_is_incomplete_rather_than_a_guess() {
        assert_eq!(FrameHeader::parse(&[0x00, 0x00]), Err(Error::Incomplete));
    }

    #[test]
    fn padding_is_stripped_from_both_ends() {
        // One byte of pad length at the front, that many bytes at the back.
        let payload = [0x02, b'h', b'i', 0x00, 0x00];
        assert_eq!(strip_padding(&payload, flags::PADDED).unwrap(), b"hi");
        // Without the flag the first byte is data, not a length.
        assert_eq!(strip_padding(&payload, 0).unwrap(), &payload);
        // Padding longer than the frame is a protocol error, not a wrap-around.
        assert_eq!(
            strip_padding(&[0x09, b'h'], flags::PADDED),
            Err(Error::Protocol)
        );
    }
}
