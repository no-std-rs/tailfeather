//! A client connection: one HPACK context, a few streams, and flow control.
//!
//! # Flow control is the part that bites
//!
//! An HTTP/2 receiver advertises how much it is willing to accept, and a sender
//! that has used up that allowance simply stops. Both windows start at 65535
//! bytes — one for the connection, one for each stream — and neither grows
//! unless the receiver says so with `WINDOW_UPDATE`.
//!
//! For a client that fetches small responses this never comes up, which is
//! exactly why it is dangerous: the netmap long-poll streams megabytes, and a
//! client that never sends `WINDOW_UPDATE` receives precisely 65535 bytes and
//! then hangs forever. It looks like the server stopped talking. It did, because
//! we told it to.
//!
//! So this connection raises the connection window immediately after the
//! preface, advertises a large per-stream window in its `SETTINGS`, and returns
//! a `WINDOW_UPDATE` for every byte of `DATA` it consumes.
//!
//! # Sans-io
//!
//! The caller reads [`frame::HEADER_LEN`] bytes, learns the payload length,
//! reads that, and hands the whole frame to [`Connection::recv`]. Anything that
//! must be sent in reply is written to the caller's buffer.

use crate::frame::{self, FrameHeader, FrameType, flags, settings};
use crate::hpack::{self, Decoder};
use crate::{Error, hpack::encode};

/// How many requests may be in flight at once. Registration and the map
/// long-poll, with one spare.
pub const MAX_STREAMS: usize = 4;

/// The largest header block this client will reassemble across `CONTINUATION`
/// frames.
pub const MAX_HEADER_BLOCK: usize = 2048;

/// What we advertise as our per-stream receive window, and what we top the
/// connection window up to.
///
/// Large enough that a streaming response is never throttled by the round trip
/// of a `WINDOW_UPDATE`, and it costs nothing: the window bounds what the peer
/// may have in flight, not what we must buffer, because every `DATA` frame is
/// handed to the caller as it arrives.
pub const RECEIVE_WINDOW: u32 = 1 << 20;

/// The default both windows start at, before anything is negotiated.
const DEFAULT_WINDOW: u32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stream {
    id: u32,
    /// Bytes received since the last `WINDOW_UPDATE` for this stream.
    consumed: u32,
    open: bool,
}

/// What arrived.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// Nothing the caller needs to act on: a settings exchange, a ping, an
    /// unknown frame type. Anything that needed a reply is already in `out`.
    Nothing,
    /// A complete header block. The fields were passed to the callback.
    Headers { stream: u32, end_stream: bool },
    /// Response body bytes. Borrowed from the caller's own frame buffer, so
    /// nothing is copied.
    Data {
        stream: u32,
        data: &'a [u8],
        end_stream: bool,
    },
    /// The peer reset one stream. The connection is still usable.
    Reset { stream: u32, code: u32 },
    /// The peer is shutting the connection down.
    GoAway { code: u32 },
}

pub struct Connection {
    decoder: Decoder,
    streams: heapless::Vec<Stream, MAX_STREAMS>,
    next_stream: u32,
    /// Reassembly buffer for a header block split across `CONTINUATION` frames.
    header_block: heapless::Vec<u8, MAX_HEADER_BLOCK>,
    /// Which stream the block being reassembled belongs to.
    header_stream: u32,
    header_end_stream: bool,
    /// Bytes received on the connection since the last `WINDOW_UPDATE`.
    consumed: u32,
    /// What the peer said it will accept in one frame.
    peer_max_frame: usize,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Connection {
    pub fn new() -> Self {
        Self {
            decoder: Decoder::new(hpack::DEFAULT_TABLE_SIZE),
            streams: heapless::Vec::new(),
            // Client-initiated streams are odd-numbered.
            next_stream: 1,
            header_block: heapless::Vec::new(),
            header_stream: 0,
            header_end_stream: false,
            consumed: 0,
            peer_max_frame: frame::DEFAULT_MAX_FRAME,
        }
    }

    /// Write the client preface, our settings, and the connection-level window
    /// update that stops a large response stalling at 65535 bytes.
    pub fn start(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let preface = frame::CLIENT_PREFACE;
        out.get_mut(..preface.len())
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(preface);
        let mut len = preface.len();

        // Push is refused outright rather than handled: a client that never
        // accepts a promise needs no state for one.
        let mut payload = [0u8; 24];
        write_setting(
            &mut payload[0..6],
            settings::HEADER_TABLE_SIZE,
            hpack::DEFAULT_TABLE_SIZE as u32,
        );
        write_setting(&mut payload[6..12], settings::ENABLE_PUSH, 0);
        write_setting(
            &mut payload[12..18],
            settings::INITIAL_WINDOW_SIZE,
            RECEIVE_WINDOW,
        );
        write_setting(
            &mut payload[18..24],
            settings::MAX_CONCURRENT_STREAMS,
            MAX_STREAMS as u32,
        );
        len += frame::write_frame(FrameType::Settings, 0, 0, &payload, &mut out[len..])?;

        // SETTINGS_INITIAL_WINDOW_SIZE applies to streams only; the connection
        // window can be raised only by an explicit update.
        let increment = (RECEIVE_WINDOW - DEFAULT_WINDOW).to_be_bytes();
        len += frame::write_frame(FrameType::WindowUpdate, 0, 0, &increment, &mut out[len..])?;
        Ok(len)
    }

    /// Open a stream and send a request, headers and body together.
    ///
    /// Returns the stream identifier and how many bytes were written.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        scheme: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        out: &mut [u8],
    ) -> Result<(u32, usize), Error> {
        let id = self.next_stream;
        self.streams
            .push(Stream {
                id,
                consumed: 0,
                open: true,
            })
            .map_err(|_| Error::TooManyStreams)?;
        self.next_stream += 2;

        // Pseudo-headers must come first and in this order; a server is entitled
        // to reject a block that interleaves them with ordinary fields.
        let mut block = [0u8; MAX_HEADER_BLOCK];
        let mut block_len = 0;
        block_len = encode::encode_header(":method", method, &mut block, block_len)?;
        block_len = encode::encode_header(":path", path, &mut block, block_len)?;
        block_len = encode::encode_header(":scheme", scheme, &mut block, block_len)?;
        block_len = encode::encode_header(":authority", authority, &mut block, block_len)?;
        for (name, value) in extra {
            block_len = encode::encode_header(name, value, &mut block, block_len)?;
        }

        // No CONTINUATION is emitted: a header block that does not fit one frame
        // would need one, and these two request shapes never come close.
        if block_len > self.peer_max_frame {
            return Err(Error::FrameTooLarge);
        }

        let end_stream = if body.is_empty() {
            flags::END_STREAM
        } else {
            0
        };
        let mut len = frame::write_frame(
            FrameType::Headers,
            flags::END_HEADERS | end_stream,
            id,
            &block[..block_len],
            out,
        )?;

        if !body.is_empty() {
            if body.len() > self.peer_max_frame {
                return Err(Error::FrameTooLarge);
            }
            len += frame::write_frame(
                FrameType::Data,
                flags::END_STREAM,
                id,
                body,
                &mut out[len..],
            )?;
        }
        Ok((id, len))
    }

    /// Consume one whole frame.
    ///
    /// `frame` is the nine-byte header followed by exactly its payload. Replies
    /// this connection owes — settings and ping acknowledgements, window updates
    /// — are written to `out`, and the caller must send them.
    pub fn recv<'a>(
        &mut self,
        bytes: &'a [u8],
        mut on_header: impl FnMut(&str, &str),
        out: &mut [u8],
    ) -> Result<(Event<'a>, usize), Error> {
        let header = FrameHeader::parse(bytes)?;
        let payload = bytes
            .get(frame::HEADER_LEN..frame::HEADER_LEN + header.length)
            .ok_or(Error::Incomplete)?;
        let mut written = 0;

        match header.kind {
            FrameType::Settings => {
                if !header.has(flags::ACK) {
                    self.apply_settings(payload)?;
                    // An unacknowledged SETTINGS blocks the peer indefinitely.
                    written = frame::write_frame(FrameType::Settings, flags::ACK, 0, &[], out)?;
                }
                Ok((Event::Nothing, written))
            }

            FrameType::Ping => {
                if !header.has(flags::ACK) {
                    // The payload must be echoed exactly.
                    written = frame::write_frame(FrameType::Ping, flags::ACK, 0, payload, out)?;
                }
                Ok((Event::Nothing, written))
            }

            FrameType::Headers | FrameType::Continuation => {
                let block = if header.kind == FrameType::Headers {
                    self.header_block.clear();
                    self.header_stream = header.stream;
                    self.header_end_stream = header.has(flags::END_STREAM);
                    let body = frame::strip_padding(payload, header.flags)?;
                    // A priority block sits between the padding and the header
                    // block, and feeding it to HPACK fails on a valid frame.
                    if header.has(flags::PRIORITY) {
                        body.get(5..).ok_or(Error::Protocol)?
                    } else {
                        body
                    }
                } else {
                    payload
                };

                self.header_block
                    .extend_from_slice(block)
                    .map_err(|_| Error::BufferTooSmall)?;

                if !header.has(flags::END_HEADERS) {
                    // More CONTINUATION frames to come. Decoding a partial block
                    // would corrupt the HPACK state for the whole connection.
                    return Ok((Event::Nothing, 0));
                }

                let stream = self.header_stream;
                let end_stream = self.header_end_stream;
                self.decoder.decode(&self.header_block, &mut on_header)?;
                if end_stream {
                    self.close(stream);
                }
                Ok((Event::Headers { stream, end_stream }, 0))
            }

            FrameType::Data => {
                let data = frame::strip_padding(payload, header.flags)?;
                // The window is consumed by the whole payload, padding included,
                // not just the bytes we hand back.
                written = self.credit(header.stream, header.length as u32, out)?;
                let end_stream = header.has(flags::END_STREAM);
                if end_stream {
                    self.close(header.stream);
                }
                Ok((
                    Event::Data {
                        stream: header.stream,
                        data,
                        end_stream,
                    },
                    written,
                ))
            }

            FrameType::RstStream => {
                let code = read_u32(payload).ok_or(Error::Protocol)?;
                self.close(header.stream);
                Ok((
                    Event::Reset {
                        stream: header.stream,
                        code,
                    },
                    0,
                ))
            }

            FrameType::GoAway => {
                // last-stream-id, then the error code.
                let code = payload
                    .get(4..8)
                    .and_then(read_u32)
                    .ok_or(Error::Protocol)?;
                Ok((Event::GoAway { code }, 0))
            }

            // Window updates from the peer govern what *we* may send. Our
            // requests are a few kilobytes against a 65535-byte default, so
            // there is nothing to track; a client that streamed large bodies
            // would have to.
            FrameType::WindowUpdate | FrameType::Priority => Ok((Event::Nothing, 0)),

            // Push was refused in our SETTINGS, so a promise is a protocol
            // violation rather than something to ignore.
            FrameType::PushPromise => Err(Error::Protocol),

            // RFC 7540 requires unknown types to be discarded.
            FrameType::Unknown(_) => Ok((Event::Nothing, 0)),
        }
    }

    /// Complete a DATA frame whose payload was consumed incrementally by the
    /// transport adapter.
    ///
    /// DATA does not affect HPACK state, so constrained adapters can stream a
    /// large payload without retaining the complete frame. Flow-control credit
    /// and stream closure still happen exactly once, after every payload byte
    /// (including padding) has been authenticated and consumed.
    pub fn finish_data(&mut self, header: FrameHeader, out: &mut [u8]) -> Result<usize, Error> {
        if header.kind != FrameType::Data {
            return Err(Error::Protocol);
        }
        let written = self.credit(header.stream, header.length as u32, out)?;
        if header.has(flags::END_STREAM) {
            self.close(header.stream);
        }
        Ok(written)
    }

    /// Return flow-control credit for `length` bytes consumed on `stream`.
    fn credit(&mut self, stream: u32, length: u32, out: &mut [u8]) -> Result<usize, Error> {
        if length == 0 {
            return Ok(0);
        }
        let mut written = 0;

        // Topping up only past a threshold keeps a stream of small DATA frames
        // from producing one update each.
        const THRESHOLD: u32 = RECEIVE_WINDOW / 2;

        self.consumed += length;
        if self.consumed >= THRESHOLD {
            let increment = self.consumed.to_be_bytes();
            written += frame::write_frame(FrameType::WindowUpdate, 0, 0, &increment, out)?;
            self.consumed = 0;
        }

        if let Some(entry) = self.streams.iter_mut().find(|s| s.id == stream) {
            entry.consumed += length;
            if entry.consumed >= THRESHOLD {
                let increment = entry.consumed.to_be_bytes();
                written += frame::write_frame(
                    FrameType::WindowUpdate,
                    0,
                    stream,
                    &increment,
                    &mut out[written..],
                )?;
                entry.consumed = 0;
            }
        }
        Ok(written)
    }

    fn apply_settings(&mut self, payload: &[u8]) -> Result<(), Error> {
        if !payload.len().is_multiple_of(6) {
            return Err(Error::Protocol);
        }
        for entry in payload.chunks_exact(6) {
            let identifier = u16::from_be_bytes([entry[0], entry[1]]);
            let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
            match identifier {
                settings::MAX_FRAME_SIZE => self.peer_max_frame = value as usize,
                // This limits our encoder, which deliberately has no dynamic
                // table. The receive decoder is governed by the 256-byte limit
                // we advertised and must retain its connection-wide state.
                settings::HEADER_TABLE_SIZE => {}
                // Everything else governs what we may send, and our requests are
                // too small for any of it to bind.
                _ => {}
            }
        }
        Ok(())
    }

    fn close(&mut self, stream: u32) {
        if let Some(entry) = self.streams.iter_mut().find(|s| s.id == stream) {
            entry.open = false;
        }
        self.streams.retain(|s| s.open);
    }

    pub fn open_streams(&self) -> usize {
        self.streams.len()
    }
}

fn write_setting(out: &mut [u8], identifier: u16, value: u32) {
    out[0..2].copy_from_slice(&identifier.to_be_bytes());
    out[2..6].copy_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame the way a server would, for feeding to `recv`.
    fn frame_bytes(
        kind: FrameType,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> heapless::Vec<u8, 512> {
        let mut out = heapless::Vec::<u8, 512>::new();
        out.resize_default(512).unwrap();
        let len = frame::write_frame(kind, flags, stream, payload, &mut out).unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn the_preface_is_exactly_what_the_rfc_requires() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];
        let len = connection.start(&mut out).unwrap();
        assert!(out[..len].starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));

        // Then SETTINGS, then the connection-level window update. Without the
        // last one a streaming response stops dead at 65535 bytes.
        let after = &out[frame::CLIENT_PREFACE.len()..len];
        let settings = FrameHeader::parse(after).unwrap();
        assert_eq!(settings.kind, FrameType::Settings);
        assert_eq!(settings.stream, 0);

        let update = &after[frame::HEADER_LEN + settings.length..];
        let update_header = FrameHeader::parse(update).unwrap();
        assert_eq!(update_header.kind, FrameType::WindowUpdate);
        assert_eq!(update_header.stream, 0);
        let increment = read_u32(&update[frame::HEADER_LEN..]).unwrap();
        assert_eq!(increment, RECEIVE_WINDOW - DEFAULT_WINDOW);
    }

    #[test]
    fn a_request_opens_an_odd_numbered_stream_and_ends_it() {
        let mut connection = Connection::new();
        let mut out = [0u8; 512];
        let (stream, len) = connection
            .request(
                "POST",
                "/machine/register",
                "127.0.0.1:8080",
                "http",
                &[("content-type", "application/json")],
                b"{}",
                &mut out,
            )
            .unwrap();

        // Client streams are odd, and the first is 1.
        assert_eq!(stream, 1);
        let headers = FrameHeader::parse(&out).unwrap();
        assert_eq!(headers.kind, FrameType::Headers);
        assert!(headers.has(flags::END_HEADERS));
        assert!(!headers.has(flags::END_STREAM), "a body follows");

        let data = FrameHeader::parse(&out[frame::HEADER_LEN + headers.length..]).unwrap();
        assert_eq!(data.kind, FrameType::Data);
        assert!(data.has(flags::END_STREAM));
        assert_eq!(len, frame::HEADER_LEN * 2 + headers.length + data.length);

        // The next request must not reuse the identifier.
        let (second, _) = connection
            .request("GET", "/", "h", "http", &[], b"", &mut out)
            .unwrap();
        assert_eq!(second, 3);
    }

    #[test]
    fn settings_are_acknowledged_and_an_ack_is_not() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];

        let settings = frame_bytes(FrameType::Settings, 0, 0, &[0, 5, 0, 0, 0x40, 0]);
        let (event, written) = connection.recv(&settings, |_, _| {}, &mut out).unwrap();
        assert_eq!(event, Event::Nothing);
        let ack = FrameHeader::parse(&out[..written]).unwrap();
        assert_eq!(ack.kind, FrameType::Settings);
        assert!(ack.has(flags::ACK));
        assert_eq!(ack.length, 0);

        // Acknowledging an acknowledgement would loop forever.
        let their_ack = frame_bytes(FrameType::Settings, flags::ACK, 0, &[]);
        let (_, written) = connection.recv(&their_ack, |_, _| {}, &mut out).unwrap();
        assert_eq!(written, 0);
    }

    #[test]
    fn peer_encoder_settings_do_not_reset_receive_hpack_state() {
        let mut connection = Connection::new();
        connection
            .decoder
            .decode(&[0x40, 0x01, b'x', 0x01, b'y'], |_, _| {})
            .unwrap();
        assert_eq!(connection.decoder.table().len(), 1);

        let settings = frame_bytes(FrameType::Settings, 0, 0, &[0, 1, 0, 0, 0x10, 0]);
        let mut out = [0u8; 64];
        connection.recv(&settings, |_, _| {}, &mut out).unwrap();
        assert_eq!(connection.decoder.table().len(), 1);
        assert_eq!(
            connection.decoder.table().capacity(),
            hpack::DEFAULT_TABLE_SIZE
        );
    }

    #[test]
    fn a_ping_is_echoed_exactly() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];
        let ping = frame_bytes(FrameType::Ping, 0, 0, &payload);
        let (_, written) = connection.recv(&ping, |_, _| {}, &mut out).unwrap();
        let header = FrameHeader::parse(&out[..written]).unwrap();
        assert!(header.has(flags::ACK));
        assert_eq!(&out[frame::HEADER_LEN..written], &payload);
    }

    #[test]
    fn a_header_block_split_across_continuation_frames_is_reassembled() {
        // Decoding either half alone would corrupt the HPACK table for the rest
        // of the connection, so the partial frame must produce no event at all.
        let mut connection = Connection::new();
        let mut out = [0u8; 256];

        // ":status: 200" then ":method: GET", as two indexed fields.
        let first = frame_bytes(FrameType::Headers, 0, 1, &[0x88]);
        let (event, _) = connection.recv(&first, |_, _| {}, &mut out).unwrap();
        assert_eq!(
            event,
            Event::Nothing,
            "an unterminated block yields nothing"
        );

        let mut seen = heapless::Vec::<(heapless::String<32>, heapless::String<32>), 4>::new();
        let second = frame_bytes(FrameType::Continuation, flags::END_HEADERS, 1, &[0x82]);
        let (event, _) = connection
            .recv(
                &second,
                |name, value| {
                    let mut n = heapless::String::new();
                    let mut v = heapless::String::new();
                    n.push_str(name).unwrap();
                    v.push_str(value).unwrap();
                    seen.push((n, v)).unwrap();
                },
                &mut out,
            )
            .unwrap();

        assert!(matches!(event, Event::Headers { stream: 1, .. }));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0.as_str(), ":status");
        assert_eq!(seen[0].1.as_str(), "200");
        assert_eq!(seen[1].0.as_str(), ":method");
    }

    #[test]
    fn data_returns_the_payload_and_eventually_a_window_update() {
        let mut connection = Connection::new();
        let mut out = [0u8; 256];

        let data = frame_bytes(FrameType::Data, 0, 1, b"hello");
        let (event, written) = connection.recv(&data, |_, _| {}, &mut out).unwrap();
        assert_eq!(
            event,
            Event::Data {
                stream: 1,
                data: b"hello",
                end_stream: false
            }
        );
        // Below the threshold, so no update yet: one update per small frame
        // would be pure overhead.
        assert_eq!(written, 0);
    }

    #[test]
    fn a_long_response_gets_its_window_topped_up_before_it_can_stall() {
        // The regression test for the failure mode that looks like a server
        // fault: without this the peer stops after 65535 bytes.
        let mut connection = Connection::new();
        let mut out = [0u8; 256];
        let payload = [0u8; 400];

        let mut updates = 0;
        let mut delivered = 0usize;
        // Well past both the 65535-byte default window and our own top-up
        // threshold, so a connection that never replenishes would have stalled
        // long before the end of this loop.
        let frames = 2_000;
        for _ in 0..frames {
            let data = frame_bytes(FrameType::Data, 0, 1, &payload);
            let (event, written) = connection.recv(&data, |_, _| {}, &mut out).unwrap();
            if let Event::Data { data, .. } = event {
                delivered += data.len();
            }
            if written > 0 {
                updates += 1;
                let header = FrameHeader::parse(&out[..written]).unwrap();
                assert_eq!(header.kind, FrameType::WindowUpdate);
            }
        }
        assert_eq!(delivered, frames * 400);
        assert!(
            updates > 0,
            "the connection window must be replenished, or the server stops at 65535 bytes"
        );
    }

    #[test]
    fn padding_and_priority_are_stripped_before_hpack_sees_the_block() {
        let mut connection = Connection::new();
        let mut out = [0u8; 256];
        // pad length 2, priority (5 bytes), the block, then the padding.
        let payload = [2, 0, 0, 0, 0, 0, 0x88, 0xaa, 0xbb];
        let headers = frame_bytes(
            FrameType::Headers,
            flags::END_HEADERS | flags::PADDED | flags::PRIORITY,
            1,
            &payload,
        );
        let mut status = heapless::String::<8>::new();
        connection
            .recv(
                &headers,
                |name, value| {
                    if name == ":status" {
                        status.push_str(value).unwrap();
                    }
                },
                &mut out,
            )
            .unwrap();
        assert_eq!(status.as_str(), "200");
    }

    #[test]
    fn goaway_and_reset_are_reported_rather_than_hidden() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];

        let reset = frame_bytes(FrameType::RstStream, 0, 1, &[0, 0, 0, 8]);
        let (event, _) = connection.recv(&reset, |_, _| {}, &mut out).unwrap();
        assert_eq!(event, Event::Reset { stream: 1, code: 8 });

        let goaway = frame_bytes(FrameType::GoAway, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 2]);
        let (event, _) = connection.recv(&goaway, |_, _| {}, &mut out).unwrap();
        assert_eq!(event, Event::GoAway { code: 2 });
    }

    #[test]
    fn a_promised_push_is_a_protocol_error_because_we_refused_push() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];
        let promise = frame_bytes(FrameType::PushPromise, flags::END_HEADERS, 1, &[0, 0, 0, 2]);
        assert_eq!(
            connection.recv(&promise, |_, _| {}, &mut out).err(),
            Some(Error::Protocol)
        );
    }

    #[test]
    fn an_unknown_frame_type_is_discarded_not_fatal() {
        let mut connection = Connection::new();
        let mut out = [0u8; 128];
        let unknown = frame_bytes(FrameType::Unknown(0x63), 0, 0, b"whatever");
        let (event, written) = connection.recv(&unknown, |_, _| {}, &mut out).unwrap();
        assert_eq!(event, Event::Nothing);
        assert_eq!(written, 0);
    }
}
