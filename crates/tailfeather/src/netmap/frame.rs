//! Splitting a long-poll stream into MapResponses.
//!
//! The body is `[4-byte length][JSON]` repeated for as long as the connection
//! lives. The length is **little-endian**, unlike every other length in this
//! protocol; reading it big-endian yields a number in the hundreds of millions,
//! which looks like a corrupt stream rather than like a byte-order mistake.
//!
//! HTTP/2 `DATA` frames have nothing to do with these boundaries: one map
//! response routinely spans several, and one frame can hold the end of one
//! response and the start of the next. This reader is what absorbs that, and it
//! is deliberately the only place that buffers — it holds a length prefix and
//! whatever partial one has arrived, never a whole response.

use crate::netmap::Error;

pub const HEADER_LEN: usize = 4;

/// How the caller is told what to do with the bytes it just handed over.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// Part of the response body. Feed it to the parser.
    Body(&'a [u8]),
    /// The response that was being read is complete.
    End,
    /// Nothing further can be done until more bytes arrive.
    Need,
}

/// Tracks where one response ends and the next begins.
pub struct FrameReader {
    /// Bytes of the length prefix seen so far.
    header: [u8; HEADER_LEN],
    header_filled: usize,
    /// Bytes of the current response still to come, once the length is known.
    remaining: Option<usize>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub const fn new() -> Self {
        Self {
            header: [0; HEADER_LEN],
            header_filled: 0,
            remaining: None,
        }
    }

    /// Take as much of `input` as belongs to the current response.
    ///
    /// Returns what to do with it and how many bytes were consumed. Call
    /// repeatedly until it reports [`Chunk::Need`]: one call cannot span a
    /// response boundary, because the caller has to be told where that is.
    pub fn next<'a>(&mut self, input: &'a [u8]) -> Result<(Chunk<'a>, usize), Error> {
        if self.remaining.is_none() {
            let wanted = HEADER_LEN - self.header_filled;
            let take = input.len().min(wanted);
            self.header[self.header_filled..self.header_filled + take]
                .copy_from_slice(&input[..take]);
            self.header_filled += take;
            if self.header_filled < HEADER_LEN {
                return Ok((Chunk::Need, take));
            }
            self.remaining = Some(u32::from_le_bytes(self.header) as usize);
            self.header_filled = 0;
            return Ok((Chunk::Need, take));
        }

        let remaining = self.remaining.expect("checked above");
        if remaining == 0 {
            // A zero-length response, which the server uses as a keepalive.
            self.remaining = None;
            return Ok((Chunk::End, 0));
        }
        if input.is_empty() {
            return Ok((Chunk::Need, 0));
        }

        let take = input.len().min(remaining);
        self.remaining = Some(remaining - take);
        Ok((Chunk::Body(&input[..take]), take))
    }

    /// Whether the response being read has been fully delivered.
    pub fn is_complete(&self) -> bool {
        self.remaining == Some(0)
    }

    /// Begin the next response.
    pub fn finish_response(&mut self) {
        self.remaining = None;
        self.header_filled = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a whole input through the reader, collecting the bodies of each
    /// complete response.
    fn responses(
        reader: &mut FrameReader,
        mut input: &[u8],
    ) -> heapless::Vec<heapless::Vec<u8, 64>, 4> {
        let mut out = heapless::Vec::new();
        let mut current = heapless::Vec::<u8, 64>::new();
        loop {
            let (chunk, consumed) = reader.next(input).unwrap();
            input = &input[consumed..];
            match chunk {
                Chunk::Body(bytes) => {
                    current.extend_from_slice(bytes).unwrap();
                    if reader.is_complete() {
                        reader.finish_response();
                        out.push(core::mem::take(&mut current)).unwrap();
                    }
                }
                Chunk::End => {
                    out.push(core::mem::take(&mut current)).unwrap();
                }
                Chunk::Need => {
                    if consumed == 0 {
                        return out;
                    }
                }
            }
        }
    }

    fn framed(bodies: &[&[u8]]) -> heapless::Vec<u8, 128> {
        let mut out = heapless::Vec::new();
        for body in bodies {
            out.extend_from_slice(&(body.len() as u32).to_le_bytes())
                .unwrap();
            out.extend_from_slice(body).unwrap();
        }
        out
    }

    #[test]
    fn splits_back_to_back_responses() {
        let stream = framed(&[b"{\"a\":1}", b"{\"b\":2}"]);
        let mut reader = FrameReader::new();
        let out = responses(&mut reader, &stream);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_slice(), b"{\"a\":1}");
        assert_eq!(out[1].as_slice(), b"{\"b\":2}");
    }

    #[test]
    fn a_response_split_across_arbitrary_chunks_is_reassembled() {
        // HTTP/2 DATA frames have nothing to do with these boundaries, so every
        // split has to work — including one inside the length prefix.
        let stream = framed(&[b"{\"hello\":\"world\"}"]);
        for split in 1..stream.len() {
            let mut reader = FrameReader::new();
            let mut body = heapless::Vec::<u8, 64>::new();
            for part in [&stream[..split], &stream[split..]] {
                let mut input = part;
                loop {
                    let (chunk, consumed) = reader.next(input).unwrap();
                    input = &input[consumed..];
                    match chunk {
                        Chunk::Body(bytes) => body.extend_from_slice(bytes).unwrap(),
                        Chunk::End => {}
                        Chunk::Need if consumed == 0 => break,
                        Chunk::Need => {}
                    }
                }
            }
            assert_eq!(
                body.as_slice(),
                b"{\"hello\":\"world\"}",
                "split at {split}"
            );
        }
    }

    #[test]
    fn the_length_is_little_endian() {
        // Read the other way this is 117 440 512 bytes, which would look like a
        // corrupt stream rather than a byte-order mistake.
        let mut reader = FrameReader::new();
        let (_, consumed) = reader.next(&[0x07, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(reader.remaining, Some(7));
    }

    #[test]
    fn a_zero_length_response_is_a_keepalive_not_an_end_of_stream() {
        let stream = framed(&[b"", b"{\"a\":1}"]);
        let mut reader = FrameReader::new();
        let out = responses(&mut reader, &stream);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_empty());
        assert_eq!(out[1].as_slice(), b"{\"a\":1}");
    }
}
