//! Sans-I/O pieces of Taildrop resume.
//!
//! A receiver keeps the partial file of an interrupted upload. Before
//! uploading again, a sender `GET`s `/v0/put/<name>`: the receiver streams one
//! JSON line per [`BLOCK_SIZE`] block of what it kept,
//! `{"checksum":"<SHA-256 hex>","algo":"sha256","size":<bytes>}`. The sender
//! hashes the same blocks of its own copy, stops at the first mismatch, and
//! `PUT`s only the rest with `Range: bytes=<offset>-`. This is the exchange
//! stock Tailscale performs; a receiver without resume support answers the
//! probe with `404`/`405` and the sender starts from zero.

use sha2::{Digest, Sha256};

use super::super::http::{self, Cursor};

/// Bytes covered by one checksum, as in stock Tailscale.
pub const BLOCK_SIZE: u64 = 64 << 10;
/// Longest checksum line [`BlockChecksum::write_line`] produces.
pub const LINE_MAX: usize = 128;

/// One block of a partial file, as exchanged on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockChecksum {
    pub sha256: [u8; 32],
    /// Block length; every block but the last is [`BLOCK_SIZE`].
    pub size: u64,
}

/// A checksum line that is not the expected JSON shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidChecksum;

impl BlockChecksum {
    /// Append the newline-terminated JSON line for this block.
    pub fn write_line(&self, out: &mut Cursor<'_>) -> Result<(), http::Error> {
        out.bytes(br#"{"checksum":""#)?;
        for byte in self.sha256 {
            out.args(format_args!("{byte:02x}"))?;
        }
        out.args(format_args!(r#"","algo":"sha256","size":{}}}"#, self.size))?;
        out.bytes(b"\n")
    }

    /// Parse one line of a checksum stream. Fields may come in any order;
    /// any algorithm but `sha256`, or a block larger than [`BLOCK_SIZE`], is
    /// refused, as stock Tailscale does.
    pub fn parse_line(line: &str) -> Result<Self, InvalidChecksum> {
        let body = line
            .trim()
            .strip_prefix('{')
            .and_then(|body| body.strip_suffix('}'))
            .ok_or(InvalidChecksum)?;
        let (mut sha256, mut algorithm, mut size) = (None, false, None);
        for field in body.split(',') {
            let (key, value) = field.split_once(':').ok_or(InvalidChecksum)?;
            let value = value.trim();
            match key.trim() {
                r#""checksum""# => sha256 = Some(parse_hex(unquote(value)?)?),
                r#""algo""# => algorithm = unquote(value)? == "sha256",
                r#""size""# => {
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(InvalidChecksum);
                    }
                    size = Some(value.parse().map_err(|_| InvalidChecksum)?);
                }
                _ => {}
            }
        }
        match (sha256, algorithm, size) {
            (Some(sha256), true, Some(size)) if size <= BLOCK_SIZE => Ok(Self { sha256, size }),
            _ => Err(InvalidChecksum),
        }
    }
}

fn unquote(value: &str) -> Result<&str, InvalidChecksum> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(InvalidChecksum)
}

fn parse_hex(text: &str) -> Result<[u8; 32], InvalidChecksum> {
    let mut out = [0u8; 32];
    if text.len() != 64 {
        return Err(InvalidChecksum);
    }
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = core::str::from_utf8(pair).map_err(|_| InvalidChecksum)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| InvalidChecksum)?;
    }
    Ok(out)
}

/// Hashes one block from bytes fed in pieces of any size.
pub struct BlockHasher {
    hasher: Sha256,
    remaining: u64,
    size: u64,
}

impl BlockHasher {
    /// Hash a block of exactly `size` bytes.
    pub fn new(size: u64) -> Self {
        Self {
            hasher: Sha256::new(),
            remaining: size,
            size,
        }
    }

    /// Bytes still needed to complete the block.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Bytes hashed so far.
    pub fn len(&self) -> u64 {
        self.size - self.remaining
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hash the front of `data`; returns how much of it belonged to this block.
    pub fn feed(&mut self, data: &[u8]) -> usize {
        let take = usize::try_from(self.remaining).map_or(data.len(), |left| left.min(data.len()));
        self.hasher.update(&data[..take]);
        self.remaining -= take as u64;
        take
    }

    /// The checksum of the bytes hashed, which may be fewer than requested
    /// when the data ended early.
    pub fn finish(self) -> BlockChecksum {
        BlockChecksum {
            sha256: self.hasher.finalize().into(),
            size: self.size - self.remaining,
        }
    }
}

/// Reassembles newline-terminated lines split across reads.
pub struct LineBuffer {
    line: [u8; LINE_MAX],
    len: usize,
    ready: bool,
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self {
            line: [0; LINE_MAX],
            len: 0,
            ready: false,
        }
    }
}

impl LineBuffer {
    /// Take bytes from the front of `input` until a line completes. Returns
    /// how many were used; call [`Self::take`] when it reports a line.
    pub fn push(&mut self, input: &[u8]) -> Result<usize, InvalidChecksum> {
        if self.ready {
            self.len = 0;
            self.ready = false;
        }
        for (used, &byte) in input.iter().enumerate() {
            if byte == b'\n' {
                self.ready = true;
                return Ok(used + 1);
            }
            *self.line.get_mut(self.len).ok_or(InvalidChecksum)? = byte;
            self.len += 1;
        }
        Ok(input.len())
    }

    /// The completed line, once [`Self::push`] has found its newline.
    pub fn take(&self) -> Option<&str> {
        self.ready
            .then(|| core::str::from_utf8(&self.line[..self.len]).ok())
            .flatten()
    }

    /// Unterminated bytes are left: a stream ending mid-line.
    pub fn has_partial(&self) -> bool {
        !self.ready && self.len != 0
    }
}

/// The start offset of a resumed upload's `Range: bytes=<offset>-` header.
/// Only that single open-ended form is valid, as in stock Tailscale.
pub fn parse_range(value: &str) -> Option<u64> {
    let start = value.trim().strip_prefix("bytes=")?.strip_suffix('-')?;
    if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    start.parse().ok()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn checksum_lines_round_trip_in_stock_format() {
        let block = BlockChecksum {
            sha256: Sha256::digest(b"abc").into(),
            size: 3,
        };
        let mut buf = [0u8; LINE_MAX];
        let mut cursor = Cursor::new(&mut buf);
        block.write_line(&mut cursor).unwrap();
        let len = cursor.len();
        let line = core::str::from_utf8(&buf[..len]).unwrap();
        // The exact bytes Go's json.Encoder emits for blockChecksum.
        assert_eq!(
            line,
            "{\"checksum\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"algo\":\"sha256\",\"size\":3}\n"
        );
        assert_eq!(BlockChecksum::parse_line(line), Ok(block));
        let reordered = "{ \"size\": 3, \"algo\": \"sha256\", \"checksum\": \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" }";
        assert_eq!(BlockChecksum::parse_line(reordered), Ok(block));
        let full = BlockChecksum {
            sha256: [0xff; 32],
            size: BLOCK_SIZE,
        };
        let mut cursor = Cursor::new(&mut buf);
        full.write_line(&mut cursor).unwrap();
    }

    #[test]
    fn refuses_unexpected_checksums() {
        let hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        for line in [
            std::format!("{{\"checksum\":\"{hex}\",\"algo\":\"md5\",\"size\":3}}"),
            std::format!("{{\"checksum\":\"{hex}\",\"algo\":\"sha256\",\"size\":65537}}"),
            std::format!("{{\"checksum\":\"{hex}\",\"algo\":\"sha256\",\"size\":-1}}"),
            std::format!(
                "{{\"checksum\":\"{}\",\"algo\":\"sha256\",\"size\":3}}",
                &hex[1..]
            ),
            std::format!("{{\"checksum\":\"{hex}\",\"size\":3}}"),
            std::string::String::from("[]"),
        ] {
            assert_eq!(
                BlockChecksum::parse_line(&line),
                Err(InvalidChecksum),
                "{line}"
            );
        }
    }

    #[test]
    fn hashes_blocks_fed_in_pieces() {
        let mut hasher = BlockHasher::new(5);
        assert_eq!(hasher.feed(b"he"), 2);
        assert_eq!(hasher.feed(b"llo world"), 3);
        assert_eq!(hasher.remaining(), 0);
        assert_eq!(
            hasher.finish().sha256,
            <[u8; 32]>::from(Sha256::digest(b"hello"))
        );
        let mut short = BlockHasher::new(10);
        short.feed(b"abc");
        assert_eq!(short.finish().size, 3);
    }

    #[test]
    fn reassembles_lines() {
        let mut lines = LineBuffer::default();
        assert_eq!(lines.push(b"ab"), Ok(2));
        assert_eq!(lines.take(), None);
        assert_eq!(lines.push(b"c\nde"), Ok(2));
        assert_eq!(lines.take(), Some("abc"));
        assert_eq!(lines.push(b"de"), Ok(2));
        assert!(lines.has_partial());
        assert_eq!(lines.push(&[b'x'; LINE_MAX + 1]), Err(InvalidChecksum));
    }

    #[test]
    fn parses_only_open_ended_ranges() {
        assert_eq!(parse_range("bytes=131072-"), Some(131072));
        assert_eq!(parse_range(" bytes=0- "), Some(0));
        for bad in [
            "bytes=1-2",
            "bytes=-5",
            "bytes=1-,3-",
            "items=1-",
            "bytes=x-",
            "bytes=-",
        ] {
            assert_eq!(parse_range(bad), None, "{bad}");
        }
    }
}
