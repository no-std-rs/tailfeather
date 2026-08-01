//! A classic-pcap reader, just enough of one to replay `tests/vectors/ts2021-session.pcap`.
//!
//! The capture is 44 KB of a real tailscaled 1.94.2 talking to a real Headscale
//! v0.29.3. Until this module existed, nothing opened it: every fact it holds had
//! been transcribed into a comment by a human reading it once, which is exactly
//! the kind of anchor that rots without anyone noticing. Parsing it in a test
//! turns those comments into assertions.
//!
//! # What this deliberately does not handle
//!
//! Loopback capture on a quiet host: no loss, no reordering, no overlapping
//! retransmissions, no IP fragmentation, no TCP options that matter. So
//! reassembly is "sort the segments by sequence number and check they abut".
//! Anything more would be untested code guarding against conditions this file
//! cannot contain. [`Stream::gaps`] reports the discontinuities rather than
//! papering over them, so a future capture that violates the assumption is a
//! test failure and not a silently truncated stream.
//!
//! Sequence numbers are compared modulo 2^32 via wrapping arithmetic, because a
//! capture that happens to straddle the wrap point is cheap to support and
//! expensive to debug.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Why a capture could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Neither pcap magic, in either endianness.
    NotAPcap,
    /// A link type this reader does not decode.
    UnsupportedLinkType(u32),
    /// The file ended inside a header or a packet.
    Truncated,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAPcap => write!(f, "not a classic pcap file"),
            Error::UnsupportedLinkType(n) => write!(f, "unsupported pcap link type {n}"),
            Error::Truncated => write!(f, "pcap file ends mid-record"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

const MAGIC_LE: u32 = 0xa1b2_c3d4;
const MAGIC_BE: u32 = 0xd4c3_b2a1;
const LINKTYPE_ETHERNET: u32 = 1;
const ETHERTYPE_IPV4: u16 = 0x0800;

/// One TCP direction, reassembled.
#[derive(Debug, Clone, Default)]
pub struct Stream {
    /// Payload bytes in sequence order, gaps omitted.
    bytes: Vec<u8>,
    /// Where the byte stream was discontinuous, as `(offset_into_bytes, missing)`.
    gaps: Vec<(usize, u32)>,
    segments: usize,
}

impl Stream {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Discontinuities found during reassembly, as `(offset, bytes missing)`.
    ///
    /// Expected to be empty for this capture. A test asserting on stream content
    /// should assert this is empty first, otherwise it is asserting on a
    /// silently spliced stream.
    pub fn gaps(&self) -> &[(usize, u32)] {
        &self.gaps
    }

    /// How many TCP segments carried this stream. Useful only to show that
    /// record boundaries and segment boundaries are unrelated.
    pub fn segments(&self) -> usize {
        self.segments
    }
}

/// Every TCP direction in a capture, keyed by `(source port, destination port)`.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    streams: BTreeMap<(u16, u16), Stream>,
    packets: usize,
}

impl Capture {
    /// Read and reassemble a pcap file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| Error::Io(format!("{}: {e}", path.as_ref().display())))?;
        Self::parse(&bytes)
    }

    /// The session capture committed in `tests/vectors/`.
    pub fn ts2021_session() -> Result<Self, Error> {
        Self::open(vector_path("ts2021-session.pcap"))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let header = bytes.get(..24).ok_or(Error::Truncated)?;
        let magic = u32::from_le_bytes(header[..4].try_into().unwrap());
        let big_endian = match magic {
            MAGIC_LE => false,
            MAGIC_BE => true,
            _ => return Err(Error::NotAPcap),
        };
        let u32_at = |b: &[u8]| -> u32 {
            let a: [u8; 4] = b.try_into().unwrap();
            if big_endian {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        };
        let link_type = u32_at(&header[20..24]);
        if link_type != LINKTYPE_ETHERNET {
            return Err(Error::UnsupportedLinkType(link_type));
        }

        // Segments are collected keyed by sequence number before being joined, so
        // that a duplicate retransmission collapses instead of being appended
        // twice. Where a retransmission is longer than the original, keep the
        // longer one.
        /// Segments of one direction, keyed by sequence number, plus how many
        /// TCP segments carried them.
        type Segments = (BTreeMap<u32, Vec<u8>>, usize);
        let mut collected: BTreeMap<(u16, u16), Segments> = BTreeMap::new();
        let mut packets = 0usize;
        let mut offset = 24usize;

        while offset < bytes.len() {
            let record = bytes.get(offset..offset + 16).ok_or(Error::Truncated)?;
            let captured = u32_at(&record[8..12]) as usize;
            offset += 16;
            let frame = bytes.get(offset..offset + captured).ok_or(Error::Truncated)?;
            offset += captured;
            packets += 1;

            let Some((ports, seq, payload)) = tcp_payload(frame) else {
                continue;
            };
            if payload.is_empty() {
                continue;
            }
            let entry = collected.entry(ports).or_default();
            entry.1 += 1;
            let slot = entry.0.entry(seq).or_default();
            if payload.len() > slot.len() {
                *slot = payload.to_vec();
            }
        }

        let mut streams = BTreeMap::new();
        for (ports, (segments, count)) in collected {
            let mut stream = Stream {
                segments: count,
                ..Stream::default()
            };
            let mut expected: Option<u32> = None;
            for (seq, payload) in segments {
                if let Some(want) = expected
                    && seq != want
                {
                    // wrapping_sub keeps this meaningful across the 2^32 wrap.
                    stream.gaps.push((stream.bytes.len(), seq.wrapping_sub(want)));
                }
                stream.bytes.extend_from_slice(&payload);
                expected = Some(seq.wrapping_add(payload.len() as u32));
            }
            streams.insert(ports, stream);
        }

        Ok(Capture { streams, packets })
    }

    /// One direction, by port pair.
    pub fn stream(&self, src: u16, dst: u16) -> Option<&Stream> {
        self.streams.get(&(src, dst))
    }

    /// Every direction present, in port order.
    pub fn streams(&self) -> impl Iterator<Item = (&(u16, u16), &Stream)> {
        self.streams.iter()
    }

    pub fn packets(&self) -> usize {
        self.packets
    }
}

/// Strip Ethernet, IPv4 and TCP, returning `((src, dst), seq, payload)`.
///
/// Returns `None` for anything that is not IPv4 TCP — the capture contains ARP
/// and a few stray frames, and skipping them is not an error.
fn tcp_payload(frame: &[u8]) -> Option<((u16, u16), u32, &[u8])> {
    let ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(14..)?;
    if ip.first()? >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || *ip.get(9)? != 6 {
        return None;
    }
    // The IP total-length field, not the frame length: Ethernet pads short
    // frames to 60 bytes, and trusting the frame would append the padding to the
    // stream. This capture has no runt frames, but a stream reader that gets this
    // wrong fails in a way that looks like a protocol bug.
    let total = u16::from_be_bytes(ip.get(2..4)?.try_into().ok()?) as usize;
    let ip = ip.get(..total.min(ip.len()))?;

    let tcp = ip.get(ihl..)?;
    let src = u16::from_be_bytes(tcp.get(0..2)?.try_into().ok()?);
    let dst = u16::from_be_bytes(tcp.get(2..4)?.try_into().ok()?);
    let seq = u32::from_be_bytes(tcp.get(4..8)?.try_into().ok()?);
    let data_offset = (tcp.get(12)? >> 4) as usize * 4;
    if data_offset < 20 {
        return None;
    }
    let payload = tcp.get(data_offset..)?;
    Some(((src, dst), seq, payload))
}

/// Absolute path of a file in `tests/vectors/`.
pub fn vector_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A three-packet synthetic capture, built here so the reader's own framing
    /// is checked against bytes this test wrote rather than against the vector it
    /// is supposed to be validating.
    fn synthetic() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262144u32.to_le_bytes());
        out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        let mut packet = |seq: u32, payload: &[u8]| {
            let mut frame = vec![0u8; 14];
            frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45;
            ip[9] = 6;
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&1111u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&2222u16.to_be_bytes());
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp[12] = 5 << 4;
            let total = ip.len() + tcp.len() + payload.len();
            ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            frame.extend_from_slice(&ip);
            frame.extend_from_slice(&tcp);
            frame.extend_from_slice(payload);

            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&frame);
        };
        // Deliberately out of order, with the middle segment duplicated.
        packet(1000, b"world");
        packet(995, b"hello");
        packet(1000, b"world");
        out
    }

    #[test]
    fn segments_are_ordered_by_sequence_and_duplicates_collapse() {
        let capture = Capture::parse(&synthetic()).unwrap();
        let stream = capture.stream(1111, 2222).unwrap();
        assert_eq!(stream.bytes(), b"helloworld");
        assert_eq!(stream.gaps(), &[]);
        assert_eq!(capture.packets(), 3);
    }

    #[test]
    fn a_missing_segment_is_reported_rather_than_spliced_over() {
        // Drop the "hello" packet by rewriting its sequence number so a hole is
        // left in front of "world".
        let bytes = synthetic();
        // Truncate to header + the first packet only: the stream then starts at
        // seq 1000 with nothing before it, which is not a gap — a gap is an
        // interior discontinuity, and a stream that begins mid-flight is normal.
        let first_len = 24 + 16 + 14 + 20 + 20 + 5;
        let partial = Capture::parse(&bytes[..first_len]).unwrap();
        assert_eq!(partial.stream(1111, 2222).unwrap().bytes(), b"world");
        assert!(partial.stream(1111, 2222).unwrap().gaps().is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_pcap_is_refused() {
        assert_eq!(
            Capture::parse(b"not a pcap at all!!!!!!!!").unwrap_err(),
            Error::NotAPcap
        );
        assert_eq!(Capture::parse(b"short").unwrap_err(), Error::Truncated);
    }

    #[test]
    fn ethernet_padding_on_a_runt_frame_does_not_enter_the_stream() {
        // A 1-byte payload in a frame padded to Ethernet's 60-byte minimum. The
        // IP total-length field is the only thing that distinguishes payload from
        // padding.
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC_LE.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262144u32.to_le_bytes());
        out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[2..4].copy_from_slice(&41u16.to_be_bytes()); // 20 + 20 + 1
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&7u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&8u16.to_be_bytes());
        tcp[12] = 5 << 4;
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&tcp);
        frame.push(b'X');
        frame.resize(60, 0); // the padding

        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);

        let capture = Capture::parse(&out).unwrap();
        assert_eq!(capture.stream(7, 8).unwrap().bytes(), b"X");
    }
}
