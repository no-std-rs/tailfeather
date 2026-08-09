//! The early payload the server may send before its HTTP/2 preface.
//!
//! # What it is
//!
//! Once the Noise handshake completes, the *decrypted* stream from the server
//! either begins with an HTTP/2 SETTINGS frame, or with a short out-of-band
//! message that HTTP/2 knows nothing about. The message carries a node-key
//! challenge, which registration needs before any HTTP/2 request is made.
//!
//! ```text
//! ff ff ff 'T' 'S'   5-byte magic
//! xx xx xx xx        payload length, big-endian
//! { … }              that many bytes of JSON
//! ```
//!
//! # The trap
//!
//! The probe is nine bytes, and nine bytes is also exactly the length of an
//! HTTP/2 frame header. That is not a coincidence — it is what makes the two
//! cases distinguishable — but it means the nine bytes must be *pushed back*
//! when the magic does not match, or the HTTP/2 layer starts mid-header and
//! every frame after it is misparsed.
//!
//! # What the capture actually shows
//!
//! Headscale v0.29.3 does send one. The record lengths in
//! `tests/vectors/ts2021-session.pcap` are 21, 20, 111 — plaintexts of 5, 4 and
//! 95 bytes. So the magic, the length and the JSON each arrive in a *separate
//! record*, and the nine-byte probe spans three of them.
//!
//! That is the second trap, and it is why this is a reader with an internal
//! buffer rather than a function over one slice: the payload is framed in the
//! decrypted byte stream, and the record boundaries have nothing to do with it.

use crate::noise::Error;

/// `\xff\xff\xffTS`. Not valid at the start of an HTTP/2 frame header: the first
/// three bytes are a 24-bit length, and 0xffffff exceeds any legal frame size.
pub const MAGIC: [u8; 5] = [0xff, 0xff, 0xff, b'T', b'S'];

/// Magic plus a four-byte length. Also the length of an HTTP/2 frame header,
/// which is what makes one read enough to tell the two apart.
pub const PROBE_LEN: usize = MAGIC.len() + 4;

/// An upper bound on the early payload, so a hostile length cannot demand an
/// unbounded buffer. The captured challenge is 95 bytes.
pub const MAX_PAYLOAD: usize = 1024;

/// What the first nine decrypted bytes turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Early<'a> {
    /// An early payload of this many bytes; its contents follow.
    Payload(&'a [u8]),
    /// No early payload. These nine bytes are the start of an HTTP/2 frame
    /// header and must be handed to the HTTP/2 layer unconsumed.
    PushBack(&'a [u8; PROBE_LEN]),
}

/// Accumulates decrypted bytes until the early-payload question can be answered.
///
/// Fed plaintext as records are opened; it says how many more bytes it needs.
pub struct EarlyReader {
    buffer: [u8; PROBE_LEN + MAX_PAYLOAD],
    filled: usize,
    /// Set once the probe has been read and the magic matched.
    payload_len: Option<usize>,
}

impl Default for EarlyReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EarlyReader {
    pub fn new() -> Self {
        Self {
            buffer: [0; PROBE_LEN + MAX_PAYLOAD],
            filled: 0,
            payload_len: None,
        }
    }

    /// Add decrypted bytes.
    ///
    /// Returns how many were consumed. Anything left over belongs to the HTTP/2
    /// layer and must not be given here again.
    pub fn push(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let mut consumed = 0;
        loop {
            let wanted = self.wanted()?;
            if wanted == 0 || consumed == bytes.len() {
                return Ok(consumed);
            }
            let take = (bytes.len() - consumed).min(wanted);
            self.buffer[self.filled..self.filled + take]
                .copy_from_slice(&bytes[consumed..consumed + take]);
            self.filled += take;
            consumed += take;
            // Completing the probe changes how much more is wanted, so the loop
            // runs again rather than returning a short count and making the
            // caller re-push what it still holds.
            self.resolve_length()?;
        }
    }

    /// Once the probe is complete and the magic matches, read the length.
    fn resolve_length(&mut self) -> Result<(), Error> {
        if self.payload_len.is_some() || self.filled < PROBE_LEN || !self.magic_matches() {
            return Ok(());
        }
        let len = u32::from_be_bytes([
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
            self.buffer[8],
        ]) as usize;
        if len > MAX_PAYLOAD {
            return Err(Error::RecordTooLong);
        }
        self.payload_len = Some(len);
        Ok(())
    }

    /// How many more bytes are needed before [`EarlyReader::finish`] can answer.
    fn wanted(&self) -> Result<usize, Error> {
        match self.payload_len {
            None => Ok(PROBE_LEN.saturating_sub(self.filled)),
            Some(len) => Ok((PROBE_LEN + len).saturating_sub(self.filled)),
        }
    }

    /// Whether enough bytes have arrived to decide.
    pub fn is_complete(&self) -> bool {
        self.wanted().is_ok_and(|w| w == 0)
    }

    fn magic_matches(&self) -> bool {
        self.buffer[..MAGIC.len()] == MAGIC
    }

    /// Report what the bytes were.
    pub fn finish(&self) -> Result<Early<'_>, Error> {
        if !self.is_complete() {
            return Err(Error::Incomplete);
        }
        match self.payload_len {
            Some(len) => Ok(Early::Payload(&self.buffer[PROBE_LEN..PROBE_LEN + len])),
            None => Ok(Early::PushBack(
                self.buffer[..PROBE_LEN]
                    .try_into()
                    .expect("completeness implies the probe is full"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape Headscale v0.29.3 sent, as read from the capture: 5 bytes of
    /// magic, 4 of length, then that many of JSON.
    fn captured_shape() -> ([u8; PROBE_LEN], &'static [u8]) {
        let payload = br#"{"nodeKeyChallenge":"nodekey:0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let mut probe = [0u8; PROBE_LEN];
        probe[..5].copy_from_slice(&MAGIC);
        probe[5..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        (probe, payload)
    }

    #[test]
    fn reads_an_early_payload_delivered_all_at_once() {
        let (probe, payload) = captured_shape();
        let mut reader = EarlyReader::new();
        reader.push(&probe).unwrap();
        reader.push(payload).unwrap();
        assert_eq!(reader.finish(), Ok(Early::Payload(payload)));
    }

    /// The case the capture actually produced: the nine-byte probe arrives
    /// split across three records, as 5 bytes then 4 then the body.
    #[test]
    fn reads_an_early_payload_split_across_record_boundaries() {
        let (probe, payload) = captured_shape();
        let mut reader = EarlyReader::new();

        assert_eq!(reader.push(&probe[..5]).unwrap(), 5);
        assert!(!reader.is_complete());
        assert_eq!(reader.finish(), Err(Error::Incomplete));

        assert_eq!(reader.push(&probe[5..9]).unwrap(), 4);
        assert!(!reader.is_complete());

        for chunk in payload.chunks(7) {
            reader.push(chunk).unwrap();
        }
        assert_eq!(reader.finish(), Ok(Early::Payload(payload)));
    }

    #[test]
    fn an_http2_settings_frame_is_pushed_back_intact() {
        // SETTINGS: 24-bit length 18, type 0x04, flags 0, stream 0. Handing
        // these nine bytes to HTTP/2 is the whole point — consuming them would
        // leave the parser one header short forever.
        let header = [0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = EarlyReader::new();
        assert_eq!(reader.push(&header).unwrap(), PROBE_LEN);
        assert_eq!(reader.finish(), Ok(Early::PushBack(&header)));
    }

    #[test]
    fn a_probe_that_only_partly_matches_the_magic_is_pushed_back() {
        let mut header = [0u8; PROBE_LEN];
        header[..4].copy_from_slice(&MAGIC[..4]);
        header[4] = b'X';
        let mut reader = EarlyReader::new();
        reader.push(&header).unwrap();
        assert_eq!(reader.finish(), Ok(Early::PushBack(&header)));
    }

    #[test]
    fn push_reports_what_it_consumed_so_the_rest_reaches_http2() {
        let (probe, payload) = captured_shape();
        let mut stream = [0u8; PROBE_LEN + 200];
        stream[..PROBE_LEN].copy_from_slice(&probe);
        stream[PROBE_LEN..PROBE_LEN + payload.len()].copy_from_slice(payload);
        // Whatever follows the payload is HTTP/2 and must be left alone.
        let total = PROBE_LEN + payload.len();
        stream[total..total + 9].copy_from_slice(&[0, 0, 0x12, 4, 0, 0, 0, 0, 0]);

        let mut reader = EarlyReader::new();
        let consumed = reader.push(&stream[..total + 9]).unwrap();
        assert_eq!(consumed, total, "the HTTP/2 frame must not be swallowed");
        assert_eq!(reader.finish(), Ok(Early::Payload(payload)));
    }

    #[test]
    fn a_length_larger_than_the_bound_is_refused() {
        let mut probe = [0u8; PROBE_LEN];
        probe[..5].copy_from_slice(&MAGIC);
        probe[5..].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        let mut reader = EarlyReader::new();
        assert_eq!(reader.push(&probe), Err(Error::RecordTooLong));
    }
}
