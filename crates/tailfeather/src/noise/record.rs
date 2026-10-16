//! The controlbase record layer: what carries HTTP/2 once the handshake is done.
//!
//! # The nonce
//!
//! This is the sharpest edge in the crate. A record's AEAD nonce is four zero
//! bytes followed by the message counter **big-endian**. WireGuard, whose
//! primitives this crate reuses, writes the same counter **little-endian**.
//!
//! The two agree at counter zero and diverge from counter one. So an
//! implementation with the wrong convention completes the handshake, exchanges
//! the first record in each direction correctly, and then fails — at a point far
//! enough from the cause to look like a framing bug or a server problem. The
//! nonce is therefore built here explicitly rather than inherited from
//! `wirefeather`'s convenience wrappers, and `wirefeather::crypto` has a test asserting
//! the two orderings are not interchangeable.
//!
//! # Framing
//!
//! `1B type ‖ 2B length BE ‖ ciphertext`. The length counts the ciphertext,
//! which includes the 16-byte tag, so the plaintext is 16 bytes shorter. The
//! capture shows the server's first records as `04 00 15`, `04 00 14`,
//! `04 00 6f` — type 4, lengths 21, 20 and 111.

use wirefeather::crypto::{self, Key};
use zeroize::Zeroizing;

use crate::noise::Error;

/// The only record type that appears after the handshake.
pub const TYPE_RECORD: u8 = 4;

/// `1B type ‖ 2B length BE`.
pub const HEADER_LEN: usize = 3;

/// The largest a whole record may be, header included.
pub const MAX_MESSAGE: usize = 4096;

/// Authentication tag appended to every encrypted record body.
pub const TAG_LEN: usize = wirefeather::crypto::TAG_LEN;

/// The largest plaintext one record can carry: the message, less the header and
/// the tag.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - HEADER_LEN - TAG_LEN;

/// The counter value at which a key must not be used again.
///
/// Upstream reserves the all-ones counter as an "invalid" marker, so the last
/// usable value is one below it. Reaching this needs 2^64 records; the check
/// exists because silently wrapping would reuse a nonce, which for a stream
/// cipher discloses the plaintext.
const MAX_COUNTER: u64 = u64::MAX - 1;

/// One direction's key and counter.
struct Cipher {
    key: Zeroizing<Key>,
    counter: u64,
}

impl Cipher {
    /// Four zero bytes, then the counter big-endian.
    ///
    /// The whole reason this is spelled out rather than delegated: see the
    /// module documentation.
    fn nonce(&self) -> crypto::Nonce {
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }

    fn advance(&mut self) -> Result<(), Error> {
        if self.counter >= MAX_COUNTER {
            return Err(Error::Exhausted);
        }
        self.counter += 1;
        Ok(())
    }
}

/// An established ts2021 connection: a record layer over the two keys the
/// handshake produced.
pub struct Session {
    tx: Cipher,
    rx: Cipher,
}

impl Session {
    pub(crate) fn new(tx: Key, rx: Key) -> Self {
        Self {
            tx: Cipher {
                key: Zeroizing::new(tx),
                counter: 0,
            },
            rx: Cipher {
                key: Zeroizing::new(rx),
                counter: 0,
            },
        }
    }

    /// Seal `plaintext` as one record in `out`, returning its total length.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::RecordTooLong);
        }
        let total = HEADER_LEN + plaintext.len() + TAG_LEN;
        let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;

        out[0] = TYPE_RECORD;
        out[1..3].copy_from_slice(&((plaintext.len() + TAG_LEN) as u16).to_be_bytes());
        out[HEADER_LEN..HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);

        // The header is not authenticated: upstream passes no additional data,
        // and the length is implicitly covered because a wrong one produces a
        // ciphertext of the wrong length whose tag then fails.
        let tag = crypto::aead_seal_nonce(
            &self.tx.key,
            &self.tx.nonce(),
            &[],
            &mut out[HEADER_LEN..HEADER_LEN + plaintext.len()],
        );
        out[HEADER_LEN + plaintext.len()..].copy_from_slice(&tag);
        self.tx.advance()?;
        Ok(total)
    }

    /// How long the ciphertext of the record beginning with `header` is.
    ///
    /// Callers read [`HEADER_LEN`] bytes, ask this, then read exactly that many
    /// more. Splitting it this way is what lets a caller with a fixed buffer
    /// refuse an over-long record before reading it.
    pub fn ciphertext_len(header: &[u8]) -> Result<usize, Error> {
        if header.len() < HEADER_LEN {
            return Err(Error::Incomplete);
        }
        if header[0] != TYPE_RECORD {
            return Err(Error::Malformed);
        }
        let len = u16::from_be_bytes([header[1], header[2]]) as usize;
        if !(TAG_LEN..=MAX_MESSAGE - HEADER_LEN).contains(&len) {
            return Err(Error::RecordTooLong);
        }
        Ok(len)
    }

    /// Open one record's ciphertext into `out`, returning the plaintext length.
    ///
    /// `ciphertext` is the body only, without the header.
    pub fn open(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let plaintext_len = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::Malformed)?;
        let out = out.get_mut(..plaintext_len).ok_or(Error::BufferTooSmall)?;

        out.copy_from_slice(&ciphertext[..plaintext_len]);
        crypto::aead_open_nonce(
            &self.rx.key,
            &self.rx.nonce(),
            &[],
            out,
            &ciphertext[plaintext_len..],
        )
        .map_err(|_| Error::Decryption)?;
        self.rx.advance()?;
        Ok(plaintext_len)
    }

    /// Open one record whose ciphertext and tag were read into separate buffers.
    pub(crate) fn open_parts(&mut self, plaintext: &mut [u8], tag: &[u8]) -> Result<usize, Error> {
        if tag.len() != TAG_LEN {
            return Err(Error::Malformed);
        }
        crypto::aead_open_nonce(&self.rx.key, &self.rx.nonce(), &[], plaintext, tag)
            .map_err(|_| Error::Decryption)?;
        self.rx.advance()?;
        Ok(plaintext.len())
    }

    /// How many records have been sent and received.
    pub fn counters(&self) -> (u64, u64) {
        (self.tx.counter, self.rx.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        // What Split produces: the client sends under the first key, the server
        // under the second, so the server's session is the mirror image.
        let a = [0x11; 32];
        let b = [0x22; 32];
        (Session::new(a, b), Session::new(b, a))
    }

    #[test]
    fn records_round_trip_in_both_directions() {
        let (mut client, mut server) = pair();
        let mut record = [0u8; MAX_MESSAGE];
        let mut plain = [0u8; MAX_MESSAGE];

        let len = client.seal(b"GET /machine/map", &mut record).unwrap();
        assert_eq!(record[0], TYPE_RECORD);
        let body = Session::ciphertext_len(&record[..HEADER_LEN]).unwrap();
        assert_eq!(len, HEADER_LEN + body);
        let n = server
            .open(&record[HEADER_LEN..HEADER_LEN + body], &mut plain)
            .unwrap();
        assert_eq!(&plain[..n], b"GET /machine/map");

        let len = server.seal(b"200 OK", &mut record).unwrap();
        let body = Session::ciphertext_len(&record[..HEADER_LEN]).unwrap();
        assert_eq!(len, HEADER_LEN + body);
        let body = &mut record[HEADER_LEN..HEADER_LEN + body];
        let (plaintext, tag) = body.split_at_mut(body.len() - TAG_LEN);
        let n = client.open_parts(plaintext, tag).unwrap();
        assert_eq!(&record[HEADER_LEN..HEADER_LEN + n], b"200 OK");
    }

    /// The regression test for the whole point of this module.
    ///
    /// A little-endian implementation passes the *first* record and fails the
    /// second, because the two conventions agree only at counter zero. So a test
    /// that sends one record proves nothing; this one sends three.
    #[test]
    fn the_counter_advances_and_a_little_endian_peer_would_diverge() {
        let (mut client, mut server) = pair();
        let mut record = [0u8; MAX_MESSAGE];
        let mut plain = [0u8; MAX_MESSAGE];

        for i in 0..3u8 {
            let payload = [i; 8];
            let len = client.seal(&payload, &mut record).unwrap();
            let n = server.open(&record[HEADER_LEN..len], &mut plain).unwrap();
            assert_eq!(&plain[..n], &payload, "record {i} did not survive");
        }
        assert_eq!(client.counters().0, 3);
        assert_eq!(server.counters().1, 3);

        // Now seal record 3 and try to open it under WireGuard's nonce, which is
        // what a peer that reused `wirefeather::aead_open` would compute.
        let len = client.seal(b"fourth", &mut record).unwrap();
        let body = &record[HEADER_LEN..len];
        let plaintext_len = body.len() - TAG_LEN;
        plain[..plaintext_len].copy_from_slice(&body[..plaintext_len]);
        assert!(
            crypto::aead_open(
                &[0x11; 32],
                3,
                &[],
                &mut plain[..plaintext_len],
                &body[plaintext_len..]
            )
            .is_err(),
            "a little-endian nonce must not open a big-endian record"
        );
    }

    #[test]
    fn an_over_long_or_mistyped_record_is_refused_before_it_is_read() {
        // Refusing on the header alone is what lets a caller with a fixed buffer
        // avoid reading a length it cannot hold.
        assert_eq!(
            Session::ciphertext_len(&[0x04, 0xff, 0xff]),
            Err(Error::RecordTooLong)
        );
        assert_eq!(
            Session::ciphertext_len(&[0x04, 0x10, 0x00]),
            Err(Error::RecordTooLong)
        );
        assert_eq!(Session::ciphertext_len(&[0x04, 0x0f, 0xfd]), Ok(4093));
        // Shorter than a tag: there is no plaintext, valid or otherwise.
        assert_eq!(
            Session::ciphertext_len(&[0x04, 0x00, 0x0f]),
            Err(Error::RecordTooLong)
        );
        assert_eq!(Session::ciphertext_len(&[0x04, 0x00, 0x10]), Ok(16));
        assert_eq!(
            Session::ciphertext_len(&[0x01, 0x00, 0x20]),
            Err(Error::Malformed)
        );
        assert_eq!(
            Session::ciphertext_len(&[0x04, 0x00]),
            Err(Error::Incomplete)
        );
    }

    #[test]
    fn a_record_larger_than_the_limit_cannot_be_sealed() {
        let (mut client, _) = pair();
        let mut out = [0u8; MAX_MESSAGE + 64];
        assert_eq!(
            client.seal(&[0u8; MAX_PLAINTEXT + 1], &mut out),
            Err(Error::RecordTooLong)
        );
        assert!(client.seal(&[0u8; MAX_PLAINTEXT], &mut out).is_ok());
    }

    #[test]
    fn a_tampered_record_does_not_advance_the_counter() {
        let (mut client, mut server) = pair();
        let mut record = [0u8; MAX_MESSAGE];
        let mut plain = [0u8; MAX_MESSAGE];

        let len = client.seal(b"authentic", &mut record).unwrap();
        record[HEADER_LEN] ^= 0x01;
        assert_eq!(
            server.open(&record[HEADER_LEN..len], &mut plain),
            Err(Error::Decryption)
        );
        // If a forgery advanced the counter, the next genuine record would be
        // opened under the wrong nonce and the connection would be dead.
        assert_eq!(server.counters().1, 0);
    }
}
