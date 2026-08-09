//! Type-4 transport data: sealing outbound packets and opening inbound ones.

use zeroize::Zeroizing;

use crate::Error;
use crate::budget::{PAD_TO, TAG_LEN};
use crate::crypto::{self, Key};
use crate::messages::{self, data};
use crate::noise::TransportKeys;
use crate::replay::ReplayWindow;
use crate::timers::{self, Instant, REJECT_AFTER_MESSAGES};

/// One direction-pair of keys plus the counters that keep them safe to use.
///
/// A session is bound to the handshake that produced it. It stops being usable
/// once it ages past `REJECT_AFTER_TIME_MS` or its send counter reaches
/// [`REJECT_AFTER_MESSAGES`], whichever comes first.
pub struct Session {
    /// The index we chose; the peer puts it in the packets it sends us.
    pub local_index: u32,
    /// The index the peer chose; we put it in the packets we send.
    pub peer_index: u32,
    sending: Zeroizing<Key>,
    receiving: Zeroizing<Key>,
    send_counter: u64,
    replay: ReplayWindow,
    established: Instant,
    confirmed: bool,
}

impl Session {
    pub fn new(keys: TransportKeys, local_index: u32, peer_index: u32, now: Instant) -> Self {
        Self {
            local_index,
            peer_index,
            sending: keys.sending,
            receiving: keys.receiving,
            send_counter: 0,
            replay: ReplayWindow::new(),
            established: now,
            confirmed: false,
        }
    }

    pub fn established(&self) -> Instant {
        self.established
    }

    /// Whether the peer has proved it derived the same keys we did.
    ///
    /// A responder finishes the handshake with keys it believes are correct,
    /// but has no evidence the initiator agrees until a packet arrives that
    /// opens under them. WireGuard requires waiting for that evidence before
    /// sending data, so a key mismatch fails silently rather than emitting
    /// traffic the peer cannot read.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Record that a packet from the peer opened successfully.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether this session may still be used at `now`, by age and by counter.
    pub fn is_usable(&self, now: Instant) -> bool {
        timers::session_is_alive(self.established, now) && self.send_counter < REJECT_AFTER_MESSAGES
    }

    /// Seal `packet` as a type-4 message in `out`, returning its length.
    ///
    /// An empty `packet` produces a keepalive, which is a well-formed data
    /// message whose plaintext is zero bytes long.
    pub fn seal(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // Padding hides the exact length of the inner packet from an observer,
        // who would otherwise see it directly in the datagram size.
        let padded = packet.len().next_multiple_of(PAD_TO);
        let total = data::HEADER_LEN + padded + TAG_LEN;
        let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;

        let counter = self.send_counter;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::SessionExpired);
        }
        self.send_counter += 1;

        messages::put_header(out, messages::TYPE_DATA);
        out[data::RECEIVER].copy_from_slice(&self.peer_index.to_le_bytes());
        out[data::COUNTER].copy_from_slice(&counter.to_le_bytes());

        let body = &mut out[data::HEADER_LEN..data::HEADER_LEN + padded];
        body[..packet.len()].copy_from_slice(packet);
        body[packet.len()..].fill(0);

        let tag = crypto::aead_seal(&self.sending, counter, &[], body);
        out[data::HEADER_LEN + padded..].copy_from_slice(&tag);
        Ok(total)
    }

    /// Open a type-4 message, writing the plaintext to `out` and returning its
    /// length. A length of zero means the packet was a keepalive.
    ///
    /// The replay window is only updated once the tag verifies, so a forged
    /// packet cannot burn a counter slot and cause a legitimate one to be
    /// dropped later.
    pub fn open(&mut self, datagram: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let body = datagram.get(data::HEADER_LEN..).ok_or(Error::Malformed)?;
        let ciphertext_len = body.len().checked_sub(TAG_LEN).ok_or(Error::Malformed)?;
        if ciphertext_len % PAD_TO != 0 {
            return Err(Error::Malformed);
        }
        let out = out.get_mut(..ciphertext_len).ok_or(Error::BufferTooSmall)?;

        let counter = messages::get_u64(&datagram[data::COUNTER]);
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(Error::SessionExpired);
        }

        out.copy_from_slice(&body[..ciphertext_len]);
        crypto::aead_open(&self.receiving, counter, &[], out, &body[ciphertext_len..])?;

        if !self.replay.accept(counter) {
            return Err(Error::Replay);
        }
        Ok(ciphertext_len)
    }
}
