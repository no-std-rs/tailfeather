//! The outer packet: magic, sender key, and a NaCl box.
//!
//! ```text
//! TS💬                       6 bytes of magic
//! sender disco public key   32 bytes, in the clear
//! nonce                     24 bytes, random per message
//! sealed message            16-byte Poly1305 tag, then the ciphertext
//! ```
//!
//! The sender's key travels unencrypted because the receiver needs it to
//! *derive* the shared secret that opens the box — it is the one thing that
//! cannot be inside. That also means a receiver learns which peer a message
//! claims to be from before authenticating it, and must treat the claim as
//! unverified until the box opens.

use crate::keys::{DiscoPrivate, DiscoPublic};
use crypto_box::aead::AeadInPlace;
use crypto_box::{PublicKey, SalsaBox, SecretKey};

use crate::disco::{Error, HEADER_LEN, MAGIC, NONCE_LEN, TAG_LEN};

/// Big enough for any disco message plus its framing. A `CallMeMaybe` with the
/// maximum endpoints is the largest at 290 bytes of payload.
pub const MAX_PACKET: usize = 512;

/// A source of random bytes for the nonce.
///
/// A repeated nonce under the same key is fatal for a stream cipher, so this is
/// not somewhere a counter will do: two nodes independently sealing to the same
/// peer would collide.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

fn shared(ours: &DiscoPrivate, theirs: &DiscoPublic) -> SalsaBox {
    let secret = SecretKey::from_bytes(ours.to_bytes());
    let public = PublicKey::from_bytes(*theirs.as_bytes());
    SalsaBox::new(&public, &secret)
}

/// Seal `plaintext` for `recipient`, writing a complete packet into `out`.
pub fn seal(
    ours: &DiscoPrivate,
    our_public: &DiscoPublic,
    recipient: &DiscoPublic,
    plaintext: &[u8],
    rng: &mut impl Rng,
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = HEADER_LEN + plaintext.len() + TAG_LEN;
    let out = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;

    out[..MAGIC.len()].copy_from_slice(&MAGIC);
    out[MAGIC.len()..MAGIC.len() + 32].copy_from_slice(our_public.as_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    out[MAGIC.len() + 32..HEADER_LEN].copy_from_slice(&nonce);

    // NaCl's layout is tag *then* ciphertext, not ciphertext then tag. Every
    // other AEAD in this project appends its tag, so this is the one place the
    // habit is wrong — and a round-trip test between two copies of this code
    // cannot tell, because both halves would be wrong together. A real
    // tailscaled reports it as "failed to open naclbox (wrong rcpt?)".
    let body = &mut out[HEADER_LEN + TAG_LEN..total];
    body.copy_from_slice(plaintext);
    let tag = shared(ours, recipient)
        .encrypt_in_place_detached(&nonce.into(), &[], body)
        .map_err(|_| Error::Decryption)?;
    out[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&tag);
    Ok(total)
}

/// What opening a packet yields: who sent it, and what they said.
pub struct Opened {
    /// The sender's disco key, now verified — the box opening is the proof.
    pub sender: DiscoPublic,
    /// How many bytes of `out` hold the plaintext.
    pub len: usize,
}

/// Open a packet addressed to us.
///
/// `expected_sender` is the disco key the netmap says a peer has. Passing it
/// means the box only opens if the packet really came from that peer, which is
/// what makes a disco message unforgeable; passing the key from the packet
/// itself would authenticate nothing.
pub fn open(
    ours: &DiscoPrivate,
    expected_sender: &DiscoPublic,
    packet: &[u8],
    out: &mut [u8],
) -> Result<Opened, Error> {
    let sender = sender_key(packet)?;
    // The claimed sender is not the authenticated one. Checking it here turns
    // "the box did not open" into a clear mismatch, and avoids doing the
    // Diffie-Hellman for a packet that names someone else entirely.
    if sender != *expected_sender {
        return Err(Error::Decryption);
    }

    let sealed = packet.get(HEADER_LEN..).ok_or(Error::Malformed)?;
    let len = sealed.len().checked_sub(TAG_LEN).ok_or(Error::Malformed)?;
    let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&packet[MAGIC.len() + 32..HEADER_LEN]);

    // Tag first, then ciphertext — see `seal`.
    let (tag, ciphertext) = sealed.split_at(TAG_LEN);
    out.copy_from_slice(ciphertext);
    shared(ours, &sender)
        .decrypt_in_place_detached(&nonce.into(), &[], out, tag.into())
        .map_err(|_| Error::Decryption)?;

    Ok(Opened { sender, len })
}

/// The disco key a packet claims to be from.
///
/// Unverified until the box opens, and named that way so a caller cannot mistake
/// it for identity. It is what lets a receiver look up which peer to expect.
pub fn sender_key(packet: &[u8]) -> Result<DiscoPublic, Error> {
    if !packet.starts_with(&MAGIC) || packet.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Malformed);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&packet[MAGIC.len()..MAGIC.len() + 32]);
    Ok(DiscoPublic::from_bytes(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disco::message::{Message, Ping};

    struct Counter(u8);

    impl Rng for Counter {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn keys() -> (DiscoPrivate, DiscoPublic, DiscoPrivate, DiscoPublic) {
        let ours = DiscoPrivate::from_bytes([0x11; 32]);
        let theirs = DiscoPrivate::from_bytes([0x22; 32]);
        let (a, b) = (ours.public(), theirs.public());
        (ours, a, theirs, b)
    }

    #[test]
    fn a_message_round_trips_between_two_nodes() {
        let (ours, our_public, theirs, their_public) = keys();
        let ping = Message::Ping(Ping {
            tx_id: *b"0123456789ab",
            node_key: None,
        });

        let mut plaintext = [0u8; 64];
        let len = ping.encode(&mut plaintext).unwrap();

        let mut packet = [0u8; MAX_PACKET];
        let total = seal(
            &ours,
            &our_public,
            &their_public,
            &plaintext[..len],
            &mut Counter(1),
            &mut packet,
        )
        .unwrap();

        // The framing a receiver demultiplexes on.
        assert!(crate::disco::is_disco(&packet[..total]));
        assert_eq!(&packet[6..38], our_public.as_bytes());
        assert_eq!(total, HEADER_LEN + len + TAG_LEN);

        let mut opened = [0u8; 64];
        let result = open(&theirs, &our_public, &packet[..total], &mut opened).unwrap();
        assert_eq!(result.sender, our_public);
        assert_eq!(Message::decode(&opened[..result.len]).unwrap(), ping);
    }

    #[test]
    fn a_packet_from_someone_else_does_not_open() {
        // The check that makes disco unforgeable: a packet is only accepted if
        // it came from the key the netmap says the peer has.
        let (ours, our_public, theirs, their_public) = keys();
        let stranger = DiscoPrivate::from_bytes([0x99; 32]);

        let mut packet = [0u8; MAX_PACKET];
        let total = seal(
            &stranger,
            &stranger.public(),
            &their_public,
            b"hello",
            &mut Counter(1),
            &mut packet,
        )
        .unwrap();

        let mut opened = [0u8; 64];
        assert_eq!(
            open(&theirs, &our_public, &packet[..total], &mut opened).err(),
            Some(Error::Decryption),
            "a packet naming a different sender must be refused"
        );
        // And it does open when the expectation matches who really sent it.
        assert!(open(&theirs, &stranger.public(), &packet[..total], &mut opened).is_ok());
        let _ = ours;
    }

    #[test]
    fn a_tampered_packet_does_not_open() {
        let (ours, our_public, theirs, their_public) = keys();
        let mut packet = [0u8; MAX_PACKET];
        let total = seal(
            &ours,
            &our_public,
            &their_public,
            b"hello",
            &mut Counter(1),
            &mut packet,
        )
        .unwrap();

        // Flip a byte of the ciphertext, which now begins after the tag.
        packet[HEADER_LEN + TAG_LEN] ^= 0x01;
        let mut opened = [0u8; 64];
        assert_eq!(
            open(&theirs, &our_public, &packet[..total], &mut opened).err(),
            Some(Error::Decryption)
        );
    }

    #[test]
    fn the_nonce_is_not_reused_between_messages() {
        // A repeated nonce under the same key discloses the plaintext, so this
        // is not somewhere a counter shared between peers would do.
        let (ours, our_public, _, their_public) = keys();
        let mut rng = Counter(1);
        let mut first = [0u8; MAX_PACKET];
        let mut second = [0u8; MAX_PACKET];
        seal(
            &ours,
            &our_public,
            &their_public,
            b"x",
            &mut rng,
            &mut first,
        )
        .unwrap();
        seal(
            &ours,
            &our_public,
            &their_public,
            b"x",
            &mut rng,
            &mut second,
        )
        .unwrap();
        assert_ne!(
            &first[38..HEADER_LEN],
            &second[38..HEADER_LEN],
            "two messages used the same nonce"
        );
    }

    /// A `crypto_box` vector generated with libsodium, the reference NaCl
    /// implementation.
    ///
    /// This exists because a round-trip test cannot catch the mistake it pins.
    /// The first version of this module appended the Poly1305 tag, the way every
    /// other AEAD in this project does; sealing and opening with our own code
    /// agreed perfectly, and a real tailscaled answered "failed to open naclbox
    /// (wrong rcpt?)". NaCl puts the tag *first*. Only bytes from another
    /// implementation can tell the two apart.
    #[test]
    fn the_box_matches_libsodiums_output() {
        // Alice's secret and Bob's public key from NaCl's own documentation.
        let secret = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let recipient = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let message = hex32("be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc");
        let expected_tag =
            hex32("864d070c8064de5d20473088418481970000000000000000000000000000000f");
        let expected_ciphertext =
            hex32("8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a");

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(
            &hex32("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b370000000000000000")[..NONCE_LEN],
        );

        /// Hands back NaCl's fixed nonce, so the output is comparable with the
        /// published one.
        struct Fixed([u8; NONCE_LEN]);
        impl Rng for Fixed {
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.copy_from_slice(&self.0);
            }
        }

        let ours = DiscoPrivate::from_bytes(secret);
        // The secret really is Alice's: libsodium derives this public key.
        assert_eq!(
            ours.public().as_bytes(),
            &hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );

        let mut packet = [0u8; MAX_PACKET];
        let total = seal(
            &ours,
            &ours.public(),
            &DiscoPublic::from_bytes(recipient),
            &message,
            &mut Fixed(nonce),
            &mut packet,
        )
        .unwrap();

        assert_eq!(&packet[MAGIC.len() + 32..HEADER_LEN], &nonce);
        // Tag first...
        assert_eq!(
            &packet[HEADER_LEN..HEADER_LEN + TAG_LEN],
            &expected_tag[..TAG_LEN],
            "the Poly1305 tag must come before the ciphertext"
        );
        // ...then the ciphertext.
        assert_eq!(&packet[HEADER_LEN + TAG_LEN..total], &expected_ciphertext);
    }

    fn hex32(text: &str) -> [u8; 32] {
        let bytes = text.as_bytes();
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
            *slot = hi << 4 | lo;
        }
        out
    }

    #[test]
    fn packets_too_short_to_be_disco_are_refused() {
        assert_eq!(sender_key(&[]), Err(Error::Malformed));
        assert_eq!(sender_key(&MAGIC), Err(Error::Malformed));
        // Magic and a key, but no room for a nonce and a tag.
        let mut almost = [0u8; HEADER_LEN];
        almost[..6].copy_from_slice(&MAGIC);
        assert_eq!(sender_key(&almost), Err(Error::Malformed));
    }
}
