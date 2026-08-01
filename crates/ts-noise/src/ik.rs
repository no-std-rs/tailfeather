//! The Noise IK handshake, client side.
//!
//! # How this differs from WireGuard's
//!
//! Both are Noise with X25519, ChaCha20-Poly1305 and BLAKE2s, and this crate
//! reuses `wg_core::crypto` for every primitive. Four things differ, and each
//! one fails silently at the same place — the response tag — with nothing in the
//! message to say which:
//!
//! 1. **IK, not IKpsk2.** No pre-shared key. In particular the `e` token here
//!    only mixes into the *hash*. WireGuard additionally mixes it into the
//!    chaining key, which is what PSK modes require and plain IK does not, so
//!    carrying that habit across is the easiest mistake to make.
//! 2. **A prologue.** `Tailscale Control Protocol v131` is mixed in before the
//!    responder's static key, binding the version to the handshake so the
//!    plaintext version field at the front of the message cannot be downgraded.
//! 3. **An empty sealed payload in each message.** Noise encrypts the payload of
//!    every handshake message, empty or not, so both messages end in a 16-byte
//!    tag that carries nothing. Omitting it makes the initiation 85 bytes; the
//!    capture shows 101.
//! 4. **No MACs.** ts2021 runs over TCP and has no cookie mechanism, so
//!    WireGuard's `mac1`/`mac2` fields do not exist.
//!
//! ```text
//! -> e, es, s, ss
//! <- e, ee, se
//! ```

use wg_core::crypto::{self, Key, TAG_LEN};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{CAPABILITY_VERSION, Error};

/// `Noise_IK_25519_ChaChaPoly_BLAKE2s` — 33 bytes, one past the boundary at
/// which Noise switches from zero-padding the name to hashing it, so the initial
/// hash is `BLAKE2s(name)`.
const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The prologue is this prefix followed by the capability version in decimal.
const PROLOGUE_PREFIX: &[u8] = b"Tailscale Control Protocol v";

/// The prefix plus at most five digits of `u16`.
const PROLOGUE_MAX: usize = 28 + 5;

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;

/// `2B version BE ‖ 1B type ‖ 2B length BE ‖ 32B e ‖ 48B sealed static ‖ 16B tag`.
///
/// The capture shows a real client sending exactly this: 101 bytes, version 131,
/// type 1, declared length 96 — and 5 + 96 is 101, so the wire's own length field
/// corroborates this constant rather than merely being consistent with it.
///
/// Note where those bytes travel. The initiation is **not** sent on the TCP
/// stream: it rides base64-encoded in the `X-Tailscale-Handshake` header of the
/// `POST /ts2021` request, and the first byte after that request's blank line is
/// already the client's first record. `ts-conformance`'s `pcap_replay` test
/// reads it back out of the header and checks all of this against the capture.
pub const INITIATION_LEN: usize = 5 + 32 + (32 + TAG_LEN) + TAG_LEN;

/// `1B type ‖ 2B length BE ‖ 32B e ‖ 16B tag`.
///
/// Note the asymmetry: the response carries **no** version field. The capture
/// shows the server replying with 51 bytes beginning `02 00 30`. Assuming the
/// two messages share a header shape puts every field two bytes out.
pub const RESPONSE_LEN: usize = 3 + 32 + TAG_LEN;

const INITIATION_BODY_LEN: u16 = (INITIATION_LEN - 5) as u16;
const RESPONSE_BODY_LEN: u16 = (RESPONSE_LEN - 3) as u16;

/// Every handshake message is sealed under nonce zero, so the endianness of the
/// counter does not arise until the record layer — where it does, and differs
/// from WireGuard. See [`crate::record`].
const HANDSHAKE_NONCE: crypto::Nonce = [0u8; crypto::NONCE_LEN];

/// Build the prologue for a capability version.
///
/// The version is written in decimal, matching upstream's `strconv.AppendUint`.
/// Zero-padding it or writing it in hex changes the chaining key.
fn prologue(version: u16, out: &mut [u8; PROLOGUE_MAX]) -> &[u8] {
    out[..PROLOGUE_PREFIX.len()].copy_from_slice(PROLOGUE_PREFIX);
    let mut len = PROLOGUE_PREFIX.len();

    let mut digits = [0u8; 5];
    let mut count = 0;
    let mut value = version;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for i in 0..count {
        out[len] = digits[count - 1 - i];
        len += 1;
    }
    &out[..len]
}

/// Client state between sending the initiation and receiving the response.
pub struct Handshake {
    /// Needed for the `se` mix, which happens only once the server's ephemeral
    /// key has arrived.
    machine_private: StaticSecret,
    ephemeral: StaticSecret,
    chaining_key: Zeroizing<Key>,
    hash: Key,
}

/// Write an initiation into `out`.
///
/// `machine_private` is this node's *machine* key. The control plane
/// authenticates the machine; the node key is data-plane identity and never
/// appears in this handshake.
///
/// `ephemeral_private` must be freshly random and never reused.
pub fn initiate(
    machine_private: &StaticSecret,
    server_public: &PublicKey,
    ephemeral_private: &StaticSecret,
    out: &mut [u8],
) -> Result<(usize, Handshake), Error> {
    let out = out
        .get_mut(..INITIATION_LEN)
        .ok_or(Error::BufferTooSmall)?;

    // h = HASH(protocol_name); ck = h. Then the prologue, then the responder's
    // static key, in that order — swapping the last two produces a handshake the
    // server rejects with no diagnostic.
    let mut chaining_key = Zeroizing::new(crypto::hash(&[PROTOCOL_NAME]));
    let mut hash = *chaining_key;

    let mut prologue_buffer = [0u8; PROLOGUE_MAX];
    hash = crypto::hash(&[&hash, prologue(CAPABILITY_VERSION, &mut prologue_buffer)]);
    hash = crypto::hash(&[&hash, server_public.as_bytes()]);

    out[..2].copy_from_slice(&CAPABILITY_VERSION.to_be_bytes());
    out[2] = TYPE_INITIATION;
    out[3..5].copy_from_slice(&INITIATION_BODY_LEN.to_be_bytes());

    // -> e. Hash only: plain IK does not mix the ephemeral into the chaining
    // key, unlike the PSK mode WireGuard uses.
    let ephemeral_public = PublicKey::from(ephemeral_private);
    out[5..37].copy_from_slice(ephemeral_public.as_bytes());
    hash = crypto::hash(&[&hash, ephemeral_public.as_bytes()]);

    // es, sealing our own static key — this is what makes IK identity-hiding.
    let (ck, key) = crypto::kdf2(
        &chaining_key,
        &crypto::dh(ephemeral_private, server_public).map_err(|_| Error::InvalidPublicKey)?,
    );
    *chaining_key = ck;
    let machine_public = PublicKey::from(machine_private);
    out[37..69].copy_from_slice(machine_public.as_bytes());
    let tag = crypto::aead_seal_nonce(&key, &HANDSHAKE_NONCE, &hash, &mut out[37..69]);
    out[69..85].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[37..85]]);

    // ss, then the payload — which is empty, but Noise seals it anyway, and the
    // resulting tag is the last 16 bytes of the message.
    let (ck, key) = crypto::kdf2(
        &chaining_key,
        &crypto::dh(machine_private, server_public).map_err(|_| Error::InvalidPublicKey)?,
    );
    *chaining_key = ck;
    let tag = crypto::aead_seal_nonce(&key, &HANDSHAKE_NONCE, &hash, &mut []);
    out[85..101].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[85..101]]);

    Ok((
        INITIATION_LEN,
        Handshake {
            machine_private: machine_private.clone(),
            ephemeral: ephemeral_private.clone(),
            chaining_key,
            hash,
        },
    ))
}

impl Handshake {
    /// Verify the server's response and derive the record-layer keys.
    ///
    /// [`Error::Decryption`] here almost always means one of the inputs to the
    /// hash was wrong — the server's key, the prologue, or the order things were
    /// mixed in — rather than that the bytes were corrupted in transit.
    pub fn consume_response(self, msg: &[u8]) -> Result<crate::Session, Error> {
        if msg.len() != RESPONSE_LEN || msg[0] != TYPE_RESPONSE {
            return Err(Error::Malformed);
        }
        if u16::from_be_bytes([msg[1], msg[2]]) != RESPONSE_BODY_LEN {
            return Err(Error::Malformed);
        }

        let mut chaining_key = self.chaining_key;
        let mut hash = self.hash;

        let mut peer_ephemeral = [0u8; 32];
        peer_ephemeral.copy_from_slice(&msg[3..35]);
        let peer_ephemeral = PublicKey::from(peer_ephemeral);
        hash = crypto::hash(&[&hash, peer_ephemeral.as_bytes()]);

        // ee. The key this yields is discarded: nothing is encrypted between
        // here and the next mix.
        let (ck, _) = crypto::kdf2(
            &chaining_key,
            &crypto::dh(&self.ephemeral, &peer_ephemeral).map_err(|_| Error::InvalidPublicKey)?,
        );
        *chaining_key = ck;

        // se: our static against their ephemeral. This key does the work.
        let (ck, key) = crypto::kdf2(
            &chaining_key,
            &crypto::dh(&self.machine_private, &peer_ephemeral)
                .map_err(|_| Error::InvalidPublicKey)?,
        );
        *chaining_key = ck;

        // The empty payload's tag is the server's proof it derived the same
        // keys we did.
        crypto::aead_open_nonce(&key, &HANDSHAKE_NONCE, &hash, &mut [], &msg[35..51])
            .map_err(|_| Error::Decryption)?;

        // Split. The initiator sends under the first key and receives under the
        // second; the server does the mirror image.
        let (tx, rx) = crypto::kdf2(&chaining_key, &[]);
        Ok(crate::Session::new(tx, rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prologue_matches_what_the_capture_shows() {
        let mut buffer = [0u8; PROLOGUE_MAX];
        assert_eq!(prologue(131, &mut buffer), b"Tailscale Control Protocol v131");
        // Decimal, neither zero-padded nor hexadecimal.
        assert_eq!(prologue(1, &mut buffer), b"Tailscale Control Protocol v1");
        assert_eq!(
            prologue(65535, &mut buffer),
            b"Tailscale Control Protocol v65535"
        );
    }

    #[test]
    fn the_protocol_name_is_the_length_that_forces_hashing() {
        // Noise pads a name of 32 bytes or fewer into the initial hash and
        // hashes anything longer. At 33 this is hashed, by one byte.
        assert_eq!(PROTOCOL_NAME.len(), 33);
    }

    #[test]
    fn the_message_lengths_match_the_capture() {
        // A real tailscaled sent 101 bytes; a real Headscale replied with 51.
        assert_eq!(INITIATION_LEN, 101);
        assert_eq!(RESPONSE_LEN, 51);
        assert_eq!(INITIATION_BODY_LEN, 96);
        assert_eq!(RESPONSE_BODY_LEN, 48);
    }

    #[test]
    fn an_initiation_has_the_header_the_capture_shows() {
        let machine = StaticSecret::from([0x11; 32]);
        let server = PublicKey::from([0x22; 32]);
        let ephemeral = StaticSecret::from([0x33; 32]);
        let mut out = [0u8; 256];
        let (len, _) = initiate(&machine, &server, &ephemeral, &mut out).unwrap();

        assert_eq!(len, 101);
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), 131);
        assert_eq!(out[2], TYPE_INITIATION);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]), 96);
        // The ephemeral public key is in the clear; the static key is not.
        assert_eq!(&out[5..37], PublicKey::from(&ephemeral).as_bytes());
        assert_ne!(&out[37..69], PublicKey::from(&machine).as_bytes());
    }

    #[test]
    fn a_response_of_the_wrong_shape_is_rejected_before_any_crypto() {
        let machine = StaticSecret::from([0x11; 32]);
        let server = PublicKey::from([0x22; 32]);
        let ephemeral = StaticSecret::from([0x33; 32]);
        let mut out = [0u8; 256];

        let (_, handshake) = initiate(&machine, &server, &ephemeral, &mut out).unwrap();
        assert_eq!(
            handshake.consume_response(&[2, 0, 48]).err(),
            Some(Error::Malformed)
        );

        let (_, handshake) = initiate(&machine, &server, &ephemeral, &mut out).unwrap();
        let mut response = [0u8; RESPONSE_LEN];
        response[0] = TYPE_INITIATION; // wrong type
        response[1..3].copy_from_slice(&RESPONSE_BODY_LEN.to_be_bytes());
        assert_eq!(
            handshake.consume_response(&response).err(),
            Some(Error::Malformed)
        );

        // An all-zero ephemeral is a low-order point, which Diffie-Hellman must
        // refuse before the tag is ever reached: it would let the sender fix the
        // shared secret to a known value.
        let (_, handshake) = initiate(&machine, &server, &ephemeral, &mut out).unwrap();
        response[0] = TYPE_RESPONSE;
        assert_eq!(
            handshake.consume_response(&response).err(),
            Some(Error::InvalidPublicKey)
        );

        // Right type, right length, a usable ephemeral — but nobody sealed it.
        let (_, handshake) = initiate(&machine, &server, &ephemeral, &mut out).unwrap();
        response[3..35].copy_from_slice(PublicKey::from(&StaticSecret::from([0x44; 32])).as_bytes());
        assert_eq!(
            handshake.consume_response(&response).err(),
            Some(Error::Decryption)
        );
    }
}
