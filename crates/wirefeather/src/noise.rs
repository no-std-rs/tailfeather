//! The Noise IKpsk2 handshake, both roles.
//!
//! The functions here follow the WireGuard paper's notation line for line.
//!
//! The responder half is split in two because the middle of the handshake is
//! where we first learn *who* is talking to us: the initiator's static public
//! key arrives encrypted, and only once it is decrypted can we look up that
//! peer's pre-shared key and finish the exchange. [`consume_initiation`] runs up
//! to that point; [`create_response`] takes it from there.
//!
//! The initiator half is split for a different reason: [`create_initiation`]
//! leaves behind a [`Handshake`] holding the ephemeral key and the chaining
//! state, which [`consume_response`] needs and which must survive the round trip
//! over the network. Both halves walk the same ladder in the same order, so a
//! mistake in one is visible as disagreement with the other.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto::{self, KEY_LEN, Key, Mac16, TAG_LEN, TIMESTAMP_LEN};
use crate::messages::{self, initiation, response};

/// The Noise protocol name, which seeds the entire key ladder.
///
/// Note the cipher is spelled `ChaChaPoly`, the short name from the Noise
/// specification, not `ChaCha20Poly1305`. WireGuard's own paper uses the long
/// spelling in prose, but every implementation hashes the short one — the Linux
/// kernel pins it as `static const u8 handshake_name[37]`, and 37 is the length
/// of this string. Getting it wrong changes the initial chaining key, so the
/// handshake fails only at the first AEAD tag check, far from the cause.
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

/// The initial chaining key: `HASH(CONSTRUCTION)`.
fn initial_chaining_key() -> Key {
    crypto::hash(&[CONSTRUCTION])
}

/// The initial hash: `HASH(HASH(CONSTRUCTION) ‖ IDENTIFIER ‖ responder_static)`.
fn initial_hash(responder_static: &PublicKey) -> Key {
    let c = initial_chaining_key();
    let h = crypto::hash(&[&c, IDENTIFIER]);
    crypto::hash(&[&h, responder_static.as_bytes()])
}

/// The key every peer uses to compute `mac1` against us: derived from our own
/// static public key, so it is not a secret — it only proves the sender knew
/// which server it was addressing.
pub fn mac1_key(responder_static: &PublicKey) -> Key {
    crypto::hash(&[LABEL_MAC1, responder_static.as_bytes()])
}

/// Everything learned from a valid handshake initiation, carried forward into
/// [`create_response`].
pub struct Initiation {
    /// The initiator's static public key, now decrypted: this identifies the
    /// peer, and hence which pre-shared key applies.
    pub peer_static: PublicKey,
    /// The initiator's ephemeral public key.
    pub peer_ephemeral: PublicKey,
    /// The initiator's session index, which our replies must echo back.
    pub peer_index: u32,
    /// The initiator's TAI64N timestamp. Callers must reject any value that is
    /// not strictly greater than the last one seen from this peer; that check
    /// needs per-peer state this function does not have.
    pub timestamp: [u8; TIMESTAMP_LEN],
    chaining_key: Zeroizing<Key>,
    hash: Key,
}

/// Check that `msg` is a well-formed initiation carrying a valid `mac1`.
///
/// Split out from [`consume_initiation`] so a caller can run it *before*
/// applying a handshake rate limit. Both checks are a length comparison and one
/// keyed hash, so they cost almost nothing, whereas the rate limiter exists to
/// protect the two X25519 operations that follow. Screening first means traffic
/// from someone who does not even know our public key cannot consume the rate
/// limit budget and lock out a legitimate peer.
///
/// `mac2` is not checked: this implementation never issues cookies, so it has
/// nothing to validate one against.
pub fn verify_initiation_mac1(mac1_key: &Key, msg: &[u8]) -> Result<(), Error> {
    if msg.len() != initiation::LEN || msg[0] != messages::TYPE_INITIATION {
        return Err(Error::Malformed);
    }
    let expected: Mac16 = crypto::mac(mac1_key, &[&msg[initiation::MAC1_INPUT]]);
    if !crypto::ct_eq(&expected, &msg[initiation::MAC1]) {
        return Err(Error::InvalidMac);
    }
    Ok(())
}

/// Verify and decrypt a type-1 handshake initiation.
///
/// `mac1` is checked before any Diffie-Hellman work, so forged packets are
/// discarded for the cost of one keyed hash rather than two X25519 operations.
pub fn consume_initiation(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    mac1_key: &Key,
    msg: &[u8],
) -> Result<Initiation, Error> {
    verify_initiation_mac1(mac1_key, msg)?;

    let mut chaining_key = Zeroizing::new(initial_chaining_key());
    let mut hash = initial_hash(static_public);

    let peer_ephemeral = {
        let mut e = [0u8; 32];
        e.copy_from_slice(&msg[initiation::EPHEMERAL]);
        PublicKey::from(e)
    };
    *chaining_key = crypto::kdf1(&chaining_key, peer_ephemeral.as_bytes());
    hash = crypto::hash(&[&hash, peer_ephemeral.as_bytes()]);

    // Decrypt the initiator's static key using our static and their ephemeral.
    let (ck, key) = crypto::kdf2(&chaining_key, &crypto::dh(static_private, &peer_ephemeral)?);
    *chaining_key = ck;
    let mut peer_static_bytes = [0u8; 32];
    let sealed_static = &msg[initiation::STATIC];
    peer_static_bytes.copy_from_slice(&sealed_static[..32]);
    crypto::aead_open(
        &key,
        0,
        &hash,
        &mut peer_static_bytes,
        &sealed_static[32..32 + TAG_LEN],
    )?;
    let peer_static = PublicKey::from(peer_static_bytes);
    hash = crypto::hash(&[&hash, sealed_static]);

    // Decrypt the timestamp using both static keys.
    let (ck, key) = crypto::kdf2(&chaining_key, &crypto::dh(static_private, &peer_static)?);
    *chaining_key = ck;
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    let sealed_timestamp = &msg[initiation::TIMESTAMP];
    timestamp.copy_from_slice(&sealed_timestamp[..TIMESTAMP_LEN]);
    crypto::aead_open(
        &key,
        0,
        &hash,
        &mut timestamp,
        &sealed_timestamp[TIMESTAMP_LEN..TIMESTAMP_LEN + TAG_LEN],
    )?;
    hash = crypto::hash(&[&hash, sealed_timestamp]);

    Ok(Initiation {
        peer_static,
        peer_ephemeral,
        peer_index: messages::get_u32(&msg[initiation::SENDER]),
        timestamp,
        chaining_key,
        hash,
    })
}

/// The two directional keys a completed handshake yields.
pub struct TransportKeys {
    /// Opens data the peer sends us.
    pub receiving: Zeroizing<Key>,
    /// Seals data we send the peer.
    pub sending: Zeroizing<Key>,
}

/// Write a type-2 handshake response into `out` and derive the session keys.
///
/// `ephemeral_private` must be freshly random and never reused; reusing it
/// across handshakes would destroy forward secrecy. `preshared_key` is all
/// zeros when the peer has no PSK configured, which is what makes IKpsk2
/// degrade cleanly to plain IK.
///
/// Returns the number of bytes written to `out`.
pub fn create_response(
    initiation: &Initiation,
    preshared_key: &Key,
    local_index: u32,
    ephemeral_private: &StaticSecret,
    out: &mut [u8],
) -> Result<(usize, TransportKeys), Error> {
    let out = out.get_mut(..response::LEN).ok_or(Error::BufferTooSmall)?;

    let mut chaining_key = Zeroizing::new(*initiation.chaining_key);
    let mut hash = initiation.hash;

    messages::put_header(out, messages::TYPE_RESPONSE);
    out[response::SENDER].copy_from_slice(&local_index.to_le_bytes());
    out[response::RECEIVER].copy_from_slice(&initiation.peer_index.to_le_bytes());

    let ephemeral_public = PublicKey::from(ephemeral_private);
    out[response::EPHEMERAL].copy_from_slice(ephemeral_public.as_bytes());
    *chaining_key = crypto::kdf1(&chaining_key, ephemeral_public.as_bytes());
    hash = crypto::hash(&[&hash, ephemeral_public.as_bytes()]);

    // Mix in both remaining Diffie-Hellman combinations.
    *chaining_key = crypto::kdf1(
        &chaining_key,
        &crypto::dh(ephemeral_private, &initiation.peer_ephemeral)?,
    );
    *chaining_key = crypto::kdf1(
        &chaining_key,
        &crypto::dh(ephemeral_private, &initiation.peer_static)?,
    );

    // Mix in the pre-shared key, which also contributes to the hash via `tau`.
    let (ck, tau, key) = crypto::kdf3(&chaining_key, preshared_key);
    *chaining_key = ck;
    hash = crypto::hash(&[&hash, &tau]);

    // Seal an empty plaintext: the tag alone proves we completed the handshake.
    let tag = crypto::aead_seal(&key, 0, &hash, &mut []);
    out[response::EMPTY].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[response::EMPTY]]);
    let _ = hash; // The response is the last message; the hash is not used again.

    let mac1_key = crypto::hash(&[LABEL_MAC1, initiation.peer_static.as_bytes()]);
    let mac1 = crypto::mac(&mac1_key, &[&out[response::MAC1_INPUT]]);
    out[response::MAC1].copy_from_slice(&mac1);
    // We never received a cookie, so mac2 is zero.
    out[response::MAC2].fill(0);

    // KDF2 yields the initiator's (sending, receiving) pair; ours is the
    // mirror image of it.
    let (initiator_sending, initiator_receiving) = crypto::kdf2(&chaining_key, &[]);
    Ok((
        response::LEN,
        TransportKeys {
            receiving: Zeroizing::new(initiator_sending),
            sending: Zeroizing::new(initiator_receiving),
        },
    ))
}

/// Initiator state carried between sending an initiation and receiving the
/// matching response.
///
/// It holds the ephemeral private key, so it is as sensitive as a session key
/// and must not outlive the handshake. Dropping it abandons the attempt, which
/// is exactly what a retry does.
pub struct Handshake {
    ephemeral: StaticSecret,
    chaining_key: Zeroizing<Key>,
    hash: Key,
    /// The session index we chose and wrote into the initiation. The responder
    /// echoes it back in the response's `receiver` field, which is how a device
    /// with several handshakes in flight knows which one a response answers.
    pub local_index: u32,
}

/// Write a type-1 handshake initiation into `out`.
///
/// `ephemeral_private` must be freshly random and never reused. `timestamp` is
/// TAI64N; the responder requires it to be strictly greater than the last one it
/// accepted from us, so a device whose clock runs backwards across a reboot
/// cannot re-handshake until it catches up. That is a property of the protocol,
/// not of this implementation.
///
/// Returns the number of bytes written along with the state
/// [`consume_response`] needs.
pub fn create_initiation(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    responder_static: &PublicKey,
    local_index: u32,
    ephemeral_private: &StaticSecret,
    timestamp: &[u8; TIMESTAMP_LEN],
    out: &mut [u8],
) -> Result<(usize, Handshake), Error> {
    let out = out
        .get_mut(..initiation::LEN)
        .ok_or(Error::BufferTooSmall)?;

    let mut chaining_key = Zeroizing::new(initial_chaining_key());
    let mut hash = initial_hash(responder_static);

    messages::put_header(out, messages::TYPE_INITIATION);
    out[initiation::SENDER].copy_from_slice(&local_index.to_le_bytes());

    let ephemeral_public = PublicKey::from(ephemeral_private);
    out[initiation::EPHEMERAL].copy_from_slice(ephemeral_public.as_bytes());
    *chaining_key = crypto::kdf1(&chaining_key, ephemeral_public.as_bytes());
    hash = crypto::hash(&[&hash, ephemeral_public.as_bytes()]);

    // Seal our static public key under a key derived from our ephemeral and
    // their static. This is what makes IK "identity hiding": an observer who
    // does not know the responder's static key cannot tell who is connecting.
    let (ck, key) = crypto::kdf2(
        &chaining_key,
        &crypto::dh(ephemeral_private, responder_static)?,
    );
    *chaining_key = ck;
    let sealed = &mut out[initiation::STATIC];
    sealed[..KEY_LEN].copy_from_slice(static_public.as_bytes());
    let tag = crypto::aead_seal(&key, 0, &hash, &mut sealed[..KEY_LEN]);
    sealed[KEY_LEN..].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[initiation::STATIC]]);

    // Seal the timestamp under a key derived from both static keys, which only
    // the intended responder can derive.
    let (ck, key) = crypto::kdf2(
        &chaining_key,
        &crypto::dh(static_private, responder_static)?,
    );
    *chaining_key = ck;
    let sealed = &mut out[initiation::TIMESTAMP];
    sealed[..TIMESTAMP_LEN].copy_from_slice(timestamp);
    let tag = crypto::aead_seal(&key, 0, &hash, &mut sealed[..TIMESTAMP_LEN]);
    sealed[TIMESTAMP_LEN..].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[initiation::TIMESTAMP]]);

    let mac1 = crypto::mac(&mac1_key(responder_static), &[&out[initiation::MAC1_INPUT]]);
    out[initiation::MAC1].copy_from_slice(&mac1);
    // We hold no cookie, so mac2 is zero. A responder that is under load enough
    // to demand one will reply with a cookie message, which this implementation
    // drops; the handshake then simply retries.
    out[initiation::MAC2].fill(0);

    Ok((
        initiation::LEN,
        Handshake {
            ephemeral: ephemeral_private.clone(),
            chaining_key,
            hash,
            local_index,
        },
    ))
}

/// Check that `msg` is a well-formed response carrying a valid `mac1`.
///
/// `mac1_key` is the one derived from *our* static public key — the responder
/// computes it over the key it is replying to. This is the mirror of
/// [`verify_initiation_mac1`] and exists for the same reason: to reject
/// forgeries before spending two X25519 operations on them.
pub fn verify_response_mac1(mac1_key: &Key, msg: &[u8]) -> Result<(), Error> {
    if msg.len() != response::LEN || msg[0] != messages::TYPE_RESPONSE {
        return Err(Error::Malformed);
    }
    let expected: Mac16 = crypto::mac(mac1_key, &[&msg[response::MAC1_INPUT]]);
    if !crypto::ct_eq(&expected, &msg[response::MAC1]) {
        return Err(Error::InvalidMac);
    }
    Ok(())
}

/// Verify a type-2 handshake response and derive the session keys.
///
/// Returns the responder's session index — which we must put in every data
/// message we send it — along with the keys. `preshared_key` must be the same
/// one the responder has configured for us; a mismatch shows up here as
/// [`Error::Decryption`], because the PSK is mixed in before the tag is checked.
pub fn consume_response(
    handshake: &Handshake,
    static_private: &StaticSecret,
    preshared_key: &Key,
    msg: &[u8],
) -> Result<(u32, TransportKeys), Error> {
    if msg.len() != response::LEN || msg[0] != messages::TYPE_RESPONSE {
        return Err(Error::Malformed);
    }
    if messages::get_u32(&msg[response::RECEIVER]) != handshake.local_index {
        // Not an answer to this handshake.
        return Err(Error::UnknownSession);
    }

    let mut chaining_key = Zeroizing::new(*handshake.chaining_key);
    let mut hash = handshake.hash;

    let peer_ephemeral = {
        let mut e = [0u8; KEY_LEN];
        e.copy_from_slice(&msg[response::EPHEMERAL]);
        PublicKey::from(e)
    };
    *chaining_key = crypto::kdf1(&chaining_key, peer_ephemeral.as_bytes());
    hash = crypto::hash(&[&hash, peer_ephemeral.as_bytes()]);

    // The same two Diffie-Hellman combinations `create_response` mixed in, in
    // the same order, from the other side.
    *chaining_key = crypto::kdf1(
        &chaining_key,
        &crypto::dh(&handshake.ephemeral, &peer_ephemeral)?,
    );
    *chaining_key = crypto::kdf1(&chaining_key, &crypto::dh(static_private, &peer_ephemeral)?);

    let (ck, tau, key) = crypto::kdf3(&chaining_key, preshared_key);
    *chaining_key = ck;
    hash = crypto::hash(&[&hash, &tau]);
    crypto::aead_open(&key, 0, &hash, &mut [], &msg[response::EMPTY])?;

    // KDF2 yields the initiator's pair directly; the responder is the one that
    // has to swap them.
    let (sending, receiving) = crypto::kdf2(&chaining_key, &[]);
    Ok((
        messages::get_u32(&msg[response::SENDER]),
        TransportKeys {
            receiving: Zeroizing::new(receiving),
            sending: Zeroizing::new(sending),
        },
    ))
}

/// Whether `candidate` is strictly newer than `last_seen`.
///
/// TAI64N is big-endian seconds followed by big-endian nanoseconds, so ordinary
/// lexicographic byte comparison is chronological order. WireGuard uses this to
/// reject replayed initiations: a peer's timestamps must strictly increase.
pub fn timestamp_is_newer(
    candidate: &[u8; TIMESTAMP_LEN],
    last_seen: &[u8; TIMESTAMP_LEN],
) -> bool {
    candidate > last_seen
}
