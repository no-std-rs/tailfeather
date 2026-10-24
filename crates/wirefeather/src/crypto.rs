//! The primitives WireGuard is built from, wrapped in the exact shapes the
//! protocol uses them in.
//!
//! Nothing here is a novel construction: BLAKE2s, HMAC, HKDF-style expansion,
//! ChaCha20-Poly1305 and X25519 all come from published, audited crates. The
//! value this module adds is naming them the way the WireGuard paper does, so
//! [`crate::noise`] reads like the specification.

use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{Digest, Mac};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::Error;

#[cfg(all(
    feature = "accelerated-crypto",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(target_family = "unix", target_family = "windows")
))]
mod native;
#[cfg(any(
    test,
    not(all(
        feature = "accelerated-crypto",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(target_family = "unix", target_family = "windows")
    ))
))]
mod portable;
#[cfg(all(
    feature = "accelerated-crypto",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(target_family = "unix", target_family = "windows")
))]
use native as aead_backend;
#[cfg(not(all(
    feature = "accelerated-crypto",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(target_family = "unix", target_family = "windows")
)))]
use portable as aead_backend;

/// The configured AEAD provider. Providers dispatch supported SIMD at runtime.
pub fn aead_backend() -> &'static str {
    aead_backend::NAME
}

/// A 32-byte symmetric key, chaining key, or hash value.
pub type Key = [u8; 32];

/// A 16-byte MAC, as used by the `mac1`/`mac2` handshake fields.
pub type Mac16 = [u8; 16];

pub const KEY_LEN: usize = 32;
pub const MAC_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const TIMESTAMP_LEN: usize = 12;

/// BLAKE2s-256 over the concatenation of `inputs`.
pub fn hash(inputs: &[&[u8]]) -> Key {
    let mut h = Blake2s256::new();
    for i in inputs {
        h.update(i);
    }
    h.finalize().into()
}

/// Keyed BLAKE2s truncated to 16 bytes — WireGuard's `MAC()`.
pub fn mac(key: &Key, inputs: &[&[u8]]) -> Mac16 {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key)
        .expect("Blake2sMac accepts any key up to 32 bytes");
    for i in inputs {
        m.update(i);
    }
    m.finalize().into_bytes().into()
}

/// HMAC-BLAKE2s-256.
///
/// Uses `SimpleHmac` rather than `Hmac` because it is generic over any `Digest`
/// without extra trait bounds. HMAC is only on the handshake path (a few calls
/// per session), never the data path, so the block-level optimisation `Hmac`
/// would add is not worth the tighter bounds.
fn hmac(key: &[u8], inputs: &[&[u8]]) -> Key {
    let mut m = <hmac::SimpleHmac<Blake2s256> as Mac>::new_from_slice(key)
        .expect("SimpleHmac accepts keys of any length");
    for i in inputs {
        m.update(i);
    }
    m.finalize().into_bytes().into()
}

/// The HKDF-style expansion the WireGuard paper writes as `KDF_n`.
///
/// `τ₀ = HMAC(chaining_key, input)`, then `τᵢ = HMAC(τ₀, τᵢ₋₁ ‖ i)` with
/// `τ₀`'s successor seeded by the single byte `0x1`.
fn kdf<const N: usize>(chaining_key: &Key, input: &[u8]) -> [Key; N] {
    let t0 = hmac(chaining_key, &[input]);
    let mut out = [[0u8; KEY_LEN]; N];
    let mut prev = [0u8; KEY_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let counter = [(i + 1) as u8];
        *slot = if i == 0 {
            hmac(&t0, &[&counter])
        } else {
            hmac(&t0, &[&prev, &counter])
        };
        prev = *slot;
    }
    out
}

pub fn kdf1(chaining_key: &Key, input: &[u8]) -> Key {
    let [a] = kdf::<1>(chaining_key, input);
    a
}

pub fn kdf2(chaining_key: &Key, input: &[u8]) -> (Key, Key) {
    let [a, b] = kdf::<2>(chaining_key, input);
    (a, b)
}

pub fn kdf3(chaining_key: &Key, input: &[u8]) -> (Key, Key, Key) {
    let [a, b, c] = kdf::<3>(chaining_key, input);
    (a, b, c)
}

/// X25519, rejecting the all-zero output.
///
/// A zero shared secret means the peer sent a low-order point and controls the
/// result, which would let them force a known key. WireGuard requires this
/// check; X25519 itself does not perform it.
pub fn dh(secret: &StaticSecret, public: &PublicKey) -> Result<Key, Error> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(Error::InvalidPublicKey);
    }
    Ok(shared.to_bytes())
}

/// The AEAD nonce length ChaCha20-Poly1305 uses.
pub const NONCE_LEN: usize = 12;

/// A 96-bit AEAD nonce.
pub type Nonce = [u8; NONCE_LEN];

/// Seal `buffer` in place under an explicit nonce, returning the tag.
///
/// Protocols built on Noise all derive the nonce from a message counter, but
/// they do not agree on how. WireGuard writes the counter little-endian;
/// Tailscale's control protocol writes the same counter big-endian. Taking the
/// nonce as bytes means each protocol states its own convention at the point of
/// use, where the disagreement is visible, rather than inheriting whichever one
/// happened to be baked in here — a mistake that produces a valid-looking
/// ciphertext the peer silently rejects.
pub fn aead_seal_nonce(key: &Key, nonce: &Nonce, aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
    aead_backend::seal(key, nonce, aad, buffer)
}

/// Open `buffer` in place under an explicit nonce, verifying `tag`.
/// Authentication failure clears the buffer on every backend.
pub fn aead_open_nonce(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    if tag.len() != TAG_LEN {
        return Err(Error::Malformed);
    }
    let result = aead_backend::open(key, nonce, aad, buffer, tag);
    if result.is_err() {
        buffer.zeroize();
    }
    result
}

/// WireGuard's AEAD nonce: 4 zero bytes followed by a 64-bit little-endian
/// counter.
pub fn nonce_le(counter: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Seal `buffer` in place under WireGuard's nonce convention.
pub fn aead_seal(key: &Key, counter: u64, aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
    aead_seal_nonce(key, &nonce_le(counter), aad, buffer)
}

/// Open `buffer` in place under WireGuard's nonce convention.
pub fn aead_open(
    key: &Key,
    counter: u64,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    aead_open_nonce(key, &nonce_le(counter), aad, buffer, tag)
}

/// Constant-time equality, for comparing MACs and other attacker-supplied
/// values against expected ones.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two byte orders must not be interchangeable, or the bug this API
    /// exists to prevent would be invisible.
    ///
    /// WireGuard puts the counter in the low bytes; Tailscale's control
    /// protocol puts it in the high bytes of the same twelve. For counter 1
    /// they differ, and a ciphertext sealed under one cannot be opened under the
    /// other — which is what the second half of this test checks, because that
    /// is the failure a caller would actually see.
    #[test]
    fn the_two_nonce_conventions_disagree() {
        let mut big_endian = [0u8; NONCE_LEN];
        big_endian[4..].copy_from_slice(&1u64.to_be_bytes());
        let little_endian = nonce_le(1);

        assert_ne!(big_endian, little_endian);
        assert_eq!(little_endian, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(big_endian, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let key = [0x5a; KEY_LEN];
        let mut buffer = *b"sixteen bytes...";
        let tag = aead_seal_nonce(&key, &big_endian, &[], &mut buffer);
        let ciphertext = buffer;
        assert_eq!(
            aead_open_nonce(&key, &little_endian, &[], &mut buffer, &tag),
            Err(Error::Decryption)
        );
        assert!(buffer.iter().all(|byte| *byte == 0));
        buffer = ciphertext;
        assert_eq!(
            aead_open_nonce(&key, &big_endian, &[], &mut buffer, &tag),
            Ok(())
        );
        assert_eq!(&buffer, b"sixteen bytes...");
    }

    /// Counter zero is the one value where the two agree, which is why a
    /// handshake built on the wrong convention still passes its first message
    /// and fails on the second.
    #[test]
    fn counter_zero_hides_the_difference() {
        let mut big_endian = [0u8; NONCE_LEN];
        big_endian[4..].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(big_endian, nonce_le(0));
    }
}
