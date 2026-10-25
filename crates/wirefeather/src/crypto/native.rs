//! Reuse ring's fused CPU-dispatched implementation without heap allocation.
use super::{Error, Key, Nonce, TAG_LEN};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce as RingNonce, Tag, UnboundKey};

pub(super) const NAME: &str = "ring";
fn cipher(key: &Key) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte ChaCha20 key"))
}

pub(super) fn seal(key: &Key, nonce: &Nonce, aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
    let tag = cipher(key)
        .seal_in_place_separate_tag(
            RingNonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            buffer,
        )
        .expect("in-range ChaCha20-Poly1305 plaintext");
    tag.as_ref().try_into().expect("16-byte AEAD tag")
}

pub(super) fn open(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag = Tag::from(<[u8; TAG_LEN]>::try_from(tag).map_err(|_| Error::Malformed)?);
    cipher(key)
        .open_in_place_separate_tag(
            RingNonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            tag,
            buffer,
            0..,
        )
        .map(|_| ())
        .map_err(|_| Error::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::portable;

    #[test]
    fn accelerated_and_portable_aead_match_and_reject_corruption() {
        for length in [
            0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1280, 1536, 4096,
        ] {
            for counter in [0, 1, u32::MAX as u64, u64::MAX] {
                for aad in [b"".as_slice(), b"associated data".as_slice()] {
                    let key = [0x5a; 32];
                    let mut nonce = crate::crypto::nonce_le(counter);
                    for big_endian in [false, true] {
                        if big_endian {
                            nonce[4..].copy_from_slice(&counter.to_be_bytes());
                        }
                        let mut a = [0x42; 4096];
                        let mut b = a;
                        let tag_a = seal(&key, &nonce, aad, &mut a[..length]);
                        let tag_b = portable::seal(&key, &nonce, aad, &mut b[..length]);
                        assert_eq!(tag_a, tag_b);
                        assert_eq!(&a[..length], &b[..length]);
                        open(&key, &nonce, aad, &mut b[..length], &tag_b).unwrap();
                        portable::open(&key, &nonce, aad, &mut a[..length], &tag_a).unwrap();
                        assert!(a[..length].iter().all(|byte| *byte == 0x42));
                        assert_eq!(&a[..length], &b[..length]);
                        let mut corrupted = tag_a;
                        corrupted[0] ^= 1;
                        let mut encrypted = [0x42; 4096];
                        seal(&key, &nonce, aad, &mut encrypted[..length]);
                        assert_eq!(
                            open(&key, &nonce, aad, &mut encrypted[..length], &corrupted),
                            Err(Error::Decryption)
                        );
                    }
                }
            }
        }
    }
}
