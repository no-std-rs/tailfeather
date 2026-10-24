use super::{Error, Key, Nonce, TAG_LEN};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag, aead::AeadInPlace};

#[cfg_attr(test, allow(dead_code))]
pub(super) const NAME: &str = "rustcrypto";

pub(super) fn seal(key: &Key, nonce: &Nonce, aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .encrypt_in_place_detached(nonce.into(), aad, buffer)
        .expect("in-place detached sealing cannot fail for an in-range buffer")
        .into()
}

pub(super) fn open(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    let tag = Tag::from(<[u8; TAG_LEN]>::try_from(tag).map_err(|_| Error::Malformed)?);
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, buffer, &tag)
        .map_err(|_| Error::Decryption)
}
