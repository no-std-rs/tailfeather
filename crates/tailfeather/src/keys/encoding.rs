//! The `prefix:hex` form the control protocol writes keys in.
//!
//! Pinned by the server rather than by documentation: `/key` publishes its own
//! machine key as `mkey:` followed by exactly 64 lowercase hex characters, and
//! `tests/vectors/server_key.json` holds a captured example. Whatever it emits
//! is what we must both parse and produce, so the conformance suite checks this
//! module against that vector rather than against our reading of the spec.

use subtle::ConstantTimeEq;

use crate::keys::KEY_LEN;

/// Bytes needed to hold the longest encoded key: `discokey:` plus 64 hex digits.
pub const MAX_ENCODED_LEN: usize = 9 + KEY_LEN * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The text did not begin with the expected `prefix:`.
    WrongPrefix,
    /// Not exactly 64 hex characters after the prefix.
    WrongLength,
    /// A character outside `[0-9a-fA-F]`.
    NotHex,
    /// The output buffer was too short.
    BufferTooSmall,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::WrongPrefix => "wrong key prefix",
            Self::WrongLength => "a key must be 64 hex characters",
            Self::NotHex => "not a hex digit",
            Self::BufferTooSmall => "output buffer too small",
        })
    }
}

impl core::error::Error for DecodeError {}

/// Parse `prefix:<64 hex chars>` into 32 bytes.
pub fn decode_prefixed(prefix: &str, text: &str) -> Result<[u8; KEY_LEN], DecodeError> {
    let rest = text
        .strip_prefix(prefix)
        .and_then(|r| r.strip_prefix(':'))
        .ok_or(DecodeError::WrongPrefix)?;
    decode_hex(rest)
}

/// Parse 64 hex characters into 32 bytes.
pub fn decode_hex(text: &str) -> Result<[u8; KEY_LEN], DecodeError> {
    let bytes = text.as_bytes();
    if bytes.len() != KEY_LEN * 2 {
        return Err(DecodeError::WrongLength);
    }
    let mut out = [0u8; KEY_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = nibble(bytes[i * 2])? << 4 | nibble(bytes[i * 2 + 1])?;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Accepted on input but never produced: being liberal in what we accept
        // costs nothing here, and a server that changed case would otherwise
        // take the whole node offline.
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DecodeError::NotHex),
    }
}

/// Write `prefix:<64 hex chars>` into `out`.
pub fn encode_prefixed<'o>(
    prefix: &str,
    key: &[u8; KEY_LEN],
    out: &'o mut [u8],
) -> Result<&'o str, DecodeError> {
    let total = prefix.len() + 1 + KEY_LEN * 2;
    let out = out.get_mut(..total).ok_or(DecodeError::BufferTooSmall)?;
    out[..prefix.len()].copy_from_slice(prefix.as_bytes());
    out[prefix.len()] = b':';
    write_hex(key, &mut out[prefix.len() + 1..]);
    Ok(core::str::from_utf8(out).expect("hex and the prefix are both ASCII"))
}

fn write_hex(bytes: &[u8], out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in bytes.iter().enumerate() {
        out[i * 2] = DIGITS[(byte >> 4) as usize];
        out[i * 2 + 1] = DIGITS[(byte & 0xf) as usize];
    }
}

/// Constant-time equality, for comparing a key against an expected one.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact string this project's Headscale published at `/key`, copied
    /// from `tests/vectors/server_key.json`. It is here so this crate's own
    /// tests are anchored to a real server's output rather than to a shape we
    /// invented.
    const CAPTURED: &str = "mkey:d7b3946fd91a9f5c1d3a18008ab5735d236373ae4c5207966e3d8d582feb2833";

    #[test]
    fn parses_a_key_a_real_server_published() {
        let key = decode_prefixed("mkey", CAPTURED).unwrap();
        assert_eq!(key[0], 0xd7);
        assert_eq!(key[31], 0x33);

        let mut out = [0u8; MAX_ENCODED_LEN];
        assert_eq!(encode_prefixed("mkey", &key, &mut out).unwrap(), CAPTURED);
    }

    #[test]
    fn rejects_the_wrong_prefix() {
        // A node key parsed as a machine key would authenticate to the control
        // plane with the data-plane identity, so this must not be lenient.
        assert_eq!(
            decode_prefixed("nodekey", CAPTURED),
            Err(DecodeError::WrongPrefix)
        );
        assert_eq!(
            decode_prefixed("mkey", "mkeyd7b3"),
            Err(DecodeError::WrongPrefix)
        );
    }

    #[test]
    fn rejects_lengths_and_characters_that_are_not_a_key() {
        assert_eq!(
            decode_prefixed("mkey", "mkey:"),
            Err(DecodeError::WrongLength)
        );
        assert_eq!(
            decode_prefixed("mkey", "mkey:00"),
            Err(DecodeError::WrongLength)
        );
        let too_long = "mkey:d7b3946fd91a9f5c1d3a18008ab5735d236373ae4c5207966e3d8d582feb283300";
        assert_eq!(
            decode_prefixed("mkey", too_long),
            Err(DecodeError::WrongLength)
        );

        let not_hex = "mkey:z7b3946fd91a9f5c1d3a18008ab5735d236373ae4c5207966e3d8d582feb2833";
        assert_eq!(decode_prefixed("mkey", not_hex), Err(DecodeError::NotHex));
    }

    #[test]
    fn accepts_uppercase_but_emits_lowercase() {
        let upper = "mkey:D7B3946FD91A9F5C1D3A18008AB5735D236373AE4C5207966E3D8D582FEB2833";
        let key = decode_prefixed("mkey", upper).unwrap();
        let mut out = [0u8; MAX_ENCODED_LEN];
        assert_eq!(encode_prefixed("mkey", &key, &mut out).unwrap(), CAPTURED);
    }

    #[test]
    fn refuses_to_write_into_a_buffer_that_is_one_byte_short() {
        let key = [0u8; KEY_LEN];
        let mut exact = [0u8; 5 + 64];
        assert!(encode_prefixed("mkey", &key, &mut exact).is_ok());
        let mut short = [0u8; 5 + 63];
        assert_eq!(
            encode_prefixed("mkey", &key, &mut short),
            Err(DecodeError::BufferTooSmall)
        );
    }
}
