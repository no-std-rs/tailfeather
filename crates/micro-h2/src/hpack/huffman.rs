//! HPACK's Huffman code (RFC 7541 Appendix B).
//!
//! # Only decoding
//!
//! Requests this crate emits use literal, unencoded strings, which is always
//! legal. Responses are another matter: Go's HTTP/2 server Huffman-encodes a
//! header whenever that makes it shorter, so a client that cannot decode reads
//! `content-type` as line noise. Hence decode-only.
//!
//! # Only the lengths
//!
//! The code is *canonical*: sort the symbols by (length, symbol) and the codes
//! are consecutive, shifting left at each length boundary. So the codes are
//! implied by the lengths, and only the lengths are transcribed here — the rest
//! is derived into lookup tables at compile time. That removes 257 hand-copied
//! 32-bit constants, each of which could have been wrong in a way that only
//! showed up on one rare character.
//!
//! The transcription was checked before it was written down: canonicality,
//! prefix-freedom, and byte-exact reproduction of all eleven encoded strings in
//! RFC 7541 Appendix C. The decode tests below re-check the last of those
//! against this implementation.

use crate::Error;

/// Bit length of each symbol's code. Index 256 is EOS, which may never appear
/// as a decoded value.
const LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

/// The end-of-string symbol. Receiving it is a connection error: a compliant
/// encoder pads with EOS *bits* but never emits the whole symbol.
const EOS: u16 = 256;

const MIN_LENGTH: usize = 5;
const MAX_LENGTH: usize = 30;

/// Everything canonicality lets us derive from [`LENGTHS`] alone.
struct Tables {
    /// Symbols ordered by (length, symbol).
    sorted: [u16; 257],
    /// The numeric value of the first code of each length.
    first_code: [u32; MAX_LENGTH + 1],
    /// Where that length's symbols start in `sorted`.
    first_index: [u16; MAX_LENGTH + 1],
    counts: [u16; MAX_LENGTH + 1],
}

/// Built with a `const fn` so the arrays are in flash, not computed at startup.
static TABLES: Tables = build();

const fn build() -> Tables {
    let mut counts = [0u16; MAX_LENGTH + 1];
    let mut symbol = 0;
    while symbol < 257 {
        counts[LENGTHS[symbol] as usize] += 1;
        symbol += 1;
    }

    // Sort by (length, symbol) with a counting sort, which is what canonical
    // ordering is: walk the lengths, and within each, the symbols in order.
    let mut sorted = [0u16; 257];
    let mut first_index = [0u16; MAX_LENGTH + 1];
    let mut first_code = [0u32; MAX_LENGTH + 1];
    let mut code = 0u32;
    let mut index = 0u16;
    let mut length = 1;
    while length <= MAX_LENGTH {
        code <<= 1;
        first_code[length] = code;
        first_index[length] = index;

        let mut symbol = 0;
        while symbol < 257 {
            if LENGTHS[symbol] as usize == length {
                sorted[index as usize] = symbol as u16;
                index += 1;
            }
            symbol += 1;
        }
        code += counts[length] as u32;
        length += 1;
    }

    Tables {
        sorted,
        first_code,
        first_index,
        counts,
    }
}

/// Decode `input` into `out`, returning the number of bytes written.
///
/// Bit-at-a-time canonical decoding: shift a bit in, and once the accumulated
/// code falls inside the range belonging to the current length, that range's
/// offset indexes the symbol directly. No tree, no allocation, and the state is
/// two integers.
pub fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut written = 0;
    let mut code = 0u32;
    let mut length = 0usize;

    for byte in input {
        for bit in (0..8).rev() {
            code = code << 1 | ((byte >> bit) & 1) as u32;
            length += 1;
            if length > MAX_LENGTH {
                return Err(Error::Hpack);
            }
            if length < MIN_LENGTH {
                continue;
            }

            let count = TABLES.counts[length] as u32;
            let first = TABLES.first_code[length];
            if count == 0 || code < first || code >= first + count {
                continue;
            }

            let index = TABLES.first_index[length] as u32 + (code - first);
            let symbol = TABLES.sorted[index as usize];
            if symbol == EOS {
                // A well-formed stream pads with EOS bits, never the symbol.
                return Err(Error::Hpack);
            }
            *out.get_mut(written).ok_or(Error::BufferTooSmall)? = symbol as u8;
            written += 1;
            code = 0;
            length = 0;
        }
    }

    // Whatever is left must be padding: fewer than eight bits, and all ones.
    // Anything else is a corrupt stream rather than a short one, and accepting
    // it silently would turn a framing bug into a truncated header value.
    if length >= 8 || code != (1u32 << length) - 1 {
        return Err(Error::Hpack);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(hex: &str) -> heapless::Vec<u8, 128> {
        let mut bytes = heapless::Vec::<u8, 128>::new();
        for pair in hex.as_bytes().chunks(2) {
            let value = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
            bytes.push(value).unwrap();
        }
        let mut out = heapless::Vec::<u8, 128>::new();
        out.resize_default(128).unwrap();
        let n = decode(&bytes, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// The encoded strings from RFC 7541 Appendix C, decoded back.
    ///
    /// These are the specification's own bytes, so they check this
    /// implementation against the RFC rather than against itself.
    #[test]
    fn decodes_the_rfc_7541_appendix_c_strings() {
        for (hex, expected) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("6402", "302"),
            ("aec3771a4b", "private"),
            (
                "d07abe941054d444a8200595040b8166e082a62d1bff",
                "Mon, 21 Oct 2013 20:13:21 GMT",
            ),
            (
                "9d29ad171863c78f0b97c8e9ae82ae43d3",
                "https://www.example.com",
            ),
            ("640eff", "307"),
            ("9bd9ab", "gzip"),
            (
                "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
        ] {
            assert_eq!(
                core::str::from_utf8(&decoded(hex)).unwrap(),
                expected,
                "decoding {hex}"
            );
        }
    }

    #[test]
    fn the_derived_tables_agree_with_the_specification() {
        // Spot-check the boundaries the const fn computes, against values read
        // straight out of Appendix B: '0' is the first 5-bit code, ' ' the
        // first 6-bit one, and ':' the first 7-bit one.
        assert_eq!(TABLES.first_code[5], 0x0);
        assert_eq!(TABLES.sorted[TABLES.first_index[5] as usize], b'0' as u16);
        assert_eq!(TABLES.first_code[6], 0x14);
        assert_eq!(TABLES.sorted[TABLES.first_index[6] as usize], b' ' as u16);
        assert_eq!(TABLES.first_code[7], 0x5c);
        assert_eq!(TABLES.sorted[TABLES.first_index[7] as usize], b':' as u16);
        assert_eq!(TABLES.counts.iter().sum::<u16>(), 257);
    }

    #[test]
    fn padding_that_is_not_all_ones_is_rejected() {
        // "no-cache" is 43 bits, so its last byte carries five bits of padding,
        // all ones: 0xbf. Zeroing one is a stream no compliant encoder produces,
        // and accepting it would mean accepting a value truncated in transit.
        let mut out = [0u8; 32];
        assert!(decode(&hex(b"a8eb10649cbf"), &mut out).is_ok());
        assert_eq!(decode(&hex(b"a8eb10649cbe"), &mut out), Err(Error::Hpack));

        // "302" happens to be exactly sixteen bits, so it has no padding at all
        // — a reminder that "the last byte ends in ones" is not the rule.
        assert!(decode(&[0x64, 0x02], &mut out).is_ok());
    }

    #[test]
    fn a_padding_run_long_enough_to_be_a_symbol_is_rejected() {
        // Eight or more bits left over is a dropped symbol, not padding.
        let mut out = [0u8; 32];
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff], &mut out),
            Err(Error::Hpack)
        );
    }

    #[test]
    fn a_short_output_buffer_is_an_error_not_a_truncation() {
        let mut out = [0u8; 4];
        assert_eq!(
            decode(&hex(b"f1e3c2e5f23a6ba0ab90f4ff"), &mut out),
            Err(Error::BufferTooSmall)
        );
    }

    fn hex(text: &[u8]) -> heapless::Vec<u8, 64> {
        let mut bytes = heapless::Vec::new();
        for pair in text.chunks(2) {
            bytes
                .push(u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .unwrap();
        }
        bytes
    }
}
