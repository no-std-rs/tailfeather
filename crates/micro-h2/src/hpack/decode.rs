//! Decoding a header block.
//!
//! The five representations of RFC 7541 section 6, distinguished by the top
//! bits of the first byte:
//!
//! ```text
//! 1xxxxxxx   indexed header field                    (7-bit prefix)
//! 01xxxxxx   literal, incremental indexing           (6-bit prefix)
//! 001xxxxx   dynamic table size update               (5-bit prefix)
//! 0001xxxx   literal, never indexed                  (4-bit prefix)
//! 0000xxxx   literal, without indexing               (4-bit prefix)
//! ```
//!
//! The order matters: `0001xxxx` must be tested before `0000xxxx`, and the size
//! update before both. Getting the prefix lengths wrong misreads the integer
//! that follows, which then consumes the wrong number of bytes and desynchronises
//! the rest of the block.

use crate::Error;
use crate::hpack::dynamic::{DynamicTable, lookup};
use crate::hpack::huffman;
use crate::hpack::static_table;

/// The longest header name or value this decoder will materialise.
///
/// Bounded because there is no allocator. Exceeding it is an error rather than a
/// truncation: a silently shortened header value is worse than a failed request.
pub const MAX_STRING: usize = 512;

/// One decoded header.
pub struct Header {
    pub name: heapless::String<MAX_STRING>,
    pub value: heapless::String<MAX_STRING>,
}

/// Decodes header blocks, carrying the dynamic table between them.
///
/// One decoder per connection, never one per message: the table is connection
/// state, and a fresh decoder for each response would resolve every index the
/// server sent against an empty table.
pub struct Decoder {
    table: DynamicTable,
    max_capacity: usize,
}

impl Decoder {
    pub fn new(table_size: usize) -> Self {
        Self {
            table: DynamicTable::new(table_size),
            max_capacity: table_size,
        }
    }

    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Decode a complete header block, calling `on_header` for each field.
    ///
    /// A callback rather than a returned collection: a response's headers do not
    /// all need to be held at once, and the caller usually wants two of them.
    pub fn decode(
        &mut self,
        mut input: &[u8],
        mut on_header: impl FnMut(&str, &str),
    ) -> Result<(), Error> {
        while !input.is_empty() {
            let first = input[0];

            if first & 0x80 != 0 {
                // Indexed: name and value both come from a table.
                let (index, rest) = decode_integer(input, 7)?;
                input = rest;
                let (name, value) = lookup(&self.table, index as usize)?;
                on_header(name, value);
                continue;
            }

            if first & 0xe0 == 0x20 {
                // Dynamic table size update. Not a header, and legal only at the
                // start of a block, but accepting it anywhere costs nothing and
                // rejecting a legal stream costs the connection.
                let (size, rest) = decode_integer(input, 5)?;
                input = rest;
                if size as usize > self.max_capacity {
                    return Err(Error::Protocol);
                }
                self.table.set_capacity(size as usize);
                continue;
            }

            // The three literal forms differ only in what they do to the table.
            let (prefix, indexing) = if first & 0xc0 == 0x40 {
                (6, true)
            } else {
                // Both `0000xxxx` and `0001xxxx` have a 4-bit prefix and neither
                // indexes. "Never indexed" additionally means intermediaries must
                // not index it, which as an endpoint we honour by doing nothing.
                (4, false)
            };

            let (index, rest) = decode_integer(input, prefix)?;
            input = rest;

            let mut name = heapless::String::<MAX_STRING>::new();
            if index == 0 {
                input = decode_string(input, &mut name)?;
            } else {
                let (existing, _) = lookup(&self.table, index as usize)?;
                name.push_str(existing).map_err(|_| Error::BufferTooSmall)?;
            }

            let mut value = heapless::String::<MAX_STRING>::new();
            input = decode_string(input, &mut value)?;

            on_header(&name, &value);
            if indexing {
                self.table.insert(&name, &value);
            }
        }
        Ok(())
    }
}

/// RFC 7541 section 5.1: an integer with an `n`-bit prefix, continued in
/// seven-bit groups when the prefix is all ones.
///
/// Returns the value and the remaining input.
pub fn decode_integer(input: &[u8], prefix_bits: u32) -> Result<(u64, &[u8]), Error> {
    let mask = (1u64 << prefix_bits) - 1;
    let first = *input.first().ok_or(Error::Incomplete)? as u64;
    let value = first & mask;
    if value < mask {
        return Ok((value, &input[1..]));
    }

    let mut value = mask;
    let mut shift = 0;
    let mut rest = &input[1..];
    loop {
        let byte = *rest.first().ok_or(Error::Incomplete)?;
        rest = &rest[1..];
        // Bounded so a hostile encoder cannot spin here, and so the shift cannot
        // overflow — 64 bits is ten seven-bit groups.
        if shift > 63 {
            return Err(Error::Hpack);
        }
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or(Error::Hpack)?;
        if byte & 0x80 == 0 {
            return Ok((value, rest));
        }
        shift += 7;
    }
}

/// RFC 7541 section 5.2: a length-prefixed string, optionally Huffman-coded.
fn decode_string<'a>(
    input: &'a [u8],
    out: &mut heapless::String<MAX_STRING>,
) -> Result<&'a [u8], Error> {
    let huffman_coded = input.first().ok_or(Error::Incomplete)? & 0x80 != 0;
    let (len, rest) = decode_integer(input, 7)?;
    let len = len as usize;
    let bytes = rest.get(..len).ok_or(Error::Incomplete)?;

    let mut buffer = [0u8; MAX_STRING];
    let decoded: &[u8] = if huffman_coded {
        let n = huffman::decode(bytes, &mut buffer)?;
        &buffer[..n]
    } else {
        bytes
    };

    let text = core::str::from_utf8(decoded).map_err(|_| Error::Hpack)?;
    out.push_str(text).map_err(|_| Error::BufferTooSmall)?;
    Ok(&rest[len..])
}

/// The static table, re-exported so callers can name indices without reaching
/// into a sibling module.
pub use static_table::{DYNAMIC_BASE, ENTRIES as STATIC_ENTRIES};

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> heapless::Vec<u8, 256> {
        let mut bytes = heapless::Vec::new();
        for pair in text.as_bytes().chunks(2) {
            bytes
                .push(u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .unwrap();
        }
        bytes
    }

    /// Collect a block's headers as `name: value` strings.
    fn decode_all(decoder: &mut Decoder, block: &str) -> heapless::Vec<heapless::String<256>, 16> {
        let mut headers = heapless::Vec::new();
        decoder
            .decode(&hex(block), |name, value| {
                let mut entry = heapless::String::<256>::new();
                entry.push_str(name).unwrap();
                entry.push_str(": ").unwrap();
                entry.push_str(value).unwrap();
                headers.push(entry).unwrap();
            })
            .unwrap();
        headers
    }

    #[test]
    fn decodes_integers_as_the_rfc_section_5_1_examples_do() {
        // 10 in a 5-bit prefix fits inline.
        assert_eq!(decode_integer(&[0x0a], 5).unwrap().0, 10);
        // 1337 in a 5-bit prefix needs continuation bytes.
        assert_eq!(decode_integer(&[0x1f, 0x9a, 0x0a], 5).unwrap().0, 1337);
        // 42 in an 8-bit prefix.
        assert_eq!(decode_integer(&[0x2a], 8).unwrap().0, 42);
        // A prefix that is all ones with nothing following is incomplete, not 31.
        assert_eq!(decode_integer(&[0x1f], 5), Err(Error::Incomplete));
    }

    /// RFC 7541 Appendix C.3 — three requests on one connection, with the
    /// dynamic table carried between them. This is the case a per-message
    /// decoder gets wrong.
    #[test]
    fn decodes_the_rfc_appendix_c_3_request_sequence() {
        let mut decoder = Decoder::new(4096);

        let first = decode_all(&mut decoder, "828684410f7777772e6578616d706c652e636f6d");
        assert_eq!(first[0].as_str(), ":method: GET");
        assert_eq!(first[1].as_str(), ":scheme: http");
        assert_eq!(first[2].as_str(), ":path: /");
        assert_eq!(first[3].as_str(), ":authority: www.example.com");
        assert_eq!(decoder.table().len(), 1);

        // The second request references the entry the first one created.
        let second = decode_all(&mut decoder, "828684be58086e6f2d6361636865");
        assert_eq!(second[3].as_str(), ":authority: www.example.com");
        assert_eq!(second[4].as_str(), "cache-control: no-cache");
        assert_eq!(decoder.table().len(), 2);

        let third = decode_all(
            &mut decoder,
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        );
        assert_eq!(third[3].as_str(), ":authority: www.example.com");
        assert_eq!(third[4].as_str(), "custom-key: custom-value");
        assert_eq!(decoder.table().len(), 3);
    }

    /// RFC 7541 Appendix C.4 — the same three requests, Huffman-coded.
    #[test]
    fn decodes_the_rfc_appendix_c_4_huffman_request_sequence() {
        let mut decoder = Decoder::new(4096);

        let first = decode_all(&mut decoder, "828684418cf1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(first[3].as_str(), ":authority: www.example.com");

        let second = decode_all(&mut decoder, "828684be5886a8eb10649cbf");
        assert_eq!(second[4].as_str(), "cache-control: no-cache");

        let third = decode_all(
            &mut decoder,
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        );
        assert_eq!(third[4].as_str(), "custom-key: custom-value");
    }

    /// RFC 7541 Appendix C.5 — responses with a table small enough to evict,
    /// which is where an eviction bug turns into wrong headers rather than
    /// missing ones.
    #[test]
    fn decodes_the_rfc_appendix_c_5_response_sequence_with_eviction() {
        let mut decoder = Decoder::new(256);

        let first = decode_all(
            &mut decoder,
            "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        );
        assert_eq!(first[0].as_str(), ":status: 302");
        assert_eq!(first[3].as_str(), "location: https://www.example.com");

        let second = decode_all(&mut decoder, "4803333037c1c0bf");
        assert_eq!(second[0].as_str(), ":status: 307");
        assert_eq!(second[1].as_str(), "cache-control: private");
        assert_eq!(second[3].as_str(), "location: https://www.example.com");

        let third = decode_all(
            &mut decoder,
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        );
        assert_eq!(third[0].as_str(), ":status: 200");
        assert_eq!(third[4].as_str(), "content-encoding: gzip");
        assert!(
            third[5]
                .as_str()
                .starts_with("set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU")
        );
    }

    #[test]
    fn a_dynamic_table_size_update_is_applied_and_is_not_a_header() {
        let mut decoder = Decoder::new(4096);
        // 0x20 | 0 => set capacity to 0, then an indexed :method GET.
        let headers = decode_all(&mut decoder, "2082");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].as_str(), ":method: GET");
        assert_eq!(decoder.table().capacity(), 0);
    }

    #[test]
    fn a_dynamic_table_update_cannot_exceed_the_advertised_bound() {
        let mut decoder = Decoder::new(256);
        // HPACK integer with a 5-bit prefix encodes a requested capacity of 512.
        assert_eq!(
            decoder.decode(&[0x3f, 0xe1, 0x03], |_, _| {}),
            Err(Error::Protocol)
        );
        assert_eq!(decoder.table().capacity(), 256);
    }

    #[test]
    fn an_index_the_peer_never_defined_is_an_error() {
        // The failure this prevents is subtle: carrying on would shift every
        // later index, so headers would decode as *other headers* for the rest
        // of the connection.
        let mut decoder = Decoder::new(4096);
        assert_eq!(decoder.decode(&hex("be"), |_, _| {}), Err(Error::Hpack));
        // ...and a static index past the end of the table, likewise.
        assert_eq!(decoder.decode(&hex("ff00"), |_, _| {}), Err(Error::Hpack));
    }

    #[test]
    fn a_truncated_block_is_incomplete_rather_than_a_short_header() {
        let mut decoder = Decoder::new(4096);
        // A literal whose declared length runs past the end of the block.
        assert_eq!(
            decoder.decode(&hex("400a637573746f6d"), |_, _| {}),
            Err(Error::Incomplete)
        );
    }

    #[test]
    fn never_indexed_headers_do_not_enter_the_table() {
        let mut decoder = Decoder::new(4096);
        // 0x10 => literal never indexed, new name.
        let headers = decode_all(&mut decoder, "10012d0131");
        assert_eq!(headers[0].as_str(), "-: 1");
        assert!(
            decoder.table().is_empty(),
            "a never-indexed header must not be remembered"
        );
    }
}
