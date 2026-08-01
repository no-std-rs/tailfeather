//! `micro-h2`'s HPACK against `fluke-hpack`, an independent implementation.
//!
//! Two directions, and they close different gaps.
//!
//! **Ours out, theirs in.** Nothing had ever decoded our header blocks except
//! our own decoder. Both sides sharing a misreading of the integer prefix rules
//! would look exactly like success.
//!
//! **Theirs out, ours in.** This is the larger gap. Our encoder deliberately
//! never emits indexed representations, incremental indexing, Huffman coding or
//! dynamic table size updates — see `encode.rs` for why that is the right choice
//! — with the consequence that `hpack/dynamic.rs`'s eviction logic had no test
//! that ever put anything in the table. A real server uses all of it, so the
//! decoder must handle all of it, and until now only hand-written blocks
//! exercised those paths.

use micro_h2::hpack::{DEFAULT_TABLE_SIZE, Decoder};
use micro_h2::hpack::encode::encode_header;

use fluke_hpack::Decoder as TheirDecoder;
use fluke_hpack::Encoder as TheirEncoder;

/// Encode a header list with our encoder.
fn our_encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0u8; 64 * 1024];
    let mut len = 0;
    for (name, value) in headers {
        len = encode_header(name, value, &mut out, len).expect("our encoder");
    }
    out.truncate(len);
    out
}

/// Decode a header block with our decoder.
fn our_decode(decoder: &mut Decoder, block: &[u8]) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    decoder
        .decode(block, |name, value| {
            headers.push((name.to_string(), value.to_string()))
        })
        .expect("our decoder");
    headers
}

fn their_decode(decoder: &mut TheirDecoder, block: &[u8]) -> Vec<(String, String)> {
    decoder
        .decode(block)
        .expect("fluke-hpack decodes our block")
        .into_iter()
        .map(|(n, v)| {
            (
                String::from_utf8(n).expect("utf-8 name"),
                String::from_utf8(v).expect("utf-8 value"),
            )
        })
        .collect()
}

/// The header lists this client actually sends, plus the shapes that select
/// each of our encoder's three branches.
fn cases() -> Vec<Vec<(&'static str, &'static str)>> {
    vec![
        // A real /machine/map request.
        vec![
            (":method", "POST"),
            (":path", "/machine/map"),
            (":scheme", "http"),
            (":authority", "127.0.0.1:8080"),
            ("content-type", "application/json"),
            ("content-length", "349"),
        ],
        // A real /machine/register request.
        vec![
            (":method", "POST"),
            (":path", "/machine/register"),
            (":scheme", "http"),
            (":authority", "controlplane.tailscale.com"),
            ("content-type", "application/json"),
        ],
        // Branch 1: name and value both in the static table, so a bare index.
        vec![(":method", "GET"), (":scheme", "https"), (":status", "200")],
        // Branch 2: name in the table, value not.
        vec![(":path", "/machine/map"), ("user-agent", "ts-noise")],
        // Branch 3: neither in the table.
        vec![("x-tailscale-thing", "value"), ("another-one", "x")],
        // Values that stress string lengths and the integer continuation rules:
        // a 127-byte value is the largest that fits a 7-bit prefix, 128 is the
        // first that does not.
        vec![("x-len-126", &LONG[..126]), ("x-len-127", &LONG[..127])],
        vec![("x-len-128", &LONG[..128]), ("x-len-200", &LONG[..200])],
        // Empty value, and a value containing bytes that Huffman coding would
        // treat specially if we did any.
        vec![("x-empty", ""), ("x-symbols", "!#$%&'*+-.^_`|~")],
        // Repeated identical headers: a table-keeping encoder would compress the
        // second; ours must not, and their decoder must see two.
        vec![("x-repeat", "same"), ("x-repeat", "same")],
    ]
}

const LONG: &str = concat!(
    "0123456789012345678901234567890123456789012345678901234567890123",
    "4567890123456789012345678901234567890123456789012345678901234567",
    "8901234567890123456789012345678901234567890123456789012345678901",
    "2345678901234567890123456789012345678901234567890123456789012345",
);

// ---------------------------------------------------------------------------
// Our encoder, their decoder
// ---------------------------------------------------------------------------

#[test]
fn fluke_hpack_decodes_every_block_we_emit() {
    for (i, headers) in cases().iter().enumerate() {
        let block = our_encode(headers);
        // A fresh decoder per block: our encoder never touches the dynamic
        // table, so every block it produces must be self-contained. If one is
        // not, a peer that reset its table would misread it.
        let mut theirs = TheirDecoder::new();
        let decoded = their_decode(&mut theirs, &block);

        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expected, "case {i}: fluke-hpack read our block differently");
    }
}

/// The same blocks, decoded by one long-lived decoder.
///
/// This is the arrangement a real connection uses, and it is where an encoder
/// that accidentally emitted an indexing representation would show up: the
/// peer's table would grow, and a later block would resolve an index we never
/// meant to send.
#[test]
fn our_blocks_are_table_neutral_across_a_whole_connection() {
    let mut theirs = TheirDecoder::new();
    for (i, headers) in cases().iter().enumerate() {
        let block = our_encode(headers);
        let decoded = their_decode(&mut theirs, &block);
        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expected, "case {i} under a shared decoder");
    }
}

/// Our encoder must never set the "incremental indexing" bit.
///
/// Asserted on the bytes because it is a design commitment, not an emergent
/// property: `encode.rs` gives up compression precisely so that no table has to
/// be kept in lockstep.
#[test]
fn our_encoder_never_emits_an_indexing_representation() {
    for headers in cases() {
        let block = our_encode(&headers);
        let mut rest = &block[..];
        while !rest.is_empty() {
            let first = rest[0];
            if first & 0x80 != 0 {
                // Indexed header field — a read, not a table mutation.
                let (_, next) = micro_h2::hpack::decode::decode_integer(rest, 7).unwrap();
                rest = next;
                continue;
            }
            assert_eq!(
                first & 0xc0,
                0x00,
                "an incremental-indexing (0x40) or size-update (0x20) octet appeared"
            );
            assert_eq!(first & 0xf0, 0x00, "expected literal-without-indexing");

            let (name_index, next) = micro_h2::hpack::decode::decode_integer(rest, 4).unwrap();
            rest = next;
            if name_index == 0 {
                rest = skip_string(rest);
            }
            rest = skip_string(rest);
        }
    }
}

fn skip_string(input: &[u8]) -> &[u8] {
    assert_eq!(input[0] & 0x80, 0, "our encoder never Huffman-codes");
    let (len, rest) = micro_h2::hpack::decode::decode_integer(input, 7).unwrap();
    &rest[len as usize..]
}

// ---------------------------------------------------------------------------
// Their encoder, our decoder
// ---------------------------------------------------------------------------

/// `fluke-hpack`'s encoder indexes by default, so this drives the decoder paths
/// ours never produces: indexed fields, incremental indexing, and the dynamic
/// table lookups that follow.
#[test]
fn we_decode_blocks_from_an_indexing_encoder() {
    let mut theirs = TheirEncoder::new();
    let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);

    for (i, headers) in cases().iter().enumerate() {
        let owned: Vec<(Vec<u8>, Vec<u8>)> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let borrowed: Vec<(&[u8], &[u8])> =
            owned.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
        let block = theirs.encode(borrowed);

        let decoded = our_decode(&mut ours, &block);
        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expected, "case {i}: we read their block differently");
    }
}

/// Repeating a header list makes the second block resolve almost entirely out of
/// the dynamic table.
///
/// The point is the *second* pass: if our table were not carrying state between
/// blocks, or were carrying it in the wrong order, the indices would resolve to
/// the wrong entries rather than fail.
#[test]
fn a_repeated_header_list_is_read_back_out_of_the_dynamic_table() {
    let mut theirs = TheirEncoder::new();
    let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);

    let headers: Vec<(&[u8], &[u8])> = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":path", b"/machine/map"),
        (b"x-custom-one", b"first"),
        (b"x-custom-two", b"second"),
    ];
    let expected = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), "/machine/map".to_string()),
        ("x-custom-one".to_string(), "first".to_string()),
        ("x-custom-two".to_string(), "second".to_string()),
    ];

    let first = theirs.encode(headers.iter().copied());
    assert_eq!(our_decode(&mut ours, &first), expected);
    let entries_after_first = ours.table().len();
    assert!(
        entries_after_first > 0,
        "their encoder indexed nothing, so this test proves nothing about our table"
    );

    let second = theirs.encode(headers.iter().copied());
    assert!(
        second.len() < first.len(),
        "the second block should be shorter; if it is not, no indexing happened"
    );
    assert_eq!(
        our_decode(&mut ours, &second),
        expected,
        "the second block resolved to different headers"
    );
}

/// Eviction: fill the table past its capacity and keep decoding correctly.
///
/// `dynamic.rs` is 256 lines of eviction logic that, before this, nothing
/// reached. Each entry costs its name and value plus 32 bytes of overhead, so a
/// few hundred distinct headers overflow the default 4096-byte table many times
/// over.
#[test]
fn eviction_keeps_our_table_in_step_with_theirs() {
    let mut theirs = TheirEncoder::new();
    let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);

    for round in 0..200 {
        let name = format!("x-header-{round:04}");
        let value = format!("value-{round:04}-{}", "p".repeat(round % 97));
        let headers: Vec<(&[u8], &[u8])> = vec![
            (b":method".as_slice(), b"POST".as_slice()),
            (name.as_bytes(), value.as_bytes()),
        ];
        let block = theirs.encode(headers);

        let decoded = our_decode(&mut ours, &block);
        assert_eq!(
            decoded,
            vec![
                (":method".to_string(), "POST".to_string()),
                (name.clone(), value.clone()),
            ],
            "round {round}: the tables diverged"
        );
        assert!(
            ours.table().size() <= DEFAULT_TABLE_SIZE,
            "round {round}: our table grew past its limit"
        );
    }
}

/// A dynamic table size update, which our encoder never emits.
///
/// Shrinking the table must evict; setting it to zero must clear it entirely.
/// A decoder that ignored the update would keep resolving indices against
/// entries the peer has already dropped.
#[test]
fn a_dynamic_table_size_update_shrinks_and_clears_the_table() {
    let mut theirs = TheirEncoder::new();
    let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);

    let headers: Vec<(&[u8], &[u8])> = vec![
        (b"x-one".as_slice(), b"aaaaaaaaaaaaaaaa".as_slice()),
        (b"x-two", b"bbbbbbbbbbbbbbbb"),
        (b"x-three", b"cccccccccccccccc"),
    ];
    our_decode(&mut ours, &theirs.encode(headers));
    assert!(ours.table().len() >= 3, "nothing was indexed");
    let full = ours.table().size();
    assert!(full > 0);

    // 0x20 | 0 — set the maximum table size to zero, which evicts everything.
    our_decode(&mut ours, &[0x20]);
    assert_eq!(ours.table().len(), 0, "a size-zero update did not clear the table");
    assert_eq!(ours.table().size(), 0);

    // 0x3f 0xe1 0x1f — the 4096 that a real peer restores it to.
    our_decode(&mut ours, &[0x3f, 0xe1, 0x1f]);
    assert_eq!(ours.table().len(), 0);

    // And the table works again afterwards.
    let mut fresh = TheirEncoder::new();
    let again: Vec<(&[u8], &[u8])> = vec![(b"x-after".as_slice(), b"value".as_slice())];
    assert_eq!(
        our_decode(&mut ours, &fresh.encode(again.into_iter())),
        vec![("x-after".to_string(), "value".to_string())]
    );
}

/// Round-tripping through both implementations, in both orders.
#[test]
fn both_directions_agree_on_every_case() {
    for (i, headers) in cases().iter().enumerate() {
        let expected: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();

        // ours -> ours (the pre-existing self-referential check, kept as a floor)
        let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);
        assert_eq!(our_decode(&mut ours, &our_encode(headers)), expected, "case {i}");

        // ours -> theirs -> (re-encoded) -> ours
        let mut their_decoder = TheirDecoder::new();
        let round = their_decode(&mut their_decoder, &our_encode(headers));
        assert_eq!(round, expected, "case {i}");

        let mut their_encoder = TheirEncoder::new();
        let owned: Vec<(Vec<u8>, Vec<u8>)> = round
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let reencoded =
            their_encoder.encode(owned.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut ours = Decoder::new(DEFAULT_TABLE_SIZE);
        assert_eq!(our_decode(&mut ours, &reencoded), expected, "case {i}");
    }
}
