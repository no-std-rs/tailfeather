//! The JSON we emit, read back by a real parser.
//!
//! `ts-control`'s own tests compare `Writer` output to string literals that we
//! also wrote. That catches a changed field name and nothing else: an escaper
//! bug producing a document no parser accepts passes, because the literal is
//! wrong in exactly the same way. It would take a server rejecting a
//! registration to notice, and the failure would surface as "registration
//! refused" with no indication that the body was malformed.
//!
//! Here `serde_json` is the judge. It has no idea what we intended, so the only
//! way to satisfy it is to emit valid JSON — and then the *parsed* structure,
//! not its spelling, is what gets asserted.
//!
//! The hostname is the interesting input: on a real device it comes from
//! configuration, so it is the one field an outsider can influence.

use ts_control::hostinfo::Hostinfo;
use ts_control::register::RegisterRequest;
use ts_keys::NodePrivate;

/// Big enough for every document below, including the pathological hostnames.
const BUFFER: usize = 8192;

fn node_key(seed: u8) -> NodePrivate {
    NodePrivate::from_bytes([seed; 32])
}

/// Render a registration and parse it. Panics with the raw bytes if the result
/// is not valid JSON, because that is the failure this file exists to catch.
fn render(hostname: &str, auth_key: &str) -> serde_json::Value {
    let key = node_key(0x11);
    let public = key.public();
    let request = RegisterRequest {
        version: 131,
        node_key: &public,
        old_node_key: None,
        auth_key,
        hostinfo: Hostinfo {
            hostname,
            version: "1.94.2",
            os: "linux",
            routable_ips: &[],
        },
        ephemeral: false,
    };

    let mut out = [0u8; BUFFER];
    let bytes = request.write(&mut out).expect("the document fits");

    let text = std::str::from_utf8(bytes).unwrap_or_else(|e| {
        panic!("the register body is not UTF-8 ({e}): {:?}", bytes)
    });
    serde_json::from_str(text).unwrap_or_else(|e| {
        panic!("the register body is not valid JSON ({e}): {text}")
    })
}

#[test]
fn a_registration_parses_and_carries_the_fields_the_server_reads() {
    let value = render("esp-gateway", "tskey-auth-abc123");

    assert_eq!(value["Version"], 131);
    assert_eq!(value["Ephemeral"], false);
    assert_eq!(value["Auth"]["AuthKey"], "tskey-auth-abc123");
    assert_eq!(value["Hostinfo"]["Hostname"], "esp-gateway");
    assert_eq!(value["Hostinfo"]["OS"], "linux");

    let expected = node_key(0x11).public();
    let mut encoded = [0u8; 128];
    assert_eq!(value["NodeKey"], expected.encode(&mut encoded).unwrap());

    // Absent means "no previous key", spelled as Go's zero value rather than
    // omitted or null — a server reading it as a key must get 32 zero bytes.
    let old = value["OldNodeKey"].as_str().expect("OldNodeKey is a string");
    assert_eq!(old, "nodekey:{}".replace("{}", &"0".repeat(64)));

    // Services is present and empty, not missing.
    assert_eq!(
        value["Hostinfo"]["Services"].as_array().map(Vec::len),
        Some(0)
    );
}

/// The escaper, judged by a parser rather than by a literal we also wrote.
///
/// Each of these hostnames, if mis-escaped, produces a document that either
/// fails to parse or parses into a *different* string. The second case is the
/// dangerous one: it is silent.
#[test]
fn every_hostname_survives_a_round_trip_through_a_real_parser() {
    const HOSTNAMES: &[(&str, &str)] = &[
        ("plain", "the ordinary case"),
        ("with\"quote", "an unescaped quote ends the string early"),
        ("with\\backslash", "a lone backslash escapes the closing quote"),
        ("both\"and\\", "the two structural characters together"),
        ("tab\there", "a literal tab is not allowed raw in JSON"),
        ("newline\nhere", "a literal newline is not allowed raw"),
        ("carriage\rreturn", "likewise"),
        ("\u{0}nul", "NUL has no short escape and needs \\u0000"),
        ("\u{1}\u{2}\u{1f}", "control characters with no short form"),
        ("\u{7f}delete", "DEL is not a JSON control character"),
        ("héllo-wörld", "two-byte UTF-8"),
        ("日本語ホスト", "three-byte UTF-8"),
        ("emoji-\u{1f600}", "four-byte UTF-8, a surrogate pair if escaped"),
        ("\u{feff}bom", "a byte-order mark inside the string"),
        ("\\u0041", "the literal characters of an escape, not an 'A'"),
        ("}{\"Version\":9999,\"x\":\"", "an attempt to inject a field"),
        ("", "empty"),
    ];

    for (hostname, why) in HOSTNAMES {
        let value = render(hostname, "tskey-auth-x");
        assert_eq!(
            value["Hostinfo"]["Hostname"].as_str(),
            Some(*hostname),
            "hostname {hostname:?} did not survive the round trip ({why})"
        );
        // Injection specifically: the document must still have exactly the
        // fields we wrote, at the values we wrote them.
        assert_eq!(value["Version"], 131, "hostname {hostname:?} moved Version");
        assert_eq!(
            value.as_object().map(|o| o.len()),
            Some(7),
            "hostname {hostname:?} changed the top-level field count"
        );
    }
}

/// The auth key is attacker-adjacent too — it is pasted in by a human.
#[test]
fn a_hostile_auth_key_cannot_restructure_the_document() {
    let value = render("esp-gateway", "\",\"Ephemeral\":true,\"x\":\"");
    assert_eq!(value["Ephemeral"], false, "the injected field took effect");
    assert_eq!(
        value["Auth"]["AuthKey"].as_str(),
        Some("\",\"Ephemeral\":true,\"x\":\"")
    );
    assert_eq!(value["Auth"].as_object().map(|o| o.len()), Some(1));
}

/// Property-style: every string of one code point, across the ranges that
/// matter, round-trips.
///
/// This is where an escaper bug that the hand-picked list above happens to miss
/// gets caught — in particular an off-by-one at the 0x1f/0x20 boundary, where
/// escaping stops being required.
#[test]
fn every_single_character_hostname_round_trips() {
    let interesting = (0u32..0x100)
        .chain([0x7ff, 0x800, 0xfff, 0xffff, 0x10000, 0x10ffff])
        .filter_map(char::from_u32);

    for c in interesting {
        let hostname = c.to_string();
        let value = render(&hostname, "k");
        assert_eq!(
            value["Hostinfo"]["Hostname"].as_str(),
            Some(hostname.as_str()),
            "U+{:04X} did not round trip",
            c as u32
        );
    }
}

/// Non-ASCII is emitted raw, not `\u`-escaped.
///
/// Both are valid JSON and a parser cannot tell them apart, so this asserts on
/// the bytes. It is a deliberate choice recorded in `json.rs`: escaping would
/// mean UTF-16 surrogate arithmetic in a no-alloc writer, for no gain.
#[test]
fn multibyte_utf8_is_emitted_raw_rather_than_escaped() {
    let key = node_key(0x11);
    let public = key.public();
    let request = RegisterRequest {
        version: 131,
        node_key: &public,
        old_node_key: None,
        auth_key: "k",
        hostinfo: Hostinfo {
            hostname: "日本語",
            version: "1.94.2",
            os: "linux",
            routable_ips: &[],
        },
        ephemeral: false,
    };
    let mut out = [0u8; BUFFER];
    let bytes = request.write(&mut out).unwrap();

    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.contains("日本語"), "the characters were escaped");
    assert!(!text.contains("\\u65e5"));
}

/// A buffer one byte too small must fail, not truncate.
///
/// Truncation would produce a document that is not valid JSON, which is exactly
/// what the parser above would catch — but only if the writer reported success.
#[test]
fn a_document_that_does_not_fit_is_refused_rather_than_truncated() {
    let key = node_key(0x11);
    let public = key.public();
    let request = RegisterRequest {
        version: 131,
        node_key: &public,
        old_node_key: None,
        auth_key: "tskey-auth-abc123",
        hostinfo: Hostinfo {
            hostname: "esp-gateway",
            version: "1.94.2",
            os: "linux",
            routable_ips: &[],
        },
        ephemeral: false,
    };

    let mut full = [0u8; BUFFER];
    let complete = request.write(&mut full).unwrap().len();

    for size in [0, 1, complete / 2, complete - 1] {
        let mut small = vec![0u8; size];
        assert!(
            request.write(&mut small).is_err(),
            "a {size}-byte buffer accepted a {complete}-byte document"
        );
    }
    let mut exact = vec![0u8; complete];
    assert!(request.write(&mut exact).is_ok());
}

/// Routable IPs, when present, must form a real array.
#[test]
fn exit_node_routes_parse_as_an_array_of_prefixes() {
    let key = node_key(0x22);
    let public = key.public();
    let request = RegisterRequest {
        version: 131,
        node_key: &public,
        old_node_key: Some(&public),
        auth_key: "k",
        hostinfo: Hostinfo {
            hostname: "gw",
            version: "1.94.2",
            os: "linux",
            routable_ips: &ts_control::hostinfo::EXIT_NODE_ROUTES,
        },
        ephemeral: true,
    };
    let mut out = [0u8; BUFFER];
    let text = std::str::from_utf8(request.write(&mut out).unwrap()).unwrap();
    let value: serde_json::Value = serde_json::from_str(text).expect("valid JSON");

    assert_eq!(value["Ephemeral"], true);
    let routes = value["Hostinfo"]["RoutableIPs"]
        .as_array()
        .expect("RoutableIPs is an array");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0], "0.0.0.0/0");
    assert_eq!(routes[1], "::/0");

    // A supplied old key is rendered, not replaced by the zero value.
    let mut encoded = [0u8; 128];
    assert_eq!(value["OldNodeKey"], public.encode(&mut encoded).unwrap());
}
