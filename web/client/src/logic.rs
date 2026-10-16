//! Pure decisions the browser runtime makes, kept free of JavaScript so they
//! run as ordinary host unit tests: URL construction, the WebSocket byte
//! queue, IPv4 routing to peers, WireGuard timestamps, and SSH host-key trust.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use tailfeather::keys::NodePublic;
use tailfeather::netmap::{Cidr4, Peer};

/// WebSocket subprotocol for ts2021 over WebSocket (`controlhttp` upstream).
pub const CONTROL_PROTOCOL: &str = "tailscale-control-protocol";
/// WebSocket subprotocol for DERP over WebSocket.
pub const DERP_PROTOCOL: &str = "derp";

/// Percent-encode a query-string value. Everything outside RFC 3986's
/// unreserved set is escaped, which covers base64's `+`, `/` and `=`.
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A DNS host name as it may appear in a URL authority: letters, digits,
/// hyphens and dots only. Rejecting anything else keeps a hostile netmap or
/// setting from smuggling a path, port, or credentials into a URL.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && !host.starts_with('.')
        && !host.ends_with('.')
}

/// Normalize the optional relay setting to a `ws:`/`wss:` origin with no
/// trailing slash. An empty setting means "connect directly".
pub fn relay_origin(relay: &str) -> Result<Option<String>, String> {
    let relay = relay.trim().trim_end_matches('/');
    if relay.is_empty() {
        return Ok(None);
    }
    let (scheme, rest) = if let Some(rest) = relay.strip_prefix("https://") {
        ("wss://", rest)
    } else if let Some(rest) = relay.strip_prefix("wss://") {
        ("wss://", rest)
    } else if let Some(rest) = relay.strip_prefix("http://") {
        ("ws://", rest)
    } else if let Some(rest) = relay.strip_prefix("ws://") {
        ("ws://", rest)
    } else {
        return Err("relay URL must start with https:// or http://".into());
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => (host, Some(port)),
        _ => (rest, None),
    };
    if !valid_host(host) {
        return Err("relay URL must be a bare origin such as https://relay.example".into());
    }
    Ok(Some(match port {
        Some(port) => format!("{scheme}{host}:{port}"),
        None => format!("{scheme}{host}"),
    }))
}

/// `GET /key` on the control server. Hosted control answers it with
/// `Access-Control-Allow-Origin: *`, so the page fetches it directly even when
/// a relay carries the WebSockets.
pub fn key_url(control_host: &str, capability_version: u16) -> String {
    format!("https://{control_host}/key?v={capability_version}")
}

/// The ts2021 WebSocket URL. The initiation rides in the query string because
/// a browser cannot set the `X-Tailscale-Handshake` header on a WebSocket.
pub fn control_url(control_host: &str, relay: Option<&str>, initiation: &[u8]) -> String {
    use base64::Engine as _;
    let handshake = base64::engine::general_purpose::STANDARD.encode(initiation);
    let query = format!("X-Tailscale-Handshake={}", percent_encode(&handshake));
    match relay {
        None => format!("wss://{control_host}/ts2021?{query}"),
        Some(origin) => format!("{origin}/relay/control/{control_host}/ts2021?{query}"),
    }
}

/// The DERP WebSocket URL for one relay node. `host` must be the node's DNS
/// name (the browser does TLS and needs a name the certificate covers).
pub fn derp_url(host: &str, port: u16, relay: Option<&str>) -> String {
    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    match relay {
        None => format!("wss://{authority}/derp"),
        Some(origin) => format!("{origin}/relay/derp/{authority}"),
    }
}

/// How a read from a [`ByteQueue`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// This many bytes were copied out.
    Data(usize),
    /// Nothing buffered yet; wait for more.
    Pending,
    /// The peer closed cleanly and every buffered byte has been read.
    Eof,
    /// The connection failed; buffered bytes were already delivered.
    Failed(String),
}

/// Inbound bytes of one WebSocket, treated as a byte stream: message
/// boundaries mean nothing to either protocol carried here, so one message may
/// hold any fragment of a record or frame.
///
/// Bounded: a peer that outruns its reader is a failure, not a reason to grow.
pub struct ByteQueue {
    bytes: VecDeque<u8>,
    limit: usize,
    closed: Option<Result<(), String>>,
}

impl ByteQueue {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            limit,
            closed: None,
        }
    }

    /// Append one inbound message. Overflow fails the stream.
    pub fn push(&mut self, message: &[u8]) -> Result<(), String> {
        if self.closed.is_some() {
            return Ok(());
        }
        if self.bytes.len() + message.len() > self.limit {
            let error = format!("inbound buffer exceeded {} bytes", self.limit);
            self.closed = Some(Err(error.clone()));
            return Err(error);
        }
        self.bytes.extend(message);
        Ok(())
    }

    /// Record the end of the stream. The first reason wins.
    pub fn close(&mut self, result: Result<(), String>) {
        self.closed.get_or_insert(result);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Buffered bytes are delivered before the close is reported.
    pub fn read(&mut self, out: &mut [u8]) -> ReadOutcome {
        if !self.bytes.is_empty() {
            let take = out.len().min(self.bytes.len());
            for (slot, byte) in out.iter_mut().zip(self.bytes.drain(..take)) {
                *slot = byte;
            }
            return ReadOutcome::Data(take);
        }
        match &self.closed {
            None => ReadOutcome::Pending,
            Some(Ok(())) => ReadOutcome::Eof,
            Some(Err(error)) => ReadOutcome::Failed(error.clone()),
        }
    }
}

fn contains(cidr: &Cidr4, address: Ipv4Addr) -> bool {
    let prefix = u32::from(cidr.prefix.min(32));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(cidr.address) & mask == u32::from(address) & mask
}

/// The peer an outbound IPv4 packet belongs to: the peer whose own address it
/// is, otherwise the most specific `AllowedIPs` match.
pub fn route_ipv4<'a>(
    peers: impl IntoIterator<Item = &'a Peer>,
    destination: Ipv4Addr,
) -> Option<NodePublic> {
    let mut best: Option<(u8, NodePublic)> = None;
    for peer in peers {
        if peer
            .addresses
            .iter()
            .any(|cidr| cidr.address == destination)
        {
            return Some(peer.node_key);
        }
        for cidr in peer
            .allowed_ips
            .iter()
            .filter(|cidr| contains(cidr, destination))
        {
            if best.is_none_or(|(prefix, _)| cidr.prefix > prefix) {
                best = Some((cidr.prefix, peer.node_key));
            }
        }
    }
    best.map(|(_, key)| key)
}

/// The source and destination of an IPv4 header, when `packet` is one.
pub fn ipv4_addresses(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((source, destination))
}

/// WireGuard's cryptokey routing on receive: a decrypted packet is accepted
/// only if it is addressed to this node and its source routes back to the peer
/// that sent it.
///
/// The source is resolved across every peer with the same most-specific rule as
/// [`route_ipv4`], not just against the sender's own list. Otherwise a peer
/// with a broad route, such as an exit node's `0.0.0.0/0`, could send packets
/// that claim another peer's address.
pub fn inbound_allowed<'a>(
    packet: &[u8],
    sender: &NodePublic,
    peers: impl IntoIterator<Item = &'a Peer>,
    own: Ipv4Addr,
) -> bool {
    let Some((source, destination)) = ipv4_addresses(packet) else {
        return false;
    };
    destination == own && route_ipv4(peers, source) == Some(*sender)
}

/// The next TAI64N timestamp for a WireGuard initiation.
///
/// Responders reject an initiation whose timestamp is not strictly newer than
/// the last one they accepted from this key, so the value is derived from the
/// wall clock (to survive reloads) and forced strictly increasing within a
/// session.
pub fn next_tai64n(last: &mut [u8; 12], unix_ms: u64) -> [u8; 12] {
    const TAI_OFFSET: u64 = (1 << 62) + 10;
    let mut next = [0u8; 12];
    next[..8].copy_from_slice(&(unix_ms / 1000 + TAI_OFFSET).to_be_bytes());
    next[8..].copy_from_slice(&(((unix_ms % 1000) * 1_000_000) as u32).to_be_bytes());
    if next <= *last {
        next = *last;
        let nanos = u32::from_be_bytes(next[8..].try_into().expect("four bytes")) + 1;
        if nanos >= 1_000_000_000 {
            let seconds = u64::from_be_bytes(next[..8].try_into().expect("eight bytes")) + 1;
            next[..8].copy_from_slice(&seconds.to_be_bytes());
            next[8..].copy_from_slice(&0u32.to_be_bytes());
        } else {
            next[8..].copy_from_slice(&nanos.to_be_bytes());
        }
    }
    *last = next;
    next
}

/// How far the durable timestamp floor runs ahead of anything emitted, so it
/// needs rewriting only about once a minute.
pub const TAI64N_FLOOR_STEP_S: u64 = 60;

/// The initial "last emitted" timestamp for a floor loaded from storage: whole
/// TAI64 seconds, so every later timestamp is above it even if the clock has
/// moved backwards since the page was last open.
pub fn tai64n_at_floor(floor_seconds: u64) -> [u8; 12] {
    let mut last = [0u8; 12];
    last[..8].copy_from_slice(&floor_seconds.to_be_bytes());
    last
}

/// A new floor to persist, once emitted timestamps have caught up with the
/// stored one. Keeping the floor strictly above every emitted timestamp means a
/// reload can never reuse or go below one a peer has already accepted.
pub fn tai64n_floor_update(last: &[u8; 12], stored_floor: u64) -> Option<u64> {
    let seconds = u64::from_be_bytes(last[..8].try_into().ok()?);
    (seconds >= stored_floor).then(|| seconds + TAI64N_FLOOR_STEP_S)
}

/// What trust-on-first-use concludes about a presented SSH host key.
#[derive(Debug, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Never seen: accept and remember it.
    FirstUse,
    /// Matches what was remembered.
    Known,
    /// Differs from what was remembered: refuse.
    Changed { expected: String },
}

pub fn host_key_decision(stored: Option<&str>, presented: &str) -> HostKeyDecision {
    match stored {
        None | Some("") => HostKeyDecision::FirstUse,
        Some(stored) if stored == presented => HostKeyDecision::Known,
        Some(stored) => HostKeyDecision::Changed {
            expected: stored.to_string(),
        },
    }
}

/// The storage key a host fingerprint is remembered under.
pub fn host_key_slot(ip: Ipv4Addr, port: u16) -> String {
    format!("tailfeather.hostkey.{ip}:{port}")
}

/// SSH authentication methods, in the order this client tries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStep {
    KeyboardInteractive,
    Password,
    PublicKey,
}

/// The next method to try after `none` failed, given the methods the server
/// still offers and the ones already tried. Public key needs a pasted key.
pub fn next_auth_step(
    offered: &[AuthStep],
    tried: &[AuthStep],
    have_private_key: bool,
) -> Option<AuthStep> {
    [
        AuthStep::KeyboardInteractive,
        AuthStep::Password,
        AuthStep::PublicKey,
    ]
    .into_iter()
    .filter(|step| *step != AuthStep::PublicKey || have_private_key)
    .find(|step| offered.contains(step) && !tried.contains(step))
}

/// A short, recognizable form of a node key for display: `nodekey:abcd1234…`.
pub fn short_key(encoded: &str) -> String {
    match encoded.split_once(':') {
        Some((prefix, hex)) if hex.len() > 8 => format!("{prefix}:{}…", &hex[..8]),
        _ => encoded.to_string(),
    }
}

/// Carriage returns for xterm: a bare `\n` only moves down a line.
pub fn terminal_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut previous = '\0';
    for character in text.chars() {
        if character == '\n' && previous != '\r' {
            out.push('\r');
        }
        out.push(character);
        previous = character;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailfeather::keys::NodePrivate;
    use tailfeather::netmap::Cidr;

    fn cidr(text: &str) -> Cidr4 {
        Cidr4::from_cidr(Cidr::parse(text).unwrap()).unwrap()
    }

    fn peer(byte: u8, address: &str, allowed: &[&str]) -> Peer {
        let mut peer = Peer::new(
            u64::from(byte),
            NodePrivate::from_bytes([byte; 32]).public(),
        );
        peer.addresses.push(cidr(address)).unwrap();
        for route in allowed {
            peer.allowed_ips.push(cidr(route)).unwrap();
        }
        peer
    }

    #[test]
    fn base64_query_characters_are_escaped() {
        assert_eq!(percent_encode("a+b/c=="), "a%2Bb%2Fc%3D%3D");
        assert_eq!(percent_encode("AZaz09-_.~"), "AZaz09-_.~");
        assert_eq!(percent_encode("&?# "), "%26%3F%23%20");
    }

    #[test]
    fn control_urls_carry_the_initiation_in_the_query() {
        let initiation = [0xfb, 0xff, 0xfe, 0x00];
        assert_eq!(
            control_url("controlplane.tailscale.com", None, &initiation),
            "wss://controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=%2B%2F%2F%2BAA%3D%3D"
        );
        assert_eq!(
            control_url(
                "controlplane.tailscale.com",
                Some("wss://relay.example"),
                &initiation
            ),
            "wss://relay.example/relay/control/controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=%2B%2F%2F%2BAA%3D%3D"
        );
        assert_eq!(
            key_url("controlplane.tailscale.com", 131),
            "https://controlplane.tailscale.com/key?v=131"
        );
    }

    #[test]
    fn derp_urls_use_the_host_name_and_omit_the_default_port() {
        assert_eq!(
            derp_url("derp18d.tailscale.com", 443, None),
            "wss://derp18d.tailscale.com/derp"
        );
        assert_eq!(
            derp_url("derp.example", 8443, None),
            "wss://derp.example:8443/derp"
        );
        assert_eq!(
            derp_url("derp18d.tailscale.com", 443, Some("wss://relay.example")),
            "wss://relay.example/relay/derp/derp18d.tailscale.com"
        );
    }

    #[test]
    fn relay_settings_are_normalized_or_refused() {
        assert_eq!(relay_origin("").unwrap(), None);
        assert_eq!(relay_origin("  ").unwrap(), None);
        assert_eq!(
            relay_origin("https://relay.example/").unwrap().as_deref(),
            Some("wss://relay.example")
        );
        assert_eq!(
            relay_origin("http://localhost:8787").unwrap().as_deref(),
            Some("ws://localhost:8787")
        );
        assert!(relay_origin("relay.example").is_err());
        assert!(relay_origin("https://relay.example/path").is_err());
        assert!(relay_origin("https://user@relay.example").is_err());
    }

    #[test]
    fn host_names_are_validated() {
        assert!(valid_host("derp1.tailscale.com"));
        assert!(!valid_host(""));
        assert!(!valid_host("evil.example/path"));
        assert!(!valid_host("evil.example:1"));
        assert!(!valid_host(".example"));
    }

    #[test]
    fn the_byte_queue_is_a_stream_across_messages() {
        let mut queue = ByteQueue::new(8);
        let mut out = [0u8; 3];
        assert_eq!(queue.read(&mut out), ReadOutcome::Pending);
        queue.push(b"ab").unwrap();
        queue.push(b"cde").unwrap();
        assert_eq!(queue.read(&mut out), ReadOutcome::Data(3));
        assert_eq!(&out, b"abc");
        queue.close(Ok(()));
        // Buffered bytes are delivered before the end is reported.
        assert_eq!(queue.read(&mut out), ReadOutcome::Data(2));
        assert_eq!(&out[..2], b"de");
        assert_eq!(queue.read(&mut out), ReadOutcome::Eof);
        // A later failure does not replace a clean close.
        queue.close(Err("late".into()));
        assert_eq!(queue.read(&mut out), ReadOutcome::Eof);
    }

    #[test]
    fn the_byte_queue_fails_rather_than_grows() {
        let mut queue = ByteQueue::new(4);
        queue.push(b"abc").unwrap();
        assert!(queue.push(b"de").is_err());
        let mut out = [0u8; 8];
        assert_eq!(queue.read(&mut out), ReadOutcome::Data(3));
        assert!(matches!(queue.read(&mut out), ReadOutcome::Failed(_)));
    }

    #[test]
    fn packets_route_to_the_owner_then_the_most_specific_allowed_ip() {
        let bazzite = peer(1, "100.113.109.28/32", &["100.113.109.28/32"]);
        let router = peer(2, "100.64.0.2/32", &["100.64.0.2/32", "10.0.0.0/8"]);
        let narrow = peer(3, "100.64.0.3/32", &["10.1.0.0/16"]);
        let peers = [bazzite.clone(), router.clone(), narrow.clone()];
        assert_eq!(
            route_ipv4(&peers, "100.113.109.28".parse().unwrap()),
            Some(bazzite.node_key)
        );
        assert_eq!(
            route_ipv4(&peers, "10.2.3.4".parse().unwrap()),
            Some(router.node_key)
        );
        assert_eq!(
            route_ipv4(&peers, "10.1.3.4".parse().unwrap()),
            Some(narrow.node_key)
        );
        assert_eq!(route_ipv4(&peers, "192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn inbound_packets_must_come_from_the_senders_addresses() {
        let own: Ipv4Addr = "100.100.1.2".parse().unwrap();
        let sender = peer(1, "100.113.109.28/32", &["100.113.109.28/32"]);
        let peers = [sender.clone()];
        let key = &sender.node_key;
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[100, 113, 109, 28]);
        packet[16..20].copy_from_slice(&own.octets());
        assert!(inbound_allowed(&packet, key, &peers, own));

        let mut spoofed = packet;
        spoofed[12..16].copy_from_slice(&[100, 64, 0, 9]);
        assert!(!inbound_allowed(&spoofed, key, &peers, own));

        let mut elsewhere = packet;
        elsewhere[16..20].copy_from_slice(&[100, 64, 0, 9]);
        assert!(!inbound_allowed(&elsewhere, key, &peers, own));

        assert!(!inbound_allowed(&packet[..19], key, &peers, own));
        let mut ipv6 = packet;
        ipv6[0] = 0x60;
        assert!(!inbound_allowed(&ipv6, key, &peers, own));
    }

    #[test]
    fn an_exit_node_cannot_claim_another_peers_address() {
        let own: Ipv4Addr = "100.100.1.2".parse().unwrap();
        let target = peer(1, "100.113.109.28/32", &["100.113.109.28/32"]);
        let exit = peer(2, "100.81.40.57/32", &["100.81.40.57/32", "0.0.0.0/0"]);
        let peers = [target.clone(), exit.clone()];
        let mut from_target = [0u8; 20];
        from_target[0] = 0x45;
        from_target[12..16].copy_from_slice(&[100, 113, 109, 28]);
        from_target[16..20].copy_from_slice(&own.octets());

        // The target's address belongs to the target, whoever sends it.
        assert!(inbound_allowed(&from_target, &target.node_key, &peers, own));
        assert!(!inbound_allowed(&from_target, &exit.node_key, &peers, own));

        // Internet traffic through the exit node is still accepted from it.
        let mut from_internet = from_target;
        from_internet[12..16].copy_from_slice(&[93, 184, 216, 34]);
        assert!(inbound_allowed(&from_internet, &exit.node_key, &peers, own));
        assert!(!inbound_allowed(
            &from_internet,
            &target.node_key,
            &peers,
            own
        ));
    }

    #[test]
    fn tai64n_timestamps_follow_the_clock_and_never_repeat() {
        let mut last = [0u8; 12];
        let first = next_tai64n(&mut last, 1_700_000_000_123);
        assert_eq!(
            u64::from_be_bytes(first[..8].try_into().unwrap()),
            (1 << 62) + 10 + 1_700_000_000
        );
        assert_eq!(
            u32::from_be_bytes(first[8..].try_into().unwrap()),
            123_000_000
        );
        // Same millisecond, or a clock step backwards: still strictly newer.
        let second = next_tai64n(&mut last, 1_700_000_000_123);
        assert!(second > first);
        let third = next_tai64n(&mut last, 1_600_000_000_000);
        assert!(third > second);
        let later = next_tai64n(&mut last, 1_700_000_001_000);
        assert!(later > third);
    }

    #[test]
    fn the_timestamp_floor_survives_a_reload_with_the_clock_set_back() {
        // One page emits at t=1_700_000_000 and persists a floor ahead of it.
        let mut last = [0u8; 12];
        let emitted = next_tai64n(&mut last, 1_700_000_000_000);
        let floor = tai64n_floor_update(&last, 0).expect("the first emission sets a floor");
        assert!(tai64n_at_floor(floor) > emitted);
        // Until emissions catch up, nothing needs writing.
        next_tai64n(&mut last, 1_700_000_030_000);
        assert_eq!(tai64n_floor_update(&last, floor), None);

        // The next page starts from the floor while its clock reads a day earlier.
        let mut reloaded = tai64n_at_floor(floor);
        let first = next_tai64n(&mut reloaded, 1_699_913_600_000);
        assert!(
            first > emitted,
            "a reload must never go back below an accepted timestamp"
        );
        let next_floor = tai64n_floor_update(&reloaded, floor).expect("caught up with the floor");
        assert!(tai64n_at_floor(next_floor) > first);
    }

    #[test]
    fn host_keys_are_trusted_on_first_use_and_pinned_after() {
        assert_eq!(
            host_key_decision(None, "SHA256:abc"),
            HostKeyDecision::FirstUse
        );
        assert_eq!(
            host_key_decision(Some("SHA256:abc"), "SHA256:abc"),
            HostKeyDecision::Known
        );
        assert_eq!(
            host_key_decision(Some("SHA256:abc"), "SHA256:xyz"),
            HostKeyDecision::Changed {
                expected: "SHA256:abc".into()
            }
        );
        assert_eq!(
            host_key_slot("100.113.109.28".parse().unwrap(), 22),
            "tailfeather.hostkey.100.113.109.28:22"
        );
    }

    #[test]
    fn authentication_follows_the_documented_order() {
        use AuthStep::*;
        let all = [PublicKey, Password, KeyboardInteractive];
        assert_eq!(next_auth_step(&all, &[], true), Some(KeyboardInteractive));
        assert_eq!(
            next_auth_step(&all, &[KeyboardInteractive], true),
            Some(Password)
        );
        assert_eq!(
            next_auth_step(&all, &[KeyboardInteractive, Password], true),
            Some(PublicKey)
        );
        // Without a pasted key there is nothing to offer for publickey.
        assert_eq!(
            next_auth_step(&all, &[KeyboardInteractive, Password], false),
            None
        );
        assert_eq!(next_auth_step(&[PublicKey], &[], true), Some(PublicKey));
        assert_eq!(next_auth_step(&[], &[], true), None);
    }

    #[test]
    fn display_helpers() {
        assert_eq!(short_key("nodekey:0123456789abcdef"), "nodekey:01234567…");
        assert_eq!(terminal_text("a\nb\r\nc"), "a\r\nb\r\nc");
    }
}
