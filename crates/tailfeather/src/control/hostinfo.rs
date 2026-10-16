//! What a node tells the control plane about itself.
//!
//! # How the field set was chosen
//!
//! Not from documentation. `tests/vectors/map_response.json` holds the
//! `Hostinfo` a real tailscaled 1.94.2 sent to a real Headscale, and the
//! conformance suite reads the field names out of that capture. This struct
//! carries the subset that is either load-bearing or honest to report:
//!
//! - `IPNVersion`, `OS`, `Hostname` — the server displays these, and an absent
//!   version makes a node look unsupported.
//! - `RoutableIPs` — how a node advertises itself as an exit node. This is the
//!   whole mechanism; there is no separate flag.
//! - `Services` — peer API discovery for exit-node DNS, or an explicitly empty
//!   array when the caller does not provide a peer API port.
//!
//! Fields describing a Go runtime (`GoArch`, `GoVersion`, `Distro`) are omitted
//! rather than faked. A wrong value is worse than a missing one: it would be
//! displayed to a user as fact.

use crate::control::json::Writer;

/// The default routes required for Tailscale clients to recognize an exit node.
///
/// IPv6 forwarding is not implemented yet, so `::/0` is intentionally
/// blackholed by the IPv4-only data plane until that support lands.
pub const EXIT_NODE_ROUTES: [&str; 2] = ["0.0.0.0/0", "::/0"];

/// What this node reports about itself.
#[derive(Clone, Copy)]
pub struct Hostinfo<'a> {
    pub hostname: &'a str,
    /// What the server shows as the client version. Ours, not a Tailscale
    /// release number, because claiming to be a release we are not would make
    /// any incompatibility that follows extremely confusing to diagnose.
    pub version: &'a str,
    pub os: &'a str,
    /// Subnets this node offers to route for others. `EXIT_NODE_ROUTES` to
    /// advertise as an exit node.
    pub routable_ips: &'a [&'a str],
    /// Relay selected from measured STUN latency. Zero omits `NetInfo` until a
    /// usable region has actually answered.
    pub preferred_derp: u16,
    /// TCP port of the IPv4 peer API. When present, the node also advertises
    /// the exit-node DNS proxy capability whose sentinel port is always one.
    pub peer_api_port: Option<u16>,
}

impl Hostinfo<'_> {
    /// What a real device calls itself.
    ///
    /// Exposed as a constant because the harness accepts a `--hostname`
    /// override — the conformance suite tags the nodes it registers so it can
    /// delete them again — and the default has to come from somewhere both can
    /// name.
    pub const DEFAULT_HOSTNAME: &'static str = "esp-gateway";
}

impl Default for Hostinfo<'_> {
    fn default() -> Self {
        Self {
            hostname: Self::DEFAULT_HOSTNAME,
            version: concat!("esp-gateway-", env!("CARGO_PKG_VERSION")),
            os: "esp32",
            routable_ips: &[],
            preferred_derp: 0,
            peer_api_port: None,
        }
    }
}

impl Hostinfo<'_> {
    pub fn write(&self, writer: &mut Writer<'_>) {
        writer
            .begin_object()
            .field_str("IPNVersion", self.version)
            .field_str("OS", self.os)
            .field_str("Hostname", self.hostname);

        if !self.routable_ips.is_empty() {
            writer.key("RoutableIPs").begin_array();
            for route in self.routable_ips {
                writer.str(route);
            }
            writer.end_array();
        }

        if self.preferred_derp != 0 {
            writer
                .key("NetInfo")
                .begin_object()
                .field_u64("PreferredDERP", u64::from(self.preferred_derp))
                .end_object();
        }

        // Present even when empty. The DNS capability is a separate sentinel
        // service; its Port is fixed by tailcfg and does not carry the peer API
        // listener port.
        writer.key("Services").begin_array();
        if let Some(port) = self.peer_api_port {
            writer
                .begin_object()
                .field_str("Proto", "peerapi4")
                .field_u64("Port", u64::from(port))
                .end_object()
                .begin_object()
                .field_str("Proto", "peerapi-dns-proxy")
                .field_u64("Port", 1)
                .end_object();
        }
        writer.end_array();
        writer.end_object();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered<'a>(buffer: &'a mut [u8], hostinfo: &Hostinfo<'_>) -> &'a str {
        let mut writer = Writer::new(buffer);
        hostinfo.write(&mut writer);
        core::str::from_utf8(writer.finish().unwrap()).unwrap()
    }

    #[test]
    fn a_default_hostinfo_advertises_no_routes() {
        let mut buffer = [0u8; 256];
        let text = rendered(&mut buffer, &Hostinfo::default());
        assert!(text.contains(r#""OS":"esp32""#));
        assert!(text.contains(r#""Hostname":"esp-gateway""#));
        assert!(text.contains(r#""IPNVersion":"esp-gateway-"#));
        assert!(text.contains(r#""Services":[]"#));
        assert!(
            !text.contains("RoutableIPs"),
            "a node that is not an exit node must not claim routes"
        );
    }

    #[test]
    fn an_exit_node_advertises_both_default_routes() {
        let mut buffer = [0u8; 256];
        let hostinfo = Hostinfo {
            routable_ips: &EXIT_NODE_ROUTES,
            ..Default::default()
        };
        let text = rendered(&mut buffer, &hostinfo);
        assert!(
            text.contains(r#""RoutableIPs":["0.0.0.0/0","::/0"]"#),
            "{text}"
        );
    }

    #[test]
    fn a_hostname_with_a_quote_in_it_cannot_break_the_document() {
        let mut buffer = [0u8; 256];
        let hostinfo = Hostinfo {
            hostname: r#"evil","OS":"linux"#,
            ..Default::default()
        };
        let text = rendered(&mut buffer, &hostinfo);
        assert!(text.contains(r#""OS":"esp32""#));
        assert!(!text.contains(r#""OS":"linux""#), "injection: {text}");
    }

    #[test]
    fn preferred_derp_is_reported_only_after_measurement() {
        let mut buffer = [0u8; 256];
        let text = rendered(&mut buffer, &Hostinfo::default());
        assert!(!text.contains("NetInfo"));

        let hostinfo = Hostinfo {
            preferred_derp: 7,
            ..Default::default()
        };
        let text = rendered(&mut buffer, &hostinfo);
        assert!(text.contains(r#""NetInfo":{"PreferredDERP":7}"#));
    }

    #[test]
    fn peer_api_advertises_ipv4_listener_and_dns_capability() {
        let mut buffer = [0u8; 384];
        let hostinfo = Hostinfo {
            peer_api_port: Some(5254),
            ..Default::default()
        };
        let text = rendered(&mut buffer, &hostinfo);
        assert!(
            text.contains(
                r#""Services":[{"Proto":"peerapi4","Port":5254},{"Proto":"peerapi-dns-proxy","Port":1}]"#
            ),
            "{text}"
        );
    }
}
