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
//! - `Services` — empty, but present, because the reference client sends it.
//!
//! Fields describing a Go runtime (`GoArch`, `GoVersion`, `Distro`) are omitted
//! rather than faked. A wrong value is worse than a missing one: it would be
//! displayed to a user as fact.

use crate::json::Writer;

/// The subnets an exit node advertises. Both are needed: a node offering only
/// the v4 default route is not an exit node as far as a client is concerned.
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

        // Present but empty. The reference client always sends it, and a server
        // that distinguishes "no services" from "did not say" would otherwise
        // see us as the latter.
        writer.key("Services").begin_array().end_array();
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
        // Both, and in one array: a node offering only the v4 default route is
        // not treated as an exit node.
        assert!(text.contains(r#""RoutableIPs":["0.0.0.0/0","::/0"]"#), "{text}");
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
}
