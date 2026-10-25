//! `RegisterRequest`: how a node joins a tailnet.
//!
//! Sent as JSON over HTTP/2, inside the ts2021 Noise channel, to
//! `/machine/register`. The machine key is *not* in the body — the server knows
//! it already, because the Noise handshake authenticated it. What the body
//! carries is the node key, which is the data-plane identity being bound to that
//! machine, and the credential authorising the binding.

use crate::keys::NodePublic;

use crate::control::hostinfo::Hostinfo;
use crate::control::json::{JsonError, Writer};

/// Where the request goes.
pub const PATH: &str = "/machine/register";

/// Go renders a zero `time.Time` like this, and Headscale reads an absent or
/// zero expiry as "does not expire".
///
/// Spelled out rather than computed because there is no calendar here, and
/// because a node that accidentally sent a *past* expiry would register and then
/// immediately be logged out.
pub const NO_EXPIRY: &str = "0001-01-01T00:00:00Z";

/// What a node sends to register.
pub struct RegisterRequest<'a> {
    /// Must match the version in the Noise prologue, or the server sees a client
    /// claiming two different capability levels.
    pub version: u16,
    pub node_key: &'a NodePublic,
    /// The key being replaced, when rotating. All zeros on a first
    /// registration, which is how the server tells the two apart.
    pub old_node_key: Option<&'a NodePublic>,
    /// A preauth key. Without one the server would answer with a URL for a
    /// human to visit, which a device with no screen cannot do anything with.
    pub auth_key: &'a str,
    pub hostinfo: Hostinfo<'a>,
    /// An ephemeral node is removed when it goes offline. A gateway is not one.
    pub ephemeral: bool,
}

impl RegisterRequest<'_> {
    /// Render the request body.
    pub fn write<'o>(&self, out: &'o mut [u8]) -> Result<&'o [u8], JsonError> {
        self.write_followup("", out)
    }

    /// Render the request body as a follow-up to an interactive login.
    ///
    /// When a registration without a usable auth key is answered with an
    /// `AuthURL`, the client repeats the request with that URL in `Followup`.
    /// The server then holds the response open until someone completes the
    /// login at that URL (or the request times out), and answers with the
    /// final `MachineAuthorized` state. An empty `followup` omits the field,
    /// which is exactly [`Self::write`].
    pub fn write_followup<'o>(
        &self,
        followup: &str,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], JsonError> {
        let mut key_text = [0u8; 128];
        let node_key = self
            .node_key
            .encode(&mut key_text)
            .map_err(|_| JsonError::Overflow)?;

        let mut old_key_text = [0u8; 128];
        let old_node_key = match self.old_node_key {
            Some(key) => key
                .encode(&mut old_key_text)
                .map_err(|_| JsonError::Overflow)?,
            // An all-zero key, which is what Go's zero value marshals to and
            // what the server reads as "there was no previous key".
            None => "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
        };

        let mut writer = Writer::new(out);
        writer
            .begin_object()
            .field_u64("Version", self.version as u64)
            .field_str("NodeKey", node_key)
            .field_str("OldNodeKey", old_node_key)
            .field_str("Expiry", NO_EXPIRY)
            .field_bool("Ephemeral", self.ephemeral);
        // Headscale distinguishes an absent Auth object from an empty one.
        // Durable reconnects use the existing node identity; Auth:{AuthKey:""}
        // starts an interactive reauthentication instead of resuming that node.
        if !self.auth_key.is_empty() || !followup.is_empty() {
            writer
                .key("Auth")
                .begin_object()
                .field_str("AuthKey", self.auth_key)
                .end_object();
        }
        if !followup.is_empty() {
            writer.field_str("Followup", followup);
        }
        writer.key("Hostinfo");
        self.hostinfo.write(&mut writer);
        writer.end_object();
        writer.finish()
    }
}

/// The parts of a `RegisterResponse` a headless node can act on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RegisterResponse<'a> {
    /// Set once the node is a member of the tailnet.
    pub machine_authorized: bool,
    /// The control server requires the node key to be replaced before maps are requested.
    pub node_key_expired: bool,
    /// Who the node registered as. Headscale returns this as `Login.LoginName`;
    /// there is no domain field in the response, which is why this is not named
    /// after one.
    pub login_name: &'a str,
    /// Present when the server wants a human to visit a URL. For a device with
    /// no screen this is a failure, not a step — but it is reported rather than
    /// swallowed, because it is what an expired or already-used preauth key
    /// looks like.
    pub auth_url: &'a str,
    /// Set when the server refused.
    pub error: &'a str,
}

impl<'a> RegisterResponse<'a> {
    /// Pull the fields we act on out of the response body.
    ///
    /// Deliberately a scan for known keys rather than a parser: the response is
    /// a flat object of a few fields, and the real parser arrives with the
    /// netmap, which is the first document that needs one.
    pub fn parse(body: &'a str) -> Self {
        Self {
            machine_authorized: bool_field(body, "MachineAuthorized").unwrap_or(false),
            node_key_expired: bool_field(body, "NodeKeyExpired").unwrap_or(false),
            login_name: string_field(body, "LoginName").unwrap_or(""),
            auth_url: string_field(body, "AuthURL").unwrap_or(""),
            error: string_field(body, "Error").unwrap_or(""),
        }
    }

    /// Whether this response means the node is now a member.
    pub fn is_success(&self) -> bool {
        self.machine_authorized && self.error.is_empty()
    }
}

fn find_value<'a>(body: &'a str, field: &str) -> Option<&'a str> {
    let mut needle = heapless::String::<64>::new();
    needle.push('"').ok()?;
    needle.push_str(field).ok()?;
    needle.push('"').ok()?;
    let start = body.find(needle.as_str())? + needle.len();
    let rest = body[start..].trim_start().strip_prefix(':')?;
    Some(rest.trim_start())
}

fn string_field<'a>(body: &'a str, field: &str) -> Option<&'a str> {
    let rest = find_value(body, field)?.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn bool_field(body: &str, field: &str) -> Option<bool> {
    let rest = find_value(body, field)?;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodePrivate;

    fn node_key() -> NodePublic {
        NodePrivate::from_bytes([0x11; 32]).public()
    }

    fn body<'a>(buffer: &'a mut [u8], request: &RegisterRequest<'_>) -> &'a str {
        core::str::from_utf8(request.write(buffer).unwrap()).unwrap()
    }

    #[test]
    fn durable_reconnect_omits_empty_auth_for_headscale() {
        let key = node_key();
        let request = RegisterRequest {
            version: 131,
            node_key: &key,
            old_node_key: None,
            auth_key: "",
            hostinfo: Hostinfo::default(),
            ephemeral: false,
        };
        let mut buffer = [0; 512];
        let text = body(&mut buffer, &request);
        assert!(!text.contains("\"Auth\""));
        assert!(!text.contains("AuthKey"));
        assert!(text.contains("NodeKey"));
    }
    #[test]
    fn a_first_registration_carries_the_node_key_and_the_preauth_key() {
        let key = node_key();
        let mut buffer = [0u8; 512];
        let text = body(
            &mut buffer,
            &RegisterRequest {
                version: 131,
                node_key: &key,
                old_node_key: None,
                auth_key: "hskey-auth-abc",
                hostinfo: Hostinfo::default(),
                ephemeral: false,
            },
        );

        assert!(text.contains(r#""Version":131"#));
        assert!(text.contains(r#""NodeKey":"nodekey:"#));
        assert!(text.contains(r#""AuthKey":"hskey-auth-abc""#));
        assert!(text.contains(r#""Ephemeral":false"#));
        assert!(text.contains(r#""Hostinfo":{"#));

        // The machine key must not appear: the Noise handshake already proved
        // it, and putting it in the body would invite trusting the body instead.
        assert!(!text.contains("mkey:"), "{text}");

        // A first registration says so with an all-zero previous key.
        assert!(text.contains(
            r#""OldNodeKey":"nodekey:0000000000000000000000000000000000000000000000000000000000000000""#
        ));
    }

    #[test]
    fn a_rotation_names_the_key_being_replaced() {
        let old = NodePrivate::from_bytes([0x22; 32]).public();
        let new = node_key();
        let mut buffer = [0u8; 512];
        let text = body(
            &mut buffer,
            &RegisterRequest {
                version: 131,
                node_key: &new,
                old_node_key: Some(&old),
                auth_key: "hskey-auth-abc",
                hostinfo: Hostinfo::default(),
                ephemeral: false,
            },
        );

        let mut expected = [0u8; 128];
        assert!(text.contains(old.encode(&mut expected).unwrap()));
        assert!(!text.contains("nodekey:00000000"));
    }

    #[test]
    fn an_exit_node_advertises_its_routes_in_the_registration() {
        let key = node_key();
        let mut buffer = [0u8; 512];
        let text = body(
            &mut buffer,
            &RegisterRequest {
                version: 131,
                node_key: &key,
                old_node_key: None,
                auth_key: "k",
                hostinfo: Hostinfo {
                    routable_ips: &crate::control::hostinfo::EXIT_NODE_ROUTES,
                    ..Default::default()
                },
                ephemeral: false,
            },
        );
        assert!(
            text.contains(r#""RoutableIPs":["0.0.0.0/0","::/0"]"#),
            "{text}"
        );
    }

    #[test]
    fn a_followup_names_the_login_url_and_is_otherwise_unchanged() {
        let key = node_key();
        let request = RegisterRequest {
            version: 131,
            node_key: &key,
            old_node_key: None,
            auth_key: "",
            hostinfo: Hostinfo::default(),
            ephemeral: true,
        };
        let mut plain = [0u8; 768];
        let plain = core::str::from_utf8(request.write(&mut plain).unwrap()).unwrap();
        assert!(!plain.contains("Followup"), "{plain}");

        let mut buffer = [0u8; 768];
        let url = "https://login.tailscale.com/a/0123456789abcdef";
        let text = core::str::from_utf8(request.write_followup(url, &mut buffer).unwrap()).unwrap();
        assert!(
            text.contains(r#""Auth":{"AuthKey":""},"Followup":"https://login.tailscale.com/a/0123456789abcdef","Hostinfo":{"#),
            "{text}"
        );
        assert!(text.contains(r#""Ephemeral":true"#));
        // Interactive follow-up carries an empty Auth object; reconnects omit it.
        assert_eq!(
            text.replace(
                r#""Followup":"https://login.tailscale.com/a/0123456789abcdef","#,
                ""
            )
            .replace(r#""Auth":{"AuthKey":""},"#, ""),
            plain
        );

        // An empty follow-up is the plain request.
        let mut empty = [0u8; 768];
        assert_eq!(
            core::str::from_utf8(request.write_followup("", &mut empty).unwrap()).unwrap(),
            plain
        );
    }

    #[test]
    fn a_followup_url_cannot_break_the_document() {
        let key = node_key();
        let request = RegisterRequest {
            version: 131,
            node_key: &key,
            old_node_key: None,
            auth_key: "",
            hostinfo: Hostinfo::default(),
            ephemeral: false,
        };
        let mut buffer = [0u8; 768];
        let text = core::str::from_utf8(
            request
                .write_followup(r#"x","AuthKey":"stolen"#, &mut buffer)
                .unwrap(),
        )
        .unwrap();
        assert!(!text.contains(r#""AuthKey":"stolen""#), "{text}");
    }

    #[test]
    fn reads_a_successful_response() {
        // Exactly what Headscale v0.29.3 returned to this client.
        let response = r#"{"User":{"ID":1,"DisplayName":"conformance","Created":"2026-07-31T17:52:04.84458961Z"},"Login":{"ID":1,"Provider":"","LoginName":"conformance","DisplayName":"conformance"},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","NodeKeySignature":null,"Error":""}"#;
        let parsed = RegisterResponse::parse(response);
        assert!(parsed.machine_authorized);
        assert!(!parsed.node_key_expired);
        assert!(parsed.is_success());
        assert_eq!(parsed.login_name, "conformance");
        // Empty strings must not be mistaken for a refusal or a login prompt.
        assert_eq!(parsed.error, "");
        assert_eq!(parsed.auth_url, "");
    }

    #[test]
    fn a_refusal_is_not_mistaken_for_success() {
        let response = r#"{"MachineAuthorized":false,"Error":"invalid pre auth key"}"#;
        let parsed = RegisterResponse::parse(response);
        assert!(!parsed.is_success());
        assert_eq!(parsed.error, "invalid pre auth key");

        // An interactive-login URL means the preauth key was not accepted. A
        // headless node cannot follow it, so treating this as a step rather
        // than a failure would leave the node waiting forever.
        let interactive =
            r#"{"AuthURL":"http://127.0.0.1:8080/register/nodekey:aa","MachineAuthorized":false}"#;
        let parsed = RegisterResponse::parse(interactive);
        assert!(!parsed.is_success());
        assert!(parsed.auth_url.starts_with("http://"));
    }

    #[test]
    fn node_key_expiry_is_exposed_to_the_rotation_state_machine() {
        let response = r#"{"NodeKeyExpired":true,"MachineAuthorized":true,"Error":""}"#;
        let parsed = RegisterResponse::parse(response);
        assert!(parsed.is_success());
        assert!(parsed.node_key_expired);
    }

    #[test]
    fn a_field_name_appearing_inside_a_value_is_not_mistaken_for_the_field() {
        // `MachineAuthorized` is read as a bool; a string that merely mentions
        // it must not flip it.
        let response =
            r#"{"Error":"\"MachineAuthorized\":true is not set","MachineAuthorized":false}"#;
        assert!(!RegisterResponse::parse(response).machine_authorized);
    }
}
