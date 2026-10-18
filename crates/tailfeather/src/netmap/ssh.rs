//! Small compiled Tailscale SSH policy subset.
//!
//! Only unconditional accept/reject actions and IPv4 `nodeIP` / `any`
//! principals are supported. Unsupported requirements invalidate the entire
//! policy: an earlier check/expiry/recording rule must never be skipped in
//! favour of a later accept. No policy, malformed input, or capacity overflow
//! authorizes nobody. Absent/null map deltas preserve the previous policy.

use core::net::Ipv4Addr;
use heapless::{String, Vec};

use super::scanner::Token;

pub const MAX_RULES: usize = 4;
pub const MAX_PRINCIPALS: usize = 8;
pub const MAX_USERS: usize = 4;
pub const MAX_USERNAME: usize = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Any,
    Address(Ipv4Addr),
}

#[derive(Clone, Default)]
struct Rule {
    sources: Vec<Source, MAX_PRINCIPALS>,
    users: Vec<(String<MAX_USERNAME>, String<MAX_USERNAME>), MAX_USERS>,
    accept: bool,
    reject: bool,
}

/// Fixed-capacity, ordered policy from `MapResponse.SSHPolicy`.
#[derive(Clone, Default)]
pub struct Policy {
    rules: Vec<Rule, MAX_RULES>,
    valid: bool,
}

impl Policy {
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            valid: false,
        }
    }

    /// Whether the complete policy was understood. An empty valid policy denies.
    pub fn is_supported(&self) -> bool {
        self.valid
    }

    /// Evaluate SSH policy after independently authenticating the peer and
    /// enforcing the network packet filter. `local_user` names the one console
    /// the application exposes; this crate does not resolve Unix accounts.
    pub fn allows(&self, source: Ipv4Addr, requested: &str, local_user: &str) -> bool {
        if !self.valid || requested.is_empty() || local_user.is_empty() {
            return false;
        }
        for rule in &self.rules {
            if !rule
                .sources
                .iter()
                .any(|s| *s == Source::Any || *s == Source::Address(source))
            {
                continue;
            }
            if rule.reject {
                return false;
            }
            let mapping = rule
                .users
                .iter()
                .find(|(name, _)| name == requested)
                .or_else(|| rule.users.iter().find(|(name, _)| name == "*"));
            let Some((_, mapped)) = mapping else { continue };
            if mapped.is_empty() {
                continue;
            }
            // '=' implements autogroup:nonroot, not unrestricted identity mapping.
            let mapped = if mapped == "=" {
                if requested == "root" || requested.parse::<u32>() == Ok(0) {
                    continue;
                }
                requested
            } else {
                mapped.as_str()
            };
            return rule.accept && mapped == local_user;
        }
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Policy,
    Rules,
    Rule,
    Principals,
    Principal,
    Users,
    Action,
    Empty,
    Ignore,
}

/// One extra token consumer; reuses the netmap's JSON scanner and token buffer.
pub(crate) struct Builder {
    stack: Vec<(Context, u16), 16>,
    key: String<64>,
    rule: Rule,
    bad: bool,
    seen: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub const fn new() -> Self {
        Self {
            stack: Vec::new(),
            key: String::new(),
            rule: Rule {
                sources: Vec::new(),
                users: Vec::new(),
                accept: false,
                reject: false,
            },
            bad: false,
            seen: false,
        }
    }

    pub(crate) fn token(&mut self, policy: &mut Policy, token: &Token<'_>, field: bool) {
        if self.stack.is_empty() {
            if !field {
                return;
            }
            let duplicate = self.seen;
            self.seen = true;
            if matches!(token, Token::Null) {
                if duplicate {
                    policy.valid = false;
                }
                return;
            }
            policy.rules.clear();
            policy.valid = false;
            self.bad = duplicate;
            self.key.clear();
            if matches!(token, Token::StartObject) {
                let _ = self.stack.push((Context::Policy, 0));
            }
            return;
        }
        let context = self.stack.last().unwrap().0;
        match token {
            Token::Key(key) => {
                self.key.clear();
                if self.key.push_str(key).is_err() {
                    self.bad = true;
                }
                let bit = match (context, *key) {
                    (Context::Policy, "rules") => 1,
                    (Context::Rule, "principals") => 1,
                    (Context::Rule, "sshUsers") => 2,
                    (Context::Rule, "action") => 4,
                    (Context::Rule, "ruleExpires") => 8,
                    (Context::Rule, "acceptEnv") => 16,
                    (Context::Principal, "nodeIP") => 1,
                    (Context::Principal, "any") => 2,
                    (Context::Action, "accept") => 1,
                    (Context::Action, "reject") => 2,
                    (Context::Action, "message") => 4,
                    (Context::Action, "holdAndDelegate") => 8,
                    (Context::Action, "sessionDuration") => 16,
                    (Context::Action, "recorders") => 32,
                    (Context::Action, "onRecordingFailure") => 64,
                    (Context::Action, "allowAgentForwarding") => 128,
                    (Context::Action, "allowLocalPortForwarding") => 256,
                    (Context::Action, "allowRemotePortForwarding") => 512,
                    (Context::Users | Context::Ignore, _) => 0,
                    _ => {
                        self.bad = true;
                        0
                    }
                };
                let seen = &mut self.stack.last_mut().unwrap().1;
                if *seen & bit != 0 {
                    self.bad = true;
                }
                *seen |= bit;
            }
            Token::StartObject | Token::StartArray => {
                let object = matches!(token, Token::StartObject);
                let next = match (context, self.key.as_str(), object) {
                    (Context::Policy, "rules", false) => Context::Rules,
                    (Context::Rules, _, true) => {
                        self.rule = Rule::default();
                        Context::Rule
                    }
                    (Context::Rule, "principals", false) => Context::Principals,
                    (Context::Principals, _, true) => Context::Principal,
                    (Context::Rule, "sshUsers", true) => Context::Users,
                    (Context::Rule, "action", true) => Context::Action,
                    // No environment variables are forwarded by the console.
                    (Context::Rule, "acceptEnv", false) => Context::Ignore,
                    (Context::Action, "recorders", false) => Context::Empty,
                    (Context::Ignore, _, _) => Context::Ignore,
                    _ => {
                        self.bad = true;
                        Context::Ignore
                    }
                };
                if self.stack.push((next, 0)).is_err() {
                    self.bad = true;
                    // Keep nesting balanced even for hostile deeply nested input:
                    // the outer netmap scanner will report its depth bound.
                    policy.valid = false;
                }
                self.key.clear();
            }
            Token::EndObject | Token::EndArray => {
                let closed = self.stack.pop().unwrap().0;
                if closed == Context::Rule && policy.rules.push(self.rule.clone()).is_err() {
                    self.bad = true;
                }
                if self.stack.is_empty() {
                    policy.valid = !self.bad;
                }
                self.key.clear();
            }
            Token::Str(value) => match (context, self.key.as_str()) {
                (Context::Principal, "nodeIP") => match value.parse::<Ipv4Addr>() {
                    Ok(address) => self.source(Source::Address(address)),
                    Err(_) => self.bad = true,
                },
                (Context::Users, key) => {
                    if self.rule.users.iter().any(|(name, _)| name == key) {
                        self.bad = true;
                    }
                    match (String::try_from(key), String::try_from(*value)) {
                        (Ok(name), Ok(mapped)) => {
                            if self.rule.users.push((name, mapped)).is_err() {
                                self.bad = true;
                            }
                        }
                        _ => self.bad = true,
                    }
                }
                (Context::Action, "message") | (Context::Ignore, _) => (),
                (Context::Action, "holdAndDelegate") if value.is_empty() => (),
                _ => self.bad = true,
            },
            Token::Bool(value) => match (context, self.key.as_str()) {
                (Context::Principal, "any") => {
                    if *value {
                        self.source(Source::Any);
                    }
                }
                (Context::Action, "accept") => self.rule.accept = *value,
                (Context::Action, "reject") => self.rule.reject = *value,
                (
                    Context::Action,
                    "allowAgentForwarding"
                    | "allowLocalPortForwarding"
                    | "allowRemotePortForwarding",
                ) => (),
                (Context::Ignore, _) => (),
                _ => self.bad = true,
            },
            Token::Int(0) if context == Context::Action && self.key == "sessionDuration" => (),
            Token::Null => match (context, self.key.as_str()) {
                (Context::Policy, "rules")
                | (
                    Context::Rule,
                    "principals" | "sshUsers" | "action" | "ruleExpires" | "acceptEnv",
                )
                | (Context::Action, "recorders" | "onRecordingFailure")
                | (Context::Ignore, _) => (),
                _ => self.bad = true,
            },
            _ => self.bad = true,
        }
    }

    fn source(&mut self, source: Source) {
        if self.rule.sources.push(source).is_err() {
            self.bad = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netmap::{Netmap, Parser};

    fn apply(map: &mut Netmap<1>, json: &str) {
        let mut parser = Parser::new();
        for chunk in json.as_bytes().chunks(1) {
            parser.push(map, chunk).unwrap();
        }
        parser.finish(map).unwrap();
    }

    fn allowed(map: &Netmap<1>, username: &str) -> bool {
        map.ssh_policy
            .allows(Ipv4Addr::new(100, 64, 0, 2), username, username)
    }

    const ACCEPT: &str = r#"{"SSHPolicy":{"rules":[{"principals":[{"nodeIP":"100.64.0.2"}],"sshUsers":{"*":"=","root":""},"action":{"accept":true}}]}}"#;

    #[test]
    fn fragmented_policy_and_deltas_preserve_or_revoke_access() {
        let mut map = Netmap::new();
        assert!(!allowed(&map, "console"));
        apply(&mut map, ACCEPT);
        assert!(allowed(&map, "console"));
        assert!(!allowed(&map, "root"));
        assert!(!allowed(&map, "0"));
        assert!(
            !map.ssh_policy
                .allows(Ipv4Addr::new(100, 64, 0, 3), "console", "console")
        );
        assert!(
            !map.ssh_policy
                .allows(Ipv4Addr::new(100, 64, 0, 2), "console", "another")
        );
        apply(&mut map, r#"{"SSHPolicy":null,"KeepAlive":true}"#);
        assert!(allowed(&map, "console"));
        apply(&mut map, r#"{"KeepAlive":true}"#);
        assert!(allowed(&map, "console"));
        apply(&mut map, r#"{"SSHPolicy":{"rules":[]}}"#);
        assert!(!allowed(&map, "console"));
    }

    #[test]
    fn unsupported_requirements_never_fall_through_to_an_accept() {
        let mut map = Netmap::new();
        for extra in [
            r#", "holdAndDelegate":"https://control/check""#,
            r#", "sessionDuration":1"#,
            r#", "sessionDuration":0.5"#,
            r#", "sessionDuration":1e9"#,
            r#", "sessionDuration":18446744073709551616"#,
            r#", "recorders":["100.64.0.3:80"]"#,
            r#", "onRecordingFailure":{}"#,
            r#", "futureRequirement":true"#,
            r#", "accept":true"#,
        ] {
            let json = std::format!(
                r#"{{"SSHPolicy":{{"rules":[{{"principals":[{{"any":true}}],"sshUsers":{{"*":"="}},"action":{{"accept":true{extra}}}}}]}}}}"#
            );
            apply(&mut map, &json);
            assert!(!map.ssh_policy.is_supported(), "{extra}");
            assert!(!allowed(&map, "console"));
        }
        for rule in [
            r#"{"principals":[{"any":true}],"ruleExpires":"2099-01-01T00:00:00Z","sshUsers":{"*":"="},"action":{"accept":true}}"#,
            r#"{"principals":[{"userLogin":"user@example.com"}],"sshUsers":{"*":"="},"action":{"accept":true}}"#,
            r#"{"principals":[{"node":"n123"}],"sshUsers":{"*":"="},"action":{"accept":true}}"#,
            r#"{"principals":[{"nodeIP":true}],"sshUsers":{"*":"="},"action":{"accept":true}}"#,
        ] {
            let json = std::format!(
                r#"{{"SSHPolicy":{{"rules":[{rule},{{"principals":[{{"any":true}}],"sshUsers":{{"*":"="}},"action":{{"accept":true}}}}]}}}}"#
            );
            apply(&mut map, &json);
            assert!(!allowed(&map, "console"), "{rule}");
        }
    }

    #[test]
    fn rejects_ordering_and_explicit_username_mapping_are_enforced() {
        let mut map = Netmap::new();
        apply(
            &mut map,
            r#"{"SSHPolicy":{"rules":[{"principals":[{"any":true}],"action":{"reject":true,"accept":true}},{"principals":[{"any":true}],"sshUsers":{"console":"console"},"action":{"accept":true}}]}}"#,
        );
        assert!(!allowed(&map, "console"));
        apply(
            &mut map,
            r#"{"SSHPolicy":{"rules":[{"principals":[{"any":true}],"sshUsers":{"dev":"console","*":"other"},"action":{"accept":true,"recorders":[],"sessionDuration":0,"allowLocalPortForwarding":true}}]}}"#,
        );
        assert!(map.ssh_policy.allows(Ipv4Addr::LOCALHOST, "dev", "console"));
        assert!(!map.ssh_policy.allows(Ipv4Addr::LOCALHOST, "dev", "other"));
    }

    #[test]
    fn incomplete_policy_and_capacity_overflow_authorize_nobody() {
        let mut map = Netmap::new();
        apply(&mut map, ACCEPT);
        let mut parser = Parser::new();
        parser
            .push(
                &mut map,
                br#"{"SSHPolicy":{"rules":[{"principals":[{"any":true}]"#,
            )
            .unwrap();
        assert!(!allowed(&map, "console"));
        assert!(parser.finish(&mut map).is_err());
        let rule = r#"{"principals":[{"any":true}],"sshUsers":{"*":"="},"action":{"accept":true}}"#;
        let rules = [rule; MAX_RULES + 1].join(",");
        apply(
            &mut map,
            &std::format!(r#"{{"SSHPolicy":{{"rules":[{rules}]}}}}"#),
        );
        assert!(!allowed(&map, "console"));
        apply(&mut map, ACCEPT);
        let duplicate = ACCEPT.replacen('{', "{\"SSHPolicy\":null,", 1);
        apply(&mut map, &duplicate);
        assert!(!allowed(&map, "console"));
    }
}
