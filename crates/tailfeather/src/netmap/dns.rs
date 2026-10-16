//! The DNS configuration the control plane publishes.
//!
//! `DNSConfig` was skipped wholesale until a real Headscale payload was read
//! closely: alongside the three fields a headless node can act on — the search
//! domains, the upstream resolvers, and whether the tailnet expects DNS to be
//! proxied — it carries a `Routes` map with one entry per reverse-DNS zone the
//! tailnet claims. That map has sixty-five members in the captured lab response
//! and grows with the address space, so it is the one part of this subtree with
//! no fixed bound at all.
//!
//! Nothing here retains it. `Routes` stays an ignored subtree, traversed for the
//! cost of a push and a pop, which is what keeps an unbounded map from becoming
//! an unbounded table. What *is* retained is bounded twice over: a fixed number
//! of entries, each a fixed-length string.
//!
//! # Overflow drops rather than fails
//!
//! Unlike the DERP map, a domain or resolver past the bound is discarded and
//! recorded, not turned into an error. A relay this node cannot reach makes it
//! unreachable; a fourth search domain it cannot remember costs a suffix. The
//! netmap is still usable, and rejecting the whole response would cost the node
//! its control-plane session over a field it barely reads.

use crate::netmap::{MAX_DNS_DOMAINS, MAX_DNS_NAME, MAX_DNS_RESOLVERS};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    domains: heapless::Vec<heapless::String<MAX_DNS_NAME>, MAX_DNS_DOMAINS>,
    resolvers: heapless::Vec<heapless::String<MAX_DNS_NAME>, MAX_DNS_RESOLVERS>,
    /// The tailnet expects name resolution to go through the node rather than
    /// around it. Reported as sent; acting on it is the caller's decision.
    pub proxied: bool,
    /// Entries the bounds above discarded. Kept so a caller can say "the
    /// tailnet named more than this device retains" rather than silently
    /// presenting a shortened list as complete.
    pub truncated: bool,
}

impl DnsConfig {
    pub const fn new() -> Self {
        Self {
            domains: heapless::Vec::new(),
            resolvers: heapless::Vec::new(),
            proxied: false,
            truncated: false,
        }
    }

    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(heapless::String::as_str)
    }

    /// The upstream resolvers, as published. Tailscale's `Addr` is an IP
    /// literal for a plain resolver and a URL for a DoH one, so this stays text
    /// and [`Self::resolver_addresses`] does the narrowing.
    pub fn resolvers(&self) -> impl Iterator<Item = &str> {
        self.resolvers.iter().map(heapless::String::as_str)
    }

    /// Just the resolvers this node can send a UDP query to.
    pub fn resolver_addresses(&self) -> impl Iterator<Item = core::net::IpAddr> + '_ {
        self.resolvers.iter().filter_map(|addr| addr.parse().ok())
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.resolvers.is_empty() && !self.proxied
    }

    pub fn clear(&mut self) {
        self.domains.clear();
        self.resolvers.clear();
        self.proxied = false;
        self.truncated = false;
    }

    /// Retain one search domain, or record that it did not fit.
    pub fn push_domain(&mut self, domain: &str) {
        self.truncated |= match heapless::String::try_from(domain) {
            Ok(domain) => self.domains.push(domain).is_err(),
            Err(_) => true,
        };
    }

    /// Retain one resolver address, or record that it did not fit.
    pub fn push_resolver(&mut self, address: &str) {
        self.truncated |= match heapless::String::try_from(address) {
            Ok(address) => self.resolvers.push(address).is_err(),
            Err(_) => true,
        };
    }

    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.domains.clear();
        for domain in &source.domains {
            self.domains
                .push(domain.clone())
                .expect("equal DNS domain capacities");
        }
        self.resolvers.clear();
        for resolver in &source.resolvers {
            self.resolvers
                .push(resolver.clone())
                .expect("equal DNS resolver capacities");
        }
        self.proxied = source.proxied;
        self.truncated = source.truncated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_is_recorded_rather_than_dropped_silently() {
        let mut config = DnsConfig::new();
        for index in 0..MAX_DNS_DOMAINS {
            config.push_domain(&alloc_name(index));
        }
        assert!(!config.truncated);
        assert_eq!(config.domains().count(), MAX_DNS_DOMAINS);
        config.push_domain("one.too.many");
        assert!(config.truncated);
        assert_eq!(config.domains().count(), MAX_DNS_DOMAINS);
    }

    #[test]
    fn a_name_longer_than_the_bound_is_not_stored_truncated() {
        let mut config = DnsConfig::new();
        let long = [b'a'; MAX_DNS_NAME + 1];
        config.push_domain(core::str::from_utf8(&long).unwrap());
        assert!(config.truncated);
        assert_eq!(config.domains().count(), 0);
    }

    #[test]
    fn only_resolvers_that_parse_become_addresses() {
        let mut config = DnsConfig::new();
        config.push_resolver("1.1.1.1");
        config.push_resolver("https://dns.example/dns-query");
        assert_eq!(config.resolvers().count(), 2);
        let addresses: heapless::Vec<_, MAX_DNS_RESOLVERS> = config.resolver_addresses().collect();
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0],
            "1.1.1.1".parse::<core::net::IpAddr>().unwrap()
        );
    }

    fn alloc_name(index: usize) -> heapless::String<MAX_DNS_NAME> {
        let mut name = heapless::String::new();
        use core::fmt::Write as _;
        write!(name, "domain{index}.internal").unwrap();
        name
    }
}
