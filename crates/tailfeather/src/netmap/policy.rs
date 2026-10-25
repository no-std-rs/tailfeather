//! Bounded packet-filter state carried by streaming netmaps.

use core::net::{IpAddr, Ipv4Addr};
use core::str::FromStr;

use heapless::{String, Vec};

use crate::netmap::{CapacityError, Cidr, Error};

pub const MAX_FILTER_SETS: usize = 8;
/// Preserve the hosted-policy capacity supported by earlier firmware while
/// keeping every collection statically bounded.
pub const MAX_FILTER_RULES: usize = 32;
#[cfg(not(feature = "hosted-policy"))]
pub const MAX_FILTER_SOURCES: usize = 8;
#[cfg(feature = "hosted-policy")]
pub const MAX_FILTER_SOURCES: usize = 512;
#[cfg(not(feature = "hosted-policy"))]
pub const MAX_FILTER_DESTINATIONS: usize = 8;
#[cfg(feature = "hosted-policy")]
pub const MAX_FILTER_DESTINATIONS: usize = 512;
pub const MAX_FILTER_PROTOCOLS: usize = 8;
pub const MAX_FILTER_SET_NAME: usize = 32;

/// An inclusive IPv4 range. IPv6 entries use the empty `1..=0` sentinel: they
/// are valid tailcfg but never match this IPv4-only forwarding milestone.
/// Keeping this at eight bytes matters because a bounded policy contains up to
/// 1024 source/destination networks in hosted builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    first: u32,
    last: u32,
}

impl Network {
    pub const ANY: Self = Self {
        first: 0,
        last: u32::MAX,
    };
    const V6: Self = Self { first: 1, last: 0 };

    pub fn parse(text: &str) -> Result<Self, Error> {
        if text == "*" {
            return Ok(Self::ANY);
        }
        if let Some((first, last)) = text.split_once('-') {
            return match (IpAddr::from_str(first), IpAddr::from_str(last)) {
                (Ok(IpAddr::V4(first)), Ok(IpAddr::V4(last))) if first <= last => Ok(Self {
                    first: u32::from(first),
                    last: u32::from(last),
                }),
                (Ok(IpAddr::V6(first)), Ok(IpAddr::V6(last))) if first <= last => Ok(Self::V6),
                _ => Err(Error::Malformed),
            };
        }
        let (address, prefix) = if text.contains('/') {
            let cidr = Cidr::parse(text)?;
            (cidr.address, cidr.prefix)
        } else {
            let address = IpAddr::from_str(text).map_err(|_| Error::Malformed)?;
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            (address, prefix)
        };
        match address {
            IpAddr::V4(address) => {
                let mask = prefix_mask(prefix);
                let first = u32::from(address) & mask;
                Ok(Self {
                    first,
                    last: first | !mask,
                })
            }
            IpAddr::V6(_) => Ok(Self::V6),
        }
    }

    fn contains_v4(self, address: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(address))
    }
}

const fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    pub network: Network,
    pub first_port: u16,
    pub last_port: u16,
}

impl Destination {
    fn matches(self, address: Ipv4Addr, port: u16) -> bool {
        self.network.contains_v4(address) && (self.first_port..=self.last_port).contains(&port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub sources: Vec<Network, MAX_FILTER_SOURCES>,
    pub destinations: Vec<Destination, MAX_FILTER_DESTINATIONS>,
    /// Empty means any IP protocol, matching tailcfg semantics.
    pub protocols: Vec<u8, MAX_FILTER_PROTOCOLS>,
}

impl FilterRule {
    pub const fn new() -> Self {
        Self {
            sources: Vec::new(),
            destinations: Vec::new(),
            protocols: Vec::new(),
        }
    }

    pub fn is_well_formed(&self) -> bool {
        !self.sources.is_empty()
            && !self.destinations.is_empty()
            && self
                .destinations
                .iter()
                .all(|destination| destination.first_port <= destination.last_port)
    }

    fn matches(&self, source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, port: u16) -> bool {
        (self.protocols.is_empty() || self.protocols.contains(&protocol))
            && self
                .sources
                .iter()
                .any(|network| network.contains_v4(source))
            && self
                .destinations
                .iter()
                .any(|rule| rule.matches(destination, port))
    }
}

impl Default for FilterRule {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct StoredRule {
    set: u8,
    rule: FilterRule,
}

#[derive(Debug, Clone)]
struct FilterSet {
    name: String<MAX_FILTER_SET_NAME>,
    id: u8,
}

/// Incremental named filter sets with one global rule bound.
#[derive(Debug, Clone)]
pub struct PacketPolicy {
    sets: Vec<FilterSet, MAX_FILTER_SETS>,
    rules: Vec<StoredRule, MAX_FILTER_RULES>,
    valid: bool,
}

impl PacketPolicy {
    pub const fn new() -> Self {
        Self {
            sets: Vec::new(),
            rules: Vec::new(),
            valid: false,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn set_count(&self) -> usize {
        self.sets.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.sets.clear();
        for set in &source.sets {
            self.sets
                .push(set.clone())
                .expect("equal packet-filter set capacities");
        }
        self.rules.clear();
        for rule in &source.rules {
            self.rules
                .push(rule.clone())
                .expect("equal packet-filter rule capacities");
        }
        self.valid = source.valid;
    }

    pub fn mark_present(&mut self) {
        self.valid = true;
    }

    pub fn replace_set(&mut self, name: &str) -> Result<(), Error> {
        self.valid_name(name)?;
        self.delete_set(name);
        let id = (0..MAX_FILTER_SETS as u8)
            .find(|candidate| self.sets.iter().all(|set| set.id != *candidate))
            .ok_or(Error::Full(CapacityError::PacketPolicy))?;
        self.sets
            .push(FilterSet {
                name: String::try_from(name)
                    .map_err(|_| Error::Full(CapacityError::PacketPolicy))?,
                id,
            })
            .map_err(|_| Error::Full(CapacityError::PacketPolicy))?;
        self.valid = true;
        Ok(())
    }

    pub fn delete_set(&mut self, name: &str) {
        if let Some(id) = self
            .sets
            .iter()
            .find(|set| set.name.as_str() == name)
            .map(|set| set.id)
        {
            self.rules.retain(|rule| rule.set != id);
        }
        self.sets.retain(|set| set.name.as_str() != name);
        self.valid = true;
    }

    pub fn clear(&mut self) {
        self.sets.clear();
        self.rules.clear();
        self.valid = true;
    }

    pub fn push_rule(&mut self, set: &str, rule: FilterRule) -> Result<(), Error> {
        if !rule.is_well_formed() {
            return Err(Error::Malformed);
        }
        let set = self
            .sets
            .iter()
            .find(|entry| entry.name.as_str() == set)
            .map(|entry| entry.id)
            .ok_or(Error::Malformed)?;
        self.rules
            .push(StoredRule { set, rule })
            .map_err(|_| Error::Full(CapacityError::PacketPolicy))
    }

    pub fn allows(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        destination_port: u16,
    ) -> bool {
        self.valid
            && self.rules.iter().any(|stored| {
                stored
                    .rule
                    .matches(source, destination, protocol, destination_port)
            })
    }

    /// Whether `source` holds a UDP DNS grant for the exit-node proxy.
    ///
    /// The proxy is a service of the exit node, not a client-originated packet
    /// to its upstream resolver. A grant to any IPv4 destination on port 53
    /// therefore authorizes use of the service; the gateway's DHCP-selected
    /// upstream is deliberately not matched against the client's policy.
    pub fn allows_dns_from(&self, source: Ipv4Addr) -> bool {
        self.valid
            && self.rules.iter().any(|stored| {
                let rule = &stored.rule;
                (rule.protocols.is_empty() || rule.protocols.contains(&17))
                    && rule
                        .sources
                        .iter()
                        .any(|network| network.contains_v4(source))
                    && rule.destinations.iter().any(|destination| {
                        destination.network.first <= destination.network.last
                            && (destination.first_port..=destination.last_port).contains(&53)
                    })
            })
    }

    /// Parse the fields needed for an IPv4 ACL decision and fail closed on
    /// fragments or malformed lengths.
    pub fn allows_ipv4(&self, packet: &[u8]) -> bool {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return false;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_len < 20 || total_len < header_len || total_len > packet.len() {
            return false;
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if fragment & 0x3fff != 0 {
            return false;
        }
        let source = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap());
        let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap());
        let protocol = packet[9];
        let destination_port = match protocol {
            6 | 17 if total_len >= header_len + 4 => {
                u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]])
            }
            6 | 17 => return false,
            _ => 0,
        };
        self.allows(source, destination, protocol, destination_port)
    }

    fn valid_name(&self, name: &str) -> Result<(), Error> {
        if name.is_empty() || name.len() > MAX_FILTER_SET_NAME {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
}

impl Default for PacketPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_rule() -> FilterRule {
        let mut rule = FilterRule::new();
        rule.sources.push(Network::ANY).unwrap();
        rule.destinations
            .push(Destination {
                network: Network::ANY,
                first_port: 0,
                last_port: u16::MAX,
            })
            .unwrap();
        rule
    }

    #[test]
    fn replacement_and_deletion_are_set_scoped() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("base").unwrap();
        policy.push_rule("base", any_rule()).unwrap();
        policy.replace_set("ssh").unwrap();
        policy.push_rule("ssh", any_rule()).unwrap();
        assert_eq!(policy.rule_count(), 2);
        policy.replace_set("base").unwrap();
        assert_eq!(policy.rule_count(), 1);
        policy.delete_set("ssh");
        assert_eq!(policy.rule_count(), 0);
        assert!(policy.is_valid());
    }

    #[test]
    fn bounds_are_errors_not_truncation() {
        let mut policy = PacketPolicy::new();
        for index in 0..MAX_FILTER_SETS {
            let mut name = String::<8>::new();
            use core::fmt::Write as _;
            write!(name, "s{index}").unwrap();
            policy.replace_set(&name).unwrap();
        }
        assert_eq!(
            policy.replace_set("overflow"),
            Err(Error::Full(CapacityError::PacketPolicy))
        );
    }

    #[test]
    fn hosted_source_hosts_and_ranges_are_exact() {
        let host = Network::parse("100.64.0.7").unwrap();
        assert!(host.contains_v4("100.64.0.7".parse().unwrap()));
        assert!(!host.contains_v4("100.64.0.8".parse().unwrap()));

        let range = Network::parse("100.64.0.7-100.64.0.9").unwrap();
        assert!(range.contains_v4("100.64.0.8".parse().unwrap()));
        assert!(!range.contains_v4("100.64.0.10".parse().unwrap()));
        assert_eq!(
            Network::parse("100.64.0.9-100.64.0.7"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn dns_proxy_accepts_a_grant_to_any_destination() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("dns").unwrap();
        let mut rule = FilterRule::new();
        rule.sources
            .push(Network::parse("100.64.0.0/10").unwrap())
            .unwrap();
        rule.protocols.push(17).unwrap();
        rule.destinations
            .push(Destination {
                // The proxy's own uplink may choose a different resolver; this
                // narrow private grant still authorizes the proxy service.
                network: Network::parse("10.211.0.2").unwrap(),
                first_port: 53,
                last_port: 53,
            })
            .unwrap();
        policy.push_rule("dns", rule).unwrap();

        assert!(policy.allows_dns_from("100.64.0.2".parse().unwrap()));
        assert!(!policy.allows_dns_from("100.128.0.2".parse().unwrap()));
    }
}
