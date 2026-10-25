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
pub const MAX_FILTER_SOURCES: usize = 256;
#[cfg(not(feature = "hosted-policy"))]
pub const MAX_FILTER_DESTINATIONS: usize = 8;
#[cfg(feature = "hosted-policy")]
pub const MAX_FILTER_DESTINATIONS: usize = 256;
pub const MAX_FILTER_PROTOCOLS: usize = 8;
pub const MAX_FILTER_SET_NAME: usize = 32;

/// An inclusive address range. Wildcards match both address families; an
/// IPv4 default route never implicitly grants access to IPv6 destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Any,
    V4 { first: u32, last: u32 },
    V6 { first: [u8; 16], last: [u8; 16] },
}

impl Network {
    pub const ANY: Self = Self::Any;
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text == "*" {
            return Ok(Self::Any);
        }
        if let Some((first, last)) = text.split_once('-') {
            return match (IpAddr::from_str(first), IpAddr::from_str(last)) {
                (Ok(IpAddr::V4(first)), Ok(IpAddr::V4(last))) if first <= last => Ok(Self::V4 {
                    first: u32::from(first),
                    last: u32::from(last),
                }),
                (Ok(IpAddr::V6(first)), Ok(IpAddr::V6(last))) if first <= last => Ok(Self::V6 {
                    first: first.octets(),
                    last: last.octets(),
                }),
                _ => Err(Error::Malformed),
            };
        }
        let (address, prefix) = if text.contains('/') {
            let cidr = Cidr::parse(text)?;
            (cidr.address, cidr.prefix)
        } else {
            let address = IpAddr::from_str(text).map_err(|_| Error::Malformed)?;
            (address, if address.is_ipv4() { 32 } else { 128 })
        };
        match address {
            IpAddr::V4(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let first = u32::from(address) & mask;
                Ok(Self::V4 {
                    first,
                    last: first | !mask,
                })
            }
            IpAddr::V6(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let first = u128::from(address) & mask;
                Ok(Self::V6 {
                    first: first.to_be_bytes(),
                    last: (first | !mask).to_be_bytes(),
                })
            }
        }
    }
    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::Any, _) => true,
            (Self::V4 { first, last }, IpAddr::V4(address)) => {
                (first..=last).contains(&u32::from(address))
            }
            (Self::V6 { first, last }, IpAddr::V6(address)) => {
                (first..=last).contains(&address.octets())
            }
            _ => false,
        }
    }
    fn contains_v4(self, address: Ipv4Addr) -> bool {
        self.contains(IpAddr::V4(address))
    }
}

// Existing IPv4 policies keep their eight-byte network storage. At most 32
// distinct IPv6 ranges are interned separately; overflow rejects the map,
// never broadens an ACL. Deleting a named set reclaims unreferenced ranges.
#[cfg(not(feature = "hosted-policy"))]
const MAX_V6_NETWORKS: usize = 32;
#[cfg(feature = "hosted-policy")]
const MAX_V6_NETWORKS: usize = 256;
#[derive(Debug, Clone, Copy)]
struct StoredNetwork {
    first: u32,
    last: u32,
}
#[derive(Debug, Clone)]
struct StoredDestination {
    network: StoredNetwork,
    first_port: u16,
    last_port: u16,
}
#[derive(Debug, Clone)]
struct StoredFilterRule {
    sources: Vec<StoredNetwork, MAX_FILTER_SOURCES>,
    destinations: Vec<StoredDestination, MAX_FILTER_DESTINATIONS>,
    protocols: Vec<u8, MAX_FILTER_PROTOCOLS>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    pub network: Network,
    pub first_port: u16,
    pub last_port: u16,
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
}

impl Default for FilterRule {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct StoredRule {
    set: u8,
    rule: StoredFilterRule,
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
    v6_networks: [Option<Network>; MAX_V6_NETWORKS],
}

impl PacketPolicy {
    pub const fn new() -> Self {
        Self {
            sets: Vec::new(),
            rules: Vec::new(),
            valid: false,
            v6_networks: [None; MAX_V6_NETWORKS],
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
        self.v6_networks = source.v6_networks;
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
        self.collect_networks();
        self.valid = true;
    }

    pub fn clear(&mut self) {
        self.sets.clear();
        self.rules.clear();
        self.v6_networks.fill(None);
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
        let result = (|| {
            let mut compact = StoredFilterRule {
                sources: Vec::new(),
                destinations: Vec::new(),
                protocols: rule.protocols,
            };
            for network in rule.sources {
                let network = self.store_network(network)?;
                compact
                    .sources
                    .push(network)
                    .map_err(|_| Error::Full(CapacityError::PacketPolicy))?;
            }
            for destination in rule.destinations {
                let network = self.store_network(destination.network)?;
                compact
                    .destinations
                    .push(StoredDestination {
                        network,
                        first_port: destination.first_port,
                        last_port: destination.last_port,
                    })
                    .map_err(|_| Error::Full(CapacityError::PacketPolicy))?;
            }
            self.rules
                .push(StoredRule { set, rule: compact })
                .map_err(|_| Error::Full(CapacityError::PacketPolicy))
        })();
        if result.is_err() {
            self.collect_networks();
        }
        result
    }

    fn store_network(&mut self, network: Network) -> Result<StoredNetwork, Error> {
        match network {
            Network::Any => Ok(StoredNetwork {
                first: u32::MAX,
                last: 0,
            }),
            Network::V4 { first, last } if first <= last => Ok(StoredNetwork { first, last }),
            Network::V6 { first, last } if first <= last => {
                let index = self
                    .v6_networks
                    .iter()
                    .position(|entry| *entry == Some(network))
                    .or_else(|| self.v6_networks.iter().position(Option::is_none))
                    .ok_or(Error::Full(CapacityError::PacketPolicy))?;
                self.v6_networks[index] = Some(network);
                Ok(StoredNetwork {
                    first: index as u32 + 1,
                    last: 0,
                })
            }
            _ => Err(Error::Malformed),
        }
    }
    fn network(&self, stored: StoredNetwork) -> Option<Network> {
        if stored.first <= stored.last {
            Some(Network::V4 {
                first: stored.first,
                last: stored.last,
            })
        } else if stored.first == u32::MAX {
            Some(Network::Any)
        } else {
            self.v6_networks
                .get(stored.first as usize - 1)
                .copied()
                .flatten()
        }
    }
    fn collect_networks(&mut self) {
        for index in 0..MAX_V6_NETWORKS {
            let used = self.rules.iter().any(|stored| {
                stored
                    .rule
                    .sources
                    .iter()
                    .chain(stored.rule.destinations.iter().map(|d| &d.network))
                    .any(|network| network.first == index as u32 + 1 && network.last == 0)
            });
            if !used {
                self.v6_networks[index] = None;
            }
        }
    }
    fn allows_ip(&self, source: IpAddr, destination: IpAddr, protocol: u8, port: u16) -> bool {
        self.valid
            && self.rules.iter().any(|stored| {
                let rule = &stored.rule;
                (rule.protocols.is_empty() || rule.protocols.contains(&protocol))
                    && rule
                        .sources
                        .iter()
                        .any(|network| self.network(*network).is_some_and(|n| n.contains(source)))
                    && rule.destinations.iter().any(|d| {
                        self.network(d.network)
                            .is_some_and(|n| n.contains(destination))
                            && (d.first_port..=d.last_port).contains(&port)
                    })
            })
    }
    pub fn allows(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        destination_port: u16,
    ) -> bool {
        self.allows_ip(
            IpAddr::V4(source),
            IpAddr::V4(destination),
            protocol,
            destination_port,
        )
    }

    /// Match fixed-header IPv6 UDP/TCP/ICMPv6 packets. Extension/fragment
    /// headers are unsupported and fail closed, matching the gateway parser.
    pub fn allows_ipv6(&self, packet: &[u8]) -> bool {
        if packet.len() < 40
            || packet[0] >> 4 != 6
            || 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])) != packet.len()
        {
            return false;
        }
        let protocol = packet[6];
        let port = match protocol {
            6 if packet.len() >= 60 => u16::from_be_bytes([packet[42], packet[43]]),
            17 if packet.len() >= 48 => u16::from_be_bytes([packet[42], packet[43]]),
            58 if packet.len() >= 48 => 0,
            _ => return false,
        };
        let source = core::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
        let destination = core::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        self.allows_ip(source.into(), destination.into(), protocol, port)
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
                    && rule.sources.iter().any(|network| {
                        self.network(*network)
                            .is_some_and(|n| n.contains_v4(source))
                    })
                    && rule.destinations.iter().any(|destination| {
                        self.network(destination.network).is_some_and(|network| {
                            matches!(network, Network::Any | Network::V4 { .. })
                        }) && (destination.first_port..=destination.last_port).contains(&53)
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

    #[test]
    fn ipv6_grants_preserve_prefix_ranges_protocols_and_family_boundaries() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("v6").unwrap();
        let mut rule = FilterRule::new();
        rule.sources
            .push(Network::parse("fd7a:115c:a1e0::1-fd7a:115c:a1e0::3").unwrap())
            .unwrap();
        rule.destinations
            .push(Destination {
                network: Network::parse("2001:db8::/64").unwrap(),
                first_port: 443,
                last_port: 443,
            })
            .unwrap();
        rule.protocols.push(6).unwrap();
        policy.push_rule("v6", rule).unwrap();
        let mut packet = [0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = 6;
        packet[8..24].copy_from_slice(
            &"fd7a:115c:a1e0::2"
                .parse::<core::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(
            &"2001:db8::5"
                .parse::<core::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        assert!(policy.allows_ipv6(&packet));
        packet[43] = 80;
        assert!(!policy.allows_ipv6(&packet));
        packet[43] = 187;
        packet[23] = 4;
        assert!(!policy.allows_ipv6(&packet));
        assert!(!policy.allows(
            "100.64.0.2".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            6,
            443
        ));
        assert!(
            !Network::parse("0.0.0.0/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert!(
            !Network::parse("::/0")
                .unwrap()
                .contains("192.0.2.1".parse().unwrap())
        );
        assert!(Network::ANY.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn replacing_named_sets_reclaims_interned_ipv6_networks() {
        let mut policy = PacketPolicy::new();
        for index in 0..MAX_V6_NETWORKS * 2 {
            policy.replace_set("rotating").unwrap();
            let mut rule = any_rule();
            rule.sources.clear();
            let mut text = String::<48>::new();
            use core::fmt::Write as _;
            write!(&mut text, "2001:db8::{index:x}").unwrap();
            rule.sources.push(Network::parse(&text).unwrap()).unwrap();
            policy.push_rule("rotating", rule).unwrap();
            assert_eq!(policy.v6_networks.iter().flatten().count(), 1);
        }
    }

    #[test]
    fn ipv6_pool_overflow_preserves_existing_grants_and_rejects_new_ones() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("v6").unwrap();
        let mut index = 0;
        while index < MAX_V6_NETWORKS {
            let mut rule = any_rule();
            rule.sources.clear();
            for _ in 0..MAX_FILTER_SOURCES.min(MAX_V6_NETWORKS - index) {
                let mut text = String::<48>::new();
                use core::fmt::Write as _;
                write!(&mut text, "2001:db8::{index:x}").unwrap();
                rule.sources.push(Network::parse(&text).unwrap()).unwrap();
                index += 1;
            }
            policy.push_rule("v6", rule).unwrap();
        }
        let count = policy.rule_count();
        let mut rule = any_rule();
        rule.sources.clear();
        rule.sources
            .push(Network::parse("2001:db9::1").unwrap())
            .unwrap();
        assert_eq!(
            policy.push_rule("v6", rule),
            Err(Error::Full(CapacityError::PacketPolicy))
        );
        assert_eq!(policy.rule_count(), count);
        assert!(policy.allows_ip(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ffff".parse().unwrap(),
            6,
            443
        ));
        assert!(!policy.allows_ip(
            "2001:db9::1".parse().unwrap(),
            "2001:db8::ffff".parse().unwrap(),
            6,
            443
        ));
    }

    #[test]
    fn invalid_ranges_cannot_alias_wildcard_or_interned_handles() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("invalid").unwrap();
        let mut rule = any_rule();
        rule.sources[0] = Network::V4 {
            first: u32::MAX,
            last: 0,
        };
        assert_eq!(policy.push_rule("invalid", rule), Err(Error::Malformed));
        assert_eq!(policy.rule_count(), 0);
    }

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
