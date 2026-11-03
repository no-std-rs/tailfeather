//! Bounded packet-filter state carried by streaming netmaps.
//!
//! Without the `alloc` feature every collection here has a fixed capacity
//! reserved inline. With it, sets, rules, their sources and destinations,
//! and interned IPv6 ranges grow on the heap with no configured limit; only
//! allocation failure drops rules, and it is reported the same way.

use core::net::{IpAddr, Ipv4Addr};
use core::str::FromStr;

use heapless::{String, Vec};

use crate::BoundedVec;
use crate::netmap::{CapacityError, Cidr, Error};

#[cfg(not(feature = "alloc"))]
pub const MAX_FILTER_SETS: usize = 8;
#[cfg(feature = "alloc")]
pub const MAX_FILTER_SETS: usize = crate::UNBOUNDED;
/// Preserve the hosted-policy capacity supported by earlier firmware while
/// keeping every collection statically bounded.
#[cfg(not(feature = "alloc"))]
pub const MAX_FILTER_RULES: usize = 32;
#[cfg(feature = "alloc")]
pub const MAX_FILTER_RULES: usize = crate::UNBOUNDED;
#[cfg(all(not(feature = "alloc"), not(feature = "hosted-policy")))]
pub const MAX_FILTER_SOURCES: usize = 8;
#[cfg(all(not(feature = "alloc"), feature = "hosted-policy"))]
pub const MAX_FILTER_SOURCES: usize = 512;
#[cfg(feature = "alloc")]
pub const MAX_FILTER_SOURCES: usize = crate::UNBOUNDED;
#[cfg(all(not(feature = "alloc"), not(feature = "hosted-policy")))]
pub const MAX_FILTER_DESTINATIONS: usize = 8;
#[cfg(all(not(feature = "alloc"), feature = "hosted-policy"))]
pub const MAX_FILTER_DESTINATIONS: usize = 512;
#[cfg(feature = "alloc")]
pub const MAX_FILTER_DESTINATIONS: usize = crate::UNBOUNDED;
pub const MAX_FILTER_PROTOCOLS: usize = 8;
pub const MAX_FILTER_SET_NAME: usize = 32;
/// Unstored filter sets tracked by name for truncation reporting.
#[cfg(not(feature = "alloc"))]
const MAX_UNSTORED_SETS: usize = 2;
#[cfg(feature = "alloc")]
const MAX_UNSTORED_SETS: usize = crate::UNBOUNDED;

/// Which set a stored rule belongs to: one byte on firmware, wider when sets
/// are unbounded.
#[cfg(not(feature = "alloc"))]
type SetId = u8;
#[cfg(feature = "alloc")]
type SetId = u32;

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

// Existing IPv4 policies keep their eight-byte network storage. IPv6 ranges
// are interned separately (at most 32 without `alloc`); a rule that does not
// fit is refused, never broadened. Deleting a named set reclaims
// unreferenced ranges.
#[cfg(all(not(feature = "alloc"), not(feature = "hosted-policy")))]
const MAX_V6_NETWORKS: usize = 32;
#[cfg(all(not(feature = "alloc"), feature = "hosted-policy"))]
const MAX_V6_NETWORKS: usize = 256;
#[cfg(feature = "alloc")]
const MAX_V6_NETWORKS: usize = crate::UNBOUNDED;
/// An IPv4 range when `first <= last`; otherwise a wildcard (`first ==
/// u32::MAX`) or a handle `first = index + 1` into the IPv6 pool.
#[derive(Debug, Clone, Copy)]
struct StoredNetwork {
    first: u32,
    last: u32,
}

impl StoredNetwork {
    fn v6_index(self) -> Option<usize> {
        (self.first > self.last && self.first != u32::MAX).then(|| self.first as usize - 1)
    }
}
#[derive(Debug, Clone)]
struct StoredDestination {
    network: StoredNetwork,
    first_port: u16,
    last_port: u16,
}
#[derive(Debug, Clone)]
struct StoredRule {
    sources: BoundedVec<StoredNetwork, MAX_FILTER_SOURCES>,
    destinations: BoundedVec<StoredDestination, MAX_FILTER_DESTINATIONS>,
    protocols: Vec<u8, MAX_FILTER_PROTOCOLS, u8>,
    set: SetId,
}

impl StoredRule {
    fn try_clone(&self) -> Option<Self> {
        Some(Self {
            sources: self.sources.try_clone()?,
            destinations: self.destinations.try_clone()?,
            protocols: self.protocols.clone(),
            set: self.set,
        })
    }

    fn networks_mut(&mut self) -> impl Iterator<Item = &mut StoredNetwork> {
        self.sources.iter_mut().chain(
            self.destinations
                .iter_mut()
                .map(|destination| &mut destination.network),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    pub network: Network,
    pub first_port: u16,
    pub last_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub sources: BoundedVec<Network, MAX_FILTER_SOURCES>,
    pub destinations: BoundedVec<Destination, MAX_FILTER_DESTINATIONS>,
    /// Empty means any IP protocol, matching tailcfg semantics.
    pub protocols: Vec<u8, MAX_FILTER_PROTOCOLS>,
}

impl FilterRule {
    pub const fn new() -> Self {
        Self {
            sources: BoundedVec::new(),
            destinations: BoundedVec::new(),
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
struct FilterSet {
    name: String<MAX_FILTER_SET_NAME>,
    id: SetId,
    /// Rules of this set were dropped for not fitting.
    truncated: bool,
}

/// An interned range needs no address-family tag: this pool stores only IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct V6Range {
    first: [u8; 16],
    last: [u8; 16],
}

/// Incremental named filter sets with one global rule bound.
#[derive(Debug, Clone)]
pub struct PacketPolicy {
    sets: BoundedVec<FilterSet, MAX_FILTER_SETS>,
    rules: BoundedVec<StoredRule, MAX_FILTER_RULES>,
    valid: bool,
    /// Sets whose rules could not be stored at all (no free set slot). Their
    /// earlier rules are gone; the marker clears when the set is replaced or
    /// deleted. Only a few names are kept (firmware RAM is tight); beyond
    /// that the policy-wide `truncated` marker is set instead, which errs
    /// towards reporting truncation, never towards hiding it.
    unstored: BoundedVec<String<MAX_FILTER_SET_NAME>, MAX_UNSTORED_SETS>,
    /// Truncation that cannot be tied to a set (an unreadable set name, or
    /// more unstored sets than are tracked). Clears only with the policy.
    truncated: bool,
    /// Interned IPv6 ranges, referenced by index from stored rules. Kept
    /// dense: collecting unreferenced ranges compacts it and renumbers.
    v6_networks: BoundedVec<V6Range, MAX_V6_NETWORKS>,
}

impl PacketPolicy {
    pub const fn new() -> Self {
        Self {
            sets: BoundedVec::new(),
            rules: BoundedVec::new(),
            unstored: BoundedVec::new(),
            truncated: false,
            valid: false,
            v6_networks: BoundedVec::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Control sent rules this policy could not hold, and they were dropped.
    /// Every rule only allows traffic, so a dropped rule denies what it would
    /// have allowed; nothing is permitted that control did not grant.
    pub fn truncated(&self) -> bool {
        self.truncated || !self.unstored.is_empty() || self.sets.iter().any(|set| set.truncated)
    }

    /// Record that rules of `set` were dropped. Cleared when that set is
    /// next replaced or deleted, so a later complete update is not reported
    /// as incomplete.
    pub(crate) fn mark_truncated(&mut self, set: &str) {
        if let Some(entry) = self
            .sets
            .iter_mut()
            .find(|entry| entry.name.as_str() == set)
        {
            entry.truncated = true;
            return;
        }
        if self.unstored.iter().any(|name| name.as_str() == set) {
            return;
        }
        match String::try_from(set) {
            Ok(name) if self.unstored.push(name.clone()).is_ok() => {}
            _ => self.truncated = true,
        }
    }

    /// Record truncation not attributable to a nameable set.
    pub(crate) fn mark_truncated_unnamed(&mut self) {
        self.truncated = true;
    }

    pub fn set_count(&self) -> usize {
        self.sets.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Copy `source` into this policy. Without `alloc` both have the same
    /// capacity and this always succeeds. With `alloc`, rules the allocator
    /// cannot hold are dropped and the copy reports truncation. Dropping only
    /// denies; if the sets or the IPv6 pool cannot be copied, no rules are,
    /// so no rule can end up attached to the wrong set or range.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.clear();
        self.valid = source.valid;
        self.truncated = source.truncated;
        match source.unstored.try_clone() {
            Some(unstored) => self.unstored = unstored,
            None => self.truncated = true,
        }
        let (Some(sets), Some(v6_networks)) =
            (source.sets.try_clone(), source.v6_networks.try_clone())
        else {
            self.truncated = true;
            return;
        };
        self.sets = sets;
        self.v6_networks = v6_networks;
        let _ = self.rules.try_reserve_total(source.rules.len());
        for rule in source.rules.iter() {
            let Some(rule) = rule.try_clone() else {
                self.truncated = true;
                break;
            };
            if self.rules.push(rule).is_err() {
                self.truncated = true;
                break;
            }
        }
    }

    pub fn mark_present(&mut self) {
        self.valid = true;
    }

    pub fn replace_set(&mut self, name: &str) -> Result<(), Error> {
        self.valid_name(name)?;
        self.delete_set(name);
        let id = self
            .free_set_id()
            .ok_or(Error::Full(CapacityError::PacketPolicy))?;
        self.sets
            .push(FilterSet {
                name: String::try_from(name)
                    .map_err(|_| Error::Full(CapacityError::PacketPolicy))?,
                id,
                truncated: false,
            })
            .map_err(|_| Error::Full(CapacityError::PacketPolicy))?;
        self.valid = true;
        Ok(())
    }

    /// An id no stored set uses, found in one pass over the sets: one past
    /// the highest id when that fits, otherwise the lowest gap. Only the
    /// fixed table (or a heap table that exhausted `SetId`) needs the gap.
    fn free_set_id(&self) -> Option<SetId> {
        if self.sets.is_full() {
            return None;
        }
        let next = match self.sets.iter().map(|set| set.id).max() {
            None => Some(0),
            Some(highest) => highest.checked_add(1),
        };
        if let Some(next) = next.filter(|&next| (next as usize) < MAX_FILTER_SETS) {
            return Some(next);
        }
        // Fewer sets than ids, so a gap exists. Mark the ids in use and
        // take the first free one; ids past the set count cannot be the
        // first gap, so a bitmap of `len + 1` bits suffices.
        let mut used = BoundedVec::<bool, MAX_FILTER_SETS>::new();
        let slots = self.sets.len() + 1;
        if !used.try_reserve_total(slots) {
            return None;
        }
        for _ in 0..slots {
            let _ = used.push(false);
        }
        for set in self.sets.iter() {
            if let Some(slot) = used.get_mut(set.id as usize) {
                *slot = true;
            }
        }
        used.iter()
            .position(|used| !used)
            .and_then(|index| SetId::try_from(index).ok())
    }

    pub fn delete_set(&mut self, name: &str) {
        if let Some(index) = self.sets.iter().position(|set| set.name.as_str() == name) {
            let id = self.sets.remove(index).id;
            let rules = self.rules.len();
            self.rules.retain(|rule| rule.set != id);
            // Only removed rules can leave ranges unreferenced; replacing a
            // new set (the common case while a map loads) collects nothing.
            if self.rules.len() != rules {
                self.collect_networks();
            }
        }
        self.unstored.retain(|unstored| unstored.as_str() != name);
        self.valid = true;
    }

    pub fn clear(&mut self) {
        self.sets.clear();
        self.rules.clear();
        self.v6_networks.clear();
        self.valid = true;
        self.unstored.clear();
        self.truncated = false;
    }

    pub fn push_rule(&mut self, set: &str, rule: FilterRule) -> Result<(), Error> {
        if !rule.is_well_formed() {
            return Err(Error::Malformed);
        }
        // The parser fills one set at a time, and the set being filled was
        // the last one added, so look there first.
        let set = self
            .sets
            .iter()
            .rev()
            .find(|entry| entry.name.as_str() == set)
            .map(|entry| entry.id)
            .ok_or(Error::Malformed)?;
        let result = (|| {
            let mut compact = StoredRule {
                sources: BoundedVec::new(),
                destinations: BoundedVec::new(),
                protocols: rule.protocols.cast_len_type(),
                set,
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
                .push(compact)
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
                let range = V6Range { first, last };
                // The fixed pool is small, so sharing a range between rules
                // is worth a scan; a heap pool just grows, which keeps large
                // policies linear to load.
                #[cfg(not(feature = "alloc"))]
                let existing = self.v6_networks.iter().position(|stored| *stored == range);
                #[cfg(feature = "alloc")]
                let existing = None;
                let index = match existing {
                    Some(index) => index,
                    None => {
                        // Handles are `index + 1` and must stay below the
                        // wildcard's `u32::MAX`.
                        if self.v6_networks.len() >= (u32::MAX - 1) as usize {
                            return Err(Error::Full(CapacityError::PacketPolicy));
                        }
                        self.v6_networks
                            .push(range)
                            .map_err(|_| Error::Full(CapacityError::PacketPolicy))?;
                        self.v6_networks.len() - 1
                    }
                };
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
            let index = stored.v6_index()?;
            self.v6_networks.get(index).map(|range| Network::V6 {
                first: range.first,
                last: range.last,
            })
        }
    }
    /// Drop interned IPv6 ranges no stored rule refers to, compacting the
    /// pool and renumbering the references that remain. If the renumbering
    /// table cannot be allocated, the unreferenced ranges stay until the
    /// next collection; they are unreachable, so this only costs memory.
    fn collect_networks(&mut self) {
        let Self {
            rules, v6_networks, ..
        } = self;
        // For each pool index, the new handle (`new index + 1`), or zero if
        // no rule refers to it.
        let mut handles = BoundedVec::<u32, MAX_V6_NETWORKS>::new();
        if !handles.try_reserve_total(v6_networks.len()) {
            return;
        }
        for _ in 0..v6_networks.len() {
            let _ = handles.push(0);
        }
        for network in rules.iter_mut().flat_map(StoredRule::networks_mut) {
            if let Some(slot) = network.v6_index().and_then(|index| handles.get_mut(index)) {
                *slot = 1;
            }
        }
        let mut kept = 0;
        for index in 0..v6_networks.len() {
            if handles[index] != 0 {
                v6_networks[kept] = v6_networks[index];
                kept += 1;
                handles[index] = kept as u32;
            }
        }
        v6_networks.truncate(kept);
        for network in rules.iter_mut().flat_map(StoredRule::networks_mut) {
            if let Some(&handle) = network.v6_index().and_then(|index| handles.get(index)) {
                network.first = handle;
            }
        }
    }
    fn allows_ip(&self, source: IpAddr, destination: IpAddr, protocol: u8, port: u16) -> bool {
        self.valid
            && self.rules.iter().any(|stored| {
                let rule = stored;
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
                let rule = stored;
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
    fn zero_ipv6_range_survives_copy_and_reclaims_without_aliasing_free_slots() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("zero").unwrap();
        let mut rule = any_rule();
        rule.sources.clear();
        rule.sources
            .push(Network::parse("::/128").unwrap())
            .unwrap();
        policy.push_rule("zero", rule).unwrap();
        let source = "::".parse().unwrap();
        let destination = "2001:db8::1".parse().unwrap();
        let mut copied = PacketPolicy::new();
        copied.copy_from(&policy);
        policy.clear();
        assert!(!policy.allows_ip(source, destination, 6, 443));
        assert!(copied.allows_ip(source, destination, 6, 443));
        assert!(!copied.allows_ip("::1".parse().unwrap(), destination, 6, 443));
        copied.delete_set("zero");
        assert!(!copied.allows_ip(source, destination, 6, 443));
        assert!(copied.v6_networks.is_empty());
    }

    #[test]
    fn replacing_named_sets_reclaims_interned_ipv6_networks() {
        let mut policy = PacketPolicy::new();
        for index in 0..64 {
            policy.replace_set("rotating").unwrap();
            let mut rule = any_rule();
            rule.sources.clear();
            let mut text = String::<48>::new();
            use core::fmt::Write as _;
            write!(&mut text, "2001:db8::{index:x}").unwrap();
            rule.sources.push(Network::parse(&text).unwrap()).unwrap();
            policy.push_rule("rotating", rule).unwrap();
            assert_eq!(policy.v6_networks.len(), 1);
        }
    }

    #[cfg(not(feature = "alloc"))]
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

    fn v6_rule(sources: &[&str]) -> FilterRule {
        let mut rule = any_rule();
        rule.sources.clear();
        for source in sources {
            rule.sources.push(Network::parse(source).unwrap()).unwrap();
        }
        rule
    }

    #[test]
    fn collecting_ipv6_ranges_renumbers_the_rules_that_remain() {
        let mut policy = PacketPolicy::new();
        policy.replace_set("first").unwrap();
        policy
            .push_rule("first", v6_rule(&["2001:db8::1", "2001:db8::2"]))
            .unwrap();
        policy.replace_set("second").unwrap();
        policy
            .push_rule("second", v6_rule(&["2001:db8::3", "2001:db8::/120"]))
            .unwrap();
        assert_eq!(policy.v6_networks.len(), 4);
        policy.delete_set("first");
        // The second set's ranges moved to the front of the pool; its rule
        // must follow them, not inherit the deleted set's ranges.
        assert_eq!(policy.v6_networks.len(), 2);
        let destination = "2001:db8::ffff".parse().unwrap();
        let allows = |policy: &PacketPolicy, source: &str| {
            policy.allows_ip(source.parse().unwrap(), destination, 6, 443)
        };
        assert!(allows(&policy, "2001:db8::3"));
        assert!(allows(&policy, "2001:db8::80"));
        assert!(!allows(&policy, "2001:db8::1:0"));
        // A range interned after compaction does not alias a live one.
        policy.replace_set("third").unwrap();
        policy
            .push_rule("third", v6_rule(&["2001:db9::1"]))
            .unwrap();
        assert!(allows(&policy, "2001:db9::1"));
        assert!(allows(&policy, "2001:db8::3"));
        assert!(!allows(&policy, "2001:db9::2"));
        policy.delete_set("second");
        assert!(allows(&policy, "2001:db9::1"));
        assert!(!allows(&policy, "2001:db8::3"));
        assert_eq!(policy.v6_networks.len(), 1);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_heap_policy_holds_large_tailnets_without_truncating() {
        use core::fmt::Write as _;
        let mut policy = PacketPolicy::new();
        for set in 0..300 {
            let mut name = String::<8>::new();
            write!(name, "s{set}").unwrap();
            policy.replace_set(&name).unwrap();
            let mut rule = any_rule();
            rule.sources.clear();
            for host in 0..20u32 {
                rule.sources
                    .push(Network::V4 {
                        first: 0x6440_0000 + set * 64 + host,
                        last: 0x6440_0000 + set * 64 + host,
                    })
                    .unwrap();
                let mut text = String::<48>::new();
                write!(text, "fd7a:115c:a1e0::{set:x}:{host:x}").unwrap();
                rule.sources.push(Network::parse(&text).unwrap()).unwrap();
            }
            policy.push_rule(&name, rule).unwrap();
        }
        assert_eq!(policy.set_count(), 300);
        assert_eq!(policy.rule_count(), 300);
        assert_eq!(policy.v6_networks.len(), 300 * 20);
        assert!(!policy.truncated());
        let mut copy = PacketPolicy::new();
        copy.copy_from(&policy);
        assert!(!copy.truncated());
        let destination = "fd7a:115c:a1e0::1".parse().unwrap();
        assert!(copy.allows_ip(
            "fd7a:115c:a1e0::12b:13".parse().unwrap(),
            destination,
            6,
            22
        ));
        assert!(!copy.allows_ip("fd7a:115c:a1e0::12c:0".parse().unwrap(), destination, 6, 22));
        copy.delete_set("s0");
        assert_eq!(copy.v6_networks.len(), 299 * 20);
        assert!(copy.allows_ip(
            "fd7a:115c:a1e0::12b:13".parse().unwrap(),
            destination,
            6,
            22
        ));
        assert!(!copy.allows_ip("fd7a:115c:a1e0::0:1".parse().unwrap(), destination, 6, 22));
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
    fn set_ids_are_reused_after_deletion_without_colliding() {
        use core::fmt::Write as _;
        let mut policy = PacketPolicy::new();
        let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        for name in names {
            policy.replace_set(name).unwrap();
            policy.push_rule(name, any_rule()).unwrap();
        }
        // Free a middle id and the highest; new sets must not share ids
        // with surviving sets, or deleting one would delete the other's rules.
        policy.delete_set("c");
        policy.delete_set("h");
        for index in 0..2 {
            let mut name = String::<8>::new();
            write!(name, "n{index}").unwrap();
            policy.replace_set(&name).unwrap();
            policy.push_rule(&name, any_rule()).unwrap();
        }
        let mut ids: std::vec::Vec<_> = policy.sets.iter().map(|set| set.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 8);
        assert_eq!(policy.rule_count(), 8);
        policy.delete_set("n0");
        policy.delete_set("n1");
        assert_eq!(policy.rule_count(), 6);
    }

    #[cfg(not(feature = "alloc"))]
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
