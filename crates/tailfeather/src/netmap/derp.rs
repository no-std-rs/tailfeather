//! The DERP map: relays to reach peers with no direct path.
//!
//! Only what is needed to open a relayed connection — a region, and a host and
//! port within it. The map the hosted service publishes describes dozens of
//! regions with latency hints and IPv6 addresses; the lab publishes one. Both
//! are read the same way. Regions past [`crate::netmap::MAX_DERP_REGIONS`] are
//! dropped, keeping the lowest ids, and [`DerpMap::truncated`] reports it.
//! With the `alloc` feature the map grows on the heap instead, and only
//! allocation failure truncates it.

use crate::BoundedVec;
use crate::netmap::{CapacityError, Error, MAX_DERP_HOSTNAME, MAX_DERP_NODES, MAX_DERP_REGIONS};

/// The port a DERP node listens on when it does not say otherwise.
pub const DEFAULT_DERP_PORT: u16 = 443;
/// Upstream uses this port when STUNPort is omitted or zero; -1 disables it.
pub const DEFAULT_STUN_PORT: u16 = 3478;
/// Distinct certificate-name overrides retained across the DERP map. Most
/// relays either omit `CertName` or repeat `HostName`, so only exceptions use
/// this bounded table. With `alloc` it grows on the heap, up to what a
/// reference can index.
#[cfg(not(feature = "alloc"))]
const MAX_DERP_CERT_NAMES: usize = 4;
#[cfg(feature = "alloc")]
const MAX_DERP_CERT_NAMES: usize = NO_CERT_NAME as usize;

/// A one-byte reference keeps firmware relays small; heap builds use a wider
/// one so the certificate-name table is not the limit.
#[cfg(not(feature = "alloc"))]
type CertIndex = u8;
#[cfg(feature = "alloc")]
type CertIndex = u32;
/// The top bit of a reference marks InsecureForTests; the rest is an index,
/// with all ones meaning "no override".
const INSECURE_BIT: CertIndex = 1 << (CertIndex::BITS - 1);
const NO_CERT_NAME: CertIndex = !INSECURE_BIT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerpCertName(CertIndex);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpNode {
    /// The name to connect to. Kept as text rather than an address because the
    /// hosted service publishes host names, and resolving them is the caller's
    /// problem — the lab publishes a dotted quad, which parses trivially.
    pub host_name: heapless::String<MAX_DERP_HOSTNAME>,
    /// Reference to a certificate-name override in the containing map. When
    /// absent, the certificate name is [`Self::host_name`].
    pub cert_name: Option<DerpCertName>,
    pub port: u16,
    pub stun_port: u16,
}

impl DerpNode {
    pub fn insecure_for_tests(&self) -> bool {
        self.cert_name.is_some_and(DerpCertName::is_insecure)
    }

    pub(crate) fn mark_insecure_for_tests(&mut self) {
        let index = self
            .cert_name
            .map_or(NO_CERT_NAME, |name| name.0 & NO_CERT_NAME);
        self.cert_name = Some(DerpCertName(index | INSECURE_BIT));
    }
}

impl DerpCertName {
    const fn is_insecure(self) -> bool {
        self.0 & INSECURE_BIT != 0
    }

    const fn index(self) -> Option<usize> {
        let index = self.0 & NO_CERT_NAME;
        if index == NO_CERT_NAME {
            None
        } else {
            Some(index as usize)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpRegion {
    pub id: u16,
    pub code: heapless::String<16>,
    /// Exclude from measurement and home selection, but allow peer-directed
    /// connections when a peer advertises this region as its home.
    pub no_measure_no_home: bool,
    pub nodes: BoundedVec<DerpNode, MAX_DERP_NODES>,
}

impl DerpRegion {
    /// Whether this region can be selected as our home or compatibility relay.
    /// A peer may still explicitly name a NoMeasureNoHome region as its home.
    pub fn can_be_home(&self) -> bool {
        !self.no_measure_no_home && self.nodes.iter().any(|node| node.port != 0)
    }
}

#[derive(Debug, Default, Clone)]
pub struct DerpMap {
    regions: BoundedVec<DerpRegion, MAX_DERP_REGIONS>,
    cert_names: BoundedVec<heapless::String<MAX_DERP_HOSTNAME>, MAX_DERP_CERT_NAMES>,
    truncated: bool,
}

impl DerpMap {
    pub const fn new() -> Self {
        Self {
            regions: BoundedVec::new(),
            cert_names: BoundedVec::new(),
            truncated: false,
        }
    }

    /// Control named more regions (or relays) than this map retains. The
    /// lowest region ids are kept, so the subset does not depend on the
    /// order control lists them in.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    pub fn len(&self) -> usize {
        self.regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &DerpRegion> {
        self.regions.iter()
    }

    /// Copy `source` into this map. Without `alloc` both maps have the same
    /// capacity and this always succeeds. With `alloc`, whatever the
    /// allocator refuses is left out and the copy is marked truncated; a
    /// relay is dropped rather than kept without its certificate name.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.regions.clear();
        self.cert_names.clear();
        self.truncated = source.truncated;
        let _ = self.cert_names.try_reserve_total(source.cert_names.len());
        for name in source.cert_names.iter() {
            if self.cert_names.push(name.clone()).is_err() {
                self.truncated = true;
                break;
            }
        }
        let names = self.cert_names.len();
        let _ = self.regions.try_reserve_total(source.regions.len());
        for region in source.iter() {
            let mut copy = DerpRegion {
                id: region.id,
                code: region.code.clone(),
                no_measure_no_home: region.no_measure_no_home,
                nodes: BoundedVec::new(),
            };
            let _ = copy.nodes.try_reserve_total(region.nodes.len());
            for node in region.nodes.iter() {
                let named = node
                    .cert_name
                    .and_then(DerpCertName::index)
                    .is_none_or(|index| index < names);
                if !named || copy.nodes.push(node.clone()).is_err() {
                    self.truncated = true;
                }
            }
            // Like a parse, an allocation failure keeps the lowest ids
            // whatever order the source holds them in.
            self.insert_bounded(copy);
        }
    }

    pub fn region(&self, id: u16) -> Option<&DerpRegion> {
        self.regions.iter().find(|r| r.id == id)
    }

    /// Return the name used for TLS verification for a retained relay.
    pub fn cert_name<'a>(&'a self, node: &'a DerpNode) -> &'a str {
        node.cert_name
            .and_then(DerpCertName::index)
            .and_then(|index| self.cert_names.get(index))
            .map_or(node.host_name.as_str(), |name| name.as_str())
    }

    /// Intern a certificate-name override. `pending` holds relays of the
    /// region being parsed, which are not in the map yet but already refer to
    /// interned names; they are renumbered if the pool has to be compacted.
    pub(crate) fn intern_cert_name(
        &mut self,
        name: &str,
        pending: &mut [DerpNode],
    ) -> Result<DerpCertName, Error> {
        if let Some(index) = self
            .cert_names
            .iter()
            .position(|existing| existing.as_str() == name)
        {
            return Ok(DerpCertName(index as CertIndex));
        }
        let name = heapless::String::try_from(name)
            .map_err(|_| Error::Full(super::CapacityError::String))?;
        #[cfg(not(feature = "alloc"))]
        if self.cert_names.is_full() {
            // Regions evicted by the bounded insert may have left names no
            // retained relay uses any more.
            self.compact_cert_names(pending);
        }
        #[cfg(feature = "alloc")]
        let _ = pending;
        self.cert_names
            .push(name)
            .map_err(|_| Error::Full(super::CapacityError::String))?;
        Ok(DerpCertName((self.cert_names.len() - 1) as CertIndex))
    }

    /// Drop certificate names that no retained or pending relay refers to,
    /// renumbering the references that remain. Only the fixed-size table
    /// fills up; a heap table is limited by memory, which this cannot free.
    #[cfg(not(feature = "alloc"))]
    fn compact_cert_names(&mut self, pending: &mut [DerpNode]) {
        let Self {
            regions,
            cert_names,
            ..
        } = self;
        let mut kept = BoundedVec::<_, MAX_DERP_CERT_NAMES>::new();
        let mut remap = [None::<u8>; MAX_DERP_CERT_NAMES];
        let nodes = regions
            .iter_mut()
            .flat_map(|region| region.nodes.iter_mut())
            .chain(pending.iter_mut());
        for node in nodes {
            let Some(reference) = node.cert_name else {
                continue;
            };
            let Some(index) = reference.index() else {
                continue;
            };
            let Some(name) = cert_names.get(index) else {
                continue;
            };
            let new = *remap[index].get_or_insert_with(|| {
                let _ = kept.push(name.clone());
                (kept.len() - 1) as u8
            });
            node.cert_name = Some(DerpCertName(new | (reference.0 & INSECURE_BIT)));
        }
        *cert_names = kept;
    }

    pub(crate) fn region_mut(&mut self, id: u16) -> Option<&mut DerpRegion> {
        self.regions.iter_mut().find(|r| r.id == id)
    }

    pub fn insert(&mut self, region: DerpRegion) -> Result<(), Error> {
        if let Some(existing) = self.regions.iter_mut().find(|r| r.id == region.id) {
            *existing = region;
            return Ok(());
        }
        self.regions
            .push(region)
            .map_err(|_| Error::Full(CapacityError::DerpRegions))
    }

    /// Insert into a possibly full map, keeping the lowest region ids and
    /// recording that the map was truncated.
    pub(crate) fn insert_bounded(&mut self, region: DerpRegion) {
        if let Some(existing) = self.regions.iter_mut().find(|r| r.id == region.id) {
            *existing = region;
            return;
        }
        let Err(region) = self.regions.push(region) else {
            return;
        };
        self.truncated = true;
        if let Some(highest) = self
            .regions
            .iter_mut()
            .max_by_key(|existing| existing.id)
            .filter(|existing| existing.id > region.id)
        {
            *highest = region;
        }
    }

    pub fn clear(&mut self) {
        self.regions.clear();
        self.cert_names.clear();
        self.truncated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(id: u16) -> DerpRegion {
        DerpRegion {
            id,
            code: heapless::String::try_from("lab").unwrap(),
            no_measure_no_home: false,
            nodes: BoundedVec::new(),
        }
    }

    #[test]
    fn a_region_replaces_rather_than_duplicates() {
        let mut map = DerpMap::new();
        map.insert(region(999)).unwrap();
        map.insert(region(999)).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.region(999).is_some());
        assert!(map.region(1).is_none());
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn a_map_larger_than_the_table_reports_rather_than_truncating() {
        let mut map = DerpMap::new();
        for id in 0..MAX_DERP_REGIONS {
            map.insert(region(id as u16)).unwrap();
        }
        assert_eq!(
            map.insert(region(999)),
            Err(Error::Full(CapacityError::DerpRegions))
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_heap_map_holds_every_region() {
        let mut map = DerpMap::new();
        for id in 0..1000 {
            map.insert_bounded(region(id));
        }
        assert_eq!(map.len(), 1000);
        assert!(!map.truncated());
        let mut copy = DerpMap::new();
        copy.copy_from(&map);
        assert_eq!(copy.len(), 1000);
        assert!(!copy.truncated());
    }
}
