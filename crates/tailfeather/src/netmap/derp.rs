//! The DERP map: relays to reach peers with no direct path.
//!
//! Only what is needed to open a relayed connection — a region, and a host and
//! port within it. The map the hosted service publishes describes dozens of
//! regions with latency hints and IPv6 addresses; the lab publishes one. Both
//! are read the same way, and regions past [`crate::netmap::MAX_DERP_REGIONS`] are
//! rejected rather than silently truncating the map this device will act on.

use crate::netmap::{CapacityError, Error, MAX_DERP_HOSTNAME, MAX_DERP_NODES, MAX_DERP_REGIONS};

/// The port a DERP node listens on when it does not say otherwise.
pub const DEFAULT_DERP_PORT: u16 = 443;
/// Distinct certificate-name overrides retained across the DERP map. Most
/// relays either omit `CertName` or repeat `HostName`, so only exceptions use
/// this bounded table.
const MAX_DERP_CERT_NAMES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerpCertName(u8);

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
        let index = self.cert_name.map_or(0x7f, |name| name.0 & 0x7f);
        self.cert_name = Some(DerpCertName(index | 0x80));
    }
}

impl DerpCertName {
    const fn is_insecure(self) -> bool {
        self.0 & 0x80 != 0
    }

    const fn index(self) -> Option<usize> {
        let index = self.0 & 0x7f;
        if index == 0x7f {
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
    pub nodes: heapless::Vec<DerpNode, MAX_DERP_NODES>,
}

#[derive(Debug, Default, Clone)]
pub struct DerpMap {
    regions: heapless::Vec<DerpRegion, MAX_DERP_REGIONS>,
    cert_names: heapless::Vec<heapless::String<MAX_DERP_HOSTNAME>, MAX_DERP_CERT_NAMES>,
}

impl DerpMap {
    pub const fn new() -> Self {
        Self {
            regions: heapless::Vec::new(),
            cert_names: heapless::Vec::new(),
        }
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

    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.regions.clear();
        self.cert_names.clear();
        for name in source.cert_names.iter() {
            self.cert_names
                .push(name.clone())
                .expect("equal DERP certificate-name capacities");
        }
        for region in source.iter() {
            self.regions
                .push(region.clone())
                .expect("equal DERP capacities");
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

    pub(crate) fn intern_cert_name(&mut self, name: &str) -> Result<DerpCertName, Error> {
        if let Some(index) = self
            .cert_names
            .iter()
            .position(|existing| existing.as_str() == name)
        {
            return Ok(DerpCertName(index as u8));
        }
        let name = heapless::String::try_from(name)
            .map_err(|_| Error::Full(super::CapacityError::String))?;
        self.cert_names
            .push(name)
            .map_err(|_| Error::Full(super::CapacityError::String))?;
        Ok(DerpCertName((self.cert_names.len() - 1) as u8))
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

    pub fn clear(&mut self) {
        self.regions.clear();
        self.cert_names.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(id: u16) -> DerpRegion {
        DerpRegion {
            id,
            code: heapless::String::try_from("lab").unwrap(),
            nodes: heapless::Vec::new(),
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
}
