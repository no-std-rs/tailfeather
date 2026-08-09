//! The DERP map: relays to reach peers with no direct path.
//!
//! Only what is needed to open a relayed connection — a region, and a host and
//! port within it. The map the hosted service publishes describes dozens of
//! regions with latency hints and IPv6 addresses; the lab publishes one. Both
//! are read the same way, and regions past [`crate::netmap::MAX_DERP_REGIONS`] are
//! dropped rather than growing a table this device cannot hold.

use crate::netmap::{Error, MAX_DERP_NODES, MAX_DERP_REGIONS};

/// The port a DERP node listens on when it does not say otherwise.
pub const DEFAULT_DERP_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpNode {
    /// The name to connect to. Kept as text rather than an address because the
    /// hosted service publishes host names, and resolving them is the caller's
    /// problem — the lab publishes a dotted quad, which parses trivially.
    pub host_name: heapless::String<64>,
    pub port: u16,
    pub stun_port: u16,
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
}

impl DerpMap {
    pub const fn new() -> Self {
        Self {
            regions: heapless::Vec::new(),
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

    pub fn region(&self, id: u16) -> Option<&DerpRegion> {
        self.regions.iter().find(|r| r.id == id)
    }

    pub fn insert(&mut self, region: DerpRegion) -> Result<(), Error> {
        if let Some(existing) = self.regions.iter_mut().find(|r| r.id == region.id) {
            *existing = region;
            return Ok(());
        }
        self.regions.push(region).map_err(|_| Error::Full)
    }

    pub fn clear(&mut self) {
        self.regions.clear();
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
        assert_eq!(map.insert(region(999)), Err(Error::Full));
    }
}
