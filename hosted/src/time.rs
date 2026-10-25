use crate::store::FileStore;
#[derive(Default)]
pub struct Timestamp {
    last: [u8; 12],
    reserved: [u8; 12],
    store: Option<FileStore>,
}
impl Timestamp {
    pub fn new(directory: &std::path::Path) -> Result<Self, &'static str> {
        let store = FileStore::timestamp(directory);
        let mut floor = [0; 12];
        if let Some(len) = store.load(&mut floor).map_err(|_| "timestamp state read")? {
            let seconds = u64::from_be_bytes(floor[..8].try_into().unwrap());
            let nanos = u32::from_be_bytes(floor[8..].try_into().unwrap());
            if len != 12
                || !((1u64 << 62) + 10..=u64::MAX - 60).contains(&seconds)
                || nanos >= 1_000_000_000
            {
                return Err("invalid timestamp state");
            }
        }
        Ok(Self {
            last: floor,
            reserved: floor,
            store: Some(store),
        })
    }
    pub fn candidate(&self) -> Result<wirefeather::Tai64n, &'static str> {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "wall clock unavailable")?
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let mut last = self.last;
        Ok(crate::logic::next_tai64n(&mut last, millis))
    }
    #[cfg(test)]
    fn next_at(&mut self, millis: u64) -> Result<wirefeather::Tai64n, &'static str> {
        let mut last = self.last;
        let next = crate::logic::next_tai64n(&mut last, millis);
        self.commit(next)?;
        Ok(next)
    }
    pub fn commit(&mut self, next: wirefeather::Tai64n) -> Result<(), &'static str> {
        if let Some(store) = &self.store
            && next > self.reserved
        {
            // Reserve a minute before emitting any timestamp in that range.
            // Restarting begins above the reservation even after RTC rollback,
            // without syncing a file on every packet-driver iteration.
            let mut reserved = next;
            let seconds = u64::from_be_bytes(next[..8].try_into().unwrap())
                .checked_add(60)
                .ok_or("timestamp range exhausted")?;
            reserved[..8].copy_from_slice(&seconds.to_be_bytes());
            store.save(&reserved).map_err(|_| "timestamp state write")?;
            self.reserved = reserved;
        }
        self.last = next;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_after_clock_rollback_stays_above_every_reserved_timestamp() {
        let root = tempfile::tempdir().unwrap();
        let mut timestamp = Timestamp::new(root.path()).unwrap();
        let before = timestamp.next_at(1_700_000_000_000).unwrap();
        for _ in 0..1000 {
            assert!(timestamp.next_at(1_700_000_000_000).unwrap() > before);
        }
        let reserved = std::fs::read(root.path().join("tai64n.floor")).unwrap();
        drop(timestamp);
        let mut timestamp = Timestamp::new(root.path()).unwrap();
        let after = timestamp.next_at(1_699_000_000_000).unwrap();
        assert!(after.as_slice() > reserved.as_slice());
        assert!(after > before);
        drop(timestamp);
        std::fs::write(root.path().join("tai64n.floor"), b"corrupt").unwrap();
        assert!(Timestamp::new(root.path()).is_err());
    }
}
