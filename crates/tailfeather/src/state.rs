//! Power-loss-safe storage for a node's persistent state.
//!
//! The storage adapter exposes two independently erasable slots.  A save is
//! written to the older slot, verified byte-for-byte, and committed with a
//! final four-byte write.  Consequently a reset at any point leaves either the
//! previous generation or the new one readable.

use crate::PersistState;

/// One ESP32 flash sector. Each state slot occupies exactly one sector.
pub const SLOT_SIZE: usize = 4096;

const MAGIC: [u8; 4] = *b"TFSL";
const VERSION: u8 = 1;
const COMMITTED: [u8; 4] = [0x43, 0x4f, 0x4d, 0x54]; // `COMT`
const HEADER_LEN: usize = 4 + 1 + 3 + 8 + 2 + 2;
const CHECKSUM_LEN: usize = 16;
const COMMIT_OFFSET: usize = SLOT_SIZE - COMMITTED.len();

/// Minimal operations required from a pair of flash sectors.
pub trait SlotStorage {
    type Error;

    fn read(&mut self, slot: usize, offset: usize, out: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, slot: usize) -> Result<(), Self::Error>;
    fn write(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    Storage(E),
    Corrupt,
    StaleGeneration,
}

/// What was found in one physical slot during a load.
///
/// Invalid slots deliberately do not expose the generation bytes from their
/// untrusted header. A torn or corrupted write must never be able to move a
/// replacement identity's generation backwards or forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotMetadata {
    Erased,
    Invalid,
    Valid { generation: u64 },
}

/// A loaded state together with the durability information needed at boot.
pub struct LoadResult {
    state: Option<PersistState>,
    slots: [SlotMetadata; 2],
    max_valid_generation: Option<u64>,
}

impl LoadResult {
    pub fn state(&self) -> Option<&PersistState> {
        self.state.as_ref()
    }

    pub fn into_state(self) -> Option<PersistState> {
        self.state
    }

    pub fn slots(&self) -> [SlotMetadata; 2] {
        self.slots
    }

    pub fn valid_slot_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, SlotMetadata::Valid { .. }))
            .count()
    }

    pub fn needs_repair(&self) -> bool {
        self.state.is_some() && self.valid_slot_count() < 2
    }

    pub fn max_valid_generation(&self) -> Option<u64> {
        self.max_valid_generation
    }

    /// Generation for an identity that replaces all currently valid state.
    pub fn replacement_generation(&self) -> Option<u64> {
        self.max_valid_generation.unwrap_or(0).checked_add(1)
    }

    pub fn is_redundant_at(&self, generation: u64) -> bool {
        self.slots.iter().all(
            |slot| matches!(slot, SlotMetadata::Valid { generation: saved } if *saved == generation),
        )
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "state storage: {error}"),
            Self::Corrupt => f.write_str("both persistent-state slots are invalid"),
            Self::StaleGeneration => f.write_str("refusing to overwrite newer persistent state"),
        }
    }
}

/// Atomic two-slot store. `load` returns the highest valid generation.
pub struct TwoSlot<S> {
    storage: S,
}

impl<S: SlotStorage> TwoSlot<S> {
    pub const fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn into_inner(self) -> S {
        self.storage
    }

    /// Return `Ok(None)` when no verified identity exists. A single invalid
    /// slot beside an erased slot can only be an interrupted first write, so
    /// it is safe to initialize a replacement identity.
    pub fn load(&mut self) -> Result<Option<PersistState>, Error<S::Error>> {
        Ok(self.load_with_metadata()?.into_state())
    }

    /// Load the newest valid record and report the state of both slots.
    ///
    /// Callers use this at boot to repair a lost copy before networking and to
    /// choose a strictly newer generation when the configured authority
    /// changes. Only generations from checksum-verified records contribute to
    /// `max_valid_generation`.
    pub fn load_with_metadata(&mut self) -> Result<LoadResult, Error<S::Error>> {
        let a = self.read_slot(0)?;
        let b = self.read_slot(1)?;
        let slots = [a.metadata(), b.metadata()];
        let max_valid_generation = slots
            .iter()
            .filter_map(|slot| match slot {
                SlotMetadata::Valid { generation } => Some(*generation),
                SlotMetadata::Erased | SlotMetadata::Invalid => None,
            })
            .max();
        let state = match (a, b) {
            (Slot::Valid(a), Slot::Valid(b)) => Some(if a.generation() >= b.generation() {
                a
            } else {
                b
            }),
            (Slot::Valid(state), _) | (_, Slot::Valid(state)) => Some(state),
            // A fully checksummed record with no commit marker is normally an
            // interrupted update, so an existing committed record always wins.
            // It is recoverable only on the very first write, where the other
            // slot is still erased and no prior identity can be replaced.
            (Slot::Staged(state), Slot::Erased) | (Slot::Erased, Slot::Staged(state)) => {
                Some(state)
            }
            // A torn first record has no previous committed identity to lose.
            // Treat it as a fresh device so provisioning can retry the write.
            (Slot::Invalid, Slot::Erased) | (Slot::Erased, Slot::Invalid) => None,
            (Slot::Erased, Slot::Erased) => None,
            _ => return Err(Error::Corrupt),
        };
        Ok(LoadResult {
            state,
            slots,
            max_valid_generation,
        })
    }

    /// Save and read back `state`, committing only after verification.
    pub fn save(&mut self, state: &PersistState) -> Result<(), Error<S::Error>> {
        let a = self.read_slot(0)?;
        let b = self.read_slot(1)?;
        let newest = [a.metadata(), b.metadata()]
            .into_iter()
            .filter_map(|slot| match slot {
                SlotMetadata::Valid { generation } => Some(generation),
                SlotMetadata::Erased | SlotMetadata::Invalid => None,
            })
            .max();
        if newest.is_some_and(|generation| state.generation() < generation) {
            return Err(Error::StaleGeneration);
        }
        let target = target_slot(&a, &b);

        let mut record = [0xff; HEADER_LEN + PersistState::BLOB_LEN + CHECKSUM_LEN];
        record[..4].copy_from_slice(&MAGIC);
        record[4] = VERSION;
        record[8..16].copy_from_slice(&state.generation().to_le_bytes());
        record[16..18].copy_from_slice(&(PersistState::BLOB_LEN as u16).to_le_bytes());
        let payload_end = HEADER_LEN + PersistState::BLOB_LEN;
        record[HEADER_LEN..payload_end].copy_from_slice(state.as_bytes());
        let checksum = crate::tunnel::crypto::hash(&[&record[..payload_end]]);
        record[payload_end..].copy_from_slice(&checksum[..CHECKSUM_LEN]);

        self.storage.erase(target).map_err(Error::Storage)?;
        self.storage
            .write(target, 0, &record)
            .map_err(Error::Storage)?;

        let mut verify = [0; HEADER_LEN + PersistState::BLOB_LEN + CHECKSUM_LEN];
        self.storage
            .read(target, 0, &mut verify)
            .map_err(Error::Storage)?;
        if verify != record {
            return Err(Error::Corrupt);
        }

        // NOR flash changes one bits to zero. The erased marker is all ones;
        // this final write is therefore the atomic visibility point.
        self.storage
            .write(target, COMMIT_OFFSET, &COMMITTED)
            .map_err(Error::Storage)?;

        match self.read_slot(target)? {
            Slot::Valid(saved)
                if saved.generation() == state.generation()
                    && saved.as_bytes() == state.as_bytes() =>
            {
                Ok(())
            }
            _ => Err(Error::Corrupt),
        }
    }

    fn read_slot(&mut self, slot: usize) -> Result<Slot, Error<S::Error>> {
        let mut marker = [0; 4];
        self.storage
            .read(slot, COMMIT_OFFSET, &mut marker)
            .map_err(Error::Storage)?;

        let mut prefix = [0; HEADER_LEN];
        self.storage
            .read(slot, 0, &mut prefix)
            .map_err(Error::Storage)?;
        if prefix.iter().all(|byte| *byte == 0xff) && marker == [0xff; 4] {
            return Ok(Slot::Erased);
        }
        let state_len = usize::from(u16::from_le_bytes([prefix[16], prefix[17]]));
        if prefix[..4] != MAGIC
            || prefix[4] != VERSION
            || !matches!(
                state_len,
                PersistState::BLOB_LEN | PersistState::V2_BLOB_LEN | PersistState::LEGACY_BLOB_LEN
            )
        {
            return Ok(Slot::Invalid);
        }

        let mut record = [0; HEADER_LEN + PersistState::BLOB_LEN + CHECKSUM_LEN];
        self.storage
            .read(
                slot,
                0,
                &mut record[..HEADER_LEN + state_len + CHECKSUM_LEN],
            )
            .map_err(Error::Storage)?;
        let payload_end = HEADER_LEN + state_len;
        let expected = crate::tunnel::crypto::hash(&[&record[..payload_end]]);
        if !crate::tunnel::crypto::ct_eq(
            &expected[..CHECKSUM_LEN],
            &record[payload_end..payload_end + CHECKSUM_LEN],
        ) {
            return Ok(Slot::Invalid);
        }
        let Ok(state) = PersistState::from_bytes(&record[HEADER_LEN..payload_end]) else {
            return Ok(Slot::Invalid);
        };
        let generation = u64::from_le_bytes(record[8..16].try_into().unwrap());
        if generation != state.generation() {
            return Ok(Slot::Invalid);
        }
        match marker {
            COMMITTED => Ok(Slot::Valid(state)),
            marker if marker == [0xff; 4] => Ok(Slot::Staged(state)),
            _ => Ok(Slot::Invalid),
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the fixed-size persisted state is stack-owned while comparing two flash slots"
)]
enum Slot {
    Erased,
    Invalid,
    Staged(PersistState),
    Valid(PersistState),
}

impl Slot {
    fn metadata(&self) -> SlotMetadata {
        match self {
            Self::Erased => SlotMetadata::Erased,
            Self::Invalid | Self::Staged(_) => SlotMetadata::Invalid,
            Self::Valid(state) => SlotMetadata::Valid {
                generation: state.generation(),
            },
        }
    }
}

fn target_slot(a: &Slot, b: &Slot) -> usize {
    match (a, b) {
        (Slot::Valid(a), Slot::Valid(b)) => usize::from(a.generation() > b.generation()),
        (Slot::Valid(_), _) => 1,
        (_, Slot::Valid(_)) => 0,
        (Slot::Staged(_), _) => 1,
        (_, Slot::Staged(_)) => 0,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Identity, Rng};
    use crate::{Node, NodeAction};

    struct Counter(u8);
    impl Rng for Counter {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[derive(Clone)]
    struct Memory {
        slots: [[u8; SLOT_SIZE]; 2],
        writes_before_failure: Option<usize>,
    }

    impl Memory {
        fn erased() -> Self {
            Self {
                slots: [[0xff; SLOT_SIZE]; 2],
                writes_before_failure: None,
            }
        }
    }

    impl SlotStorage for Memory {
        type Error = ();
        fn read(&mut self, slot: usize, offset: usize, out: &mut [u8]) -> Result<(), ()> {
            out.copy_from_slice(&self.slots[slot][offset..offset + out.len()]);
            Ok(())
        }
        fn erase(&mut self, slot: usize) -> Result<(), ()> {
            self.slots[slot].fill(0xff);
            Ok(())
        }
        fn write(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<(), ()> {
            if self.writes_before_failure == Some(0) {
                return Err(());
            }
            if let Some(left) = &mut self.writes_before_failure {
                *left -= 1;
            }
            for (stored, new) in self.slots[slot][offset..offset + bytes.len()]
                .iter_mut()
                .zip(bytes)
            {
                *stored &= *new;
            }
            Ok(())
        }
    }

    fn fresh_state(seed: u8, generation: u64) -> PersistState {
        let mut node = Node::<1>::factory_reset(Identity::generate(&mut Counter(seed)), generation);
        match node.poll(0).unwrap().unwrap() {
            NodeAction::PersistState(state) => state,
            _ => unreachable!(),
        }
    }

    #[test]
    fn empty_store_and_round_trip() {
        let mut store = TwoSlot::new(Memory::erased());
        assert!(store.load().unwrap().is_none());
        let state = fresh_state(1, 7);
        store.save(&state).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.generation(), 7);
        assert_eq!(loaded.as_bytes(), state.as_bytes());
    }

    #[test]
    fn a_version_one_slot_is_loaded_and_normalized() {
        let identity = Identity::generate(&mut Counter(7));
        let mut legacy = [0; PersistState::LEGACY_BLOB_LEN];
        legacy[..4].copy_from_slice(b"TFST");
        legacy[4] = 1;
        legacy[5..13].copy_from_slice(&5u64.to_le_bytes());
        legacy[13..21].copy_from_slice(&99u64.to_le_bytes());
        legacy[21..53].copy_from_slice(&identity.machine.to_bytes());
        legacy[53..85].copy_from_slice(&identity.node.to_bytes());
        legacy[85..117].copy_from_slice(&identity.disco.to_bytes());
        let checksum = crate::tunnel::crypto::hash(&[&legacy[..PersistState::LEGACY_PAYLOAD_LEN]]);
        legacy[PersistState::LEGACY_PAYLOAD_LEN..].copy_from_slice(&checksum[..CHECKSUM_LEN]);
        assert!(PersistState::from_bytes(&legacy).is_ok());

        let mut memory = Memory::erased();
        let record = &mut memory.slots[0];
        record[..4].copy_from_slice(&MAGIC);
        record[4] = VERSION;
        record[8..16].copy_from_slice(&5u64.to_le_bytes());
        record[16..18].copy_from_slice(&(PersistState::LEGACY_BLOB_LEN as u16).to_le_bytes());
        let payload_end = HEADER_LEN + legacy.len();
        record[HEADER_LEN..payload_end].copy_from_slice(&legacy);
        let checksum = crate::tunnel::crypto::hash(&[&record[..payload_end]]);
        record[payload_end..payload_end + CHECKSUM_LEN].copy_from_slice(&checksum[..CHECKSUM_LEN]);
        record[COMMIT_OFFSET..].copy_from_slice(&COMMITTED);

        let mut store = TwoSlot::new(memory);
        assert!(matches!(store.read_slot(0).unwrap(), Slot::Valid(_)));
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.generation(), 5);
        assert_eq!(loaded.trusted_time_floor(), 99);
        assert_eq!(loaded.as_bytes()[4], PersistState::VERSION);
    }

    #[test]
    fn newest_valid_slot_wins_and_one_corrupt_slot_recovers() {
        let mut store = TwoSlot::new(Memory::erased());
        store.save(&fresh_state(1, 1)).unwrap();
        store.save(&fresh_state(2, 2)).unwrap();
        assert_eq!(store.load().unwrap().unwrap().generation(), 2);
        store.storage.slots[1][HEADER_LEN + 3] ^= 1;
        assert_eq!(store.load().unwrap().unwrap().generation(), 1);
    }

    #[test]
    fn load_reports_only_verified_generations_and_a_repair_restores_redundancy() {
        let mut store = TwoSlot::new(Memory::erased());
        let state = fresh_state(1, 7);
        store.save(&state).unwrap();

        let loaded = store.load_with_metadata().unwrap();
        assert_eq!(loaded.valid_slot_count(), 1);
        assert!(loaded.needs_repair());
        assert_eq!(loaded.max_valid_generation(), Some(7));
        assert_eq!(loaded.replacement_generation(), Some(8));
        assert_eq!(
            loaded.slots(),
            [SlotMetadata::Valid { generation: 7 }, SlotMetadata::Erased,]
        );

        store.save(&state).unwrap();
        let repaired = store.load_with_metadata().unwrap();
        assert!(repaired.is_redundant_at(7));

        // A corrupt header that claims a much newer generation is not
        // authoritative and cannot influence identity replacement.
        store.storage.slots[1][8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let recovered = store.load_with_metadata().unwrap();
        assert_eq!(recovered.max_valid_generation(), Some(7));
        assert_eq!(recovered.replacement_generation(), Some(8));
        assert!(recovered.needs_repair());
    }

    #[test]
    fn saving_a_replacement_twice_replaces_both_old_authority_slots() {
        let mut store = TwoSlot::new(Memory::erased());
        store.save(&fresh_state(1, 10)).unwrap();
        store.save(&fresh_state(1, 11)).unwrap();
        let loaded = store.load_with_metadata().unwrap();
        let replacement = fresh_state(9, loaded.replacement_generation().unwrap());

        store.save(&replacement).unwrap();
        assert!(
            !store
                .load_with_metadata()
                .unwrap()
                .is_redundant_at(replacement.generation())
        );
        store.save(&replacement).unwrap();
        assert!(
            store
                .load_with_metadata()
                .unwrap()
                .is_redundant_at(replacement.generation())
        );
    }

    #[test]
    fn a_lower_generation_is_rejected_before_erasing_valid_state() {
        let mut store = TwoSlot::new(Memory::erased());
        let newest = fresh_state(1, 7);
        store.save(&newest).unwrap();
        assert_eq!(store.save(&fresh_state(2, 6)), Err(Error::StaleGeneration));
        assert_eq!(store.load().unwrap().unwrap().generation(), 7);

        // Rewriting the current generation is required to repair redundancy.
        store.save(&newest).unwrap();
        assert!(store.load_with_metadata().unwrap().is_redundant_at(7));
    }

    #[test]
    fn torn_body_or_commit_keeps_previous_generation() {
        let mut store = TwoSlot::new(Memory::erased());
        store.save(&fresh_state(1, 1)).unwrap();

        store.storage.writes_before_failure = Some(1); // body succeeds, commit fails
        assert!(store.save(&fresh_state(2, 2)).is_err());
        store.storage.writes_before_failure = None;
        assert_eq!(store.load().unwrap().unwrap().generation(), 1);
    }

    #[test]
    fn torn_first_commit_recovers_the_verified_identity() {
        let mut store = TwoSlot::new(Memory::erased());
        let state = fresh_state(1, 1);

        store.storage.writes_before_failure = Some(1); // body succeeds, commit fails
        assert!(store.save(&state).is_err());
        store.storage.writes_before_failure = None;

        let loaded = store.load_with_metadata().unwrap();
        assert!(loaded.needs_repair());
        let restored = loaded.into_state().unwrap();
        assert_eq!(restored.as_bytes(), state.as_bytes());

        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().unwrap().generation(), 1);
    }

    #[test]
    fn torn_first_body_allows_provisioning_to_restart() {
        let mut memory = Memory::erased();
        memory.slots[0][0] = 0;

        let loaded = TwoSlot::new(memory).load_with_metadata().unwrap();
        assert!(loaded.into_state().is_none());
    }

    #[test]
    fn dual_corruption_is_not_reported_as_first_boot() {
        let mut memory = Memory::erased();
        memory.slots[0][0] = 0;
        memory.slots[1][0] = 0;
        assert_eq!(TwoSlot::new(memory).load().unwrap_err(), Error::Corrupt);
    }
}
