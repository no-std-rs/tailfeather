//! Serialising an identity so it survives a reboot.
//!
//! This crate defines the *format* and the *interface*; it deliberately does
//! not know what it is stored on. The harness writes a file, the firmware will
//! write an NVS entry, and neither should be able to change what the bytes mean.
//!
//! The format is fixed-size on purpose. A variable-length encoding would need a
//! parser, and a parser is another thing that can be wrong about a value nobody
//! ever reads until the day the device reboots.

use zeroize::Zeroize;

use crate::keys::{DiscoPrivate, Identity, KEY_LEN, MachinePrivate, NodePrivate};

/// `magic ‖ version ‖ machine ‖ node ‖ disco`.
pub const BLOB_LEN: usize = 4 + 1 + KEY_LEN * 3;

const MAGIC: &[u8; 4] = b"TSID";
const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// Not this format, or a version this build does not understand.
    ///
    /// A future version must refuse rather than guess: reading a longer blob as
    /// a shorter one yields a syntactically valid identity that is not the
    /// device's, and the node silently becomes a different machine.
    Unrecognised,
    /// The buffer was not [`BLOB_LEN`] bytes.
    WrongLength,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unrecognised => "not a recognised identity blob",
            Self::WrongLength => "wrong blob length",
        })
    }
}

impl core::error::Error for StoreError {}

/// A serialised identity, sized at compile time.
pub struct Blob(pub [u8; BLOB_LEN]);

impl Drop for Blob {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Identity {
    /// Serialise into a fixed-size blob.
    pub fn to_blob(&self) -> Blob {
        let mut out = [0u8; BLOB_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5..37].copy_from_slice(&self.machine.to_bytes());
        out[37..69].copy_from_slice(&self.node.to_bytes());
        out[69..101].copy_from_slice(&self.disco.to_bytes());
        Blob(out)
    }

    /// Parse a blob written by [`Identity::to_blob`].
    pub fn from_blob(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != BLOB_LEN {
            return Err(StoreError::WrongLength);
        }
        if &bytes[..4] != MAGIC || bytes[4] != VERSION {
            return Err(StoreError::Unrecognised);
        }
        let mut key = [0u8; KEY_LEN];

        key.copy_from_slice(&bytes[5..37]);
        let machine = MachinePrivate::from_bytes(key);
        key.copy_from_slice(&bytes[37..69]);
        let node = NodePrivate::from_bytes(key);
        key.copy_from_slice(&bytes[69..101]);
        let disco = DiscoPrivate::from_bytes(key);
        key.zeroize();

        Ok(Self {
            machine,
            node,
            disco,
        })
    }
}

/// Somewhere an identity can be kept across restarts.
///
/// The two implementations that matter are a file on the harness and an NVS
/// entry on the device. Integrity is the *store's* job, not this crate's: the
/// harness checksums its blob and the ESP32's NVS checksums its entries, and
/// duplicating that here would be a second mechanism to keep correct.
pub trait Store {
    type Error;

    /// Read the stored blob into `out`, returning its length, or `None` if
    /// nothing has been stored yet.
    fn load(&self, out: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    fn save(&self, blob: &[u8]) -> Result<(), Self::Error>;
}

/// Load the stored identity, generating and saving a new one if there is none.
///
/// Returns whether the identity is new, because that distinction matters
/// upstream: a fresh identity has to register, an existing one only re-attaches.
pub fn load_or_create<S: Store>(
    store: &S,
    rng: &mut impl crate::keys::Rng,
) -> Result<(Identity, bool), IdentityError<S::Error>> {
    let mut buffer = [0u8; BLOB_LEN];
    let existing = store.load(&mut buffer).map_err(IdentityError::Store)?;

    if let Some(len) = existing {
        let identity = Identity::from_blob(&buffer[..len]).map_err(IdentityError::Format);
        buffer.zeroize();
        return identity.map(|i| (i, false));
    }

    let identity = Identity::generate(rng);
    let blob = identity.to_blob();
    store.save(&blob.0).map_err(IdentityError::Store)?;
    Ok((identity, true))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError<E> {
    Store(E),
    Format(StoreError),
}

impl<E: core::fmt::Display> core::fmt::Display for IdentityError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Format(e) => write!(f, "{e}"),
        }
    }
}

impl<E: core::fmt::Display + core::fmt::Debug> core::error::Error for IdentityError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Rng;

    struct Counter(u8);

    impl Rng for Counter {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn an_identity_survives_a_round_trip() {
        let original = Identity::generate(&mut Counter(1));
        let blob = original.to_blob();
        assert_eq!(blob.0.len(), 101);

        let restored = Identity::from_blob(&blob.0).unwrap();
        assert_eq!(restored.machine.public(), original.machine.public());
        assert_eq!(restored.node.public(), original.node.public());
        assert_eq!(restored.disco.public(), original.disco.public());
    }

    #[test]
    fn the_three_keys_are_not_swapped_by_the_round_trip() {
        // Serialising and parsing in a different order would be undetectable
        // from a single-key test, and would silently make the node key the
        // machine key.
        let original = Identity::generate(&mut Counter(1));
        let restored = Identity::from_blob(&original.to_blob().0).unwrap();
        assert_ne!(
            restored.machine.public().as_bytes(),
            restored.node.public().as_bytes()
        );
        assert_eq!(
            restored.machine.to_bytes(),
            original.machine.to_bytes(),
            "the machine key must not come back as one of the others"
        );
    }

    #[test]
    fn a_blob_from_another_format_or_version_is_refused() {
        let mut blob = Identity::generate(&mut Counter(1)).to_blob().0;
        assert!(Identity::from_blob(&blob).is_ok());

        blob[4] = VERSION + 1;
        assert_eq!(
            Identity::from_blob(&blob).err(),
            Some(StoreError::Unrecognised)
        );

        blob[4] = VERSION;
        blob[0] = b'X';
        assert_eq!(
            Identity::from_blob(&blob).err(),
            Some(StoreError::Unrecognised)
        );

        assert_eq!(
            Identity::from_blob(&blob[..BLOB_LEN - 1]).err(),
            Some(StoreError::WrongLength)
        );
    }

    /// A store that keeps the blob in memory, standing in for a file or NVS.
    struct Memory(core::cell::RefCell<Option<[u8; BLOB_LEN]>>);

    impl Store for Memory {
        type Error = ();

        fn load(&self, out: &mut [u8]) -> Result<Option<usize>, ()> {
            match *self.0.borrow() {
                None => Ok(None),
                Some(blob) => {
                    out[..BLOB_LEN].copy_from_slice(&blob);
                    Ok(Some(BLOB_LEN))
                }
            }
        }

        fn save(&self, blob: &[u8]) -> Result<(), ()> {
            let mut stored = [0u8; BLOB_LEN];
            stored.copy_from_slice(blob);
            *self.0.borrow_mut() = Some(stored);
            Ok(())
        }
    }

    #[test]
    fn the_first_run_creates_an_identity_and_the_second_reuses_it() {
        let store = Memory(core::cell::RefCell::new(None));

        let (first, is_new) = load_or_create(&store, &mut Counter(1)).unwrap();
        assert!(is_new, "the first run must report a fresh identity");

        // A different generator, so reuse cannot be mistaken for regenerating
        // the same bytes by luck.
        let (second, is_new) = load_or_create(&store, &mut Counter(99)).unwrap();
        assert!(!is_new, "the second run must not report a fresh identity");
        assert_eq!(first.machine.public(), second.machine.public());
        assert_eq!(first.node.public(), second.node.public());
        assert_eq!(first.disco.public(), second.disco.public());
    }
}
