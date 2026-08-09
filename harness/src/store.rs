//! Durable state, in a file, without an allocator or a filesystem library.
//!
//! The node's identity has to survive a restart: a node that regenerates its
//! keys re-registers as a stranger, and on a real tailnet that means a new
//! machine appearing every reboot. This is the harness's stand-in for the NVS
//! partition the firmware will use, and it exists behind the same narrow
//! interface so the code above cannot tell which it is talking to.
//!
//! # What it guarantees
//!
//! A read returns either the last blob fully written or nothing. That is worth
//! more than it sounds: the alternative — a torn write leaving half a key — does
//! not fail loudly, it produces a valid-looking identity that no server has ever
//! heard of. Two mechanisms give it. Writes go to a temporary file which is
//! `fsync`ed and then renamed over the target, and a rename within a directory
//! is atomic. And every blob carries a checksum, so corruption from anything
//! *outside* our control is refused rather than used.

use rustix::fs::{AtFlags, CWD, Mode, OFlags};
use rustix::io::Errno;
use wirefeather::crypto;

const MAGIC: &[u8; 4] = b"ESPG";
const VERSION: u8 = 1;
/// Truncated BLAKE2s. Sixteen bytes is far past what accidental corruption
/// could survive, and this is not a defence against an attacker who can already
/// write to the file.
const CHECKSUM_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 2;

/// The largest payload a blob may hold. Sized for the three 32-byte secrets a
/// node identity needs plus room for what later phases add.
pub const MAX_PAYLOAD: usize = 256;

/// The longest path the store will build, terminator included.
const PATH_MAX: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The path was too long or contained a NUL.
    BadPath,
    Errno(Errno),
    /// The file exists but is not a blob this version can read.
    Corrupt,
    /// The payload does not fit [`MAX_PAYLOAD`].
    TooLarge,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadPath => f.write_str("bad path"),
            Self::Errno(e) => write!(f, "errno {}", e.raw_os_error()),
            Self::Corrupt => f.write_str("stored state is corrupt"),
            Self::TooLarge => f.write_str("payload too large"),
        }
    }
}

/// A NUL-terminated path built in place.
///
/// `rustix` takes a `&CStr`, and building one without an allocator means owning
/// the bytes somewhere. This is that somewhere.
pub struct Path {
    bytes: [u8; PATH_MAX],
    len: usize,
}

impl Path {
    pub fn new(parts: &[&str]) -> Result<Self, StoreError> {
        let mut path = Self {
            bytes: [0; PATH_MAX],
            len: 0,
        };
        for part in parts {
            let bytes = part.as_bytes();
            // Leave room for the terminator, which the buffer is already zeroed
            // for but which must not be overwritten by the last byte.
            if path.len + bytes.len() >= PATH_MAX || bytes.contains(&0) {
                return Err(StoreError::BadPath);
            }
            path.bytes[path.len..path.len + bytes.len()].copy_from_slice(bytes);
            path.len += bytes.len();
        }
        Ok(path)
    }

    pub fn as_c_str(&self) -> &core::ffi::CStr {
        core::ffi::CStr::from_bytes_with_nul(&self.bytes[..self.len + 1])
            .expect("the buffer is zeroed and the constructor rejects interior NULs")
    }
}

/// A blob stored at a fixed path.
pub struct FileStore {
    path: Path,
    temporary: Path,
}

impl FileStore {
    /// Open a store at `directory/name`, creating the directory if needed.
    pub fn new(directory: &str, name: &str) -> Result<Self, StoreError> {
        let separator = if directory.ends_with('/') { "" } else { "/" };
        match rustix::fs::mkdirat(CWD, Path::new(&[directory])?.as_c_str(), Mode::RWXU) {
            // Already there is the normal case on every run but the first.
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(StoreError::Errno(e)),
        }
        Ok(Self {
            path: Path::new(&[directory, separator, name])?,
            temporary: Path::new(&[directory, separator, name, ".tmp"])?,
        })
    }

    /// Read the stored payload into `out`, returning its length.
    ///
    /// `Ok(None)` means nothing has been stored yet, which is the first-boot
    /// case and not an error. A blob that exists but does not verify *is* an
    /// error: silently treating it as absent would regenerate the identity and
    /// hide whatever damaged it.
    pub fn load(&self, out: &mut [u8]) -> Result<Option<usize>, StoreError> {
        let file = match rustix::fs::open(self.path.as_c_str(), OFlags::RDONLY, Mode::empty()) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(StoreError::Errno(e)),
        };

        let mut blob = [0u8; HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN];
        let mut filled = 0;
        loop {
            if filled == blob.len() {
                // More bytes than any valid blob can hold.
                return Err(StoreError::Corrupt);
            }
            match rustix::io::read(&file, &mut blob[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(Errno::INTR) => continue,
                Err(e) => return Err(StoreError::Errno(e)),
            }
        }

        if filled < HEADER_LEN + CHECKSUM_LEN || &blob[..4] != MAGIC || blob[4] != VERSION {
            return Err(StoreError::Corrupt);
        }
        let length = u16::from_le_bytes([blob[5], blob[6]]) as usize;
        if length > MAX_PAYLOAD || filled != HEADER_LEN + length + CHECKSUM_LEN {
            return Err(StoreError::Corrupt);
        }

        let end = HEADER_LEN + length;
        let expected = crypto::hash(&[&blob[..end]]);
        if !crypto::ct_eq(&expected[..CHECKSUM_LEN], &blob[end..filled]) {
            return Err(StoreError::Corrupt);
        }

        let out = out.get_mut(..length).ok_or(StoreError::TooLarge)?;
        out.copy_from_slice(&blob[HEADER_LEN..end]);
        Ok(Some(length))
    }

    /// Write `payload`, replacing whatever was there.
    pub fn save(&self, payload: &[u8]) -> Result<(), StoreError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(StoreError::TooLarge);
        }
        let mut blob = [0u8; HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN];
        blob[..4].copy_from_slice(MAGIC);
        blob[4] = VERSION;
        blob[5..7].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        blob[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
        let end = HEADER_LEN + payload.len();
        let checksum = crypto::hash(&[&blob[..end]]);
        blob[end..end + CHECKSUM_LEN].copy_from_slice(&checksum[..CHECKSUM_LEN]);
        let blob = &blob[..end + CHECKSUM_LEN];

        let result = self.write_temporary(blob);
        if result.is_err() {
            let _ = rustix::fs::unlinkat(CWD, self.temporary.as_c_str(), AtFlags::empty());
            return result;
        }
        rustix::fs::renameat(CWD, self.temporary.as_c_str(), CWD, self.path.as_c_str())
            .map_err(StoreError::Errno)
    }

    fn write_temporary(&self, blob: &[u8]) -> Result<(), StoreError> {
        let file = rustix::fs::open(
            self.temporary.as_c_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(StoreError::Errno)?;

        let mut written = 0;
        while written < blob.len() {
            match rustix::io::write(&file, &blob[written..]) {
                Ok(0) => return Err(StoreError::Corrupt),
                Ok(n) => written += n,
                Err(Errno::INTR) => continue,
                Err(e) => return Err(StoreError::Errno(e)),
            }
        }
        // Without this the rename can land before the data does, and a power cut
        // leaves a correctly named file full of zeroes.
        rustix::fs::fsync(&file).map_err(StoreError::Errno)
    }
}

/// Read a whole file into `out`, returning its length.
///
/// For loading a trust anchor: small, read once, and an error if it does not
/// fit rather than a truncated certificate that would fail to parse for a
/// reason nobody could guess.
pub fn read_file(path: &str, out: &mut [u8]) -> Result<usize, StoreError> {
    let path = Path::new(&[path])?;
    let file = rustix::fs::open(path.as_c_str(), OFlags::RDONLY, Mode::empty())
        .map_err(StoreError::Errno)?;
    let mut filled = 0;
    loop {
        if filled == out.len() {
            return Err(StoreError::TooLarge);
        }
        match rustix::io::read(&file, &mut out[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(n) => filled += n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(StoreError::Errno(e)),
        }
    }
}
