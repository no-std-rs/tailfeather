//! Adapter from the ESP32-C6 flash peripheral to Tailfeather's two-slot store.

use embedded_storage::ReadStorage;
use embedded_storage::nor_flash::NorFlash;
use esp_storage::{FlashStorage, FlashStorageError};
use tailfeather::state::{SLOT_SIZE, SlotStorage};

const SLOT_BASES: [u32; 2] = [0x370000, 0x371000];
const MAX_WRITE: usize = 256;

pub struct FlashSlots<'d> {
    flash: FlashStorage<'d>,
}

/// Unpartitioned sector read only by lab images: an ASCII Headscale auth key
/// terminated by erased flash (0xFF) or NUL. It lies past every partition in
/// `partitions.csv` and inside the smallest (4 MiB) supported flash.
#[cfg(tailfeather_emulab)]
pub const LAB_AUTH_KEY_ADDRESS: u32 = 0x3F_F000;
#[cfg(tailfeather_emulab)]
const LAB_AUTH_KEY_LEN: usize = 128;
#[cfg(tailfeather_emulab)]
static LAB_AUTH_KEY: static_cell::StaticCell<[u8; LAB_AUTH_KEY_LEN]> = static_cell::StaticCell::new();
#[cfg(tailfeather_emulab)]
static LAB_AUTH_KEY_VALUE: critical_section::Mutex<core::cell::Cell<Option<&'static str>>> =
    critical_section::Mutex::new(core::cell::Cell::new(None));

/// The lab-provisioned auth key, if [`FlashSlots::load_lab_auth_key`] found one.
#[cfg(tailfeather_emulab)]
pub fn lab_auth_key() -> Option<&'static str> {
    critical_section::with(|cs| LAB_AUTH_KEY_VALUE.borrow(cs).get())
}

impl<'d> FlashSlots<'d> {
    /// Read the lab auth-key sector once. Erased or non-ASCII contents leave
    /// the baked key in effect.
    #[cfg(tailfeather_emulab)]
    pub fn load_lab_auth_key(&mut self) {
        let buffer = LAB_AUTH_KEY.init([0xff; LAB_AUTH_KEY_LEN]);
        if ReadStorage::read(&mut self.flash, LAB_AUTH_KEY_ADDRESS, buffer).is_err() {
            return;
        }
        let len = buffer
            .iter()
            .position(|&byte| byte == 0xff || byte == 0)
            .unwrap_or(LAB_AUTH_KEY_LEN);
        let key = &buffer[..len];
        if key.is_empty() || !key.iter().all(|byte| byte.is_ascii_graphic()) {
            return;
        }
        if let Ok(key) = core::str::from_utf8(key) {
            log::info!("lab-auth-key=flash len={len}");
            critical_section::with(|cs| LAB_AUTH_KEY_VALUE.borrow(cs).set(Some(key)));
        }
    }


    pub fn new(flash: esp_hal::peripherals::FLASH<'d>) -> Self {
        Self {
            flash: FlashStorage::new(flash),
        }
    }

    fn address(slot: usize, offset: usize, len: usize) -> Result<u32, FlashStorageError> {
        let base = *SLOT_BASES.get(slot).ok_or(FlashStorageError::OutOfBounds)?;
        if offset > SLOT_SIZE || len > SLOT_SIZE - offset {
            return Err(FlashStorageError::OutOfBounds);
        }
        Ok(base + offset as u32)
    }
}

impl SlotStorage for FlashSlots<'_> {
    type Error = FlashStorageError;

    fn read(&mut self, slot: usize, offset: usize, out: &mut [u8]) -> Result<(), Self::Error> {
        let address = Self::address(slot, offset, out.len())?;
        ReadStorage::read(&mut self.flash, address, out)
    }

    fn erase(&mut self, slot: usize) -> Result<(), Self::Error> {
        let address = Self::address(slot, 0, SLOT_SIZE)?;
        NorFlash::erase(&mut self.flash, address, address + SLOT_SIZE as u32)
    }

    fn write(&mut self, slot: usize, offset: usize, bytes: &[u8]) -> Result<(), Self::Error> {
        if bytes.len() > MAX_WRITE {
            return Err(FlashStorageError::OutOfBounds);
        }
        let padded_len = bytes.len().div_ceil(4) * 4;
        let address = Self::address(slot, offset, padded_len)?;
        if !address.is_multiple_of(4) {
            return Err(FlashStorageError::NotAligned);
        }
        let mut padded = [0xff; MAX_WRITE];
        padded[..bytes.len()].copy_from_slice(bytes);
        NorFlash::write(&mut self.flash, address, &padded[..padded_len])
    }
}
