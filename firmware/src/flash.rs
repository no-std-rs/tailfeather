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

impl<'d> FlashSlots<'d> {
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
