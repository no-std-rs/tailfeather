//! Main-task stack depth instrumentation.
//!
//! `.stack` is not a fixed-size section: `esp-hal`'s `ld/sections/stack.x`
//! hands it whatever is left of the `RWDATA` region after `.data`/`.bss`, so
//! every byte of static growth is taken directly out of stack headroom. That
//! makes the actual depth worth measuring rather than inferring — the panic
//! handler's own report is unreliable here, because
//! `esp-rtos-0.3.0/src/lib.rs:322` builds the main-task stack slice with a
//! byte count used as a `u32` element count and therefore reports a length
//! four times the real one.
//!
//! This probe only *reads*. An earlier version painted the unused stack with a
//! sentinel and scanned for the high-water mark; that reliably faulted the
//! device with a `Load access fault` partway into the first TLS handshake,
//! because the region below the entry stack pointer is not in fact free — it
//! holds `esp-rtos`' own overflow watermark and the `stack-protector` guard
//! word. Reporting the live stack pointer gives up the transient in-handshake
//! peak, but it answers the question the enrollment sequence actually poses —
//! how much deeper the nested call site is — and it cannot corrupt anything.

use log::info;

unsafe extern "C" {
    /// Lowest address of the main-task stack (the overflow floor).
    static _stack_end_cpu0: u32;
    /// Highest address of the main-task stack (where the stack pointer starts).
    static _stack_start_cpu0: u32;
}

/// Lowest and highest address of the main-task stack.
fn bounds() -> (usize, usize) {
    (
        (&raw const _stack_end_cpu0) as usize,
        (&raw const _stack_start_cpu0) as usize,
    )
}

/// Total size of the main-task stack in bytes.
pub fn total() -> usize {
    let (floor, top) = bounds();
    top - floor
}

/// Current stack pointer, approximated by the address of a local in this
/// frame. `#[inline(never)]` keeps that approximation stable across callers.
#[inline(never)]
fn stack_pointer() -> usize {
    let anchor = 0u32;
    (&raw const anchor) as usize
}

/// Bytes of stack consumed at the point of call, and bytes still free below it.
pub fn depth() -> (usize, usize) {
    let (floor, top) = bounds();
    let sp = stack_pointer();
    (top - sp, sp - floor)
}

/// Log stack depth against a caller-supplied marker.
///
/// `label` names the point in the enrollment sequence so two marks can be
/// differenced — comparing `key-tls` against `noise-tls` isolates what the
/// deeper `open_link` nesting costs over the identical chain verification that
/// already succeeds at `key-tls`.
pub fn log_used(label: &str) {
    let (used, free) = depth();
    info!(
        "stack mark={label} stack_depth={used} stack_free={free} stack_total={}",
        total()
    );
}

/// Lab-only high-water instrumentation.
///
/// Unlike the earlier painter described above, this leaves the bottom
/// [`PAINT_FLOOR_MARGIN`] bytes alone (they hold esp-rtos' stack guard word)
/// and paints only below the live stack pointer, which on this single shared
/// stack is free by definition: an interrupt that lands mid-paint uses the
/// region and is gone before the loop resumes.
#[cfg(tailfeather_emulab)]
mod high_water {
    const PATTERN: u32 = 0xA5C3_5A3C;
    pub const PAINT_FLOOR_MARGIN: usize = 1024;
    const SP_MARGIN: usize = 512;

    /// Paint the unused stack. Call once, as early as possible.
    pub fn paint() {
        let (floor, _) = super::bounds();
        let start = (floor + PAINT_FLOOR_MARGIN + 3) & !3;
        let end = (super::stack_pointer() - SP_MARGIN) & !3;
        let mut address = start;
        while address < end {
            // SAFETY: `start..end` lies inside the main stack, above its guard
            // word and below every live frame.
            unsafe { (address as *mut u32).write_volatile(PATTERN) };
            address += 4;
        }
    }

    /// Deepest stack use since [`paint`], in bytes from the top.
    pub fn deepest() -> usize {
        let (floor, top) = super::bounds();
        let mut address = (floor + PAINT_FLOOR_MARGIN + 3) & !3;
        while address < top {
            // SAFETY: reads within the main stack.
            if unsafe { (address as *const u32).read_volatile() } != PATTERN {
                break;
            }
            address += 4;
        }
        top - address
    }
}
#[cfg(tailfeather_emulab)]
pub use high_water::{deepest, paint};
