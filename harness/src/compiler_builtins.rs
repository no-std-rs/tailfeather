//! C-ABI memory intrinsics emitted by LLVM for the supported linux-gnu target.
//!
//! A conventional binary receives these from libc. The harness deliberately
//! links no default libraries, so it supplies the small compiler surface itself.

use core::ffi::{c_int, c_void};

// These routines must not use Rust memory intrinsics or ordinary loops that
// LLVM can recognize as those intrinsics: this binary exports the symbols the
// intrinsics lower to, so such a rewrite recurses back into the same routine.
// Volatile byte accesses keep the implementations self-hosting under LTO.

/// Dependencies are compiled as ordinary Rust libraries and can retain
/// unreachable unwind edges. The harness has no unwinder: reaching one is a
/// fatal contract violation, so terminate immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Unwind_Resume(_exception: *mut c_void) -> ! {
    // SAFETY: `ud2` is the x86-64 architectural invalid-instruction trap and
    // never returns. The harness target is constrained to x86-64 Linux.
    unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
}

/// Satisfy inert EH metadata without linking libgcc, libc, or libunwind.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut c_void, value: c_int, count: usize) -> *mut c_void {
    let bytes = dst.cast::<u8>();
    let mut index = 0;
    while index < count {
        unsafe { bytes.add(index).write_volatile(value as u8) };
        index += 1;
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    let dst = dst.cast::<u8>();
    let src = src.cast::<u8>();
    let mut index = 0;
    while index < count {
        let byte = unsafe { src.add(index).read_volatile() };
        unsafe { dst.add(index).write_volatile(byte) };
        index += 1;
    }
    dst.cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    dst: *mut c_void,
    src: *const c_void,
    count: usize,
) -> *mut c_void {
    let dst_bytes = dst.cast::<u8>();
    let src_bytes = src.cast::<u8>();
    if (dst_bytes as usize) <= (src_bytes as usize) {
        let mut index = 0;
        while index < count {
            let byte = unsafe { src_bytes.add(index).read_volatile() };
            unsafe { dst_bytes.add(index).write_volatile(byte) };
            index += 1;
        }
    } else {
        let mut index = count;
        while index > 0 {
            index -= 1;
            let byte = unsafe { src_bytes.add(index).read_volatile() };
            unsafe { dst_bytes.add(index).write_volatile(byte) };
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    let mut index = 0;
    while index < count {
        let a = unsafe { left.add(index).read_volatile() };
        let b = unsafe { right.add(index).read_volatile() };
        if a != b {
            return c_int::from(a) - c_int::from(b);
        }
        index += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    unsafe { memcmp(left, right, count) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(text: *const u8) -> usize {
    let mut length = 0;
    while unsafe { text.add(length).read_volatile() } != 0 {
        length += 1;
    }
    length
}
