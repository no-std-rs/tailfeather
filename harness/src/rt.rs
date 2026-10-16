//! What is left of the operating system interface once `rustix` is doing the
//! work: process exit, and somewhere to print.
//!
//! # Why `rustix` and not raw syscalls
//!
//! The point of the harness is to run the *same* `no_std` library crates the
//! firmware runs. Linking libc would quietly reintroduce an allocator, a
//! threading runtime, and a pile of hosted assumptions the ESP32 does not have,
//! and the test would stop proving what it claims to prove.
//!
//! That argument rules out libc; it does not require writing `syscall`
//! instructions by hand. `rustix` with `default-features = false` compiles for
//! `x86_64-unknown-linux-none` with no libc, no `std` and no allocator — it
//! emits the same instructions — while replacing every hand-rolled pointer cast
//! and errno comparison with a checked API. The modules above this one contain
//! no `unsafe` at all as a result.
//!
//! Two things `rustix` cannot do for us remain here. `_start` needs a naked
//! function, because the process entry point has an ABI no Rust function
//! signature can express. And `exit_group` lives only behind `rustix`'s
//! experimental `runtime` feature, which is not worth taking a dependency on
//! for one instruction.

use core::arch::asm;

use rustix::fd::{BorrowedFd, RawFd};
use rustix::io::Errno;

pub const STDOUT: i32 = 1;

/// Mark placed on complete IPv4 packets emitted by the gateway's raw sockets.
/// The namespace harness uses it to distinguish those packets from TCP resets
/// and ICMP errors synthesized by the local kernel.
pub const GATEWAY_MARK: u32 = 0x7466;

/// Configure a raw IPv4 socket to accept caller-supplied IP headers and mark
/// every packet it emits.
///
/// `rustix` intentionally does not expose these Linux-specific socket options.
/// Keeping the syscall and pointer handling here leaves the socket abstraction
/// and every packet-processing caller safe Rust.
pub fn configure_raw_ipv4(fd: RawFd) -> Result<(), Errno> {
    const SOL_IP: i32 = 0;
    const IP_HDRINCL: i32 = 3;
    const SOL_SOCKET: i32 = 1;
    const SO_MARK: i32 = 36;

    setsockopt_int(fd, SOL_IP, IP_HDRINCL, 1)?;
    setsockopt_int(fd, SOL_SOCKET, SO_MARK, GATEWAY_MARK as i32)
}

fn setsockopt_int(fd: RawFd, level: i32, option: i32, value: i32) -> Result<(), Errno> {
    const SYS_SETSOCKOPT: usize = 54;
    let mut result = SYS_SETSOCKOPT as isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") result,
            in("rdi") fd as usize,
            in("rsi") level as usize,
            in("rdx") option as usize,
            in("r10") (&value as *const i32) as usize,
            in("r8") core::mem::size_of::<i32>(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if result < 0 {
        Err(Errno::from_raw_os_error((-result) as i32))
    } else {
        Ok(())
    }
}

/// End the process.
///
/// `exit_group` rather than `exit` so that the whole process dies, not just the
/// calling thread. There is only ever one thread here, but the distinction
/// costs nothing and the wrong one is a hang rather than an error.
pub fn exit(code: i32) -> ! {
    const SYS_EXIT_GROUP: usize = 231;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_EXIT_GROUP,
            in("rdi") code as usize,
            options(noreturn, nostack),
        )
    }
}

/// Writes to a file descriptor, so the harness can report without `std`.
pub struct Console(pub i32);

impl core::fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // SAFETY: the descriptor is one of the standard streams the kernel
        // opened before this process started, and is never closed here.
        let fd = unsafe { BorrowedFd::borrow_raw(self.0) };
        let mut written = 0;
        while written < s.len() {
            match rustix::io::write(fd, &s.as_bytes()[written..]) {
                Ok(0) => return Err(core::fmt::Error),
                Ok(n) => written += n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(core::fmt::Error),
            }
        }
        Ok(())
    }
}

/// Human-readable progress, on stdout.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::rt::Console($crate::rt::STDOUT), $($arg)*);
    }};
}

/// A machine-readable event, on stdout with a fixed prefix.
///
/// The conformance suite drives this binary as a subprocess and watches for
/// these lines. Keeping them behind a prefix means the human-facing logging
/// above can be reworded freely without breaking a check, which is exactly the
/// coupling that would otherwise make the suite brittle.
#[macro_export]
macro_rules! evt {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut console = $crate::rt::Console($crate::rt::STDOUT);
        let _ = write!(console, "#EVT ");
        let _ = writeln!(console, $($arg)*);
    }};
}

/// Cryptographically secure random bytes, from the kernel.
pub fn getrandom(dest: &mut [u8]) {
    let mut filled = 0;
    while filled < dest.len() {
        match rustix::rand::getrandom(&mut dest[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => panic!("getrandom returned nothing"),
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => panic!("getrandom failed"),
        }
    }
}
