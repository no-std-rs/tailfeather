//! Local SSH fixture over stdin/stdout; no std, libc, allocator, or executor.
#![no_std]
#![no_main]

#[path = "../../../../harness/src/compiler_builtins.rs"]
mod compiler_builtins;

use core::{
    arch::asm,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use tailfeather_ssh::{
    Console, HostKey, Reply,
    embedded_io_async::{self, ErrorType, Read, Write},
    rand_core::{self, CryptoRng, RngCore},
};

// Linux x86-64 syscall ABI, restricted to the fixture's read/write/getrandom/exit.
fn syscall(number: usize, a: usize, b: usize, c: usize) -> isize {
    let result: isize;
    // SAFETY: callers supply live slices for memory arguments. Linux reports
    // errors as negative errno; syscall clobbers rcx/r11 and no other registers.
    unsafe {
        asm!("syscall", inlateout("rax") number => result, in("rdi") a,
        in("rsi") b, in("rdx") c, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

fn exit(code: usize) -> ! {
    let _ = syscall(231, code, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

#[derive(Debug, Clone, Copy)]
struct IoError;
impl embedded_io_async::Error for IoError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}
struct Stdio;
impl ErrorType for Stdio {
    type Error = IoError;
}
impl Read for Stdio {
    async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, IoError> {
        loop {
            let result = syscall(0, 0, bytes.as_mut_ptr() as usize, bytes.len());
            if result == -4 {
                continue;
            }
            return usize::try_from(result).map_err(|_| IoError);
        }
    }
}
impl Write for Stdio {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, IoError> {
        loop {
            let result = syscall(1, 1, bytes.as_ptr() as usize, bytes.len());
            if result == -4 {
                continue;
            }
            return usize::try_from(result).map_err(|_| IoError);
        }
    }
    async fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}
struct Random;
impl RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }
    fn fill_bytes(&mut self, mut bytes: &mut [u8]) {
        while !bytes.is_empty() {
            let result = syscall(318, bytes.as_mut_ptr() as usize, bytes.len(), 0);
            if result == -4 {
                continue;
            }
            if result <= 0 {
                exit(101);
            }
            bytes = &mut bytes[result as usize..];
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for Random {}

struct Echo;
impl Console for Echo {
    fn input(&mut self, byte: u8, output: &mut [u8]) -> Reply {
        output[0] = byte;
        if byte == b'\n' {
            Reply::exit(1, 0)
        } else {
            Reply::output(1)
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}

/// # Safety
/// Only the Linux kernel may enter this symbol, with its process-entry ABI.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("xor rbp, rbp", "and rsp, -16", "call {main}", main=sym main);
}

fn main() -> ! {
    let mut random = Random;
    let key = HostKey::from_seed(&[9; 32]); // public test fixture, never a device key
    let mut packet = [0; tailfeather_ssh::PACKET_BUFFER];
    let mut response = [0; tailfeather_ssh::CONSOLE_BUFFER];
    let mut console = Echo;
    let future = tailfeather_ssh::serve(
        Stdio,
        &mut random,
        &key,
        &|username: &str| username == "console",
        &mut console,
        &mut packet,
        &mut response,
    );
    let result = pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    match result {
        Poll::Ready(Ok(())) => {
            // Drain the client's final close/disconnect before closing the
            // ProxyCommand pipe, just as a TCP reactor drains before FIN.
            let mut bytes = [0; 64];
            loop {
                let result = syscall(0, 0, bytes.as_mut_ptr() as usize, bytes.len());
                if result > 0 || result == -4 {
                    continue;
                }
                break;
            }
            exit(0)
        }
        _ => exit(1),
    }
}
