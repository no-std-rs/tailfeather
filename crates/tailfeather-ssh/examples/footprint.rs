//! Size probe; --serve-stdio runs a local SSH protocol fixture over stdin/stdout.
use core::future::Future;
use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use tailfeather_ssh::{
    Console, HostKey, Reply,
    embedded_io_async::{ErrorType, Read, Write},
    rand_core::{CryptoRng, RngCore},
};

struct Stdio;
impl ErrorType for Stdio {
    type Error = std::io::Error;
}
impl Read for Stdio {
    async fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::stdin().read(bytes)
    }
}
impl Write for Stdio {
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write(bytes)
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}
struct Random(std::fs::File);
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
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.read_exact(bytes).unwrap();
    }
    fn try_fill_bytes(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), tailfeather_ssh::rand_core::Error> {
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
struct NoWake;
impl Wake for NoWake {
    fn wake(self: Arc<Self>) {}
}

fn main() {
    let exchange = std::env::args().any(|arg| arg == "--serve-stdio");
    let key = HostKey::from_seed(&[9; 32]);
    let mut random = Random(std::fs::File::open("/dev/urandom").unwrap());
    let mut packet = [0; tailfeather_ssh::PACKET_BUFFER];
    let mut output = [0; tailfeather_ssh::CONSOLE_BUFFER];
    let mut console = Echo;
    let session = tailfeather_ssh::serve(
        Stdio,
        &mut random,
        &key,
        &|user: &str| user == "console",
        &mut console,
        &mut packet,
        &mut output,
    );
    if !exchange {
        println!(
            "packet={} response={} future={} policy={} host_key={} tcp_storage={}",
            tailfeather_ssh::PACKET_BUFFER,
            tailfeather_ssh::CONSOLE_BUFFER,
            std::mem::size_of_val(&session),
            std::mem::size_of::<tailfeather_ssh::Policy>(),
            std::mem::size_of::<HostKey>(),
            std::mem::size_of::<tailfeather_ssh::TcpStorage<'_>>()
        );
        return;
    }
    let waker = Waker::from(Arc::new(NoWake));
    match std::pin::pin!(session)
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
    {
        Poll::Ready(result) => result.unwrap(),
        Poll::Pending => panic!("blocking stdio unexpectedly suspended"),
    }
}
