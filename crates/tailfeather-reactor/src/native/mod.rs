//! Tokio socket/TLS and durable filesystem adapters for the common runtime.

use crate::{
    exec::{Clock, TokioClock},
    runtime::{Error, LinkBuffers, Network, State},
};
use std::{
    cell::Cell,
    fs::File,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub mod net;
pub mod store;
pub mod tls;

pub struct Reactor(crate::exec::Reactor<TokioClock>);
impl Default for Reactor {
    fn default() -> Self {
        Self::new()
    }
}
impl Reactor {
    pub fn new() -> Self {
        Self(crate::exec::Reactor::with_clock(TokioClock::default()))
    }
    pub fn clock_millis(&self) -> u64 {
        self.0.clock_millis()
    }
    pub async fn sleep(&self, millis: u64) {
        self.0.sleep(millis).await;
    }
}

pub struct OsRng;
macro_rules! rng {
    ($trait:path) => {
        impl $trait for OsRng {
            fn fill_bytes(&mut self, bytes: &mut [u8]) {
                getrandom::fill(bytes).expect("OS randomness unavailable");
            }
        }
    };
}
rng!(tailfeather::keys::Rng);
rng!(tailfeather::tunnel::Rng);
rng!(tailfeather::disco::packet::Rng);
rng!(tailfeather::derp::client::Rng);

pub struct TokioNetwork {
    clock: TokioClock,
    reactor: Reactor,
    udp: net::UdpSocket,
    interface: Cell<Option<Ipv4Addr>>,
}
impl TokioNetwork {
    pub async fn bind(address: Ipv4Addr, port: u16) -> io::Result<Self> {
        let reactor = Reactor::new();
        let udp = net::UdpSocket::bind(&reactor, address, port).await?;
        Ok(Self {
            clock: TokioClock::default(),
            reactor,
            udp,
            interface: Cell::new(None),
        })
    }
}
impl Clock for TokioNetwork {
    fn now_millis(&self) -> u64 {
        self.clock.now_millis()
    }
    async fn sleep_until(&self, deadline_ms: u64) {
        self.clock.sleep_until(deadline_ms).await;
    }
}
impl Network for TokioNetwork {
    type Stream<'a> = tls::Stream;
    type Rng = OsRng;
    fn rng(&self) -> OsRng {
        OsRng
    }
    fn unix_millis(&self) -> Result<u64, Error> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "wall clock unavailable")?
            .as_millis();
        u64::try_from(millis).map_err(|_| "wall clock overflow")
    }
    fn local_endpoint(&self) -> Result<SocketAddrV4, Error> {
        self.udp.local_addr().map_err(|_| "UDP endpoint")
    }
    fn interface_address(&self) -> Option<Ipv4Addr> {
        self.interface.get()
    }
    fn validate_ca(&self, ca: &[u8]) -> Result<(), Error> {
        tls::roots(ca).map(|_| ()).map_err(|_| "invalid control CA")
    }
    async fn resolve(&self, host: &str) -> Result<heapless::Vec<Ipv4Addr, 16>, Error> {
        Ok(net::resolve_v4(host)
            .await
            .map_err(|_| "DNS lookup")?
            .into_iter()
            .collect())
    }
    async fn connect<'a>(
        &'a self,
        host: &str,
        port: u16,
        tls_name: &str,
        ca: &[u8],
        buffers: &'a mut LinkBuffers,
    ) -> Result<tls::Stream, Error> {
        let socket = net::TcpStream::connect_host(&self.reactor, host, port)
            .await
            .map_err(|_| "TCP connection")?;
        if let Ok(std::net::SocketAddr::V4(endpoint)) = socket.0.local_addr() {
            self.interface.set(Some(*endpoint.ip()));
        }
        tokio::time::timeout(
            core::time::Duration::from_secs(20),
            tls::connect(
                socket,
                tls_name,
                ca,
                &mut buffers.tls_rx,
                &mut buffers.tls_tx,
            ),
        )
        .await
        .map_err(|_| "TLS deadline")?
        .map_err(|_| "TLS authentication")
    }
    async fn receive(&self, packet: &mut [u8]) -> Result<(usize, SocketAddrV4), Error> {
        self.udp.recv_from(packet).await.map_err(|_| "UDP receive")
    }
    async fn send(&self, packet: &[u8], to: SocketAddrV4) -> Result<(), Error> {
        self.udp
            .send_to(packet, &to)
            .await
            .map(|_| ())
            .map_err(|_| "UDP send")
    }
}

pub struct FileState {
    directory: PathBuf,
    _lock: File,
}
impl FileState {
    pub fn open(directory: &Path) -> io::Result<Self> {
        store::create_directory(directory)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("lock"))?;
        #[cfg(not(target_os = "android"))]
        lock.try_lock()
            .map_err(|_| io::Error::other("network identity already in use"))?;
        #[cfg(target_os = "android")]
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
        })
    }
}
impl State for FileState {
    fn load(&self, output: &mut [u8]) -> Result<Option<usize>, Error> {
        store::FileStore::new(&self.directory)
            .load(output)
            .map_err(|_| "identity read")
    }
    fn save(&self, bytes: &[u8]) -> Result<(), Error> {
        store::FileStore::new(&self.directory)
            .save(bytes)
            .map_err(|_| "identity write")
    }
    fn load_timestamp(&self, output: &mut [u8; 12]) -> Result<bool, Error> {
        match store::FileStore::timestamp(&self.directory)
            .load(output)
            .map_err(|_| "timestamp read")?
        {
            Some(12) => Ok(true),
            Some(_) => Err("timestamp state length"),
            None => Ok(false),
        }
    }
    fn save_timestamp(&self, bytes: &[u8; 12]) -> Result<(), Error> {
        store::FileStore::timestamp(&self.directory)
            .save(bytes)
            .map_err(|_| "timestamp write")
    }
}

/// Available CPU extensions; each crypto provider selects its own instructions.
#[derive(Debug, Clone, Copy)]
pub struct CpuCapabilities {
    pub aead_backend: &'static str,
    pub sse2: bool,
    pub sse41: bool,
    pub avx2: bool,
    pub bmi2: bool,
    pub avx512f: bool,
    pub neon: bool,
}
impl CpuCapabilities {
    pub fn detect() -> Self {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let (sse2, sse41, avx2, bmi2, avx512f) = (
            std::arch::is_x86_feature_detected!("sse2"),
            std::arch::is_x86_feature_detected!("sse4.1"),
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("bmi2"),
            std::arch::is_x86_feature_detected!("avx512f"),
        );
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let (sse2, sse41, avx2, bmi2, avx512f) = (false, false, false, false, false);
        #[cfg(target_arch = "aarch64")]
        let neon = std::arch::is_aarch64_feature_detected!("neon");
        #[cfg(not(target_arch = "aarch64"))]
        let neon = false;
        Self {
            aead_backend: tailfeather::tunnel::crypto::aead_backend(),
            sse2,
            sse41,
            avx2,
            bmi2,
            avx512f,
            neon,
        }
    }
}
