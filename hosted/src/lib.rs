//! Portable rootless Tailfeather node for native applications.
//!
//! Windows, macOS and Linux share the same control, DERP, WireGuard, ACL and
//! userspace TCP implementation. No OS VPN service or virtual adapter is used.
#![forbid(unsafe_code)]
mod bridge;
mod exec;
mod net;
mod netstack;
mod node;
mod relay;
mod store;
mod time;
mod tls;
use std::{io, net::Ipv4Addr, path::PathBuf, sync::Arc};
use tokio::{
    io::DuplexStream,
    sync::{mpsc, oneshot, watch},
};

pub struct Config {
    pub directory: PathBuf,
    pub control_url: String,
    pub hostname: String,
    pub auth_key: String,
    pub control_ca_der: Vec<u8>,
    pub relay_only: bool,
    /// Register a disposable node; the control server removes it after disconnect.
    pub ephemeral: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub address: Option<Ipv4Addr>,
    pub error: Option<&'static str>,
}
enum Command {
    Connect {
        address: Ipv4Addr,
        port: u16,
        reply: oneshot::Sender<io::Result<DuplexStream>>,
    },
    Listen {
        port: u16,
        incoming: mpsc::Sender<DuplexStream>,
        reply: oneshot::Sender<io::Result<()>>,
    },
}
/// Clones share one owned node. Dropping the final clone closes all networking.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}
struct Inner {
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<Status>,
}
impl Client {
    /// State is authority-bound; corrupt or mismatched state is never reset.
    /// Each directory permits one running client, including across processes.
    pub fn start(config: Config) -> io::Result<Self> {
        if config.hostname.is_empty()
            || config.hostname.len() > 63
            || config.auth_key.len() > 1024
            || config.control_ca_der.len() > 4096
        {
            return Err(io::Error::other("invalid hosted node configuration"));
        }
        tailfeather::control::authority::Authority::parse(&config.control_url, false)
            .map_err(|_| io::Error::other("HTTPS control origin required"))?;
        store::create_directory(&config.directory)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(config.directory.join("lock"))?;
        lock.try_lock()
            .map_err(|_| io::Error::other("network identity already in use"))?;
        let (commands, receiver) = mpsc::channel(16);
        let (status_tx, status) = watch::channel(Status::default());
        std::thread::Builder::new()
            .name("tailfeather".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let _lock = lock;
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        let result = tokio::task::LocalSet::new()
                            .block_on(&runtime, node::run(config, receiver, status_tx.clone()));
                        if let Err(error) = result {
                            status_tx.send_replace(Status {
                                address: None,
                                error: Some(error),
                            });
                        }
                    }
                    Err(_) => {
                        status_tx.send_replace(Status {
                            address: None,
                            error: Some("runtime start"),
                        });
                    }
                }
            })?;
        Ok(Self {
            inner: Arc::new(Inner { commands, status }),
        })
    }
    pub fn status(&self) -> Status {
        self.inner.status.borrow().clone()
    }
    pub async fn ready(&self) -> io::Result<Ipv4Addr> {
        let mut status = self.inner.status.clone();
        loop {
            let value = status.borrow().clone();
            if let Some(error) = value.error {
                return Err(io::Error::other(error));
            }
            if let Some(address) = value.address {
                return Ok(address);
            }
            status
                .changed()
                .await
                .map_err(|_| io::Error::other("node stopped"))?;
        }
    }
    /// Listen inside the tailnet. Incoming packets pass control ACL and
    /// cryptokey source checks before reaching this listener.
    pub async fn listen(&self, port: u16) -> io::Result<Listener> {
        self.ready().await?;
        let (incoming, receiver) = mpsc::channel(16);
        let (reply, received) = oneshot::channel();
        self.inner
            .commands
            .send(Command::Listen {
                port,
                incoming,
                reply,
            })
            .await
            .map_err(|_| io::Error::other("node stopped"))?;
        received
            .await
            .map_err(|_| io::Error::other("node stopped"))??;
        Ok(Listener { receiver })
    }
    /// TCP is carried inside WireGuard and follows the coordinator's policy.
    pub async fn connect(&self, address: Ipv4Addr, port: u16) -> io::Result<DuplexStream> {
        self.ready().await?;
        let (reply, received) = oneshot::channel();
        self.inner
            .commands
            .send(Command::Connect {
                address,
                port,
                reply,
            })
            .await
            .map_err(|_| io::Error::other("node stopped"))?;
        received
            .await
            .map_err(|_| io::Error::other("node stopped"))?
    }
}
/// A tailnet-only listener; dropping it stops accepting new connections.
pub struct Listener {
    receiver: mpsc::Receiver<DuplexStream>,
}
impl Listener {
    pub async fn accept(&mut self) -> io::Result<DuplexStream> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::other("listener stopped"))
    }
}
/// Inspect an existing authority-bound identity without starting networking.
pub fn is_enrolled(directory: &std::path::Path, control_url: &str) -> io::Result<bool> {
    let authority = tailfeather::control::authority::Authority::parse(control_url, false)
        .map_err(|_| io::Error::other("invalid control origin"))?;
    let mut bytes = [0; tailfeather::PersistState::BLOB_LEN];
    let Some(len) = store::FileStore::new(directory).load(&mut bytes)? else {
        return Ok(false);
    };
    let state = tailfeather::PersistState::from_bytes(&bytes[..len])
        .map_err(|_| io::Error::other("corrupt network identity; use a fresh directory"))?;
    bytes.fill(0);
    if state.authority_hash() != authority.digest() {
        return Err(io::Error::other(
            "network identity belongs to another authority",
        ));
    }
    Ok(state.enrolled())
}
struct OsRng;
macro_rules! rng {
    ($trait:path) => {
        impl $trait for OsRng {
            fn fill_bytes(&mut self, out: &mut [u8]) {
                getrandom::fill(out).expect("operating system randomness unavailable");
            }
        }
    };
}
rng!(tailfeather::keys::Rng);
rng!(tailfeather::tunnel::Rng);
rng!(tailfeather::disco::packet::Rng);
rng!(tailfeather::derp::client::Rng);

#[cfg(test)]
mod loopback_tests;
