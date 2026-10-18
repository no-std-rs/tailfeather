#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use core::net::Ipv4Addr;
use embedded_io_async::{Read, Write};
use heapless::String;
use rand_core::{CryptoRng, RngCore};
use tailfeather::{keys::NodePublic, netmap::Netmap};
use zeroize::Zeroize;

pub use ed25519_dalek;
pub use embedded_io_async;
pub use rand_core;
pub use tailfeather::netmap::ssh::{MAX_USERNAME, Policy};

/// Shared incoming/outgoing SSH packet storage. Oversized packets disconnect.
pub const PACKET_BUFFER: usize = 4096;
/// Suggested application response buffer, separate from the shared packet.
pub const CONSOLE_BUFFER: usize = 256;
pub const PORT: u16 = 22;
/// Two small TCP socket slots: one console and a spare listener.
pub type TcpStorage<'a> = tailfeather::local_tcp::Storage<'a, 2, 1024>;

/// Persist the seed on the device; this key is independent of its WireGuard key.
pub struct HostKey(zssh::SecretKey);

impl HostKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(zssh::SecretKey::Ed25519 {
            secret_key: ed25519_dalek::SigningKey::from_bytes(seed),
        })
    }

    /// OpenSSH public-key line for `Hostinfo.ssh_host_keys` (80 bytes suffice).
    pub fn public_key<'a>(&self, output: &'a mut [u8]) -> Option<&'a str> {
        const PREFIX: &[u8] = b"ssh-ed25519 ";
        let zssh::SecretKey::Ed25519 { secret_key } = &self.0;
        let mut blob = [0u8; 51];
        blob[..4].copy_from_slice(&11u32.to_be_bytes());
        blob[4..15].copy_from_slice(b"ssh-ed25519");
        blob[15..19].copy_from_slice(&32u32.to_be_bytes());
        blob[19..].copy_from_slice(secret_key.verifying_key().as_bytes());
        output.get_mut(..PREFIX.len())?.copy_from_slice(PREFIX);
        let size = STANDARD
            .encode_slice(blob, output.get_mut(PREFIX.len()..)?)
            .ok()?;
        core::str::from_utf8(&output[..PREFIX.len() + size]).ok()
    }
}

/// Consult current authorization. A closure can borrow a live netmap briefly
/// through a `RefCell`; no snapshot needs to be retained by the SSH session.
pub trait Authorizer {
    fn allows(&self, username: &str) -> bool;
}

impl<F: Fn(&str) -> bool> Authorizer for F {
    fn allows(&self, username: &str) -> bool {
        self(username)
    }
}

/// Bind the decrypted WireGuard peer to its exact node address, the destination
/// node, the TCP/22 network grant, and the separate SSH grant.
///
/// Construct this from authenticated tunnel metadata, never client-supplied
/// identity or an arbitrary LAN TCP connection. `AllowedIPs` subnet routes
/// deliberately do not prove that their traffic originates at the router.
pub struct TailnetAccess<'a, const PEERS: usize> {
    pub netmap: &'a Netmap<PEERS>,
    pub peer_key: NodePublic,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub local_user: &'a str,
}

impl<const PEERS: usize> Authorizer for TailnetAccess<'_, PEERS> {
    fn allows(&self, username: &str) -> bool {
        let Some(peer) = self.netmap.peers.by_node_key(&self.peer_key) else {
            return false;
        };
        !peer.expired()
            && peer
                .addresses
                .iter()
                .any(|address| address.prefix == 32 && address.address == self.source)
            && self.netmap.addresses.iter().any(|address| {
                address.prefix == 32 && address.address == core::net::IpAddr::V4(self.destination)
            })
            && self
                .netmap
                .packet_filter
                .allows(self.source, self.destination, 6, PORT)
            && self
                .netmap
                .ssh_policy
                .allows(self.source, username, self.local_user)
    }
}

/// Bytes written into the supplied response buffer and optional session exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub written: usize,
    pub exit_status: Option<u32>,
}

impl Reply {
    pub const fn output(written: usize) -> Self {
        Self {
            written,
            exit_status: None,
        }
    }
    pub const fn exit(written: usize, status: u32) -> Self {
        Self {
            written,
            exit_status: Some(status),
        }
    }
}

/// Application-owned console. The server performs no command parsing or echo.
/// Each input byte arrives only after current authorization has been checked.
/// A line editor can retain its own small bounded command buffer.
pub trait Console {
    fn open(&mut self, _output: &mut [u8]) -> Reply {
        Reply::output(0)
    }
    fn input(&mut self, byte: u8, output: &mut [u8]) -> Reply;
}

#[derive(Debug)]
pub enum Error<E> {
    BuffersTooSmall,
    ConsoleOverflow,
    AccessRevoked,
    Transport(zssh::Error<E>),
}

impl<E> From<zssh::Error<E>> for Error<E> {
    fn from(error: zssh::Error<E>) -> Self {
        Self::Transport(error)
    }
}

struct Behavior<'a, S, R, A> {
    stream: S,
    random: &'a mut R,
    key: &'a HostKey,
    access: &'a A,
}

impl<S: Read + Write, R: RngCore + CryptoRng, A: Authorizer> zssh::Behavior
    for Behavior<'_, S, R, A>
{
    type Stream = S;
    type Random = R;
    type User = String<MAX_USERNAME>;
    type Command = ();

    fn stream(&mut self) -> &mut S {
        &mut self.stream
    }
    fn random(&mut self) -> &mut R {
        self.random
    }
    fn host_secret_key(&self) -> &zssh::SecretKey {
        &self.key.0
    }
    fn server_id(&self) -> &'static str {
        "SSH-2.0-tailfeather"
    }
    fn allow_shell(&self) -> bool {
        true
    }
    fn parse_command(&mut self, _command: &str) {}
    fn allow_user(&mut self, username: &str, method: &zssh::AuthMethod) -> Option<Self::User> {
        if *method != zssh::AuthMethod::None || !self.access.allows(username) {
            return None;
        }
        String::try_from(username).ok()
    }
}

/// Serve one connection and one shell channel, then disconnect.
///
/// The stream must already belong to the authenticated peer passed to `access`.
/// Use `ssh -T console@device`: PTY requests, forwarding, environment variables,
/// and subsystems have no effect on the application. Exec exits with status 1.
/// The caller supplies a cryptographically secure RNG, packet storage, and
/// response storage. Neither an allocator nor an async runtime is required.
///
/// Cancel/drop this future on network removal, policy change, or your runtime's
/// handshake/idle deadline, including while a read or write is blocked. A live
/// authorizer is also checked before every console callback and response.
pub async fn serve<S: Read + Write, R: RngCore + CryptoRng, A: Authorizer, C: Console>(
    stream: S,
    random: &mut R,
    key: &HostKey,
    access: &A,
    console: &mut C,
    packet: &mut [u8],
    output: &mut [u8],
) -> Result<(), Error<S::Error>> {
    if packet.len() < PACKET_BUFFER || output.is_empty() {
        return Err(Error::BuffersTooSmall);
    }
    // Wipe on completion, error, and cancellation after the first poll.
    let packet = Wipe(packet);
    let output = Wipe(output);
    run(stream, random, key, access, console, packet.0, output.0).await
}

struct Wipe<'a>(&'a mut [u8]);
impl Drop for Wipe<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

async fn run<S: Read + Write, R: RngCore + CryptoRng, A: Authorizer, C: Console>(
    stream: S,
    random: &mut R,
    key: &HostKey,
    access: &A,
    console: &mut C,
    packet: &mut [u8],
    output: &mut [u8],
) -> Result<(), Error<S::Error>> {
    let behavior = Behavior {
        stream,
        random,
        key,
        access,
    };
    let mut transport = zssh::Transport::new(packet, behavior);
    let mut channel = transport.accept().await?;
    if matches!(channel.request(), zssh::Request::Exec(())) {
        channel.exit(1).await?;
    } else {
        let username = channel.user();
        let mut first = true;
        let status = loop {
            if !access.allows(&username) {
                return Err(Error::AccessRevoked);
            }
            let reply = if first {
                first = false;
                console.open(output)
            } else {
                // A one-byte receive window lets this single-buffer engine
                // alternate input and output without retaining unread packets.
                // This trades throughput for fixed memory and simple backpressure.
                let mut byte = [0];
                if channel.read_exact_stdin(&mut byte).await? == 0 {
                    break 0;
                }
                if !access.allows(&username) {
                    return Err(Error::AccessRevoked);
                }
                console.input(byte[0], output)
            };
            if reply.written > output.len() {
                return Err(Error::ConsoleOverflow);
            }
            if !access.allows(&username) {
                return Err(Error::AccessRevoked);
            }
            channel.write_all_stdout(&output[..reply.written]).await?;
            if let Some(status) = reply.exit_status {
                break status;
            }
        };
        channel.exit(status).await?;
    }
    // CHANNEL_CLOSE and exit-status are already on the wire. The runtime
    // closes/drains TCP; a further SSH disconnect can race the client's FIN.
    Ok(())
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use tailfeather::{
        keys::NodePrivate,
        netmap::{Cidr, Cidr4, Parser, Peer},
    };

    #[test]
    fn host_key_is_an_openssh_public_key_and_is_advertised() {
        let key = HostKey::from_seed(&[1; 32]);
        let mut buffer = [0; 80];
        let text = key.public_key(&mut buffer).unwrap();
        let mut blob = [0; 51];
        assert_eq!(
            STANDARD
                .decode_slice(text.strip_prefix("ssh-ed25519 ").unwrap(), &mut blob)
                .unwrap(),
            51
        );
        assert_eq!(
            &blob[19..],
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .as_bytes()
        );
        assert!(key.public_key(&mut [0; 79]).is_none());
        let info = tailfeather::control::Hostinfo {
            ssh_host_keys: &[text],
            ..Default::default()
        };
        let mut body = [0; 512];
        let mut writer = tailfeather::control::json::Writer::new(&mut body);
        info.write(&mut writer);
        let json = core::str::from_utf8(writer.finish().unwrap()).unwrap();
        assert!(json.contains("\"SSH_HostKeys\":[\"ssh-ed25519 "));
    }

    #[test]
    fn policy_requires_exact_wireguard_peer_address_and_network_grant() {
        let key = NodePrivate::from_bytes([2; 32]).public();
        let source = Ipv4Addr::new(100, 64, 0, 2);
        let dest = Ipv4Addr::new(100, 64, 0, 1);
        let mut map = Netmap::<1>::new();
        let mut parser = Parser::new();
        parser.push(&mut map, br#"{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}]}],"SSHPolicy":{"rules":[{"principals":[{"any":true}],"sshUsers":{"console":"console"},"action":{"accept":true}}]}}"#).unwrap();
        parser.finish(&mut map).unwrap();
        map.addresses
            .push(Cidr {
                address: dest.into(),
                prefix: 32,
            })
            .unwrap();
        let mut peer = Peer::new(1, key);
        peer.addresses
            .push(Cidr4 {
                address: source,
                prefix: 32,
            })
            .unwrap();
        peer.allowed_ips
            .push(Cidr4 {
                address: Ipv4Addr::UNSPECIFIED,
                prefix: 0,
            })
            .unwrap();
        map.peers.upsert(peer).unwrap();
        let allowed = |map: &Netmap<1>, peer_key, source, destination| {
            TailnetAccess {
                netmap: map,
                peer_key,
                source,
                destination,
                local_user: "console",
            }
            .allows("console")
        };
        assert!(allowed(&map, key, source, dest));
        let mut parser = Parser::new();
        parser
            .push(
                &mut map,
                br#"{"PeersChangedPatch":[{"NodeID":1,"Expired":true}]}"#,
            )
            .unwrap();
        parser.finish(&mut map).unwrap();
        assert!(!allowed(&map, key, source, dest));
        let mut parser = Parser::new();
        parser
            .push(
                &mut map,
                br#"{"PeersChangedPatch":[{"NodeID":1,"Expired":false}]}"#,
            )
            .unwrap();
        parser.finish(&mut map).unwrap();
        assert!(allowed(&map, key, source, dest));
        assert!(!allowed(&map, key, Ipv4Addr::new(100, 64, 0, 3), dest));
        assert!(!allowed(
            &map,
            NodePrivate::from_bytes([3; 32]).public(),
            source,
            dest
        ));
        assert!(!allowed(&map, key, source, Ipv4Addr::LOCALHOST));
        map.packet_filter = Default::default();
        assert!(!allowed(&map, key, source, dest));
    }

    struct PendingStream;
    impl embedded_io_async::ErrorType for PendingStream {
        type Error = core::convert::Infallible;
    }
    impl Read for PendingStream {
        async fn read(&mut self, _: &mut [u8]) -> Result<usize, Self::Error> {
            core::future::pending().await
        }
    }
    impl Write for PendingStream {
        async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
            Ok(bytes.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    struct EmptyConsole;
    impl Console for EmptyConsole {
        fn input(&mut self, _: u8, _: &mut [u8]) -> Reply {
            Reply::output(0)
        }
    }
    struct NoWake;
    impl std::task::Wake for NoWake {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    #[test]
    fn session_memory_is_bounded_and_cancellation_wipes_buffers() {
        use core::future::Future;
        let key = HostKey::from_seed(&[0; 32]);
        let mut random = <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed([1; 32]);
        let mut packet = [9; PACKET_BUFFER];
        let mut output = [9; CONSOLE_BUFFER];
        let mut console = EmptyConsole;
        {
            let session = serve(
                PendingStream,
                &mut random,
                &key,
                &|_: &str| false,
                &mut console,
                &mut packet,
                &mut output,
            );
            let bytes = core::mem::size_of_val(&session);
            std::println!(
                "session future: {bytes}; policy: {}; host key: {}",
                core::mem::size_of::<Policy>(),
                core::mem::size_of::<HostKey>()
            );
            assert!(bytes <= 4096, "SSH future grew to {bytes} bytes");
            assert!(core::mem::size_of::<Policy>() <= 2048);
            let mut session = std::pin::pin!(session);
            let waker = std::task::Waker::from(std::sync::Arc::new(NoWake));
            assert!(
                session
                    .as_mut()
                    .poll(&mut core::task::Context::from_waker(&waker))
                    .is_pending()
            );
        }
        assert!(packet.iter().all(|b| *b == 0));
        assert!(output.iter().all(|b| *b == 0));
    }
}
