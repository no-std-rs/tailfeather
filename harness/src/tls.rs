//! TLS 1.3, with the certificate chain actually verified.
//!
//! # Why this is worth being careful about
//!
//! A TLS client that negotiates a session but does not check who it is talking
//! to is worse than no TLS at all: it costs the same and provides confidence it
//! has not earned. The shared verifier checks a pinned trust anchor, hostname,
//! validity period, certificate constraints, and every handshake signature.
//!
//! # Allocation-free ECDSA and RSA
//!
//! The endpoint's chain selection is operational state, not a stable API.
//! `tests/vectors/hosted_tls.json` retains an ECDSA capture from 2026-08-01 and
//! an RSA capture from 2026-08-12. RSA public operations are fixed to 2048- or
//! 4096-bit exponent-65537 keys and use bounded Montgomery arithmetic; no
//! `embedded-tls` RSA or allocation feature is enabled. Certificate signatures
//! accept strict ECDSA or RSA PKCS#1/PSS encodings, while TLS 1.3
//! CertificateVerify accepts ECDSA and the protocol-valid RSA-PSS schemes.
//!
//! The built-in trust anchors are ISRG Root X2 and Root YR. One explicit
//! private root may additionally be supplied for a Headscale deployment.
//!
//! Key exchange is not the obstacle in either measurement. `embedded-tls`
//! offers `NamedGroup::Secp256r1`, which the hosted IPv4 frontend accepts.

use core::sync::atomic::{AtomicU64, Ordering};
use embedded_tls::{TlsConfig, TlsConnection, TlsContext, TlsError};
use tailfeather::control::tls::{
    RsaWorkspace, Suite, TLS_READ_BUFFER, TLS_WRITE_BUFFER, VerifyingProvider,
};

use crate::net::{NetError, TcpStream};

/// TLS records are up to 16 KiB, so the buffers cannot be smaller and still
/// speak the protocol. This is by far the largest allocation in the binary,
/// which is why it is a named constant rather than hidden in a call.
pub const RECORD_BUFFER: usize = TLS_READ_BUFFER;

/// The system clock, so certificate validity periods are enforced.
///
/// `NoClock` is the alternative and would make an expired certificate
/// indistinguishable from a current one — which is most of what a certificate
/// is for.
struct SystemClock;

const SYSTEM_TIME: u64 = u64::MAX;
static TRUSTED_TIME_OVERRIDE: AtomicU64 = AtomicU64::new(SYSTEM_TIME);

impl embedded_tls::TlsClock for SystemClock {
    fn now() -> Option<u64> {
        let trusted = TRUSTED_TIME_OVERRIDE.load(Ordering::Relaxed);
        if trusted != SYSTEM_TIME {
            return Some(trusted);
        }
        Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec as u64)
    }
}

/// `rand_core`'s generator, over the kernel's.
struct TlsRng;

impl rand_core::RngCore for TlsRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        crate::rt::getrandom(&mut bytes);
        u32::from_ne_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        crate::rt::getrandom(&mut bytes);
        u64::from_ne_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::rt::getrandom(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        crate::rt::getrandom(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TlsRng {}

#[derive(Debug)]
pub enum TlsFailure {
    Net(NetError),
    Tls(TlsError),
}

impl core::fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Net(e) => write!(f, "network: {e}"),
            Self::Tls(e) => write!(f, "tls: {e:?}"),
        }
    }
}

/// Open a verified TLS 1.3 connection.
///
/// `server_name` is checked against the certificate's subject alternative
/// names. `ca` adds the deployment's private anchor to the built-in ISRG roots;
/// a chain that reaches none of them is refused however well-formed it is.
pub async fn connect<'a>(
    stream: TcpStream<'a>,
    server_name: &str,
    ca: &[u8],
    read_buffer: &'a mut [u8],
    write_buffer: &'a mut [u8],
) -> Result<TlsConnection<'a, TcpStream<'a>, Suite>, TlsFailure> {
    let config = TlsConfig::new()
        .with_server_name(server_name)
        .enable_rsa_signatures();
    let mut connection = TlsConnection::new(stream, read_buffer, write_buffer);
    let mut rsa = RsaWorkspace::new();
    connection
        .open(TlsContext::new(
            &config,
            VerifyingProvider::<_, SystemClock>::new(TlsRng, Some(ca), &mut rsa),
        ))
        .await
        .map_err(TlsFailure::Tls)?;
    Ok(connection)
}

/// Open a verified TLS connection and fetch the control server's key over it.
///
/// The request is the same `GET /key?v=<capver>` the plaintext path makes, which
/// is the point: TLS is a layer under the protocol, not a different protocol.
/// A successful parse of the server's machine key proves bytes crossed it
/// intact in both directions, not merely that a handshake completed.
pub fn run(
    address: core::net::Ipv4Addr,
    port: u16,
    server_name: &str,
    ca_path: &str,
    trusted_time: Option<u64>,
) -> ! {
    TRUSTED_TIME_OVERRIDE.store(trusted_time.unwrap_or(SYSTEM_TIME), Ordering::Relaxed);
    let clock = crate::time::Clock::start();
    let reactor = crate::exec::Reactor::new(clock);

    match crate::exec::block_on(
        &reactor,
        fetch(&reactor, address, port, server_name, ca_path),
    ) {
        Ok(()) => {
            evt!("{{\"event\":\"tls\",\"result\":\"ok\"}}");
            crate::rt::exit(0)
        }
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"tls\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

/// The largest trust anchor this will load. A DER-encoded P-256 CA is a few
/// hundred bytes.
const MAX_CA: usize = 2048;

async fn fetch(
    reactor: &crate::exec::Reactor,
    address: core::net::Ipv4Addr,
    port: u16,
    server_name: &str,
    ca_path: &str,
) -> Result<(), TlsFailure> {
    let mut ca = [0u8; MAX_CA];
    let ca_len = crate::store::read_file(ca_path, &mut ca).map_err(|_| {
        println!("!! could not read the trust anchor at {ca_path}");
        TlsFailure::Tls(TlsError::InvalidCertificate)
    })?;
    println!("trust anchor: {ca_len} bytes of DER from {ca_path}");

    let stream = TcpStream::connect(reactor, address, port)
        .await
        .map_err(TlsFailure::Net)?;
    println!("connected to {address}:{port}, starting TLS");

    // Static, because these are the largest buffers in the program by an order
    // of magnitude and a 33 KiB stack frame is not something to put on a
    // device's stack. They are used once, by one connection.
    static mut READ: [u8; RECORD_BUFFER] = [0; RECORD_BUFFER];
    static mut WRITE: [u8; TLS_WRITE_BUFFER] = [0; TLS_WRITE_BUFFER];
    // SAFETY: single-threaded, and these are referenced only here, once.
    let (read_buffer, write_buffer) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(READ),
            &mut *core::ptr::addr_of_mut!(WRITE),
        )
    };

    let mut connection = connect(
        stream,
        server_name,
        &ca[..ca_len],
        read_buffer,
        write_buffer,
    )
    .await?;
    println!("TLS 1.3 established and the chain verified against the pinned CA");
    evt!("{{\"event\":\"handshake\",\"verified\":true,\"name\":\"{server_name}\"}}");

    use embedded_io_async::Write as _;

    let mut request = [0u8; tailfeather::noise::upgrade::MAX_REQUEST];
    let request = tailfeather::noise::upgrade::write_key_request(server_name, &mut request)
        .map_err(|_| TlsFailure::Tls(TlsError::EncodeError))?;
    connection
        .write_all(request)
        .await
        .map_err(TlsFailure::Tls)?;
    connection.flush().await.map_err(TlsFailure::Tls)?;

    let mut response = [0u8; 2048];
    let mut filled = 0;
    loop {
        match connection.read(&mut response[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(TlsFailure::Tls(e)),
        }
        if filled == response.len() {
            break;
        }
        // The body is short and ends with the response; stop as soon as the
        // machine key is in hand rather than waiting for the server to hang up.
        if crate::control::json_string(&response[..filled], "publicKey").is_some() {
            break;
        }
    }

    let Some(key) = crate::control::json_string(&response[..filled], "publicKey") else {
        println!("!! no machine key in {filled} bytes of response");
        return Err(TlsFailure::Tls(TlsError::InvalidApplicationData));
    };
    println!("server machine key over TLS: {key}");
    evt!("{{\"event\":\"key\",\"over\":\"tls\",\"key\":\"{key}\"}}");
    Ok(())
}
