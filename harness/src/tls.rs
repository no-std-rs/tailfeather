//! TLS 1.3, with the certificate chain actually verified.
//!
//! # Why this is worth being careful about
//!
//! A TLS client that negotiates a session but does not check who it is talking
//! to is worse than no TLS at all: it costs the same and provides confidence it
//! has not earned. So this wires `embedded-tls`'s `rustpki` verifier in
//! properly, against a pinned trust anchor, with hostname checking and a real
//! clock so an expired certificate is refused.
//!
//! # ECDSA only, and what that does and does not rule out
//!
//! `embedded-tls`'s verifier is allocation-free for ECDSA chains. Its RSA
//! support pulls in `alloc`, which this project does not have —
//! `rsa = ["dep:rsa", "rustpki", "alloc"]` in its own manifest.
//!
//! This comment used to go on to say that `controlplane.tailscale.com` serves
//! an RSA-PSS-only chain, and therefore that the hosted service was out of
//! reach until someone wrote an allocation-free RSA verifier. **That was
//! wrong**, and it sat in the roadmap as a blocker for longer than it should
//! have. Measured — see `tests/vectors/hosted_tls.json` for the full record:
//!
//! ```text
//! offering ECDSA+SHA256 only, 3/3 runs:
//!   TLSv1.3, TLS_AES_128_GCM_SHA256, peer sig ecdsa_secp256r1_sha256
//!   leaf  CN=controlplane.tailscale.com  P-256   ecdsa-with-SHA384
//!   ←     CN=YE1 (Let's Encrypt)         P-384   ecdsa-with-SHA384
//!   ←     CN=Root YE (ISRG)              P-384   ecdsa-with-SHA384
//!   ←     ISRG Root X2                   P-384   sha256WithRSAEncryption
//! ```
//!
//! The endpoint is dual-chain and selects on the client's `signature_algorithms`.
//! An RSA chain appears only when the client offers RSA. `Suite` here is already
//! `TLS_AES_128_GCM_SHA256`, and `ecdsa_secp256r1_sha256` is the one
//! CertificateVerify scheme `embedded-tls` supports unconditionally.
//!
//! Three real obstacles remain, none of which is RSA:
//!
//! 1. **`ecdsa-with-SHA384` chain signatures** need embedded-tls's `p384`
//!    feature. Unlike `rsa`, it does *not* pull in `alloc`:
//!    `p384 = ["dep:p384", "rustpki"]`. One line, then measure the verification
//!    cost on the device — three P-384 signatures per handshake.
//! 2. **The anchor model.** Hosted presents four entries ending at ISRG Root X2,
//!    whose own issuer is RSA-signed X1. A single pinned anchor has to be the
//!    issuer of the *topmost presented* certificate, so pinning Root YE is one
//!    hop short.
//! 3. **[`MAX_CERT`] is 4096** against a measured chain of 3411 DER bytes plus
//!    per-entry framing. That is a latent overflow, not headroom.
//!
//! Key exchange is *not* an obstacle, though it looked like one while this was
//! being measured. `embedded-tls` offers `NamedGroup::Secp256r1`, and hosted's
//! IPv4 frontend requires exactly that: X25519-only was refused by four fixed
//! IPv4 backends, 8/8, while P-256-only succeeded 8/8. Over IPv6 the same
//! X25519-only client is accepted. A client offering only X25519 would therefore
//! work over IPv6 and fail over IPv4, which would present as an intermittent
//! fault rather than a configuration difference.

use embedded_tls::{
    Aes128GcmSha256, Certificate, CryptoProvider, NoVerify, TlsConfig, TlsConnection, TlsContext,
    TlsError, TlsVerifier,
};

use crate::net::{NetError, TcpStream};

/// TLS records are up to 16 KiB, so the buffers cannot be smaller and still
/// speak the protocol. This is by far the largest allocation in the binary,
/// which is why it is a named constant rather than hidden in a call.
pub const RECORD_BUFFER: usize = 16 * 1024 + 512;

/// The cipher suite. TLS 1.3 has only a handful, and this one is mandatory to
/// implement, so no server can refuse it.
type Suite = Aes128GcmSha256;

/// How large a certificate the verifier will hold.
const MAX_CERT: usize = 4096;

/// The system clock, so certificate validity periods are enforced.
///
/// `NoClock` is the alternative and would make an expired certificate
/// indistinguishable from a current one — which is most of what a certificate
/// is for.
struct SystemClock;

impl embedded_tls::TlsClock for SystemClock {
    fn now() -> Option<u64> {
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

/// A provider that actually verifies.
///
/// `embedded-tls`'s own `UnsecureProvider` is named honestly: its `verifier`
/// returns `Unimplemented`, so the handshake completes without anyone checking
/// the certificate. Supplying one is the whole point of this type.
struct Verifying<'a> {
    rng: TlsRng,
    verifier: embedded_tls::pki::CertVerifier<'a, Suite, SystemClock, MAX_CERT>,
}

impl<'a> Verifying<'a> {
    fn new(ca: &'a [u8]) -> Self {
        Self {
            rng: TlsRng,
            verifier: embedded_tls::pki::CertVerifier::new(Certificate::X509(ca)),
        }
    }
}

impl CryptoProvider for Verifying<'_> {
    type CipherSuite = Suite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// Silences the unused warning on the type `embedded-tls` uses to mean "no
/// verification", which this module deliberately never constructs.
const _: Option<NoVerify> = None;

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
/// names, and `ca` is the only trust anchor — a chain that does not lead to it
/// is refused however well-formed it is.
pub async fn connect<'a>(
    stream: TcpStream<'a>,
    server_name: &str,
    ca: &[u8],
    read_buffer: &'a mut [u8],
    write_buffer: &'a mut [u8],
) -> Result<TlsConnection<'a, TcpStream<'a>, Suite>, TlsFailure> {
    let config = TlsConfig::new().with_server_name(server_name);
    let mut connection = TlsConnection::new(stream, read_buffer, write_buffer);
    connection
        .open(TlsContext::new(&config, Verifying::new(ca)))
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
pub fn run(address: core::net::Ipv4Addr, port: u16, server_name: &str, ca_path: &str) -> ! {
    let clock = crate::time::Clock::start();
    let reactor = crate::exec::Reactor::new(clock);

    match crate::exec::block_on(&reactor, fetch(&reactor, address, port, server_name, ca_path)) {
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
    static mut WRITE: [u8; RECORD_BUFFER] = [0; RECORD_BUFFER];
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

    let mut request = [0u8; ts_noise::upgrade::MAX_REQUEST];
    let request = ts_noise::upgrade::write_key_request(server_name, &mut request)
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
