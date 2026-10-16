//! Verified TLS adapter shared by firmware network clients.

use embassy_net::tcp::TcpSocket;
use embedded_tls::{TlsClock, TlsConfig, TlsConnection, TlsContext};
use log::warn;

use tailfeather::control::authority::Authority;
use tailfeather::control::tls::{MAX_CERTIFICATE_SIZE, Suite, VerifyingProvider};

struct PinnedRoot {
    bytes: [u8; MAX_CERTIFICATE_SIZE],
    len: usize,
}

const fn decode_root(hex: &str) -> PinnedRoot {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("private CA must be hexadecimal DER"),
        }
    }

    let input = hex.as_bytes();
    assert!(
        input.len().is_multiple_of(2),
        "private CA hex has odd length"
    );
    let len = input.len() / 2;
    assert!(len <= MAX_CERTIFICATE_SIZE, "private CA exceeds TLS bound");
    let mut bytes = [0; MAX_CERTIFICATE_SIZE];
    let mut index = 0;
    while index < len {
        bytes[index] = nibble(input[index * 2]) << 4 | nibble(input[index * 2 + 1]);
        index += 1;
    }
    PinnedRoot { bytes, len }
}

static PRIVATE_ROOT: PinnedRoot = decode_root(crate::TS_CONTROL_CA_DER_HEX);

fn private_root() -> Option<&'static [u8]> {
    (PRIVATE_ROOT.len != 0).then_some(&PRIVATE_ROOT.bytes[..PRIVATE_ROOT.len])
}

struct DeviceClock;

impl TlsClock for DeviceClock {
    fn now() -> Option<u64> {
        // This milestone has no trusted wall clock yet. Certificate identity
        // and signatures are still verified; time validation becomes active
        // when the control-plane time bootstrap is wired in.
        None
    }
}

struct TlsRng(esp_hal::rng::Rng);

impl rand_core::RngCore for TlsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.0.read(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.read(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TlsRng {}

pub async fn connect<'a>(
    socket: TcpSocket<'a>,
    authority: &Authority,
    read: &'a mut [u8],
    write: &'a mut [u8],
) -> Result<TlsConnection<'a, TcpSocket<'a>, Suite>, ()> {
    let config = TlsConfig::new().with_server_name(authority.host());
    let mut tls = TlsConnection::new(socket, read, write);
    tls.open(TlsContext::new(
        &config,
        VerifyingProvider::<_, DeviceClock>::new(TlsRng(esp_hal::rng::Rng::new()), private_root()),
    ))
    .await
    .map_err(|error| {
        warn!("derp tls-open error={error:?}");
    })?;
    Ok(tls)
}
