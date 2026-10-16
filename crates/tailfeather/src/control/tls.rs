//! Allocation-free TLS verification for control and DERP connections.
//!
//! Hosted chains may use the ECDSA hierarchy rooted at ISRG Root X2 or the RSA
//! hierarchy rooted at ISRG Root YR. Both trust anchors and all RSA arithmetic
//! are fixed-size; enabling RSA signature negotiation does not enable
//! `embedded-tls`'s allocating RSA feature.

use core::marker::PhantomData;

pub use p256::elliptic_curve::rand_core::{CryptoRng, Error as RandError, RngCore};

use embedded_tls::{
    Aes128GcmSha256, CertificateRef, CertificateVerifyRef, CryptoProvider, CryptoRngCore,
    SignatureScheme, TlsClock, TlsError, TlsVerifier,
};
use heapless::String;
use p256::ecdsa::signature::Verifier as _;
use sha2::Digest as _;

mod rsa;
mod x509;

use rsa::HashAlgorithm;
pub use rsa::RsaWorkspace;
use x509::LeafPublicKey;

use super::authority::HOST_CAPACITY;

/// Full-size TLS records plus the TLS 1.3 record overhead.
pub const TLS_READ_BUFFER: usize = 16 * 1024 + 512;
/// Writes are fragmented, so control and DERP do not need a second 16 KiB buffer.
pub const TLS_WRITE_BUFFER: usize = 2 * 1024;
/// Bound the complete presented certificate path, including framing.
pub const MAX_CERTIFICATE_BYTES: usize = 8 * 1024;
/// A leaf and a modest embedded chain are sufficient for both supported authorities.
pub const MAX_CHAIN_CERTIFICATES: usize = 8;
/// Largest individual DER certificate accepted by embedded-tls.
pub const MAX_CERTIFICATE_SIZE: usize = 4 * 1024;

/// TLS 1.3's mandatory AES-128-GCM/SHA-256 suite.
pub type Suite = Aes128GcmSha256;

static ISRG_ROOT_X2_BYTES: [u8; 543] = [
    0x30, 0x82, 0x02, 0x1b, 0x30, 0x82, 0x01, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x41,
    0xd2, 0x9d, 0xd1, 0x72, 0xea, 0xee, 0xa7, 0x80, 0xc1, 0x2c, 0x6c, 0xe9, 0x2f, 0x87, 0x52, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x4f, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x13, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x65,
    0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20,
    0x47, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c,
    0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x32, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x30, 0x30, 0x39, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34,
    0x30, 0x30, 0x39, 0x31, 0x37, 0x31, 0x36, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x4f, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x29, 0x30, 0x27, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
    0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x0c, 0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x58, 0x32, 0x30, 0x76, 0x30,
    0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00,
    0x22, 0x03, 0x62, 0x00, 0x04, 0xcd, 0x9b, 0xd5, 0x9f, 0x80, 0x83, 0x0a, 0xec, 0x09, 0x4a, 0xf3,
    0x16, 0x4a, 0x3e, 0x5c, 0xcf, 0x77, 0xac, 0xde, 0x67, 0x05, 0x0d, 0x1d, 0x07, 0xb6, 0xdc, 0x16,
    0xfb, 0x5a, 0x8b, 0x14, 0xdb, 0xe2, 0x71, 0x60, 0xc4, 0xba, 0x45, 0x95, 0x11, 0x89, 0x8e, 0xea,
    0x06, 0xdf, 0xf7, 0x2a, 0x16, 0x1c, 0xa4, 0xb9, 0xc5, 0xc5, 0x32, 0xe0, 0x03, 0xe0, 0x1e, 0x82,
    0x18, 0x38, 0x8b, 0xd7, 0x45, 0xd8, 0x0a, 0x6a, 0x6e, 0xe6, 0x00, 0x77, 0xfb, 0x02, 0x51, 0x7d,
    0x22, 0xd8, 0x0a, 0x6e, 0x9a, 0x5b, 0x77, 0xdf, 0xf0, 0xfa, 0x41, 0xec, 0x39, 0xdc, 0x75, 0xca,
    0x68, 0x07, 0x0c, 0x1f, 0xea, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x7c, 0x42, 0x96, 0xae, 0xde, 0x4b, 0x48, 0x3b, 0xfa, 0x92, 0xf8,
    0x9e, 0x8c, 0xcf, 0x6d, 0x8b, 0xa9, 0x72, 0x37, 0x95, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x7b, 0x79, 0x4e, 0x46,
    0x50, 0x84, 0xc2, 0x44, 0x87, 0x46, 0x1b, 0x45, 0x70, 0xff, 0x58, 0x99, 0xde, 0xf4, 0xfd, 0xa4,
    0xd2, 0x55, 0xa6, 0x20, 0x2d, 0x74, 0xd6, 0x34, 0xbc, 0x41, 0xa3, 0x50, 0x5f, 0x01, 0x27, 0x56,
    0xb4, 0xbe, 0x27, 0x75, 0x06, 0xaf, 0x12, 0x2e, 0x75, 0x98, 0x8d, 0xfc, 0x02, 0x31, 0x00, 0x8b,
    0xf5, 0x77, 0x6c, 0xd4, 0xc8, 0x65, 0xaa, 0xe0, 0x0b, 0x2c, 0xee, 0x14, 0x9d, 0x27, 0x37, 0xa4,
    0xf9, 0x53, 0xa5, 0x51, 0xe4, 0x29, 0x83, 0xd7, 0xf8, 0x90, 0x31, 0x5b, 0x42, 0x9f, 0x0a, 0xf5,
    0xfe, 0xae, 0x00, 0x68, 0xe7, 0x8c, 0x49, 0x0f, 0xb6, 0x6f, 0x5b, 0x5b, 0x15, 0xf2, 0xe7,
];

/// Self-signed ISRG Root X2, from Let's Encrypt's published trust anchor.
///
/// SHA-256: `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470`.
pub const ISRG_ROOT_X2_DER: &[u8] = &ISRG_ROOT_X2_BYTES;

const ROOT_YR_B64: &str = concat!(
    "MIIFKTCCAxGgAwIBAgIRAOxGNJNgz0sP+KmC2Tqpyj0wDQYJKoZIhvcNAQELBQAwLjELMAkGA1UEBhMCVVMxDTALBgNVBAoT",
    "BElTUkcxEDAOBgNVBAMTB1Jvb3QgWVIwHhcNMjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzEN",
    "MAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANvGJnN78CTJ",
    "dWL3+eGfsLN5TrNBJs+VH9hRXqRbwxu9sGNiB0BD1fcOxbSUQCJIM1xE13Db+5Cw1w0s0EBYsvuIP/6joF0w8cuImbgR1OGg",
    "YbSQ4OpzI+DG8SGuTlcE873OCS+kh3srlo6vl43M5OJg4Aeo1sfHp6kTJDoIiFBNJAY+OKfX/FUvYKuhjT+no49lmqmupSBI",
    "5PkBQiqrEGtWU5uxU/cQWHGu8jSjFBznZqvbNPLMXMLFxCb3WTfrJBXXjqvWG+v4bjzxjjeAtOlU7qarRDvNOyAuQYLln904",
    "M+faKx8hnLCpJ15ZqaEgcNlY+9MMWcC5yvL2A2j3l9+2buggZX+dOE91zYmIdawTvSZuVvlbRrAlLxIB6pwMBjneXCjYQ8+3",
    "BCCjssbSNpZU3hTcBDdhfAlEDlYr6pEatnMdmDT5BqnKC92bd0EhM1fbLHioLccLCuievT8ZkPhZrq7Mii7gNXAcUEAR8+lz",
    "Yal+9zTg7C5DALyVOeG/CqfRAMn1KSHCR0NSA6P8tn/mGRlnCct5rtVCLnVySVpU6H1qGg3DgTOuskf8eahTMiYbI5ezPJmO",
    "5ertalskQ1utp74+eDy92PI4ftHKTbq9IWhH4YZKh3WnJEIt+oQvlYZbY8tpEroKrFB6PFGzrJIDRyts4HqvuH52RFj2zv/B",
    "AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTe51tg0CJtQCh9Pw0B/qS1UrRR",
    "lDANBgkqhkiG9w0BAQsFAAOCAgEAWHnf713Bdkq7t5yN2dNIgQakUb94X9WuyhMEHHkgx4oDpSUlnG0w4g94MoqaEUE31ZjR",
    "LU7L5LD1g9ujFHTQu8AD215AHMVQFbm6j8hQxdXHAzDajFNQnOlDJrLjzIx176oyAjvUtejZx2NNmdb5fd0WGVGsCdoAJ3N8",
    "ozo7ajE8t6vfxStZb4BQ9WYJGHUDrv2Ni5tJF6CNiPnlzs3BUfECRbE4JSk+jvy8+VoGiFE8qsH/j78x2fjgQhAQFV7P7Zxy",
    "dBTZ1wEkNpZNW2qnaK1SKBLa+xf6E06YRIq5uaI+HWH8SY1y5VbRgzq40EKg3yxP06fz+uYAUIFJoLNfhwRCc3Q6pQVuMX3y",
    "AjHAes4gk4moGcLQ5p7HAh39yeylZc1J41sx/jKwLIkPE6Rr1Nf4pxdsxf9SA4yOEiAkDgq04DVxn8hgYFdUtBCuiuVC2heA",
    "EiqVEa+8QZjuw8Gj0EbHXcRd1nInvGqRS1o9Is7YBdQN57X1AYveGBNNqjICSb7cawuw1EawTDrs13VUlJVEsbQ0/O/1aaV7",
    "3mCdOQ8azqL2KTv1Ewu1xbquE2S+kdQUTo9TUwat3wUA6cwXh1EfpS/3fJ0aGah5hdpRyoCLDlsSn8tkrjMfFFX0viC+GxHc",
    "sI1ANRYvqSFC2X1VRZfDg+wD6E21BccmifG4yWc=",
);

const fn decode_base64<const N: usize>(input: &str) -> [u8; N] {
    const fn value(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 0,
            _ => panic!("invalid base64"),
        }
    }

    let input = input.as_bytes();
    let mut output = [0u8; N];
    let mut source = 0;
    let mut destination = 0;
    while source < input.len() {
        let word = ((value(input[source]) as u32) << 18)
            | ((value(input[source + 1]) as u32) << 12)
            | ((value(input[source + 2]) as u32) << 6)
            | value(input[source + 3]) as u32;
        output[destination] = (word >> 16) as u8;
        if destination + 1 < N {
            output[destination + 1] = (word >> 8) as u8;
        }
        if destination + 2 < N {
            output[destination + 2] = word as u8;
        }
        source += 4;
        destination += 3;
    }
    assert!(destination >= N && destination - N <= 2);
    output
}

static ISRG_ROOT_YR_BYTES: [u8; 1_325] = decode_base64(ROOT_YR_B64);

/// Self-signed ISRG Root YR, from Let's Encrypt's published trust anchor.
///
/// SHA-256: `e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f`.
pub const ISRG_ROOT_YR_DER: &[u8] = &ISRG_ROOT_YR_BYTES;

/// A bounded verifier with two built-in public roots and one optional private root.
pub struct TrustVerifier<'a, Clock: TlsClock> {
    private_root: Option<&'a [u8]>,
    rsa: &'a mut RsaWorkspace,
    hostname: String<HOST_CAPACITY>,
    certificate_verified: bool,
    transcript: [u8; 32],
    leaf_key: LeafPublicKey,
    _clock: PhantomData<Clock>,
}

impl<'a, Clock: TlsClock> TrustVerifier<'a, Clock> {
    #[must_use]
    pub fn new(private_root: Option<&'a [u8]>, rsa: &'a mut RsaWorkspace) -> Self {
        Self {
            private_root,
            rsa,
            hostname: String::new(),
            certificate_verified: false,
            transcript: [0; 32],
            leaf_key: LeafPublicKey::empty(),
            _clock: PhantomData,
        }
    }

    fn clear_certificate_state(&mut self) {
        self.certificate_verified = false;
        self.transcript.fill(0);
        self.leaf_key.clear();
    }
}

impl<Clock: TlsClock> TlsVerifier<Suite> for TrustVerifier<'_, Clock> {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.clear_certificate_state();
        self.hostname.clear();
        self.hostname = String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?;
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &sha2::Sha256,
        cert: CertificateRef<'_>,
    ) -> Result<(), TlsError> {
        self.clear_certificate_state();
        let leaf_key = match x509::verify_chain_with_workspace::<Clock>(
            cert,
            &self.hostname,
            self.private_root,
            self.rsa,
        ) {
            Ok(key) => key,
            Err(error) => {
                self.clear_certificate_state();
                return Err(error);
            }
        };
        self.transcript
            .copy_from_slice(&transcript.clone().finalize());
        self.leaf_key = leaf_key;
        self.certificate_verified = true;
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef<'_>) -> Result<(), TlsError> {
        if !self.certificate_verified {
            return Err(TlsError::InvalidCertificate);
        }
        self.certificate_verified = false;

        const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\0";
        let mut message = [0u8; 64 + 34 + 32];
        message[..64].fill(0x20);
        message[64..98].copy_from_slice(CONTEXT);
        message[98..].copy_from_slice(&self.transcript);

        let result = match verify.signature_scheme {
            SignatureScheme::EcdsaSecp256r1Sha256 => self.leaf_key.p256().is_some_and(|key| {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .ok()
                    .zip(p256::ecdsa::Signature::from_der(verify.signature).ok())
                    .is_some_and(|(key, signature)| key.verify(&message, &signature).is_ok())
            }),
            SignatureScheme::EcdsaSecp384r1Sha384 => self.leaf_key.p384().is_some_and(|key| {
                p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .ok()
                    .zip(p384::ecdsa::Signature::from_der(verify.signature).ok())
                    .is_some_and(|(key, signature)| key.verify(&message, &signature).is_ok())
            }),
            SignatureScheme::RsaPssRsaeSha256 => self.leaf_key.verify_pss(
                HashAlgorithm::Sha256,
                &message,
                verify.signature,
                self.rsa,
            ),
            SignatureScheme::RsaPssRsaeSha384 => self.leaf_key.verify_pss(
                HashAlgorithm::Sha384,
                &message,
                verify.signature,
                self.rsa,
            ),
            SignatureScheme::RsaPssRsaeSha512 => self.leaf_key.verify_pss(
                HashAlgorithm::Sha512,
                &message,
                verify.signature,
                self.rsa,
            ),
            // PKCS#1 schemes are advertised for certificate-chain signatures,
            // but TLS 1.3 forbids selecting them for CertificateVerify.
            _ => {
                self.clear_certificate_state();
                return Err(TlsError::InvalidSignatureScheme);
            }
        };
        self.clear_certificate_state();

        if result {
            Ok(())
        } else {
            Err(TlsError::InvalidSignature)
        }
    }
}

/// Crypto provider used by both host and Embassy transports.
pub struct VerifyingProvider<'a, Rng, Clock: TlsClock> {
    rng: Rng,
    verifier: TrustVerifier<'a, Clock>,
}

impl<'a, Rng, Clock: TlsClock> VerifyingProvider<'a, Rng, Clock> {
    #[must_use]
    pub fn new(rng: Rng, private_root: Option<&'a [u8]>, rsa: &'a mut RsaWorkspace) -> Self {
        Self {
            rng,
            verifier: TrustVerifier::new(private_root, rsa),
        }
    }
}

impl<Rng: CryptoRngCore, Clock: TlsClock> CryptoProvider for VerifyingProvider<'_, Rng, Clock> {
    type CipherSuite = Suite;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    full: &'a [u8],
}

fn next_tlv<'a>(input: &'a [u8], offset: &mut usize) -> Result<Tlv<'a>, TlsError> {
    let start = *offset;
    let tag = *input.get(*offset).ok_or(TlsError::DecodeError)?;
    *offset += 1;
    if tag & 0x1f == 0x1f {
        return Err(TlsError::DecodeError);
    }
    let first = *input.get(*offset).ok_or(TlsError::DecodeError)?;
    *offset += 1;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() || input.get(*offset) == Some(&0) {
            return Err(TlsError::DecodeError);
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = len
                .checked_mul(256)
                .and_then(|v| input.get(*offset).map(|byte| v + usize::from(*byte)))
                .ok_or(TlsError::DecodeError)?;
            *offset += 1;
        }
        if len < 128 {
            return Err(TlsError::DecodeError);
        }
        len
    };
    let end = offset.checked_add(len).ok_or(TlsError::DecodeError)?;
    let value = input.get(*offset..end).ok_or(TlsError::DecodeError)?;
    *offset = end;
    Ok(Tlv {
        tag,
        value,
        full: &input[start..end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Clock;
    impl TlsClock for Clock {
        fn now() -> Option<u64> {
            Some(0)
        }
    }

    #[test]
    fn embedded_anchors_have_the_published_sizes() {
        assert_eq!(ISRG_ROOT_X2_DER.len(), 543);
        assert_eq!(ISRG_ROOT_YR_DER.len(), 1_325);
    }

    #[test]
    fn root_yr_fingerprint_matches_the_published_anchor() {
        use sha2::Digest as _;

        assert_eq!(
            sha2::Sha256::digest(ISRG_ROOT_YR_DER).as_slice(),
            hex::decode("e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f")
                .unwrap()
        );
    }

    #[test]
    fn tls_buffers_cover_a_full_record_but_keep_writes_small() {
        const { assert!(TLS_READ_BUFFER >= 16_640) };
        assert_eq!(TLS_WRITE_BUFFER, 2_048);
        const { assert!(MAX_CERTIFICATE_BYTES >= 4_000) };
    }

    #[test]
    fn verifier_accepts_the_authority_parsers_full_hostname_capacity() {
        let hostname = "a".repeat(128);
        let mut rsa = RsaWorkspace::new();
        let mut verifier = TrustVerifier::<Clock>::new(None, &mut rsa);
        assert!(verifier.set_hostname_verification(&hostname).is_ok());
        assert!(
            verifier
                .set_hostname_verification(&(hostname + "a"))
                .is_err()
        );
    }
}
