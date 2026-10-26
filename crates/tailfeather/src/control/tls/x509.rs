//! Bounded borrowed-DER path validation for the TLS client.

mod teletex;

use core::str::FromStr as _;

use embedded_tls::{CertificateEntryRef, CertificateRef, TlsClock, TlsError};
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::Digest as _;
use zeroize::Zeroize as _;

use super::rsa::{self, HashAlgorithm, RsaPublicKey};
use super::{
    ISRG_ROOT_X2_DER, ISRG_ROOT_YR_DER, MAX_CERTIFICATE_BYTES, MAX_CHAIN_CERTIFICATES, Tlv,
    next_tlv,
};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];

const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_CRL_DISTRIBUTION: &[u8] = &[0x55, 0x1d, 0x1f];
const OID_CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const OID_AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

#[derive(Clone, Copy)]
enum SignatureAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    RsaPkcs1(HashAlgorithm),
    RsaPss(HashAlgorithm),
}

#[derive(Clone, Copy)]
pub(super) enum PublicKey<'a> {
    P256(&'a [u8]),
    P384(&'a [u8]),
    Rsa(RsaPublicKey<'a>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafKeyKind {
    Empty,
    P256,
    P384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

/// A discriminated fixed-size key buffer. Failed paths wipe the whole buffer,
/// including bytes beyond the active key length.
pub(super) struct LeafPublicKey {
    kind: LeafKeyKind,
    bytes: [u8; rsa::RSA_4096_BYTES],
}

impl LeafPublicKey {
    pub(super) const fn empty() -> Self {
        Self {
            kind: LeafKeyKind::Empty,
            bytes: [0; rsa::RSA_4096_BYTES],
        }
    }

    fn copy(kind: LeafKeyKind, key: &[u8]) -> Self {
        let mut result = Self::empty();
        result.kind = kind;
        result.bytes[..key.len()].copy_from_slice(key);
        result
    }

    pub(super) fn clear(&mut self) {
        self.bytes.zeroize();
        self.kind = LeafKeyKind::Empty;
    }

    pub(super) fn p256(&self) -> Option<&[u8; 65]> {
        (self.kind == LeafKeyKind::P256).then(|| self.bytes[..65].try_into().unwrap())
    }

    pub(super) fn p384(&self) -> Option<&[u8; 97]> {
        (self.kind == LeafKeyKind::P384).then(|| self.bytes[..97].try_into().unwrap())
    }

    pub(super) fn verify_pss(
        &self,
        hash: HashAlgorithm,
        message: &[u8],
        signature: &[u8],
        workspace: &mut rsa::RsaWorkspace,
    ) -> bool {
        let modulus = match self.kind {
            LeafKeyKind::Rsa2048 => &self.bytes[..rsa::RSA_2048_BYTES],
            LeafKeyKind::Rsa3072 => &self.bytes[..rsa::RSA_3072_BYTES],
            LeafKeyKind::Rsa4096 => &self.bytes,
            _ => return false,
        };
        rsa::verify_pss_with_workspace(
            RsaPublicKey { modulus },
            hash,
            message,
            signature,
            workspace,
        )
    }
}

#[derive(Clone, Copy, Default)]
struct BasicConstraints {
    ca: bool,
    path_len: Option<u8>,
}

#[derive(Clone, Copy, Default)]
struct Extensions<'a> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    server_auth: Option<bool>,
    san: Option<&'a [u8]>,
    name_constraints: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Default)]
struct KeyUsage {
    digital_signature: bool,
    key_cert_sign: bool,
}

#[derive(Clone, Copy)]
struct ParsedCertificate<'a> {
    tbs: &'a [u8],
    signature_algorithm: SignatureAlgorithm,
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: u64,
    not_after: u64,
    public_key: PublicKey<'a>,
    extensions: Extensions<'a>,
    signature: &'a [u8],
}

#[cfg(test)]
pub(super) fn verify_chain<Clock: TlsClock>(
    cert: CertificateRef<'_>,
    hostname: &str,
    private_root: Option<&[u8]>,
) -> Result<LeafPublicKey, TlsError> {
    let mut workspace = rsa::RsaWorkspace::new();
    verify_chain_with_workspace::<Clock>(cert, hostname, private_root, &mut workspace)
}

pub(super) fn verify_chain_with_workspace<Clock: TlsClock>(
    cert: CertificateRef<'_>,
    hostname: &str,
    private_root: Option<&[u8]>,
    workspace: &mut rsa::RsaWorkspace,
) -> Result<LeafPublicKey, TlsError> {
    let anchors = [Some(ISRG_ROOT_X2_DER), Some(ISRG_ROOT_YR_DER), private_root];
    verify_chain_with_roots::<Clock>(cert, hostname, anchors.into_iter().flatten(), workspace)
}

pub(super) fn verify_chain_with_roots<'a, Clock: TlsClock>(
    cert: CertificateRef<'_>,
    hostname: &str,
    anchors: impl IntoIterator<Item = &'a [u8]>,
    workspace: &mut rsa::RsaWorkspace,
) -> Result<LeafPublicKey, TlsError> {
    if cert.entries.is_empty() || cert.entries.len() > MAX_CHAIN_CERTIFICATES {
        return Err(TlsError::InvalidCertificate);
    }

    let now = Clock::now().ok_or(TlsError::InvalidCertificate)?;
    let mut total = 0usize;
    for entry in &cert.entries {
        let CertificateEntryRef::X509(der) = entry else {
            return Err(TlsError::InvalidCertificate);
        };
        total = total
            .checked_add(der.len())
            .filter(|size| *size <= MAX_CERTIFICATE_BYTES)
            .ok_or(TlsError::InvalidCertificate)?;
    }

    let leaf = parse_entry(&cert.entries[0])?;
    if now < leaf.not_before || now > leaf.not_after {
        return Err(TlsError::InvalidCertificate);
    }
    validate_leaf(&leaf, hostname)?;

    let mut trusted = false;
    'anchors: for anchor in anchors {
        let Ok(anchor) = parse_certificate(anchor) else {
            continue;
        };
        // A TLS peer may append certificates that are not part of the path it
        // presents. DERP does this with its self-signed Ed25519 identity cert.
        // Authenticate a non-empty prefix to our anchor; never accept an
        // unverified gap or an alternate leaf.
        for end in 1..=cert.entries.len() {
            if validate_path(&cert.entries[..end], anchor, now, workspace).is_ok() {
                trusted = true;
                break 'anchors;
            }
        }
    }
    if !trusted {
        return Err(TlsError::InvalidCertificate);
    }

    copy_leaf_key(parse_entry(&cert.entries[0])?.public_key)
}

fn validate_path(
    chain: &[CertificateEntryRef<'_>],
    anchor: ParsedCertificate<'_>,
    now: u64,
    workspace: &mut rsa::RsaWorkspace,
) -> Result<(), TlsError> {
    if now < anchor.not_before || now > anchor.not_after {
        return Err(TlsError::InvalidCertificate);
    }
    let trim_anchor = chain
        .last()
        .and_then(|entry| parse_entry(entry).ok())
        .is_some_and(|last| {
            name_equal(last.subject, anchor.subject) && same_key(last.public_key, anchor.public_key)
        });
    let path_len = chain.len() - usize::from(trim_anchor);
    if path_len == 0 {
        return Err(TlsError::InvalidCertificate);
    }

    validate_ca(&anchor, subordinate_ca_count(chain, path_len)?)?;
    validate_name_constraints(&anchor, &chain[..path_len])?;
    for index in 0..path_len {
        let certificate = parse_entry(&chain[index])?;
        if now < certificate.not_before || now > certificate.not_after {
            return Err(TlsError::InvalidCertificate);
        }
        let issuer = if index + 1 < path_len {
            parse_entry(&chain[index + 1])?
        } else {
            anchor
        };
        if !name_equal(certificate.issuer, issuer.subject)
            || !verify_certificate_signature(certificate, issuer.public_key, workspace)
        {
            return Err(TlsError::InvalidCertificate);
        }
        if index + 1 < path_len {
            validate_ca(&issuer, subordinate_ca_count(chain, index + 1)?)?;
            validate_name_constraints(&issuer, &chain[..=index])?;
        }
    }
    Ok(())
}

fn parse_entry<'a>(entry: &'a CertificateEntryRef<'a>) -> Result<ParsedCertificate<'a>, TlsError> {
    let CertificateEntryRef::X509(der) = entry else {
        return Err(TlsError::InvalidCertificate);
    };
    parse_certificate(der)
}

fn validate_leaf(certificate: &ParsedCertificate<'_>, hostname: &str) -> Result<(), TlsError> {
    if certificate
        .extensions
        .basic_constraints
        .is_some_and(|basic| basic.ca)
        || certificate
            .extensions
            .key_usage
            .is_some_and(|usage| !usage.digital_signature)
        || certificate.extensions.server_auth == Some(false)
        || !certificate
            .extensions
            .san
            .is_some_and(|san| hostname_matches_san(hostname, san))
    {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}

fn validate_ca(
    certificate: &ParsedCertificate<'_>,
    subordinate_cas: usize,
) -> Result<(), TlsError> {
    let basic = certificate
        .extensions
        .basic_constraints
        .ok_or(TlsError::InvalidCertificate)?;
    if !basic.ca
        || certificate
            .extensions
            .key_usage
            .is_some_and(|usage| !usage.key_cert_sign)
        || certificate.extensions.server_auth == Some(false)
        || basic
            .path_len
            .is_some_and(|limit| subordinate_cas > usize::from(limit))
    {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}

pub(super) fn validate_trust_anchor(der: &[u8]) -> Result<(), TlsError> {
    let certificate = parse_certificate(der)?;
    validate_ca(&certificate, 0)
}

fn subordinate_ca_count(
    chain: &[CertificateEntryRef<'_>],
    issuer_position: usize,
) -> Result<usize, TlsError> {
    let mut count = 0;
    for entry in chain.iter().take(issuer_position).skip(1) {
        let certificate = parse_entry(entry)?;
        if certificate
            .extensions
            .basic_constraints
            .is_some_and(|basic| basic.ca)
            && !name_equal(certificate.subject, certificate.issuer)
        {
            count += 1;
        }
    }
    Ok(count)
}

fn name_equal(left: &[u8], right: &[u8]) -> bool {
    let (Ok(left), Ok(right)) = (single_tlv(left, 0x30), single_tlv(right, 0x30)) else {
        return false;
    };
    let (mut left_offset, mut right_offset) = (0, 0);
    while left_offset < left.value.len() && right_offset < right.value.len() {
        let (Ok(left_rdn), Ok(right_rdn)) = (
            next_tlv(left.value, &mut left_offset),
            next_tlv(right.value, &mut right_offset),
        ) else {
            return false;
        };
        if left_rdn.tag != 0x31 || right_rdn.tag != 0x31 || !rdn_equal(left_rdn, right_rdn) {
            return false;
        }
    }
    left_offset == left.value.len() && right_offset == right.value.len()
}

fn rdn_equal(left: Tlv<'_>, right: Tlv<'_>) -> bool {
    let Ok(left_count) = tlv_count(left.value) else {
        return false;
    };
    let Ok(right_count) = tlv_count(right.value) else {
        return false;
    };
    if left_count != right_count {
        return false;
    }
    let mut left_offset = 0;
    while left_offset < left.value.len() {
        let Ok(attribute) = next_tlv(left.value, &mut left_offset) else {
            return false;
        };
        let mut left_matches = 0;
        let mut candidate_offset = 0;
        while candidate_offset < left.value.len() {
            let Ok(candidate) = next_tlv(left.value, &mut candidate_offset) else {
                return false;
            };
            left_matches += usize::from(attribute_equal(attribute, candidate));
        }
        let mut right_offset = 0;
        let mut right_matches = 0;
        while right_offset < right.value.len() {
            let Ok(candidate) = next_tlv(right.value, &mut right_offset) else {
                return false;
            };
            right_matches += usize::from(attribute_equal(attribute, candidate));
        }
        if left_matches != right_matches {
            return false;
        }
    }
    true
}

fn tlv_count(input: &[u8]) -> Result<usize, TlsError> {
    let mut offset = 0;
    let mut count = 0;
    while offset < input.len() {
        next_tlv(input, &mut offset)?;
        count += 1;
    }
    Ok(count)
}

fn attribute_equal(left: Tlv<'_>, right: Tlv<'_>) -> bool {
    if left.tag != 0x30 || right.tag != 0x30 {
        return false;
    }
    let (mut left_offset, mut right_offset) = (0, 0);
    let (Ok(left_oid), Ok(right_oid)) = (
        next_tlv(left.value, &mut left_offset),
        next_tlv(right.value, &mut right_offset),
    ) else {
        return false;
    };
    let (Ok(left_value), Ok(right_value)) = (
        next_tlv(left.value, &mut left_offset),
        next_tlv(right.value, &mut right_offset),
    ) else {
        return false;
    };
    left_offset == left.value.len()
        && right_offset == right.value.len()
        && left_oid.tag == 0x06
        && right_oid.tag == 0x06
        && left_oid.value == right_oid.value
        && directory_value_equal(left_value, right_value)
}

fn directory_value_equal(left: Tlv<'_>, right: Tlv<'_>) -> bool {
    if let (Some(left), Some(right)) = (directory_chars(left), directory_chars(right)) {
        let (mut left, mut right) = (
            normalized_directory_string(left),
            normalized_directory_string(right),
        );
        loop {
            match (left.next(), right.next()) {
                (Some(left), Some(right)) if left == right => {}
                (None, None) => {
                    return !directory_string_failed(&left) && !directory_string_failed(&right);
                }
                _ => return false,
            }
        }
    }
    // Malformed supported strings cannot compare equal through the opaque
    // fallback, including two identical malformed TeletexString values.
    !matches!(left.tag, 0x0c | 0x13 | 0x14 | 0x16 | 0x1e | 0x1c)
        && left.tag == right.tag
        && left.value == right.value
}

type PreparedDirectoryString<'a> = NormalizedDirectoryString<
    UnicodeNormalizedChars<
        crate::unicode_normalization::CaseFold<UnicodeNormalizedChars<DirectoryChars<'a>>>,
    >,
>;

fn directory_string_failed(value: &PreparedDirectoryString<'_>) -> bool {
    // Both bounded normalization stages must finish without overflow. The
    // folding iterator deliberately does not hide the inner stage's state.
    value.input.failed || value.input.input.input.get_ref().failed
}

fn normalized_directory_string(input: DirectoryChars<'_>) -> PreparedDirectoryString<'_> {
    // Normalize before folding as well as after it: folding U+0345 emits a
    // starter (iota), so canonical reordering must happen before that mapping.
    // Compatibility decomposition can also expose uppercase letters that
    // CaseFolding.txt intentionally leaves unchanged in their original form.
    NormalizedDirectoryString::new(UnicodeNormalizedChars::new(
        crate::unicode_normalization::CaseFold::new(UnicodeNormalizedChars::new(input)),
    ))
}

enum DirectoryChars<'a> {
    Utf8(core::str::Chars<'a>),
    Bmp(core::slice::ChunksExact<'a, u8>),
    Universal(core::slice::ChunksExact<'a, u8>),
    Teletex(teletex::TeletexChars<'a>),
}

impl Iterator for DirectoryChars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Utf8(chars) => chars.next(),
            Self::Teletex(chars) => chars.next(),
            Self::Bmp(chunks) => {
                let bytes = chunks.next()?;
                char::from_u32(u32::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            }
            Self::Universal(chunks) => {
                let bytes = chunks.next()?;
                char::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
        }
    }
}

fn directory_chars(value: Tlv<'_>) -> Option<DirectoryChars<'_>> {
    match value.tag {
        0x14 => teletex::TeletexChars::new(value.value).map(DirectoryChars::Teletex),
        0x0c | 0x13 | 0x16 => Some(DirectoryChars::Utf8(
            core::str::from_utf8(value.value).ok()?.chars(),
        )),
        0x1e if value.value.len().is_multiple_of(2) => {
            let chunks = value.value.chunks_exact(2);
            chunks
                .clone()
                .all(|bytes| {
                    char::from_u32(u32::from(u16::from_be_bytes([bytes[0], bytes[1]]))).is_some()
                })
                .then_some(DirectoryChars::Bmp(chunks))
        }
        0x1c if value.value.len().is_multiple_of(4) => {
            let chunks = value.value.chunks_exact(4);
            chunks
                .clone()
                .all(|bytes| {
                    char::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                        .is_some()
                })
                .then_some(DirectoryChars::Universal(chunks))
        }
        _ => None,
    }
}

const MAX_CHAR_DECOMPOSITION: usize = 32;
const MAX_COMBINING_SEQUENCE: usize = 64;

struct CompatibilityDecomposed<I> {
    input: I,
    buffer: [char; MAX_CHAR_DECOMPOSITION],
    length: usize,
    offset: usize,
    failed: bool,
}

impl<I: Iterator<Item = char>> CompatibilityDecomposed<I> {
    fn new(input: I) -> Self {
        Self {
            input,
            buffer: ['\0'; MAX_CHAR_DECOMPOSITION],
            length: 0,
            offset: 0,
            failed: false,
        }
    }
}

impl<I: Iterator<Item = char>> Iterator for CompatibilityDecomposed<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.offset < self.length {
            let value = self.buffer[self.offset];
            self.offset += 1;
            return Some(value);
        }
        let value = self.input.next()?;
        self.length = 0;
        self.offset = 0;
        crate::unicode_normalization::decompose_compatible(value, |decomposed| {
            if self.length < self.buffer.len() {
                self.buffer[self.length] = decomposed;
                self.length += 1;
            } else {
                self.failed = true;
            }
        });
        if self.failed || self.length == 0 {
            return None;
        }
        self.offset = 1;
        Some(self.buffer[0])
    }
}

struct UnicodeNormalizedChars<I> {
    input: CompatibilityDecomposed<I>,
    combining: heapless::Vec<(u8, char), MAX_COMBINING_SEQUENCE>,
    combining_offset: usize,
    pending_starter: Option<char>,
    failed: bool,
}

impl<I: Iterator<Item = char>> UnicodeNormalizedChars<I> {
    fn new(input: I) -> Self {
        Self {
            input: CompatibilityDecomposed::new(input),
            combining: heapless::Vec::new(),
            combining_offset: 0,
            pending_starter: None,
            failed: false,
        }
    }

    fn push_combining(&mut self, class: u8, value: char) -> bool {
        if self.combining.push((class, value)).is_err() {
            self.failed = true;
            return false;
        }
        true
    }

    fn sort_combining(&mut self) {
        for index in 1..self.combining.len() {
            let mut position = index;
            while position > 0 && self.combining[position - 1].0 > self.combining[position].0 {
                self.combining.swap(position - 1, position);
                position -= 1;
            }
        }
    }

    fn read_combining_sequence(&mut self) {
        while let Some(value) = self.input.next() {
            let class = crate::unicode_normalization::canonical_combining_class(value);
            if class == 0 {
                self.pending_starter = Some(value);
                break;
            }
            if !self.push_combining(class, value) {
                return;
            }
        }
        self.failed |= self.input.failed;
        self.sort_combining();
    }
}

impl<I: Iterator<Item = char>> Iterator for UnicodeNormalizedChars<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.combining_offset < self.combining.len() {
            let value = self.combining[self.combining_offset].1;
            self.combining_offset += 1;
            return Some(value);
        }
        self.combining.clear();
        self.combining_offset = 0;

        let Some(first) = self.pending_starter.take().or_else(|| self.input.next()) else {
            self.failed |= self.input.failed;
            return None;
        };
        let first_class = crate::unicode_normalization::canonical_combining_class(first);
        if first_class == 0 {
            self.read_combining_sequence();
            return (!self.failed).then_some(first);
        }

        if !self.push_combining(first_class, first) {
            return None;
        }
        self.read_combining_sequence();
        if self.failed {
            return None;
        }
        self.combining_offset = 1;
        Some(self.combining[0].1)
    }
}

struct NormalizedDirectoryString<I> {
    input: I,
    next: Option<char>,
    started: bool,
    pending_space: bool,
}

impl<I: Iterator<Item = char>> NormalizedDirectoryString<I> {
    fn new(input: I) -> Self {
        Self {
            input,
            next: None,
            started: false,
            pending_space: false,
        }
    }
}

impl<I: Iterator<Item = char>> Iterator for NormalizedDirectoryString<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_space {
            self.pending_space = false;
            return Some(' ');
        }
        let mut value = self.next.take().or_else(|| self.input.next())?;
        if value.is_whitespace() {
            loop {
                match self.input.next() {
                    Some(next) if next.is_whitespace() => {}
                    Some(next) => {
                        self.next = Some(next);
                        break;
                    }
                    None => return None,
                }
            }
            if self.started {
                self.pending_space = true;
                return self.next();
            }
            value = self.next.take()?;
        }
        self.started = true;
        Some(value)
    }
}

fn name_within_subtree(subject: &[u8], base: &[u8]) -> bool {
    let (Ok(subject), Ok(base)) = (single_tlv(subject, 0x30), single_tlv(base, 0x30)) else {
        return false;
    };
    let (mut subject_offset, mut base_offset) = (0, 0);
    while base_offset < base.value.len() {
        let (Ok(subject_rdn), Ok(base_rdn)) = (
            next_tlv(subject.value, &mut subject_offset),
            next_tlv(base.value, &mut base_offset),
        ) else {
            return false;
        };
        if subject_rdn.tag != 0x31 || base_rdn.tag != 0x31 || !rdn_equal(subject_rdn, base_rdn) {
            return false;
        }
    }
    true
}

fn validate_name_constraints_encoding(input: &[u8]) -> Result<(), TlsError> {
    let sequence = single_tlv(input, 0x30)?;
    if sequence.value.is_empty() {
        return Err(TlsError::InvalidCertificate);
    }
    let mut seen = 0u8;
    let mut offset = 0;
    while offset < sequence.value.len() {
        let group = next_tlv(sequence.value, &mut offset)?;
        let bit = match group.tag {
            0xa0 => 1,
            0xa1 => 2,
            _ => return Err(TlsError::InvalidCertificate),
        };
        if seen & bit != 0 || group.value.is_empty() {
            return Err(TlsError::InvalidCertificate);
        }
        seen |= bit;
        let mut subtree_offset = 0;
        while subtree_offset < group.value.len() {
            let subtree = next_tlv(group.value, &mut subtree_offset)?;
            if subtree.tag != 0x30 {
                return Err(TlsError::InvalidCertificate);
            }
            let mut field_offset = 0;
            let base = next_tlv(subtree.value, &mut field_offset)?;
            if field_offset != subtree.value.len() {
                return Err(TlsError::InvalidCertificate);
            }
            match base.tag {
                0x81 | 0x82 | 0x86
                    if !base.value.is_empty()
                        && base.value.is_ascii()
                        && !base.value.contains(&0) => {}
                0x87 if valid_ip_constraint(base.value) => {}
                0xa4 => {
                    single_tlv(base.value, 0x30)?;
                }
                _ => return Err(TlsError::InvalidCertificate),
            }
        }
    }
    Ok(())
}

fn validate_name_constraints(
    issuer: &ParsedCertificate<'_>,
    subordinates: &[CertificateEntryRef<'_>],
) -> Result<(), TlsError> {
    let Some(constraints) = issuer.extensions.name_constraints else {
        return Ok(());
    };
    for (index, entry) in subordinates.iter().enumerate() {
        let certificate = parse_entry(entry)?;
        if index != 0 && name_equal(certificate.subject, certificate.issuer) {
            continue;
        }
        check_subject_directory_constraints(constraints, certificate.subject)?;
        check_subject_email_constraints(constraints, certificate.subject)?;
        if let Some(san) = certificate.extensions.san {
            let sequence = single_tlv(san, 0x30)?;
            let mut offset = 0;
            while offset < sequence.value.len() {
                let name = next_tlv(sequence.value, &mut offset)?;
                if matches!(name.tag, 0x81 | 0x82 | 0x86 | 0x87 | 0xa4) {
                    check_constrained_name(constraints, name.tag, name.value)?;
                }
            }
        }
    }
    Ok(())
}

fn check_subject_directory_constraints(constraints: &[u8], subject: &[u8]) -> Result<(), TlsError> {
    if single_tlv(subject, 0x30)?.value.is_empty() {
        return Ok(());
    }
    check_constrained_name(constraints, 0xa4, subject)
}

fn check_subject_email_constraints(constraints: &[u8], subject: &[u8]) -> Result<(), TlsError> {
    let subject = single_tlv(subject, 0x30)?;
    let mut rdn_offset = 0;
    while rdn_offset < subject.value.len() {
        let rdn = next_tlv(subject.value, &mut rdn_offset)?;
        if rdn.tag != 0x31 {
            return Err(TlsError::InvalidCertificate);
        }
        let mut attribute_offset = 0;
        while attribute_offset < rdn.value.len() {
            let attribute = next_tlv(rdn.value, &mut attribute_offset)?;
            if attribute.tag != 0x30 {
                return Err(TlsError::InvalidCertificate);
            }
            let mut field_offset = 0;
            let oid = next_tlv(attribute.value, &mut field_offset)?;
            let value = next_tlv(attribute.value, &mut field_offset)?;
            if field_offset != attribute.value.len() || oid.tag != 0x06 {
                return Err(TlsError::InvalidCertificate);
            }
            if oid.value == OID_EMAIL_ADDRESS {
                if value.tag != 0x16 {
                    return Err(TlsError::InvalidCertificate);
                }
                check_constrained_name(constraints, 0x81, value.value)?;
            }
        }
    }
    Ok(())
}

fn check_constrained_name(constraints: &[u8], name_tag: u8, name: &[u8]) -> Result<(), TlsError> {
    let sequence = single_tlv(constraints, 0x30)?;
    let mut has_permitted = false;
    let mut permitted = false;
    let mut offset = 0;
    while offset < sequence.value.len() {
        let group = next_tlv(sequence.value, &mut offset)?;
        let mut subtree_offset = 0;
        while subtree_offset < group.value.len() {
            let subtree = next_tlv(group.value, &mut subtree_offset)?;
            let mut field_offset = 0;
            let base = next_tlv(subtree.value, &mut field_offset)?;
            if base.tag != name_tag {
                continue;
            }
            let matches = match name_tag {
                0x81 => email_within_constraint(name, base.value),
                0x82 if group.tag == 0xa1 => dns_overlaps_constraint(name, base.value),
                0x82 => Some(dns_within_constraint(name, base.value)),
                0x86 => uri_within_constraint(name, base.value),
                0x87 => Some(ip_within_constraint(name, base.value)),
                0xa4 => Some(name_within_subtree(name, base.value)),
                _ => Some(false),
            }
            .ok_or(TlsError::InvalidCertificate)?;
            if group.tag == 0xa1 && matches {
                return Err(TlsError::InvalidCertificate);
            }
            if group.tag == 0xa0 {
                has_permitted = true;
                permitted |= matches;
            }
        }
    }
    if has_permitted && !permitted {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(())
}

fn email_within_constraint(name: &[u8], constraint: &[u8]) -> Option<bool> {
    let separator = name.iter().rposition(|byte| *byte == b'@')?;
    let (local, domain) = name.split_at(separator);
    let domain = &domain[1..];
    if local.is_empty() || domain.is_empty() || !name.is_ascii() || name.contains(&0) {
        return None;
    }
    if let Some(separator) = constraint.iter().rposition(|byte| *byte == b'@') {
        let (constraint_local, constraint_domain) = constraint.split_at(separator);
        return Some(
            local == constraint_local && domain.eq_ignore_ascii_case(&constraint_domain[1..]),
        );
    }
    Some(host_within_constraint(domain, constraint))
}

fn uri_within_constraint(uri: &[u8], constraint: &[u8]) -> Option<bool> {
    Some(host_within_constraint(uri_host(uri)?, constraint))
}

fn uri_host(uri: &[u8]) -> Option<&[u8]> {
    let scheme_end = uri.iter().position(|byte| *byte == b':')?;
    let scheme = &uri[..scheme_end];
    if scheme.is_empty()
        || !scheme[0].is_ascii_alphabetic()
        || !scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let remainder = uri[scheme_end + 1..].strip_prefix(b"//")?;
    let authority_end = remainder
        .iter()
        .position(|byte| matches!(*byte, b'/' | b'?' | b'#'))
        .unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let host_port = authority
        .iter()
        .rposition(|byte| *byte == b'@')
        .map_or(authority, |position| &authority[position + 1..]);
    if host_port.starts_with(b"[") {
        return None;
    }
    let host = host_port
        .iter()
        .rposition(|byte| *byte == b':')
        .map_or(host_port, |position| &host_port[..position]);
    (!host.is_empty()
        && host.is_ascii()
        && !host.contains(&0)
        && host
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.')))
    .then_some(host)
}

fn host_within_constraint(host: &[u8], constraint: &[u8]) -> bool {
    if host.is_empty() || constraint.is_empty() || !host.is_ascii() || !constraint.is_ascii() {
        return false;
    }
    if let Some(domain) = constraint.strip_prefix(b".") {
        return host.len() > domain.len()
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
            && host[host.len() - domain.len() - 1] == b'.';
    }
    host.eq_ignore_ascii_case(constraint)
}

fn dns_overlaps_constraint(name: &[u8], constraint: &[u8]) -> Option<bool> {
    let Some(base) = name.strip_prefix(b"*.") else {
        return Some(dns_within_constraint(name, constraint));
    };
    let subordinate_only = constraint.starts_with(b".");
    let constraint = constraint.strip_prefix(b".").unwrap_or(constraint);
    if base.eq_ignore_ascii_case(constraint)
        || (base.len() > constraint.len()
            && base[base.len() - constraint.len()..].eq_ignore_ascii_case(constraint)
            && base[base.len() - constraint.len() - 1] == b'.')
    {
        return Some(true);
    }
    Some(
        constraint.len() > base.len()
            && constraint[constraint.len() - base.len()..].eq_ignore_ascii_case(base)
            && constraint[constraint.len() - base.len() - 1] == b'.'
            && !constraint[..constraint.len() - base.len() - 1].contains(&b'.')
            && !subordinate_only,
    )
}

fn dns_within_constraint(name: &[u8], constraint: &[u8]) -> bool {
    if name.is_empty() || constraint.is_empty() || !name.is_ascii() || !constraint.is_ascii() {
        return false;
    }
    let subordinate_only = constraint.starts_with(b".");
    let constraint = constraint.strip_prefix(b".").unwrap_or(constraint);
    if !subordinate_only && name.eq_ignore_ascii_case(constraint) {
        return true;
    }
    name.len() > constraint.len()
        && name[name.len() - constraint.len()..].eq_ignore_ascii_case(constraint)
        && name[name.len() - constraint.len() - 1] == b'.'
}

fn ip_within_constraint(address: &[u8], constraint: &[u8]) -> bool {
    if constraint.len() != address.len().saturating_mul(2) {
        return false;
    }
    let (network, mask) = constraint.split_at(address.len());
    address
        .iter()
        .zip(network)
        .zip(mask)
        .all(|((address, network), mask)| address & mask == network & mask)
}

fn valid_ip_constraint(constraint: &[u8]) -> bool {
    if !matches!(constraint.len(), 8 | 32) {
        return false;
    }
    let (_, mask) = constraint.split_at(constraint.len() / 2);
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if zero_seen && set {
                return false;
            }
            zero_seen |= !set;
        }
    }
    true
}

#[inline(never)]
fn verify_certificate_signature(
    certificate: ParsedCertificate<'_>,
    issuer_key: PublicKey<'_>,
    workspace: &mut rsa::RsaWorkspace,
) -> bool {
    match (certificate.signature_algorithm, issuer_key) {
        (
            algorithm @ (SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384),
            PublicKey::P256(key),
        ) => verify_ecdsa_p256(key, certificate.tbs, certificate.signature, algorithm),
        (
            algorithm @ (SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384),
            PublicKey::P384(key),
        ) => verify_ecdsa_p384(key, certificate.tbs, certificate.signature, algorithm),
        (SignatureAlgorithm::RsaPkcs1(hash), PublicKey::Rsa(key)) => {
            rsa::verify_pkcs1_with_workspace(
                key,
                hash,
                certificate.tbs,
                certificate.signature,
                workspace,
            )
        }
        (SignatureAlgorithm::RsaPss(hash), PublicKey::Rsa(key)) => rsa::verify_pss_with_workspace(
            key,
            hash,
            certificate.tbs,
            certificate.signature,
            workspace,
        ),
        _ => false,
    }
}

#[inline(never)]
fn verify_ecdsa_p256(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: SignatureAlgorithm,
) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
        return false;
    };
    match algorithm {
        SignatureAlgorithm::EcdsaSha256 => key
            .verify_prehash(&sha2::Sha256::digest(message), &signature)
            .is_ok(),
        SignatureAlgorithm::EcdsaSha384 => key
            .verify_prehash(&sha2::Sha384::digest(message), &signature)
            .is_ok(),
        _ => false,
    }
}

#[inline(never)]
fn verify_ecdsa_p384(
    key: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: SignatureAlgorithm,
) -> bool {
    let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(key) else {
        return false;
    };
    let Ok(signature) = p384::ecdsa::Signature::from_der(signature) else {
        return false;
    };
    match algorithm {
        SignatureAlgorithm::EcdsaSha256 => key
            .verify_prehash(&sha2::Sha256::digest(message), &signature)
            .is_ok(),
        SignatureAlgorithm::EcdsaSha384 => key
            .verify_prehash(&sha2::Sha384::digest(message), &signature)
            .is_ok(),
        _ => false,
    }
}

fn same_key(left: PublicKey<'_>, right: PublicKey<'_>) -> bool {
    match (left, right) {
        (PublicKey::P256(left), PublicKey::P256(right))
        | (PublicKey::P384(left), PublicKey::P384(right)) => left == right,
        (PublicKey::Rsa(left), PublicKey::Rsa(right)) => left.modulus == right.modulus,
        _ => false,
    }
}

fn copy_leaf_key(key: PublicKey<'_>) -> Result<LeafPublicKey, TlsError> {
    match key {
        PublicKey::P256(key) if key.len() == 65 => Ok(LeafPublicKey::copy(LeafKeyKind::P256, key)),
        PublicKey::P384(key) if key.len() == 97 => Ok(LeafPublicKey::copy(LeafKeyKind::P384, key)),
        PublicKey::Rsa(key) if key.modulus.len() == rsa::RSA_2048_BYTES => {
            Ok(LeafPublicKey::copy(LeafKeyKind::Rsa2048, key.modulus))
        }
        PublicKey::Rsa(key) if key.modulus.len() == rsa::RSA_3072_BYTES => {
            Ok(LeafPublicKey::copy(LeafKeyKind::Rsa3072, key.modulus))
        }
        PublicKey::Rsa(key) if key.modulus.len() == rsa::RSA_4096_BYTES => {
            Ok(LeafPublicKey::copy(LeafKeyKind::Rsa4096, key.modulus))
        }
        PublicKey::P256(_) | PublicKey::P384(_) | PublicKey::Rsa(_) => {
            Err(TlsError::InvalidCertificate)
        }
    }
}

fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate<'_>, TlsError> {
    let mut outer_offset = 0;
    let outer = next_tlv(der, &mut outer_offset)?;
    if outer.tag != 0x30 || outer_offset != der.len() {
        return Err(TlsError::DecodeError);
    }
    let mut offset = 0;
    let tbs = next_tlv(outer.value, &mut offset)?;
    let outer_algorithm = next_tlv(outer.value, &mut offset)?;
    let signature = next_tlv(outer.value, &mut offset)?;
    if tbs.tag != 0x30
        || outer_algorithm.tag != 0x30
        || signature.tag != 0x03
        || offset != outer.value.len()
        || signature.value.first() != Some(&0)
        || signature.value.len() < 2
    {
        return Err(TlsError::DecodeError);
    }

    let mut tbs_offset = 0;
    let version = next_tlv(tbs.value, &mut tbs_offset)?;
    if version.tag != 0xa0 || version.value != [0x02, 0x01, 0x02] {
        return Err(TlsError::InvalidCertificate);
    }
    let serial = next_tlv(tbs.value, &mut tbs_offset)?;
    let inner_algorithm = next_tlv(tbs.value, &mut tbs_offset)?;
    let issuer = next_tlv(tbs.value, &mut tbs_offset)?;
    let validity = next_tlv(tbs.value, &mut tbs_offset)?;
    let subject = next_tlv(tbs.value, &mut tbs_offset)?;
    let spki = next_tlv(tbs.value, &mut tbs_offset)?;
    if serial.tag != 0x02
        || serial.value.is_empty()
        || inner_algorithm.full != outer_algorithm.full
        || issuer.tag != 0x30
        || validity.tag != 0x30
        || subject.tag != 0x30
        || spki.tag != 0x30
    {
        return Err(TlsError::InvalidCertificate);
    }

    let (not_before, not_after) = parse_validity(validity.value)?;
    let public_key = parse_spki(spki.value)?;
    let mut extensions = None;
    while tbs_offset < tbs.value.len() {
        let optional = next_tlv(tbs.value, &mut tbs_offset)?;
        if optional.tag != 0xa3 || extensions.is_some() {
            return Err(TlsError::InvalidCertificate);
        }
        extensions = Some(parse_extensions(optional.value)?);
    }

    Ok(ParsedCertificate {
        tbs: tbs.full,
        signature_algorithm: parse_signature_algorithm(outer_algorithm)?,
        issuer: issuer.full,
        subject: subject.full,
        not_before,
        not_after,
        public_key,
        extensions: extensions.unwrap_or_default(),
        signature: &signature.value[1..],
    })
}

fn parse_spki(input: &[u8]) -> Result<PublicKey<'_>, TlsError> {
    let mut offset = 0;
    let algorithm = next_tlv(input, &mut offset)?;
    let key = next_tlv(input, &mut offset)?;
    if algorithm.tag != 0x30
        || key.tag != 0x03
        || offset != input.len()
        || key.value.first() != Some(&0)
    {
        return Err(TlsError::InvalidCertificate);
    }
    let key = &key.value[1..];
    let (oid, parameters) = parse_algorithm_identifier(algorithm)?;
    if oid == OID_EC_PUBLIC_KEY {
        let parameters = parameters.ok_or(TlsError::InvalidCertificate)?;
        if parameters.tag != 0x06 {
            return Err(TlsError::InvalidCertificate);
        }
        return match (parameters.value, key.len()) {
            (OID_P256, 65) if key.first() == Some(&4) => Ok(PublicKey::P256(key)),
            (OID_P384, 97) if key.first() == Some(&4) => Ok(PublicKey::P384(key)),
            _ => Err(TlsError::InvalidCertificate),
        };
    }
    if oid == OID_RSA_ENCRYPTION {
        if !parameters.is_none_or(is_null) {
            return Err(TlsError::InvalidCertificate);
        }
        return rsa::parse_public_key(key)
            .map(PublicKey::Rsa)
            .map_err(|_| TlsError::InvalidCertificate);
    }
    // RSASSA-PSS-constrained subject keys are intentionally unsupported.
    if oid == OID_RSA_PSS {
        return Err(TlsError::InvalidCertificate);
    }
    Err(TlsError::InvalidCertificate)
}

fn parse_signature_algorithm(algorithm: Tlv<'_>) -> Result<SignatureAlgorithm, TlsError> {
    let (oid, parameters) = parse_algorithm_identifier(algorithm)?;
    match oid {
        OID_ECDSA_SHA256 if parameters.is_none() => Ok(SignatureAlgorithm::EcdsaSha256),
        OID_ECDSA_SHA384 if parameters.is_none() => Ok(SignatureAlgorithm::EcdsaSha384),
        OID_RSA_SHA256 if parameters.is_none_or(is_null) => {
            Ok(SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha256))
        }
        OID_RSA_SHA384 if parameters.is_none_or(is_null) => {
            Ok(SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha384))
        }
        OID_RSA_SHA512 if parameters.is_none_or(is_null) => {
            Ok(SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha512))
        }
        OID_RSA_PSS => parse_pss_parameters(parameters.ok_or(TlsError::InvalidCertificate)?)
            .map(SignatureAlgorithm::RsaPss),
        _ => Err(TlsError::InvalidSignatureScheme),
    }
}

fn parse_algorithm_identifier(algorithm: Tlv<'_>) -> Result<(&[u8], Option<Tlv<'_>>), TlsError> {
    if algorithm.tag != 0x30 {
        return Err(TlsError::DecodeError);
    }
    let mut offset = 0;
    let oid = next_tlv(algorithm.value, &mut offset)?;
    if oid.tag != 0x06 || oid.value.is_empty() {
        return Err(TlsError::DecodeError);
    }
    let parameters = if offset < algorithm.value.len() {
        Some(next_tlv(algorithm.value, &mut offset)?)
    } else {
        None
    };
    if offset != algorithm.value.len() {
        return Err(TlsError::DecodeError);
    }
    Ok((oid.value, parameters))
}

fn is_null(value: Tlv<'_>) -> bool {
    value.tag == 0x05 && value.value.is_empty()
}

fn parse_pss_parameters(parameters: Tlv<'_>) -> Result<HashAlgorithm, TlsError> {
    if parameters.tag != 0x30 {
        return Err(TlsError::InvalidCertificate);
    }
    let mut offset = 0;
    let hash = explicit(parameters.value, &mut offset, 0xa0).and_then(parse_hash_algorithm)?;
    let mgf = explicit(parameters.value, &mut offset, 0xa1)?;
    let (mgf_oid, mgf_parameters) = parse_algorithm_identifier(mgf)?;
    let mgf_hash = mgf_parameters
        .ok_or(TlsError::InvalidCertificate)
        .and_then(parse_hash_algorithm)?;
    let salt = explicit(parameters.value, &mut offset, 0xa2)?;
    let salt = parse_small_integer(salt)?;
    if offset < parameters.value.len() {
        let trailer = explicit(parameters.value, &mut offset, 0xa3)?;
        if parse_small_integer(trailer)? != 1 {
            return Err(TlsError::InvalidCertificate);
        }
    }
    if offset != parameters.value.len()
        || mgf_oid != OID_MGF1
        || mgf_hash != hash
        || usize::from(salt) != hash.output_len()
    {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(hash)
}

fn explicit<'a>(input: &'a [u8], offset: &mut usize, tag: u8) -> Result<Tlv<'a>, TlsError> {
    let wrapper = next_tlv(input, offset)?;
    if wrapper.tag != tag {
        return Err(TlsError::InvalidCertificate);
    }
    let mut inner_offset = 0;
    let inner = next_tlv(wrapper.value, &mut inner_offset)?;
    if inner_offset != wrapper.value.len() {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(inner)
}

fn parse_hash_algorithm(algorithm: Tlv<'_>) -> Result<HashAlgorithm, TlsError> {
    let (oid, parameters) = parse_algorithm_identifier(algorithm)?;
    if !parameters.is_none_or(is_null) {
        return Err(TlsError::InvalidCertificate);
    }
    match oid {
        OID_SHA256 => Ok(HashAlgorithm::Sha256),
        OID_SHA384 => Ok(HashAlgorithm::Sha384),
        OID_SHA512 => Ok(HashAlgorithm::Sha512),
        _ => Err(TlsError::InvalidCertificate),
    }
}

fn parse_small_integer(integer: Tlv<'_>) -> Result<u8, TlsError> {
    match (integer.tag, integer.value) {
        (0x02, [value]) if *value & 0x80 == 0 => Ok(*value),
        _ => Err(TlsError::InvalidCertificate),
    }
}

fn parse_validity(input: &[u8]) -> Result<(u64, u64), TlsError> {
    let mut offset = 0;
    let not_before = next_tlv(input, &mut offset)?;
    let not_after = next_tlv(input, &mut offset)?;
    if offset != input.len() {
        return Err(TlsError::DecodeError);
    }
    Ok((parse_time(not_before)?, parse_time(not_after)?))
}

fn parse_time(time: Tlv<'_>) -> Result<u64, TlsError> {
    let (year, rest) = match (time.tag, time.value) {
        (0x17, [a, b, rest @ ..]) if rest.len() == 11 => {
            let year = decimal(*a, *b)?;
            (if year >= 50 { 1900 + year } else { 2000 + year }, rest)
        }
        (0x18, [a, b, c, d, rest @ ..]) if rest.len() == 11 => {
            let high = decimal(*a, *b)?;
            (high * 100 + decimal(*c, *d)?, rest)
        }
        _ => return Err(TlsError::InvalidCertificate),
    };
    let month = decimal(rest[0], rest[1])?;
    let day = decimal(rest[2], rest[3])?;
    let hour = decimal(rest[4], rest[5])?;
    let minute = decimal(rest[6], rest[7])?;
    let second = decimal(rest[8], rest[9])?;
    if rest[10] != b'Z'
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(TlsError::InvalidCertificate);
    }
    let days = days_from_civil(year, month, day).ok_or(TlsError::InvalidCertificate)?;
    u64::try_from(days)
        .ok()
        .and_then(|days| days.checked_mul(86_400))
        .and_then(|seconds| seconds.checked_add(u64::from(hour * 3600 + minute * 60 + second)))
        .ok_or(TlsError::InvalidCertificate)
}

fn decimal(high: u8, low: u8) -> Result<u32, TlsError> {
    if !high.is_ascii_digit() || !low.is_ascii_digit() {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(u32::from(high - b'0') * 10 + u32::from(low - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: u32, month: u32, day: u32) -> Option<i64> {
    let mut year = i64::from(year);
    let month = i64::from(month);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    (days >= 0).then_some(days)
}

fn parse_extensions(input: &[u8]) -> Result<Extensions<'_>, TlsError> {
    let mut wrapper_offset = 0;
    let sequence = next_tlv(input, &mut wrapper_offset)?;
    if sequence.tag != 0x30 || wrapper_offset != input.len() {
        return Err(TlsError::DecodeError);
    }

    let mut result = Extensions::default();
    let mut seen = 0u8;
    let mut offset = 0;
    while offset < sequence.value.len() {
        let extension = next_tlv(sequence.value, &mut offset)?;
        if extension.tag != 0x30 {
            return Err(TlsError::DecodeError);
        }
        let mut field_offset = 0;
        let oid = next_tlv(extension.value, &mut field_offset)?;
        if oid.tag != 0x06 {
            return Err(TlsError::DecodeError);
        }
        let critical = if extension.value.get(field_offset) == Some(&0x01) {
            let critical = next_tlv(extension.value, &mut field_offset)?;
            if critical.value != [0xff] {
                return Err(TlsError::DecodeError);
            }
            true
        } else {
            false
        };
        let value = next_tlv(extension.value, &mut field_offset)?;
        if value.tag != 0x04 || field_offset != extension.value.len() {
            return Err(TlsError::DecodeError);
        }

        let bit = match oid.value {
            OID_BASIC_CONSTRAINTS => {
                result.basic_constraints = Some(parse_basic_constraints(value.value)?);
                1
            }
            OID_KEY_USAGE => {
                result.key_usage = Some(parse_key_usage(value.value)?);
                2
            }
            OID_EXTENDED_KEY_USAGE => {
                result.server_auth = Some(parse_extended_key_usage(value.value)?);
                4
            }
            OID_SAN => {
                validate_san(value.value)?;
                result.san = Some(value.value);
                8
            }
            OID_NAME_CONSTRAINTS => {
                validate_name_constraints_encoding(value.value)?;
                result.name_constraints = Some(value.value);
                16
            }
            OID_SUBJECT_KEY_ID
            | OID_AUTHORITY_KEY_ID
            | OID_CRL_DISTRIBUTION
            | OID_CERTIFICATE_POLICIES
            | OID_AUTHORITY_INFO_ACCESS => {
                if critical {
                    return Err(TlsError::InvalidCertificate);
                }
                0
            }
            _ => {
                if critical {
                    return Err(TlsError::InvalidCertificate);
                }
                0
            }
        };
        if bit != 0 && seen & bit != 0 {
            return Err(TlsError::InvalidCertificate);
        }
        seen |= bit;
    }
    Ok(result)
}

fn parse_basic_constraints(input: &[u8]) -> Result<BasicConstraints, TlsError> {
    let mut outer_offset = 0;
    let sequence = next_tlv(input, &mut outer_offset)?;
    if sequence.tag != 0x30 || outer_offset != input.len() {
        return Err(TlsError::DecodeError);
    }
    let mut offset = 0;
    let ca = if sequence.value.get(offset) == Some(&0x01) {
        let boolean = next_tlv(sequence.value, &mut offset)?;
        if boolean.value != [0xff] {
            return Err(TlsError::DecodeError);
        }
        true
    } else {
        false
    };
    let path_len = if offset < sequence.value.len() {
        Some(parse_small_integer(next_tlv(sequence.value, &mut offset)?)?)
    } else {
        None
    };
    if offset != sequence.value.len() || path_len.is_some() && !ca {
        return Err(TlsError::InvalidCertificate);
    }
    Ok(BasicConstraints { ca, path_len })
}

fn parse_key_usage(input: &[u8]) -> Result<KeyUsage, TlsError> {
    let mut offset = 0;
    let usage = next_tlv(input, &mut offset)?;
    if usage.tag != 0x03 || offset != input.len() || usage.value.len() < 2 {
        return Err(TlsError::DecodeError);
    }
    let unused = usage.value[0];
    let bytes = &usage.value[1..];
    if unused > 7 || bytes[bytes.len() - 1] & ((1u8 << unused) - 1) != 0 {
        return Err(TlsError::DecodeError);
    }
    Ok(KeyUsage {
        digital_signature: bytes[0] & 0x80 != 0,
        key_cert_sign: bytes[0] & 0x04 != 0,
    })
}

fn parse_extended_key_usage(input: &[u8]) -> Result<bool, TlsError> {
    let mut outer_offset = 0;
    let sequence = next_tlv(input, &mut outer_offset)?;
    if sequence.tag != 0x30 || outer_offset != input.len() || sequence.value.is_empty() {
        return Err(TlsError::DecodeError);
    }
    let mut found = false;
    let mut offset = 0;
    while offset < sequence.value.len() {
        let oid = next_tlv(sequence.value, &mut offset)?;
        if oid.tag != 0x06 {
            return Err(TlsError::DecodeError);
        }
        found |= matches!(oid.value, OID_SERVER_AUTH | OID_ANY_EXTENDED_KEY_USAGE);
    }
    Ok(found)
}

fn validate_san(input: &[u8]) -> Result<(), TlsError> {
    let mut outer_offset = 0;
    let sequence = next_tlv(input, &mut outer_offset)?;
    if sequence.tag != 0x30 || outer_offset != input.len() || sequence.value.is_empty() {
        return Err(TlsError::DecodeError);
    }
    let mut offset = 0;
    while offset < sequence.value.len() {
        let name = next_tlv(sequence.value, &mut offset)?;
        if name.tag == 0x82
            && (name.value.is_empty()
                || !name.value.is_ascii()
                || name.value.contains(&0)
                || name.value.len() > 253)
        {
            return Err(TlsError::InvalidCertificate);
        }
        if name.tag == 0x87 && !matches!(name.value.len(), 4 | 16) {
            return Err(TlsError::InvalidCertificate);
        }
    }
    Ok(())
}

fn hostname_matches_san(hostname: &str, input: &[u8]) -> bool {
    if hostname.is_empty() || !hostname.is_ascii() {
        return false;
    }
    let Ok(sequence) = single_tlv(input, 0x30) else {
        return false;
    };
    let ip = core::net::IpAddr::from_str(hostname).ok();
    let mut offset = 0;
    while offset < sequence.value.len() {
        let Ok(name) = next_tlv(sequence.value, &mut offset) else {
            return false;
        };
        if let Some(address) = ip {
            let matches = match address {
                core::net::IpAddr::V4(address) => name.value == address.octets(),
                core::net::IpAddr::V6(address) => name.value == address.octets(),
            };
            if name.tag == 0x87 && matches {
                return true;
            }
        } else if name.tag == 0x82 && dns_name_matches(name.value, hostname.as_bytes()) {
            return true;
        }
    }
    false
}

fn dns_name_matches(pattern: &[u8], hostname: &[u8]) -> bool {
    if !pattern
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'*'))
        || !hostname
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.'))
    {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix(b"*.") {
        if suffix.is_empty()
            || !suffix.contains(&b'.')
            || suffix.contains(&b'*')
            || hostname.len() <= suffix.len() + 1
        {
            return false;
        }
        let split = hostname.len() - suffix.len();
        return hostname[split - 1] == b'.'
            && !hostname[..split - 1].contains(&b'.')
            && hostname[split..].eq_ignore_ascii_case(suffix);
    }
    !pattern.contains(&b'*') && pattern.eq_ignore_ascii_case(hostname)
}

fn single_tlv(input: &[u8], tag: u8) -> Result<Tlv<'_>, TlsError> {
    let mut offset = 0;
    let value = next_tlv(input, &mut offset)?;
    if value.tag != tag || offset != input.len() {
        return Err(TlsError::DecodeError);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use embedded_tls::{CertificateVerifyRef, SignatureScheme, TlsVerifier as _};

    #[test]
    fn ip_certificate_identities_match_their_complete_address_family() {
        let ipv6 = [
            0x30, 0x12, 0x87, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let ipv4 = [0x30, 0x06, 0x87, 0x04, 127, 0, 0, 1];
        assert!(hostname_matches_san("::1", &ipv6));
        assert!(hostname_matches_san("0:0:0:0:0:0:0:1", &ipv6));
        assert!(!hostname_matches_san("::2", &ipv6));
        assert!(!hostname_matches_san("127.0.0.1", &ipv6));
        assert!(hostname_matches_san("127.0.0.1", &ipv4));
        assert!(!hostname_matches_san("::ffff:127.0.0.1", &ipv4));
        assert!(!hostname_matches_san("localhost", &ipv6));
    }

    struct CaptureClock;
    impl TlsClock for CaptureClock {
        fn now() -> Option<u64> {
            Some(1_786_536_000)
        }
    }
    struct BeforeClock;
    impl TlsClock for BeforeClock {
        fn now() -> Option<u64> {
            Some(1_700_000_000)
        }
    }
    struct AfterClock;
    impl TlsClock for AfterClock {
        fn now() -> Option<u64> {
            Some(1_900_000_000)
        }
    }
    struct MissingClock;
    impl TlsClock for MissingClock {
        fn now() -> Option<u64> {
            None
        }
    }

    fn string_value(tag: u8, value: &[u8]) -> Tlv<'_> {
        Tlv {
            tag,
            value,
            full: &[],
        }
    }

    #[test]
    fn directory_strings_full_fold_all_unicode_encodings_and_canonical_forms() {
        let cases = [
            ("ϑ", "θ"),
            ("\u{345}", "ι"),
            ("ẞ", "ss"),
            ("ᾲ", "ὰι"),
            ("α\u{345}\u{301}", "άι"),
            ("ﬃ", "ffi"),
            ("Ꭰ", "ꭰ"),
            ("İ", "i\u{307}"),
            ("𝔸", "a"),
        ];
        for (input, expected) in cases {
            for tag in [0x0c, 0x1e, 0x1c] {
                let encoded: std::vec::Vec<u8> = match tag {
                    0x0c => input.as_bytes().to_vec(),
                    0x1e if input.chars().all(|c| c as u32 <= 0xffff) => input
                        .chars()
                        .flat_map(|c| (c as u16).to_be_bytes())
                        .collect(),
                    0x1e => continue,
                    _ => input
                        .chars()
                        .flat_map(|c| (c as u32).to_be_bytes())
                        .collect(),
                };
                assert!(
                    directory_value_equal(
                        string_value(tag, &encoded),
                        string_value(0x0c, expected.as_bytes())
                    ),
                    "{input:?} / {tag:x}"
                );
            }
        }
        for (left, right) in [("ı", "i"), ("İ", "i"), ("é", "e"), ("ß", "s")] {
            assert!(!directory_value_equal(
                string_value(0x0c, left.as_bytes()),
                string_value(0x0c, right.as_bytes())
            ));
        }
        // Overflow in either normalization stage must reject equal inputs.
        let oversized =
            std::string::String::from("a") + &"\u{301}".repeat(MAX_COMBINING_SEQUENCE + 1);
        assert!(!directory_value_equal(
            string_value(0x0c, oversized.as_bytes()),
            string_value(0x0c, oversized.as_bytes())
        ));
    }

    #[test]
    fn teletex_directory_strings_compare_to_unicode_and_reject_invalid_suffixes() {
        for (input, expected) in [
            (&[0xc2, b'e'][..], "É"),
            (&[0xe1, 0xc8, b'u', 0xfb][..], "æÜss"),
            (&[0xcb, b'C'][..], "c\u{327}"),
            (&[0xa4][..], "$"),
            (&[0x24][..], "¤"),
        ] {
            assert!(directory_value_equal(
                string_value(0x14, input),
                string_value(0x0c, expected.as_bytes())
            ));
        }
        for input in [
            &[0xc2][..],
            &[b'a', 0xc2][..],
            &[0xc3, 0xa9][..],
            &[0xff][..],
        ] {
            assert!(!directory_value_equal(
                string_value(0x14, input),
                string_value(0x14, input)
            ));
            assert!(!directory_value_equal(
                string_value(0x14, input),
                string_value(0x0c, b"a")
            ));
        }
    }

    #[test]
    fn teletex_capital_eth_folds_as_eth_without_aliasing_d_with_stroke() {
        let eth = string_value(0x14, &[0xe2]);
        for value in ["Ð", "ð"] {
            assert!(directory_value_equal(
                eth,
                string_value(0x0c, value.as_bytes())
            ));
        }
        assert!(directory_value_equal(eth, string_value(0x14, &[0xf3])));
        for value in ["Đ", "đ"] {
            assert!(!directory_value_equal(
                eth,
                string_value(0x0c, value.as_bytes())
            ));
        }
        assert!(!directory_value_equal(eth, string_value(0x14, &[0xf2])));
        assert!(directory_value_equal(
            string_value(0x14, &[0xf2]),
            string_value(0x0c, "Đ".as_bytes())
        ));
    }

    #[test]
    fn teletex_vertical_line_matches_each_unicode_directory_encoding() {
        let teletex = string_value(0x14, b"Root|CA");
        for (tag, bytes) in [
            (0x0c, b"root|ca".to_vec()),
            (
                0x1e,
                "root|ca"
                    .chars()
                    .flat_map(|c| (c as u16).to_be_bytes())
                    .collect(),
            ),
            (
                0x1c,
                "root|ca"
                    .chars()
                    .flat_map(|c| (c as u32).to_be_bytes())
                    .collect(),
            ),
        ] {
            assert!(directory_value_equal(teletex, string_value(tag, &bytes)));
        }
        assert!(directory_value_equal(teletex, teletex));
        for reserved in [b'\\', b'^', b'`', b'{', b'}', b'~', 0x7f] {
            let bytes = [b'|', reserved];
            let invalid = string_value(0x14, &bytes);
            assert!(!directory_value_equal(invalid, invalid));
        }
    }

    #[test]
    fn teletex_accent_pairs_follow_the_defined_case_sensitive_repertoire() {
        // T.61 Annex B defines lowercase g acute and uppercase G cedilla,
        // but their opposite-case encodings are not members of its repertoire.
        // Unicode directory-string comparison still performs full case folding.
        for (encoded, unicode) in [(&[0xc2, b'g'][..], "Ǵ"), (&[0xcb, b'G'][..], "ģ")] {
            assert!(directory_value_equal(
                string_value(0x14, encoded),
                string_value(0x0c, unicode.as_bytes())
            ));
        }
        for encoded in [&[0xc2, b'G'][..], &[0xcb, b'g'][..]] {
            let invalid = string_value(0x14, encoded);
            assert!(!directory_value_equal(invalid, invalid));
        }
    }

    #[test]
    fn hosted_rsa_path_rejects_name_time_order_overflow_and_tbs_mutation() {
        let certificates = rsa_chain();
        assert!(
            verify_chain::<CaptureClock>(chain(&certificates), "controlplane.tailscale.com", None)
                .is_ok()
        );
        assert!(verify_chain::<CaptureClock>(chain(&certificates), "wrong.example", None).is_err());
        assert!(
            verify_chain::<BeforeClock>(chain(&certificates), "controlplane.tailscale.com", None)
                .is_err()
        );
        assert!(
            verify_chain::<AfterClock>(chain(&certificates), "controlplane.tailscale.com", None)
                .is_err()
        );
        assert!(
            verify_chain::<MissingClock>(chain(&certificates), "controlplane.tailscale.com", None)
                .is_err()
        );

        let reordered = [
            certificates[0].clone(),
            certificates[2].clone(),
            certificates[1].clone(),
        ];
        assert!(
            verify_chain::<CaptureClock>(chain(&reordered), "controlplane.tailscale.com", None)
                .is_err()
        );

        let overflowing = (0..=MAX_CHAIN_CERTIFICATES)
            .map(|_| certificates[0].clone())
            .collect::<std::vec::Vec<_>>();
        assert!(
            verify_chain::<CaptureClock>(chain(&overflowing), "controlplane.tailscale.com", None)
                .is_err()
        );

        let mut mutated = certificates.clone();
        let byte = mutated[0].len() / 3;
        mutated[0][byte] ^= 1;
        assert!(
            verify_chain::<CaptureClock>(chain(&mutated), "controlplane.tailscale.com", None)
                .is_err()
        );

        let entries = chain(&certificates);
        let wrong_root = parse_certificate(ISRG_ROOT_X2_DER).unwrap();
        let mut workspace = rsa::RsaWorkspace::new();
        assert!(
            validate_path(
                &entries.entries,
                wrong_root,
                CaptureClock::now().unwrap(),
                &mut workspace,
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_anchors_do_not_fall_back_to_public_roots() {
        use super::super::TrustVerifier;
        let certificates = rsa_chain();
        let transcript = sha2::Sha256::new();
        let mut workspace = rsa::RsaWorkspace::new();
        // The default constructor intentionally keeps both public anchors.
        let mut default =
            TrustVerifier::<CaptureClock>::new(Some(ISRG_ROOT_X2_DER), &mut workspace);
        default
            .set_hostname_verification("controlplane.tailscale.com")
            .unwrap();
        assert!(
            default
                .verify_certificate(&transcript, chain(&certificates))
                .is_ok()
        );
        for roots in [
            &[][..],
            &[ISRG_ROOT_X2_DER][..],
            &[b"invalid".as_slice()][..],
        ] {
            let mut verifier = TrustVerifier::<CaptureClock>::with_roots(roots, &mut workspace);
            verifier
                .set_hostname_verification("controlplane.tailscale.com")
                .unwrap();
            assert!(
                verifier
                    .verify_certificate(&transcript, chain(&certificates))
                    .is_err()
            );
        }
        for roots in [
            &[ISRG_ROOT_YR_DER][..],
            &[ISRG_ROOT_X2_DER, ISRG_ROOT_YR_DER][..],
        ] {
            let mut verifier = TrustVerifier::<CaptureClock>::with_roots(roots, &mut workspace);
            verifier
                .set_hostname_verification("controlplane.tailscale.com")
                .unwrap();
            assert!(
                verifier
                    .verify_certificate(&transcript, chain(&certificates))
                    .is_ok()
            );
            verifier.set_hostname_verification("wrong.example").unwrap();
            assert!(
                verifier
                    .verify_certificate(&transcript, chain(&certificates))
                    .is_err()
            );
        }
        let roots = &[ISRG_ROOT_YR_DER];
        let mut verifier = TrustVerifier::<AfterClock>::with_roots(roots, &mut workspace);
        verifier
            .set_hostname_verification("controlplane.tailscale.com")
            .unwrap();
        assert!(
            verifier
                .verify_certificate(&transcript, chain(&certificates))
                .is_err()
        );
    }

    #[test]
    fn inner_and_outer_signature_algorithms_must_match() {
        let mut certificates = rsa_chain();
        let positions = certificates[0]
            .windows(OID_RSA_SHA256.len())
            .enumerate()
            .filter_map(|(position, bytes)| (bytes == OID_RSA_SHA256).then_some(position))
            .collect::<std::vec::Vec<_>>();
        assert_eq!(positions.len(), 2);
        let outer_oid = *positions.last().unwrap();
        certificates[0][outer_oid + OID_RSA_SHA256.len() - 1] = 0x0c;
        assert!(
            verify_chain::<CaptureClock>(chain(&certificates), "controlplane.tailscale.com", None)
                .is_err()
        );
    }

    #[test]
    fn a_trailing_non_path_certificate_does_not_invalidate_a_trusted_prefix() {
        let certificates = rsa_chain();
        let mut entries = chain(&certificates);
        entries
            .add(CertificateEntryRef::X509(b"not a path certificate"))
            .unwrap();
        assert!(verify_chain::<CaptureClock>(entries, "controlplane.tailscale.com", None).is_ok());
    }

    #[test]
    fn constraints_and_unknown_critical_extensions_are_enforced() {
        let certificates = rsa_chain();
        let leaf = parse_certificate(&certificates[0]).unwrap();
        let issuer = parse_certificate(&certificates[1]).unwrap();

        let mut leaf_with_optional_constraints_omitted = leaf;
        leaf_with_optional_constraints_omitted
            .extensions
            .basic_constraints = None;
        leaf_with_optional_constraints_omitted.extensions.key_usage = None;
        leaf_with_optional_constraints_omitted
            .extensions
            .server_auth = None;
        assert!(
            validate_leaf(
                &leaf_with_optional_constraints_omitted,
                "controlplane.tailscale.com"
            )
            .is_ok()
        );
        let mut ca_leaf = leaf;
        ca_leaf.extensions.basic_constraints = Some(BasicConstraints {
            ca: true,
            path_len: None,
        });
        assert!(validate_leaf(&ca_leaf, "controlplane.tailscale.com").is_err());
        let mut incompatible_leaf_usage = leaf;
        incompatible_leaf_usage.extensions.key_usage = Some(KeyUsage {
            digital_signature: false,
            key_cert_sign: false,
        });
        assert!(validate_leaf(&incompatible_leaf_usage, "controlplane.tailscale.com").is_err());
        let mut ca_without_usage = issuer;
        ca_without_usage.extensions.key_usage = None;
        assert!(validate_ca(&ca_without_usage, 0).is_ok());
        let mut ca_without_key_cert_sign = issuer;
        ca_without_key_cert_sign.extensions.key_usage = Some(KeyUsage {
            digital_signature: true,
            key_cert_sign: false,
        });
        assert!(validate_ca(&ca_without_key_cert_sign, 0).is_err());
        let mut ca_with_wrong_eku = issuer;
        ca_with_wrong_eku.extensions.server_auth = Some(false);
        assert!(validate_ca(&ca_with_wrong_eku, 0).is_err());
        let mut path_limited = issuer;
        path_limited.extensions.basic_constraints = Some(BasicConstraints {
            ca: true,
            path_len: Some(0),
        });
        assert!(validate_ca(&path_limited, 1).is_err());

        // SEQUENCE { Extension { 1.2.3.4, critical TRUE, OCTET STRING NULL } }
        let unknown_critical = [
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x01, 0x01, 0xff, 0x04, 0x02,
            0x05, 0x00,
        ];
        assert!(parse_extensions(&unknown_critical).is_err());
    }

    #[test]
    fn names_compare_canonically_and_constraints_cover_supported_name_forms() {
        fn name(tag: u8, value: &[u8]) -> std::vec::Vec<u8> {
            let mut attribute = std::vec![0x06, 0x03, 0x55, 0x04, 0x03, tag, value.len() as u8];
            attribute.extend_from_slice(value);
            let mut sequence = std::vec![0x30, attribute.len() as u8];
            sequence.extend_from_slice(&attribute);
            let mut set = std::vec![0x31, sequence.len() as u8];
            set.extend_from_slice(&sequence);
            let mut name = std::vec![0x30, set.len() as u8];
            name.extend_from_slice(&set);
            name
        }

        fn permitted_constraint(tag: u8, value: &[u8]) -> std::vec::Vec<u8> {
            let mut base = std::vec![tag, value.len() as u8];
            base.extend_from_slice(value);
            let mut subtree = std::vec![0x30, base.len() as u8];
            subtree.extend_from_slice(&base);
            let mut permitted = std::vec![0xa0, subtree.len() as u8];
            permitted.extend_from_slice(&subtree);
            let mut constraints = std::vec![0x30, permitted.len() as u8];
            constraints.extend_from_slice(&permitted);
            constraints
        }

        let printable = name(0x13, b" Example   CA ");
        let utf8 = name(0x0c, b"example ca");
        assert!(name_equal(&printable, &utf8));
        let composed = name(0x0c, " École CA ".as_bytes());
        let decomposed = name(0x0c, "e\u{301}cole   ca".as_bytes());
        assert!(name_equal(&composed, &decomposed));
        let teletex = name(
            0x14,
            &[0xc2, b'E', b'c', b'o', b'l', b'e', b' ', b'C', b'A'],
        );
        assert!(name_equal(&teletex, &composed));
        let greek = name(0x0c, "\u{345}".as_bytes());
        let folded_greek = name(0x1e, &[0x03, 0xb9]);
        assert!(name_equal(&greek, &folded_greek));
        let macron_composed = name(0x0c, "Ārbol CA".as_bytes());
        let macron_decomposed = name(0x0c, "a\u{304}rbol ca".as_bytes());
        assert!(name_equal(&macron_composed, &macron_decomposed));
        let bmp = name(
            0x1e,
            &[
                0, b'e', 0, b'x', 0, b'a', 0, b'm', 0, b'p', 0, b'l', 0, b'e', 0, b' ', 0, b'c', 0,
                b'a',
            ],
        );
        let universal = name(
            0x1c,
            &[
                0, 0, 0, b'e', 0, 0, 0, b'x', 0, 0, 0, b'a', 0, 0, 0, b'm', 0, 0, 0, b'p', 0, 0, 0,
                b'l', 0, 0, 0, b'e', 0, 0, 0, b' ', 0, 0, 0, b'c', 0, 0, 0, b'a',
            ],
        );
        assert!(name_equal(&utf8, &bmp));
        assert!(name_equal(&utf8, &universal));

        let dns = b"example.com";
        let mut subtree = std::vec![0x82, dns.len() as u8];
        subtree.extend_from_slice(dns);
        let mut subtree_sequence = std::vec![0x30, subtree.len() as u8];
        subtree_sequence.extend_from_slice(&subtree);
        let mut permitted = std::vec![0xa0, subtree_sequence.len() as u8];
        permitted.extend_from_slice(&subtree_sequence);
        let mut constraints = std::vec![0x30, permitted.len() as u8];
        constraints.extend_from_slice(&permitted);
        assert!(check_constrained_name(&constraints, 0x82, b"api.example.com").is_ok());
        assert!(check_constrained_name(&constraints, 0x82, b"example.net").is_err());
        assert!(dns_within_constraint(b"api.example.com", b".example.com"));
        assert!(!dns_within_constraint(b"example.com", b".example.com"));

        let email_constraints = permitted_constraint(0x81, b".example.com");
        assert!(validate_name_constraints_encoding(&email_constraints).is_ok());
        assert!(check_constrained_name(&email_constraints, 0x81, b"user@api.example.com").is_ok());
        assert!(check_constrained_name(&email_constraints, 0x81, b"user@example.com").is_err());
        assert!(check_constrained_name(&email_constraints, 0x82, b"example.net").is_ok());
        let mut email_attribute = std::vec![0x06, OID_EMAIL_ADDRESS.len() as u8];
        email_attribute.extend_from_slice(OID_EMAIL_ADDRESS);
        email_attribute.extend_from_slice(&[0x16, b"user@api.example.com".len() as u8]);
        email_attribute.extend_from_slice(b"user@api.example.com");
        let mut email_sequence = std::vec![0x30, email_attribute.len() as u8];
        email_sequence.extend_from_slice(&email_attribute);
        let mut email_set = std::vec![0x31, email_sequence.len() as u8];
        email_set.extend_from_slice(&email_sequence);
        let mut email_subject = std::vec![0x30, email_set.len() as u8];
        email_subject.extend_from_slice(&email_set);
        assert!(check_subject_email_constraints(&email_constraints, &email_subject).is_ok());
        let excluded_email = b".example.com";
        let mut email_name = std::vec![0x81, excluded_email.len() as u8];
        email_name.extend_from_slice(excluded_email);
        let mut subtree = std::vec![0x30, email_name.len() as u8];
        subtree.extend_from_slice(&email_name);
        let mut excluded = std::vec![0xa1, subtree.len() as u8];
        excluded.extend_from_slice(&subtree);
        let mut constraints = std::vec![0x30, excluded.len() as u8];
        constraints.extend_from_slice(&excluded);
        assert!(check_subject_email_constraints(&constraints, &email_subject).is_err());

        let uri_constraints = permitted_constraint(0x86, b"service.example.com");
        assert!(validate_name_constraints_encoding(&uri_constraints).is_ok());
        assert!(
            check_constrained_name(
                &uri_constraints,
                0x86,
                b"https://service.example.com:8443/status",
            )
            .is_ok()
        );
        assert!(check_constrained_name(&uri_constraints, 0x86, b"urn:example:service").is_err());

        let ip_constraint = [192, 0, 2, 0, 255, 255, 255, 0];
        assert!(ip_within_constraint(&[192, 0, 2, 9], &ip_constraint));
        assert!(!ip_within_constraint(&[198, 51, 100, 9], &ip_constraint));
        assert!(valid_ip_constraint(&[192, 0, 2, 9, 255, 255, 255, 0]));

        let base = name(0x13, b"example ca");
        assert!(name_within_subtree(&utf8, &base));

        let mut directory = std::vec![0xa4, base.len() as u8];
        directory.extend_from_slice(&base);
        let mut subtree = std::vec![0x30, directory.len() as u8];
        subtree.extend_from_slice(&directory);
        let mut permitted = std::vec![0xa0, subtree.len() as u8];
        permitted.extend_from_slice(&subtree);
        let mut constraints = std::vec![0x30, permitted.len() as u8];
        constraints.extend_from_slice(&permitted);
        let empty_subject = [0x30, 0x00];
        assert!(check_subject_directory_constraints(&constraints, &empty_subject).is_ok());
        assert!(check_constrained_name(&constraints, 0xa4, &utf8).is_ok());

        let excluded_dns = b"admin.example.com";
        let mut dns_name = std::vec![0x82, excluded_dns.len() as u8];
        dns_name.extend_from_slice(excluded_dns);
        let mut subtree = std::vec![0x30, dns_name.len() as u8];
        subtree.extend_from_slice(&dns_name);
        let mut excluded = std::vec![0xa1, subtree.len() as u8];
        excluded.extend_from_slice(&subtree);
        let mut constraints = std::vec![0x30, excluded.len() as u8];
        constraints.extend_from_slice(&excluded);
        assert!(check_constrained_name(&constraints, 0x82, b"*.example.com").is_err());

        let excluded_dns = b".foo.example.com";
        let mut dns_name = std::vec![0x82, excluded_dns.len() as u8];
        dns_name.extend_from_slice(excluded_dns);
        let mut subtree = std::vec![0x30, dns_name.len() as u8];
        subtree.extend_from_slice(&dns_name);
        let mut excluded = std::vec![0xa1, subtree.len() as u8];
        excluded.extend_from_slice(&subtree);
        let mut constraints = std::vec![0x30, excluded.len() as u8];
        constraints.extend_from_slice(&excluded);
        assert!(check_constrained_name(&constraints, 0x82, b"*.example.com").is_ok());
        assert!(check_constrained_name(&constraints, 0x82, b"*.foo.example.com").is_err());
    }

    #[test]
    fn ecdsa_hash_choice_is_independent_of_the_issuer_curve() {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;

        let message = b"certificate tbs";
        let p256 = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let digest = sha2::Sha384::digest(message);
        let signature: p256::ecdsa::Signature = p256.sign_prehash(&digest).unwrap();
        let point = p256.verifying_key().to_encoded_point(false);
        assert!(verify_ecdsa_p256(
            point.as_bytes(),
            message,
            signature.to_der().as_bytes(),
            SignatureAlgorithm::EcdsaSha384,
        ));

        let p384 = p384::ecdsa::SigningKey::from_bytes((&[9; 48]).into()).unwrap();
        let digest = sha2::Sha256::digest(message);
        let signature: p384::ecdsa::Signature = p384.sign_prehash(&digest).unwrap();
        let point = p384.verifying_key().to_encoded_point(false);
        assert!(verify_ecdsa_p384(
            point.as_bytes(),
            message,
            signature.to_der().as_bytes(),
            SignatureAlgorithm::EcdsaSha256,
        ));
    }

    #[test]
    fn failed_path_clears_the_leaf_and_pkcs1_certverify_is_rejected() {
        let certificates = rsa_chain();
        let mut workspace = super::super::RsaWorkspace::new();
        let mut verifier = super::super::TrustVerifier::<CaptureClock>::new(None, &mut workspace);
        verifier
            .set_hostname_verification("controlplane.tailscale.com")
            .unwrap();
        verifier
            .verify_certificate(&sha2::Sha256::new(), chain(&certificates))
            .unwrap();
        assert!(matches!(
            verifier.verify_signature(CertificateVerifyRef {
                signature_scheme: SignatureScheme::RsaPkcs1Sha256,
                signature: &[],
            }),
            Err(TlsError::InvalidSignatureScheme)
        ));

        verifier
            .verify_certificate(&sha2::Sha256::new(), chain(&certificates))
            .unwrap();
        assert!(
            verifier
                .verify_certificate(&sha2::Sha256::new(), chain(&certificates[1..]))
                .is_err()
        );
        assert!(matches!(
            verifier.verify_signature(CertificateVerifyRef {
                signature_scheme: SignatureScheme::RsaPssRsaeSha256,
                signature: &[0; 256],
            }),
            Err(TlsError::InvalidCertificate)
        ));
    }

    fn chain<'a>(certificates: &'a [std::vec::Vec<u8>]) -> CertificateRef<'a> {
        let mut chain = CertificateRef::with_context(&[]);
        for certificate in certificates {
            chain.add(CertificateEntryRef::X509(certificate)).unwrap();
        }
        chain
    }

    fn rsa_chain() -> std::vec::Vec<std::vec::Vec<u8>> {
        let pem = include_str!("../../../../../tests/vectors/hosted-rsa-chain.pem");
        pem.split("-----BEGIN CERTIFICATE-----")
            .skip(1)
            .map(|block| {
                let encoded = block
                    .split("-----END CERTIFICATE-----")
                    .next()
                    .unwrap()
                    .lines()
                    .map(str::trim)
                    .collect::<std::string::String>();
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap()
            })
            .collect()
    }
}
