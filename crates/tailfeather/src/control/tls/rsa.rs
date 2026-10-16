//! Fixed-size, allocation-free RSA verification.

use crypto_bigint::Limb;
#[cfg(test)]
use crypto_bigint::modular::montgomery_reduction;
#[cfg(test)]
use crypto_bigint::{Encoding, U2048, U4096, Uint, Word};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq as _;
#[cfg(test)]
use subtle::ConstantTimeLess as _;

use super::{Tlv, next_tlv};

pub(super) const RSA_2048_BYTES: usize = 256;
pub(super) const RSA_3072_BYTES: usize = 384;
pub(super) const RSA_4096_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub(super) const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RsaPublicKey<'a> {
    pub(super) modulus: &'a [u8],
}

/// Fixed scratch for RSA public operations. It bounds every 2048/4096-bit
/// operation to three small arrays instead of crypto-bigint's nested wide
/// multiplication frames.
pub struct RsaWorkspace {
    base: [u32; 128],
    result: [u32; 128],
    accumulator: [u32; 130],
}

impl RsaWorkspace {
    pub const fn new() -> Self {
        Self {
            base: [0; 128],
            result: [0; 128],
            accumulator: [0; 130],
        }
    }
}

impl Default for RsaWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Root YR's 4096-bit modulus. Its Montgomery parameters are evaluated at
/// compile time below, so the only 4096-bit trust operation needed in normal
/// hosted use does not build them on the device stack.
#[cfg(test)]
const ROOT_YR_MODULUS_HEX: &str = concat!(
    "dbc626737bf024c97562f7f9e19fb0b3794eb34126cf951fd8515ea45bc31bbd",
    "b06362074043d5f70ec5b494402248335c44d770dbfb90b0d70d2cd04058b2fb",
    "883ffea3a05d30f1cb8899b811d4e1a061b490e0ea7323e0c6f121ae4e5704f3",
    "bdce092fa4877b2b968eaf978dcce4e260e007a8d6c7c7a7a913243a0888504d",
    "24063e38a7d7fc552f60aba18d3fa7a38f659aa9aea52048e4f901422aab106b",
    "56539bb153f7105871aef234a3141ce766abdb34f2cc5cc2c5c426f75937eb24",
    "15d78eabd61bebf86e3cf18e3780b4e954eea6ab443bcd3b202e4182e59fdd38",
    "33e7da2b1f219cb0a9275e59a9a12070d958fbd30c59c0b9caf2f60368f797df",
    "b66ee820657f9d384f75cd898875ac13bd266e56f95b46b0252f1201ea9c0c06",
    "39de5c28d843cfb70420a3b2c6d2369654de14dc0437617c09440e562bea911a",
    "b6731d9834f906a9ca0bdd9b7741213357db2c78a82dc70b0ae89ebd3f1990f8",
    "59aeaecc8a2ee035701c504011f3e97361a97ef734e0ec2e4300bc9539e1bf0a",
    "a7d100c9f52921c247435203a3fcb67fe619196709cb79aed5422e7572495a54",
    "e87d6a1a0dc38133aeb247fc79a85332261b2397b33c998ee5eaed6a5b24435b",
    "ada7be3e783cbdd8f2387ed1ca4dbabd216847e1864a8775a724422dfa842f95",
    "865b63cb6912ba0aac507a3c51b3ac9203472b6ce07aafb87e764458f6ceffc1",
);
#[cfg(test)]
const ROOT_YR_MODULUS: U4096 = U4096::from_be_hex(ROOT_YR_MODULUS_HEX);
#[cfg(test)]
const ROOT_YR_R2_HEX: &str = concat!(
    "735700d0c0c9df9fbdf60000a731f3d09b177a515f8e871ab585d8b0db6bd037",
    "379de61e2eccee3c6bbfa5af6f61cab08e73ab98ddb64dc51beeefcde6eff745",
    "0df0fe52e81645b29e762394bb7b1fb27898aa5e8e23fffb785e49fc3ead1329",
    "dfde54babc1b95f8329542a038b5a179efde67c0cdabca04032a6ad2504815f3",
    "6883adb8205c7fa4d2a1f0917651223387d2fbb87230c425095a877b06b7b815",
    "5a174b7f08ed51bebd390cf5e8021e0709fc3fbe7743d730322965f9a02bc381",
    "843a2ba83d76491ca47f82610b6c015c0924c5441e41876d873bc898bbf6d921",
    "f19c16b6bd80c9778fb153073ed86d7627e5b1a2e9427ab39d93239755b9d47",
    "e1706379d5968069bb92c043009d31dde96d896654f70f7ab1ebfdc403f1b590",
    "7476f703ffc755bc683236526b2cecf7cbe3b55a7cfb8f27432043df82ccd83f",
    "0739419a4d21ecc57f840dca25c41df5547b4ea405a4d958816e76b10f852b6",
    "cbfb0eca30930527e1e08570916a7d55f47e1238c00bbad541b636b57ac5224",
    "249467cf01b8de45148b092ae97554c7a15735d0b3d150b1aca95ff15fbfb949",
    "5b2e98c76c64bfeb81ce549a63fc1a70657d459ae69c9972323b8aeec66bbe0",
    "c31f6350a56eed9d4c853bdbc06153091845beff3d1ee52e88c183dca49baf20",
    "b36f278a5a73075144bf8088459823ac10d7a8e308fffac52f40cb980faa8d780697",
);
#[cfg(test)]
const ROOT_YR_R2: U4096 = U4096::from_be_hex(ROOT_YR_R2_HEX);
include!("root_yr_params.rs");
#[cfg(target_pointer_width = "64")]
const ROOT_YR_NEG_INV: Limb = Limb(0x0333_aed9_ed4a_efbf);
#[cfg(target_pointer_width = "32")]
const ROOT_YR_NEG_INV: Limb = Limb(0xed4a_efbf);

pub(super) fn parse_public_key(der: &[u8]) -> Result<RsaPublicKey<'_>, ()> {
    let mut outer_offset = 0;
    let outer = next_tlv(der, &mut outer_offset).map_err(|_| ())?;
    if outer.tag != 0x30 || outer_offset != der.len() {
        return Err(());
    }

    let mut offset = 0;
    let modulus = next_tlv(outer.value, &mut offset).map_err(|_| ())?;
    let exponent = next_tlv(outer.value, &mut offset).map_err(|_| ())?;
    if offset != outer.value.len() || exponent.tag != 0x02 || exponent.value != [1, 0, 1] {
        return Err(());
    }

    let modulus = positive_integer(modulus)?;
    if !matches!(
        modulus.len(),
        RSA_2048_BYTES | RSA_3072_BYTES | RSA_4096_BYTES
    ) || modulus[0] & 0x80 == 0
        || modulus[modulus.len() - 1] & 1 == 0
    {
        return Err(());
    }
    Ok(RsaPublicKey { modulus })
}

fn positive_integer(integer: Tlv<'_>) -> Result<&[u8], ()> {
    if integer.tag != 0x02 || integer.value.is_empty() {
        return Err(());
    }
    match integer.value {
        [0, next, rest @ ..] if *next & 0x80 != 0 => {
            let start = integer.value.len() - rest.len() - 1;
            Ok(&integer.value[start..])
        }
        [first, ..] if first & 0x80 == 0 => Ok(integer.value),
        _ => Err(()),
    }
}

#[cfg(test)]
pub(super) fn verify_pss(
    key: RsaPublicKey<'_>,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let mut workspace = RsaWorkspace::new();
    verify_pss_with_workspace(key, hash, message, signature, &mut workspace)
}

pub(super) fn verify_pss_with_workspace(
    key: RsaPublicKey<'_>,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
    workspace: &mut RsaWorkspace,
) -> bool {
    let Some(limbs) = recover_generic(key, signature, workspace) else {
        return false;
    };
    verify_pss_words(hash, message, &mut workspace.result[..limbs])
}

#[cfg(test)]
pub(super) fn verify_pkcs1(
    key: RsaPublicKey<'_>,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let mut workspace = RsaWorkspace::new();
    verify_pkcs1_with_workspace(key, hash, message, signature, &mut workspace)
}

pub(super) fn verify_pkcs1_with_workspace(
    key: RsaPublicKey<'_>,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
    workspace: &mut RsaWorkspace,
) -> bool {
    // Root YR is the only 4096-bit trust operation in the hosted chain.  Its
    // fixed parameters allow a CIOS Montgomery loop that keeps just one
    // 130-limb accumulator, avoiding crypto-bigint's nested wide-product
    // frames in the ESP32-C6 TLS task.
    if root_modulus_matches(key.modulus) {
        return verify_root_yr_pkcs1(hash, message, signature, workspace);
    }
    verify_pkcs1_generic(key, hash, message, signature, workspace)
}

#[inline(never)]
fn verify_pkcs1_generic(
    key: RsaPublicKey<'_>,
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
    workspace: &mut RsaWorkspace,
) -> bool {
    let Some(limbs) = recover_generic(key, signature, workspace) else {
        return false;
    };
    verify_pkcs1_words(hash, message, &workspace.result[..limbs])
}

#[inline(never)]
fn verify_root_yr_pkcs1(
    hash: HashAlgorithm,
    message: &[u8],
    signature: &[u8],
    workspace: &mut RsaWorkspace,
) -> bool {
    root_yr_exponent(signature, workspace)
        && verify_pkcs1_root_words(hash, message, &workspace.result)
}

#[inline(never)]
fn root_yr_exponent(signature: &[u8], workspace: &mut RsaWorkspace) -> bool {
    if signature.len() != RSA_4096_BYTES {
        return false;
    }
    words_from_be(&mut workspace.base, signature);
    if !root_words_less_than_modulus(&workspace.base) {
        return false;
    }
    let RsaWorkspace {
        base,
        result,
        accumulator,
        ..
    } = workspace;
    root_montgomery_product_assign(base, RootOperand::Words(&ROOT_YR_R2_LIMBS), accumulator);
    *result = *base;
    for _ in 0..16 {
        root_montgomery_square_assign(result, accumulator);
    }
    root_montgomery_product_assign(result, RootOperand::Words(base), accumulator);
    root_montgomery_product_assign(result, RootOperand::One, accumulator);
    true
}

#[derive(Clone, Copy)]
enum RootOperand<'a> {
    Words(&'a [u32; 128]),
    One,
}

#[inline(never)]
fn root_montgomery_product_assign(
    value: &mut [u32; 128],
    rhs: RootOperand<'_>,
    accumulator: &mut [u32; 130],
) {
    accumulator.fill(0);
    for index in 0..128 {
        let rhs_limb = match rhs {
            RootOperand::Words(words) => words[index],
            RootOperand::One => u32::from(index == 0),
        };
        root_mac(accumulator, value, rhs_limb);
        let factor = accumulator[0].wrapping_mul(ROOT_YR_NEG_INV.0 as u32);
        root_mac_modulus(accumulator, factor);
        accumulator.copy_within(1..130, 0);
        accumulator[129] = 0;
    }

    value.copy_from_slice(&accumulator[..128]);
    if accumulator[128] != 0 || !root_words_less_than_modulus(value) {
        root_subtract_modulus(value);
    }
}

#[inline(never)]
fn root_montgomery_square_assign(value: &mut [u32; 128], accumulator: &mut [u32; 130]) {
    accumulator.fill(0);
    for index in 0..128 {
        root_mac(accumulator, value, value[index]);
        let factor = accumulator[0].wrapping_mul(ROOT_YR_NEG_INV.0 as u32);
        root_mac_modulus(accumulator, factor);
        accumulator.copy_within(1..130, 0);
        accumulator[129] = 0;
    }

    value.copy_from_slice(&accumulator[..128]);
    if accumulator[128] != 0 || !root_words_less_than_modulus(value) {
        root_subtract_modulus(value);
    }
}

#[inline(always)]
fn root_mac(accumulator: &mut [u32; 130], lhs: &[u32; 128], rhs: u32) {
    let mut carry = 0u64;
    for index in 0..128 {
        let value = accumulator[index] as u64 + lhs[index] as u64 * rhs as u64 + carry;
        accumulator[index] = value as u32;
        carry = value >> 32;
    }
    let value = accumulator[128] as u64 + carry;
    accumulator[128] = value as u32;
    accumulator[129] = accumulator[129].wrapping_add((value >> 32) as u32);
}

#[inline(always)]
fn root_mac_modulus(accumulator: &mut [u32; 130], factor: u32) {
    let mut carry = 0u64;
    for index in 0..128 {
        let value =
            accumulator[index] as u64 + ROOT_YR_MODULUS_LIMBS[index] as u64 * factor as u64 + carry;
        accumulator[index] = value as u32;
        carry = value >> 32;
    }
    let value = accumulator[128] as u64 + carry;
    accumulator[128] = value as u32;
    accumulator[129] = accumulator[129].wrapping_add((value >> 32) as u32);
}

#[inline(always)]
fn root_modulus_matches(modulus: &[u8]) -> bool {
    modulus.len() == RSA_4096_BYTES
        && modulus
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == root_word_byte(&ROOT_YR_MODULUS_LIMBS, index))
}

#[inline(always)]
fn root_words_less_than_modulus(words: &[u32; 128]) -> bool {
    for index in (0..128).rev() {
        let modulus = ROOT_YR_MODULUS_LIMBS[index];
        if words[index] != modulus {
            return words[index] < modulus;
        }
    }
    false
}

#[inline(always)]
fn root_subtract_modulus(words: &mut [u32; 128]) {
    let mut borrow = 0u64;
    for index in 0..128 {
        let subtrahend = ROOT_YR_MODULUS_LIMBS[index] as u64 + borrow;
        let value = words[index] as u64;
        words[index] = value.wrapping_sub(subtrahend) as u32;
        borrow = u64::from(value < subtrahend);
    }
}

fn verify_pkcs1_root_words(hash: HashAlgorithm, message: &[u8], words: &[u32; 128]) -> bool {
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_PREFIX: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_PREFIX: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    let prefix = match hash {
        HashAlgorithm::Sha256 => SHA256_PREFIX,
        HashAlgorithm::Sha384 => SHA384_PREFIX,
        HashAlgorithm::Sha512 => SHA512_PREFIX,
    };
    let hash_len = hash.output_len();
    let separator = RSA_4096_BYTES - prefix.len() - hash_len - 1;
    if root_word_byte(words, 0) != 0 || root_word_byte(words, 1) != 1 || separator < 10 {
        return false;
    }
    if root_word_byte(words, separator) != 0
        || (2..separator).any(|index| root_word_byte(words, index) != 0xff)
        || prefix
            .iter()
            .enumerate()
            .any(|(index, byte)| root_word_byte(words, separator + 1 + index) != *byte)
    {
        return false;
    }

    let mut expected = [0u8; 64];
    digest(hash, &[message], &mut expected);
    let mut actual = [0u8; 64];
    for (index, byte) in actual[..hash_len].iter_mut().enumerate() {
        *byte = root_word_byte(words, separator + 1 + prefix.len() + index);
    }
    bool::from(expected[..hash_len].ct_eq(&actual[..hash_len]))
}

#[inline(always)]
fn root_word_byte(words: &[u32; 128], index: usize) -> u8 {
    let word = words[127 - index / 4];
    (word >> ((3 - index % 4) * 8)) as u8
}

/// Recover an encoded message with a dynamic RSA modulus without placing any
/// modulus-sized values on the caller's stack. The public exponent is fixed at
/// 65537 by `parse_public_key`.
#[inline(never)]
fn recover_generic(
    key: RsaPublicKey<'_>,
    signature: &[u8],
    workspace: &mut RsaWorkspace,
) -> Option<usize> {
    let byte_len = key.modulus.len();
    if !matches!(byte_len, RSA_2048_BYTES | RSA_3072_BYTES | RSA_4096_BYTES)
        || signature.len() != byte_len
    {
        return None;
    }
    let limbs = byte_len / 4;
    let RsaWorkspace {
        base,
        result,
        accumulator,
    } = workspace;
    let base = &mut base[..limbs];
    let result = &mut result[..limbs];
    let accumulator = &mut accumulator[..limbs + 2];

    words_from_be(base, signature);
    if !words_less_than_modulus(base, key.modulus) {
        return None;
    }

    // Since every accepted modulus has its top bit set, R mod n is exactly
    // 2^bits - n. Doubling that value `bits` times produces R² mod n without
    // crypto-bigint's wide remainder frame.
    let mut carry = 1u32;
    for (index, word) in result.iter_mut().enumerate() {
        let sum = (!modulus_word(key.modulus, index) as u64) + carry as u64;
        *word = sum as u32;
        carry = (sum >> 32) as u32;
    }
    for _ in 0..limbs * 32 {
        double_mod_assign(result, key.modulus);
    }

    let neg_inv = modulus_neg_inv_word(modulus_word(key.modulus, 0));
    montgomery_words_assign(
        base,
        WordsOperand::Words(result),
        key.modulus,
        neg_inv,
        accumulator,
    );
    result.copy_from_slice(base);
    for _ in 0..16 {
        montgomery_words_assign(
            result,
            WordsOperand::Square,
            key.modulus,
            neg_inv,
            accumulator,
        );
    }
    montgomery_words_assign(
        result,
        WordsOperand::Words(base),
        key.modulus,
        neg_inv,
        accumulator,
    );
    montgomery_words_assign(result, WordsOperand::One, key.modulus, neg_inv, accumulator);
    Some(limbs)
}

#[derive(Clone, Copy)]
enum WordsOperand<'a> {
    Words(&'a [u32]),
    Square,
    One,
}

#[inline(never)]
fn montgomery_words_assign(
    value: &mut [u32],
    rhs: WordsOperand<'_>,
    modulus: &[u8],
    neg_inv: u32,
    accumulator: &mut [u32],
) {
    let limbs = value.len();
    debug_assert_eq!(modulus.len(), limbs * 4);
    debug_assert_eq!(accumulator.len(), limbs + 2);
    accumulator.fill(0);
    for index in 0..limbs {
        let rhs_limb = match rhs {
            WordsOperand::Words(words) => words[index],
            WordsOperand::Square => value[index],
            WordsOperand::One => u32::from(index == 0),
        };
        words_mac(accumulator, value, rhs_limb);
        let factor = accumulator[0].wrapping_mul(neg_inv);
        words_mac_modulus(accumulator, modulus, factor);
        accumulator.copy_within(1..limbs + 2, 0);
        accumulator[limbs + 1] = 0;
    }

    value.copy_from_slice(&accumulator[..limbs]);
    if accumulator[limbs] != 0 || !words_less_than_modulus(value, modulus) {
        subtract_modulus(value, modulus);
    }
}

#[inline(always)]
fn words_mac(accumulator: &mut [u32], lhs: &[u32], rhs: u32) {
    let mut carry = 0u64;
    for index in 0..lhs.len() {
        let value = accumulator[index] as u64 + lhs[index] as u64 * rhs as u64 + carry;
        accumulator[index] = value as u32;
        carry = value >> 32;
    }
    let index = lhs.len();
    let value = accumulator[index] as u64 + carry;
    accumulator[index] = value as u32;
    accumulator[index + 1] = accumulator[index + 1].wrapping_add((value >> 32) as u32);
}

#[inline(always)]
fn words_mac_modulus(accumulator: &mut [u32], modulus: &[u8], rhs: u32) {
    let mut carry = 0u64;
    let limbs = modulus.len() / 4;
    for (index, word) in accumulator.iter_mut().take(limbs).enumerate() {
        let value = *word as u64 + modulus_word(modulus, index) as u64 * rhs as u64 + carry;
        *word = value as u32;
        carry = value >> 32;
    }
    let index = limbs;
    let value = accumulator[index] as u64 + carry;
    accumulator[index] = value as u32;
    accumulator[index + 1] = accumulator[index + 1].wrapping_add((value >> 32) as u32);
}

#[inline(always)]
fn double_mod_assign(value: &mut [u32], modulus: &[u8]) {
    let mut carry = 0u64;
    for word in value.iter_mut() {
        let doubled = (*word as u64) * 2 + carry;
        *word = doubled as u32;
        carry = doubled >> 32;
    }
    if carry != 0 || !words_less_than_modulus(value, modulus) {
        subtract_modulus(value, modulus);
    }
}

#[inline(always)]
fn subtract_modulus(value: &mut [u32], modulus: &[u8]) {
    let mut borrow = 0u64;
    for (index, word) in value.iter_mut().enumerate() {
        let subtrahend = modulus_word(modulus, index) as u64 + borrow;
        let current = *word as u64;
        *word = current.wrapping_sub(subtrahend) as u32;
        borrow = u64::from(current < subtrahend);
    }
}

#[inline(always)]
fn words_less_than_modulus(left: &[u32], modulus: &[u8]) -> bool {
    (0..left.len())
        .rev()
        .find_map(|index| {
            let right = modulus_word(modulus, index);
            (left[index] != right).then_some(left[index] < right)
        })
        .unwrap_or(false)
}

#[inline(always)]
fn modulus_word(modulus: &[u8], index: usize) -> u32 {
    let offset = modulus.len() - (index + 1) * 4;
    u32::from_be_bytes(modulus[offset..offset + 4].try_into().expect("fixed limb"))
}

#[inline(always)]
fn words_from_be(output: &mut [u32], bytes: &[u8]) {
    for (index, word) in output.iter_mut().enumerate() {
        let offset = bytes.len() - (index + 1) * 4;
        *word = u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed limb"));
    }
}

#[inline(always)]
fn words_be_byte(words: &[u32], index: usize) -> u8 {
    let word = words[words.len() - 1 - index / 4];
    (word >> ((3 - index % 4) * 8)) as u8
}

fn modulus_neg_inv_word(low: u32) -> u32 {
    let mut inverse = 1u32;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(low.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

fn verify_pss_words(hash: HashAlgorithm, message: &[u8], em: &mut [u32]) -> bool {
    let hash_len = hash.output_len();
    let em_len = em.len() * 4;
    if em_len < hash_len * 2 + 2 || words_be_byte(em, em_len - 1) != 0xbc {
        return false;
    }

    let db_len = em_len - hash_len - 1;
    if words_be_byte(em, 0) & 0x80 != 0 {
        return false;
    }
    let mut encoded_hash = [0u8; 64];
    for (index, byte) in encoded_hash[..hash_len].iter_mut().enumerate() {
        *byte = words_be_byte(em, db_len + index);
    }
    mgf1_xor_words(hash, &encoded_hash[..hash_len], em, db_len);
    let first = words_be_byte(em, 0) & 0x7f;
    set_words_be_byte(em, 0, first);

    let delimiter = db_len - hash_len - 1;
    if (0..delimiter).any(|index| words_be_byte(em, index) != 0)
        || words_be_byte(em, delimiter) != 1
    {
        return false;
    }

    let mut message_hash = [0u8; 64];
    digest(hash, &[message], &mut message_hash);
    let mut salt = [0u8; 64];
    for (index, byte) in salt[..hash_len].iter_mut().enumerate() {
        *byte = words_be_byte(em, delimiter + 1 + index);
    }
    let mut candidate = [0u8; 64];
    digest(
        hash,
        &[&[0u8; 8], &message_hash[..hash_len], &salt[..hash_len]],
        &mut candidate,
    );
    bool::from(candidate[..hash_len].ct_eq(&encoded_hash[..hash_len]))
}

fn verify_pkcs1_words(hash: HashAlgorithm, message: &[u8], em: &[u32]) -> bool {
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_PREFIX: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_PREFIX: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    let prefix = match hash {
        HashAlgorithm::Sha256 => SHA256_PREFIX,
        HashAlgorithm::Sha384 => SHA384_PREFIX,
        HashAlgorithm::Sha512 => SHA512_PREFIX,
    };
    let hash_len = hash.output_len();
    let em_len = em.len() * 4;
    let digest_info_len = prefix.len() + hash_len;
    if em_len < digest_info_len + 11 || words_be_byte(em, 0) != 0 || words_be_byte(em, 1) != 1 {
        return false;
    }
    let separator = em_len - digest_info_len - 1;
    if separator < 10
        || (2..separator).any(|index| words_be_byte(em, index) != 0xff)
        || words_be_byte(em, separator) != 0
        || prefix
            .iter()
            .enumerate()
            .any(|(index, byte)| words_be_byte(em, separator + 1 + index) != *byte)
    {
        return false;
    }

    let mut expected = [0u8; 64];
    digest(hash, &[message], &mut expected);
    expected[..hash_len]
        .iter()
        .enumerate()
        .all(|(index, byte)| words_be_byte(em, separator + 1 + prefix.len() + index) == *byte)
}

fn mgf1_xor_words(hash: HashAlgorithm, seed: &[u8], output: &mut [u32], output_len: usize) {
    let hash_len = hash.output_len();
    let mut offset = 0;
    for counter in 0..output_len.div_ceil(hash_len) {
        let counter_bytes = u32::try_from(counter)
            .expect("MGF1 output cannot contain 2^32 digest blocks")
            .to_be_bytes();
        let mut mask = [0u8; 64];
        digest(hash, &[seed, &counter_bytes], &mut mask);
        let block_len = core::cmp::min(hash_len, output_len - offset);
        for (index, mask_byte) in mask[..block_len].iter().enumerate() {
            let current = words_be_byte(output, offset + index);
            set_words_be_byte(output, offset + index, current ^ mask_byte);
        }
        offset += block_len;
    }
}

#[inline(always)]
fn set_words_be_byte(words: &mut [u32], index: usize, byte: u8) {
    let word = &mut words[words.len() - 1 - index / 4];
    let shift = (3 - index % 4) * 8;
    *word = (*word & !(0xff << shift)) | (u32::from(byte) << shift);
}

#[cfg(test)]
#[inline(never)]
fn recover_2048(key: RsaPublicKey<'_>, signature: &[u8]) -> Option<[u8; RSA_2048_BYTES]> {
    if signature.len() != RSA_2048_BYTES || key.modulus.len() != RSA_2048_BYTES {
        return None;
    }
    let modulus = U2048::from_be_slice(key.modulus);
    let signature = U2048::from_be_slice(signature);
    if !bool::from(signature.ct_lt(&modulus)) {
        return None;
    }
    let r2 = montgomery_r2(&modulus);
    Some(rsa_exponent_65537(&signature, &modulus, &r2, modulus_neg_inv(&modulus)).to_be_bytes())
}

#[cfg(test)]
#[inline(never)]
fn recover_4096(key: RsaPublicKey<'_>, signature: &[u8]) -> Option<[u8; RSA_4096_BYTES]> {
    if signature.len() != RSA_4096_BYTES || key.modulus.len() != RSA_4096_BYTES {
        return None;
    }
    let modulus = U4096::from_be_slice(key.modulus);
    let signature = U4096::from_be_slice(signature);
    if !bool::from(signature.ct_lt(&modulus)) {
        return None;
    }
    if bool::from(modulus.ct_eq(&ROOT_YR_MODULUS)) {
        // Keep the trust-anchor operation in a separate frame.  A 4096-bit
        // Montgomery product is itself sizeable on 32-bit targets, and this
        // avoids keeping a dynamic modulus and R² beside its temporaries.
        return Some(recover_root_yr_4096(&signature).to_be_bytes());
    }

    let r2 = montgomery_r2(&modulus);
    Some(rsa_exponent_65537(&signature, &modulus, &r2, modulus_neg_inv(&modulus)).to_be_bytes())
}

#[cfg(test)]
#[inline(never)]
fn recover_root_yr_4096(signature: &U4096) -> U4096 {
    rsa_exponent_65537(signature, &ROOT_YR_MODULUS, &ROOT_YR_R2, ROOT_YR_NEG_INV)
}

#[cfg(test)]
fn rsa_exponent_65537<const LIMBS: usize>(
    signature: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    r2: &Uint<LIMBS>,
    neg_inv: Limb,
) -> Uint<LIMBS> {
    let mut base = Uint::ZERO;
    montgomery_product(&mut base, signature, r2, modulus, neg_inv);
    let mut result = base;
    for _ in 0..16 {
        montgomery_square_assign(&mut result, modulus, neg_inv);
    }
    montgomery_product_assign(&mut result, &base, modulus, neg_inv);
    montgomery_from_domain(&result, modulus, neg_inv)
}

// These helpers deliberately form call boundaries on the ESP32-C6.  Inlining
// a sequence of 4096-bit wide products retains several 1 KiB intermediates in
// the TLS task frame and can exhaust its otherwise fixed stack.
#[cfg(test)]
#[inline(never)]
fn montgomery_product<const LIMBS: usize>(
    output: &mut Uint<LIMBS>,
    lhs: &Uint<LIMBS>,
    rhs: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    neg_inv: Limb,
) {
    *output = montgomery_reduction(&lhs.mul_wide(rhs), modulus, neg_inv);
}

#[cfg(test)]
#[inline(never)]
fn montgomery_square_assign<const LIMBS: usize>(
    value: &mut Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    neg_inv: Limb,
) {
    let input = *value;
    *value = montgomery_reduction(&input.square_wide(), modulus, neg_inv);
}

#[cfg(test)]
#[inline(never)]
fn montgomery_product_assign<const LIMBS: usize>(
    value: &mut Uint<LIMBS>,
    rhs: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    neg_inv: Limb,
) {
    let lhs = *value;
    *value = montgomery_reduction(&lhs.mul_wide(rhs), modulus, neg_inv);
}

#[cfg(test)]
#[inline(never)]
fn montgomery_from_domain<const LIMBS: usize>(
    value: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
    neg_inv: Limb,
) -> Uint<LIMBS> {
    montgomery_reduction(&(*value, Uint::ZERO), modulus, neg_inv)
}

#[cfg(test)]
fn montgomery_r2<const LIMBS: usize>(modulus: &Uint<LIMBS>) -> Uint<LIMBS> {
    let r = Uint::MAX.const_rem(modulus).0.wrapping_add(&Uint::ONE);
    Uint::const_rem_wide(r.square_wide(), modulus).0
}

#[cfg(test)]
fn modulus_neg_inv<const LIMBS: usize>(modulus: &Uint<LIMBS>) -> Limb {
    let words: &[Word; LIMBS] = modulus.as_ref();
    let low = words[0];
    let mut inverse: Word = 1;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul((2 as Word).wrapping_sub(low.wrapping_mul(inverse)));
    }
    Limb(inverse.wrapping_neg())
}

#[cfg(test)]
fn verify_pss_encoding(hash: HashAlgorithm, message: &[u8], em: &mut [u8]) -> bool {
    let hash_len = hash.output_len();
    if em.len() < hash_len * 2 + 2 || em[em.len() - 1] != 0xbc {
        return false;
    }

    let db_len = em.len() - hash_len - 1;
    if em[0] & 0x80 != 0 {
        return false;
    }
    let mut encoded_hash = [0u8; 64];
    encoded_hash[..hash_len].copy_from_slice(&em[db_len..db_len + hash_len]);
    mgf1_xor(hash, &encoded_hash[..hash_len], &mut em[..db_len]);
    em[0] &= 0x7f;

    let delimiter = db_len - hash_len - 1;
    if em[..delimiter].iter().any(|byte| *byte != 0) || em[delimiter] != 1 {
        return false;
    }

    let mut message_hash = [0u8; 64];
    digest(hash, &[message], &mut message_hash);
    let mut candidate = [0u8; 64];
    digest(
        hash,
        &[
            &[0u8; 8],
            &message_hash[..hash_len],
            &em[delimiter + 1..db_len],
        ],
        &mut candidate,
    );
    bool::from(candidate[..hash_len].ct_eq(&encoded_hash[..hash_len]))
}

#[cfg(test)]
fn verify_pkcs1_encoding(hash: HashAlgorithm, message: &[u8], em: &[u8]) -> bool {
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_PREFIX: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_PREFIX: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    let prefix = match hash {
        HashAlgorithm::Sha256 => SHA256_PREFIX,
        HashAlgorithm::Sha384 => SHA384_PREFIX,
        HashAlgorithm::Sha512 => SHA512_PREFIX,
    };
    let hash_len = hash.output_len();
    let digest_info_len = prefix.len() + hash_len;
    if em.len() < digest_info_len + 11 || em[..2] != [0, 1] {
        return false;
    }
    let separator = em.len() - digest_info_len - 1;
    if separator < 10
        || em[2..separator].iter().any(|byte| *byte != 0xff)
        || em[separator] != 0
        || em[separator + 1..separator + 1 + prefix.len()] != *prefix
    {
        return false;
    }

    let mut expected = [0u8; 64];
    digest(hash, &[message], &mut expected);
    bool::from(em[separator + 1 + prefix.len()..].ct_eq(&expected[..hash_len]))
}

#[cfg(test)]
fn mgf1_xor(hash: HashAlgorithm, seed: &[u8], output: &mut [u8]) {
    let hash_len = hash.output_len();
    for (counter, block) in output.chunks_mut(hash_len).enumerate() {
        let counter_bytes = u32::try_from(counter)
            .expect("MGF1 output cannot contain 2^32 digest blocks")
            .to_be_bytes();
        let mut mask = [0u8; 64];
        digest(hash, &[seed, &counter_bytes], &mut mask);
        for (byte, mask_byte) in block.iter_mut().zip(mask.iter()) {
            *byte ^= mask_byte;
        }
    }
}

fn digest(hash: HashAlgorithm, parts: &[&[u8]], output: &mut [u8; 64]) {
    match hash {
        HashAlgorithm::Sha256 => {
            let mut digest = Sha256::new();
            parts.iter().for_each(|part| digest.update(part));
            output[..32].copy_from_slice(&digest.finalize());
        }
        HashAlgorithm::Sha384 => {
            let mut digest = Sha384::new();
            parts.iter().for_each(|part| digest.update(part));
            output[..48].copy_from_slice(&digest.finalize());
        }
        HashAlgorithm::Sha512 => {
            let mut digest = Sha512::new();
            parts.iter().for_each(|part| digest.update(part));
            output.copy_from_slice(&digest.finalize());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use rand_chacha::ChaCha20Rng;
    use rsa::pkcs8::EncodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;
    use rsa::{RsaPrivateKey, RsaPublicKey as RustCryptoPublicKey};
    use signature::{RandomizedSigner as _, SignatureEncoding as _, Verifier as _};
    use std::format;

    #[test]
    fn root_yr_montgomery_identity_round_trips() {
        assert!(root_modulus_matches(&ROOT_YR_MODULUS.to_be_bytes()));
        let mut base = [0u32; 128];
        let mut accumulator = [0u32; 130];
        base[0] = 1;
        root_montgomery_product_assign(
            &mut base,
            RootOperand::Words(&ROOT_YR_R2_LIMBS),
            &mut accumulator,
        );
        let mut result = base;
        for _ in 0..16 {
            root_montgomery_square_assign(&mut result, &mut accumulator);
        }
        root_montgomery_product_assign(&mut result, RootOperand::Words(&base), &mut accumulator);
        root_montgomery_product_assign(&mut result, RootOperand::One, &mut accumulator);
        assert_eq!(result[0], 1);
        assert!(result[1..].iter().all(|word| *word == 0));
    }

    #[test]
    fn root_yr_montgomery_matches_crypto_bigint_on_captured_issuer_signature() {
        let pem = include_str!("../../../../../tests/vectors/hosted-rsa-chain.pem");
        let certificate = pem
            .split("-----BEGIN CERTIFICATE-----")
            .nth(2)
            .unwrap()
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap()
            .lines()
            .map(str::trim)
            .collect::<std::string::String>();
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(certificate)
            .unwrap();
        let mut offset = 0;
        let outer = next_tlv(&certificate, &mut offset).unwrap();
        let mut certificate_offset = 0;
        let tbs = next_tlv(outer.value, &mut certificate_offset).unwrap();
        let _algorithm = next_tlv(outer.value, &mut certificate_offset).unwrap();
        let signature = next_tlv(outer.value, &mut certificate_offset).unwrap();
        let signature = &signature.value[1..];

        let modulus = ROOT_YR_MODULUS.to_be_bytes();
        let expected = recover_4096(RsaPublicKey { modulus: &modulus }, signature).unwrap();
        let mut workspace = RsaWorkspace::new();
        assert!(root_yr_exponent(signature, &mut workspace));
        let words = workspace.result;
        let mut actual = [0u8; RSA_4096_BYTES];
        for (index, byte) in actual.iter_mut().enumerate() {
            *byte = root_word_byte(&words, index);
        }
        assert_eq!(actual, expected);
        assert!(verify_pkcs1_encoding(
            HashAlgorithm::Sha256,
            tbs.full,
            &expected
        ));
        assert!(verify_pkcs1_root_words(
            HashAlgorithm::Sha256,
            tbs.full,
            &words
        ));
    }

    #[test]
    fn rsa_3072_public_operations_match_rustcrypto() {
        use rand_core::SeedableRng as _;
        use signature::Signer as _;

        let mut key_rng = ChaCha20Rng::from_seed([0x72; 32]);
        let private = RsaPrivateKey::new(&mut key_rng, 3_072).unwrap();
        let public = RustCryptoPublicKey::from(&private);
        let modulus = public.n().to_bytes_be();
        assert_eq!(modulus.len(), RSA_3072_BYTES);
        let key = RsaPublicKey { modulus: &modulus };
        let message = b"allocation-free RSA-3072 verification";

        let pkcs1 = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private.clone()).sign(message);
        assert!(verify_pkcs1(
            key,
            HashAlgorithm::Sha256,
            message,
            &pkcs1.to_vec()
        ));

        let mut signature_rng = ChaCha20Rng::from_seed([0x73; 32]);
        let pss = rsa::pss::SigningKey::<sha2::Sha256>::new_with_salt_len(private, 32)
            .sign_with_rng(&mut signature_rng, message);
        assert!(verify_pss(
            key,
            HashAlgorithm::Sha256,
            message,
            &pss.to_vec()
        ));
    }

    #[test]
    fn deterministic_pss_corpus_matches_rustcrypto_and_openssl() {
        use rand_core::SeedableRng as _;

        let messages = [
            std::vec![],
            (0..55).map(|index| index as u8).collect(),
            (0..129).map(|index| (index * 3) as u8).collect(),
            (0..1_024).map(|index| (index * 17) as u8).collect(),
        ];
        let mut key_rng = ChaCha20Rng::from_seed([0x31; 32]);
        let keys = [
            RsaPrivateKey::new(&mut key_rng, 2_048).unwrap(),
            RsaPrivateKey::new(&mut key_rng, 4_096).unwrap(),
        ];
        let directory = std::env::temp_dir().join(format!(
            "tailfeather-rsa-differential-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut signature_rng = ChaCha20Rng::from_seed([0xa7; 32]);
        let mut valid = 0;
        let mut invalid = 0;

        for private in &keys {
            let public = RustCryptoPublicKey::from(private);
            let modulus = public.n().to_bytes_be();
            let key = RsaPublicKey { modulus: &modulus };
            let public_der = public.to_public_key_der().unwrap();
            std::fs::write(directory.join("public.der"), public_der.as_bytes()).unwrap();

            macro_rules! exercise_hash {
                ($digest:ty, $algorithm:expr, $name:literal, $hash_len:literal) => {{
                    let signer = rsa::pss::SigningKey::<$digest>::new_with_salt_len(
                        private.clone(),
                        $hash_len,
                    );
                    let verifier = rsa::pss::VerifyingKey::<$digest>::new_with_salt_len(
                        public.clone(),
                        $hash_len,
                    );
                    for message in &messages {
                        std::fs::write(directory.join("message.bin"), message).unwrap();
                        for _ in 0..2 {
                            let signature = signer.sign_with_rng(&mut signature_rng, message);
                            let bytes = signature.to_vec();
                            assert!(verify_pss(key, $algorithm, message, &bytes));
                            assert!(verifier.verify(message, &signature).is_ok());
                            assert!(openssl_verify(&directory, $name, $hash_len, &bytes,));
                            let recovered = recover_encoded_message(key, &bytes).unwrap();
                            assert_eq!(recovered, rustcrypto_recover(&public, &bytes));
                            assert_eq!(recovered, openssl_recover(&directory, &bytes));
                            valid += 1;

                            let mut mutations = std::vec::Vec::new();
                            let mut first = bytes.clone();
                            first[0] ^= 1;
                            mutations.push(first);
                            let mut middle = bytes.clone();
                            middle[bytes.len() / 2] ^= 0x40;
                            mutations.push(middle);
                            let mut last = bytes.clone();
                            last[bytes.len() - 1] ^= 0x80;
                            mutations.push(last);
                            mutations.push(bytes[..bytes.len() - 1].to_vec());
                            mutations.push(modulus.clone());

                            for mutation in mutations {
                                assert!(!verify_pss(key, $algorithm, message, &mutation));
                                let rustcrypto = rsa::pss::Signature::try_from(mutation.as_slice())
                                    .is_ok_and(|signature| {
                                        verifier.verify(message, &signature).is_ok()
                                    });
                                assert!(!rustcrypto);
                                assert!(!openssl_verify(&directory, $name, $hash_len, &mutation,));
                                invalid += 1;
                            }
                        }
                    }
                }};
            }

            exercise_hash!(sha2::Sha256, HashAlgorithm::Sha256, "sha256", 32);
            exercise_hash!(sha2::Sha384, HashAlgorithm::Sha384, "sha384", 48);
            exercise_hash!(sha2::Sha512, HashAlgorithm::Sha512, "sha512", 64);
        }

        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(valid, 48);
        assert_eq!(invalid, 240);
    }

    fn openssl_verify(
        directory: &std::path::Path,
        hash: &str,
        hash_len: usize,
        signature: &[u8],
    ) -> bool {
        std::fs::write(directory.join("signature.bin"), signature).unwrap();
        std::process::Command::new("openssl")
            .current_dir(directory)
            .args([
                "dgst",
                &format!("-{hash}"),
                "-verify",
                "public.der",
                "-keyform",
                "DER",
                "-signature",
                "signature.bin",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                &format!("rsa_pss_saltlen:{hash_len}"),
                "-sigopt",
                &format!("rsa_mgf1_md:{hash}"),
                "message.bin",
            ])
            .output()
            .expect("OpenSSL is required for RSA differential tests")
            .status
            .success()
    }

    fn recover_encoded_message(
        key: RsaPublicKey<'_>,
        signature: &[u8],
    ) -> Option<std::vec::Vec<u8>> {
        match key.modulus.len() {
            RSA_2048_BYTES => recover_2048(key, signature).map(|encoded| encoded.to_vec()),
            RSA_4096_BYTES => recover_4096(key, signature).map(|encoded| encoded.to_vec()),
            _ => None,
        }
    }

    fn rustcrypto_recover(public: &RustCryptoPublicKey, signature: &[u8]) -> std::vec::Vec<u8> {
        let recovered = rsa::BigUint::from_bytes_be(signature)
            .modpow(public.e(), public.n())
            .to_bytes_be();
        let mut padded = std::vec![0; public.size()];
        let offset = padded.len() - recovered.len();
        padded[offset..].copy_from_slice(&recovered);
        padded
    }

    fn openssl_recover(directory: &std::path::Path, signature: &[u8]) -> std::vec::Vec<u8> {
        std::fs::write(directory.join("signature.bin"), signature).unwrap();
        let output = std::process::Command::new("openssl")
            .current_dir(directory)
            .args([
                "pkeyutl",
                "-verifyrecover",
                "-pubin",
                "-inkey",
                "public.der",
                "-keyform",
                "DER",
                "-pkeyopt",
                "rsa_padding_mode:none",
                "-in",
                "signature.bin",
                "-out",
                "recovered.bin",
            ])
            .output()
            .expect("OpenSSL is required for RSA differential tests");
        assert!(
            output.status.success(),
            "OpenSSL raw RSA recovery failed: {}",
            std::string::String::from_utf8_lossy(&output.stderr)
        );
        std::fs::read(directory.join("recovered.bin")).unwrap()
    }

    #[test]
    fn pkcs1_corpus_matches_rustcrypto_and_openssl() {
        use rand_core::SeedableRng as _;
        use signature::Signer as _;

        let messages: [&[u8]; 4] = [
            b"",
            b"boundary-length-message-31-bytes",
            &[0x5a; 129],
            &[0xa5; 1_024],
        ];
        let mut key_rng = ChaCha20Rng::from_seed([0x42; 32]);
        let keys = [
            RsaPrivateKey::new(&mut key_rng, 2_048).unwrap(),
            RsaPrivateKey::new(&mut key_rng, 4_096).unwrap(),
        ];
        let directory = std::env::temp_dir().join(format!(
            "tailfeather-pkcs1-differential-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();

        for private in &keys {
            let public = RustCryptoPublicKey::from(private);
            let modulus = public.n().to_bytes_be();
            let key = RsaPublicKey { modulus: &modulus };
            let public_der = public.to_public_key_der().unwrap();
            std::fs::write(directory.join("public.der"), public_der.as_bytes()).unwrap();

            macro_rules! exercise_pkcs1 {
                ($digest:ty, $algorithm:expr, $name:literal) => {{
                    let signer = rsa::pkcs1v15::SigningKey::<$digest>::new(private.clone());
                    let verifier = rsa::pkcs1v15::VerifyingKey::<$digest>::new(public.clone());
                    for message in messages {
                        std::fs::write(directory.join("message.bin"), message).unwrap();
                        let signature = signer.sign(message);
                        let bytes = signature.to_vec();
                        assert!(verify_pkcs1(key, $algorithm, message, &bytes));
                        assert!(verifier.verify(message, &signature).is_ok());
                        assert!(openssl_verify_pkcs1(&directory, $name, &bytes));
                        let recovered = recover_encoded_message(key, &bytes).unwrap();
                        assert_eq!(recovered, rustcrypto_recover(&public, &bytes));
                        assert_eq!(recovered, openssl_recover(&directory, &bytes));

                        let mut altered = bytes.clone();
                        altered[bytes.len() / 3] ^= 1;
                        assert!(!verify_pkcs1(key, $algorithm, message, &altered));
                        assert!(!openssl_verify_pkcs1(&directory, $name, &altered));
                    }
                }};
            }
            exercise_pkcs1!(sha2::Sha256, HashAlgorithm::Sha256, "sha256");
            exercise_pkcs1!(sha2::Sha384, HashAlgorithm::Sha384, "sha384");
            exercise_pkcs1!(sha2::Sha512, HashAlgorithm::Sha512, "sha512");

            let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private.clone());
            let signature = signer.sign(b"algorithm substitution").to_vec();
            assert!(!verify_pkcs1(
                key,
                HashAlgorithm::Sha384,
                b"algorithm substitution",
                &signature,
            ));
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    fn openssl_verify_pkcs1(directory: &std::path::Path, hash: &str, signature: &[u8]) -> bool {
        std::fs::write(directory.join("signature.bin"), signature).unwrap();
        std::process::Command::new("openssl")
            .current_dir(directory)
            .args([
                "dgst",
                &format!("-{hash}"),
                "-verify",
                "public.der",
                "-keyform",
                "DER",
                "-signature",
                "signature.bin",
                "message.bin",
            ])
            .output()
            .expect("OpenSSL is required for RSA differential tests")
            .status
            .success()
    }

    #[test]
    fn pkcs1_encoding_is_exact() {
        let message = b"strict EMSA-PKCS1-v1_5 encoding";
        let valid = encode_pkcs1_sha256(message);
        assert!(verify_pkcs1_encoding(
            HashAlgorithm::Sha256,
            message,
            &valid
        ));

        let mut short_padding = valid;
        short_padding[8] = 0;
        assert!(!verify_pkcs1_encoding(
            HashAlgorithm::Sha256,
            message,
            &short_padding,
        ));
        let mut oid = valid;
        let digest_info = RSA_2048_BYTES - 32 - 19;
        oid[digest_info + 14] ^= 1;
        assert!(!verify_pkcs1_encoding(HashAlgorithm::Sha256, message, &oid));
        let mut trailing = valid;
        trailing[RSA_2048_BYTES - 1] ^= 1;
        assert!(!verify_pkcs1_encoding(
            HashAlgorithm::Sha256,
            message,
            &trailing,
        ));
    }

    fn encode_pkcs1_sha256(message: &[u8]) -> [u8; RSA_2048_BYTES] {
        const PREFIX: &[u8] = &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let mut encoded = [0xff; RSA_2048_BYTES];
        encoded[0] = 0;
        encoded[1] = 1;
        let separator = RSA_2048_BYTES - PREFIX.len() - 32 - 1;
        encoded[separator] = 0;
        encoded[separator + 1..separator + 1 + PREFIX.len()].copy_from_slice(PREFIX);
        let mut message_hash = [0u8; 64];
        digest(HashAlgorithm::Sha256, &[message], &mut message_hash);
        encoded[separator + 1 + PREFIX.len()..].copy_from_slice(&message_hash[..32]);
        encoded
    }

    #[test]
    fn pss_encoding_rejects_each_structural_mutation() {
        for hash in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ] {
            let message = b"strict EMSA-PSS encoding";
            let mut encoded = encode_pss(hash, message);
            assert!(verify_pss_encoding(hash, message, &mut encoded));

            let mut high_bit = encode_pss(hash, message);
            high_bit[0] |= 0x80;
            assert!(!verify_pss_encoding(hash, message, &mut high_bit));

            let mut trailer = encode_pss(hash, message);
            trailer[RSA_2048_BYTES - 1] ^= 1;
            assert!(!verify_pss_encoding(hash, message, &mut trailer));

            let mut digest = encode_pss(hash, message);
            let digest_index = RSA_2048_BYTES - hash.output_len() - 1;
            digest[digest_index] ^= 1;
            assert!(!verify_pss_encoding(hash, message, &mut digest));

            let mut padding = encode_pss(hash, message);
            mutate_db(hash, &mut padding, |db| db[0] = 1);
            assert!(!verify_pss_encoding(hash, message, &mut padding));

            let mut salt_length = encode_pss(hash, message);
            let delimiter = RSA_2048_BYTES - hash.output_len() * 2 - 2;
            mutate_db(hash, &mut salt_length, |db| {
                db[delimiter] = 0;
                db[delimiter - 1] = 1;
            });
            assert!(!verify_pss_encoding(hash, message, &mut salt_length));

            let mut mgf_mismatch = encode_pss(hash, message);
            let other = match hash {
                HashAlgorithm::Sha256 => HashAlgorithm::Sha384,
                HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => HashAlgorithm::Sha256,
            };
            let hash_len = hash.output_len();
            let db_len = RSA_2048_BYTES - hash_len - 1;
            let mut h = [0u8; 64];
            h[..hash_len].copy_from_slice(&mgf_mismatch[db_len..db_len + hash_len]);
            mgf1_xor(hash, &h[..hash_len], &mut mgf_mismatch[..db_len]);
            mgf1_xor(other, &h[..hash_len], &mut mgf_mismatch[..db_len]);
            mgf_mismatch[0] &= 0x7f;
            assert!(!verify_pss_encoding(hash, message, &mut mgf_mismatch));
        }
    }

    #[test]
    fn malformed_pss_signatures_are_rejected_by_all_three_verifiers() {
        use rand_core::SeedableRng as _;

        let message = b"adversarial PSS encoded message";
        let mut rng = ChaCha20Rng::from_seed([0x9d; 32]);
        let private = RsaPrivateKey::new(&mut rng, 2_048).unwrap();
        let public = RustCryptoPublicKey::from(&private);
        let modulus = public.n().to_bytes_be();
        let key = RsaPublicKey { modulus: &modulus };
        let directory = std::env::temp_dir().join(format!(
            "tailfeather-pss-adversarial-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("public.der"),
            public.to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(directory.join("message.bin"), message).unwrap();

        macro_rules! exercise_hash {
            ($digest:ty, $algorithm:expr, $name:literal, $hash_len:literal) => {{
                let verifier =
                    rsa::pss::VerifyingKey::<$digest>::new_with_salt_len(public.clone(), $hash_len);
                let valid = encode_pss($algorithm, message);
                let signature = sign_encoded_message(&private, &valid);
                let parsed = rsa::pss::Signature::try_from(signature.as_slice()).unwrap();
                assert!(verify_pss(key, $algorithm, message, &signature));
                assert!(verifier.verify(message, &parsed).is_ok());
                assert!(openssl_verify(&directory, $name, $hash_len, &signature,));

                let wrong_salt_signer =
                    rsa::pss::SigningKey::<$digest>::new_with_salt_len(private.clone(), 0);
                let wrong_salt = wrong_salt_signer.sign_with_rng(&mut rng, message).to_vec();
                let parsed = rsa::pss::Signature::try_from(wrong_salt.as_slice()).unwrap();
                assert!(!verify_pss(key, $algorithm, message, &wrong_salt));
                assert!(verifier.verify(message, &parsed).is_err());
                assert!(!openssl_verify(&directory, $name, $hash_len, &wrong_salt,));

                let mut invalid = std::vec::Vec::new();
                let mut high_bit = valid;
                high_bit[0] |= 0x80;
                invalid.push(high_bit);
                let mut trailer = valid;
                trailer[RSA_2048_BYTES - 1] ^= 1;
                invalid.push(trailer);
                let mut digest = valid;
                digest[RSA_2048_BYTES - $hash_len - 1] ^= 1;
                invalid.push(digest);
                let mut padding = valid;
                mutate_db($algorithm, &mut padding, |db| db[0] = 1);
                invalid.push(padding);
                let mut salt_length = valid;
                let delimiter = RSA_2048_BYTES - $hash_len * 2 - 2;
                mutate_db($algorithm, &mut salt_length, |db| {
                    db[delimiter] = 0;
                    db[delimiter - 1] = 1;
                });
                invalid.push(salt_length);
                let mut mgf_mismatch = valid;
                let other = match $algorithm {
                    HashAlgorithm::Sha256 => HashAlgorithm::Sha384,
                    HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => HashAlgorithm::Sha256,
                };
                let db_len = RSA_2048_BYTES - $hash_len - 1;
                let mut encoded_hash = [0u8; 64];
                encoded_hash[..$hash_len]
                    .copy_from_slice(&mgf_mismatch[db_len..db_len + $hash_len]);
                mgf1_xor(
                    $algorithm,
                    &encoded_hash[..$hash_len],
                    &mut mgf_mismatch[..db_len],
                );
                mgf1_xor(
                    other,
                    &encoded_hash[..$hash_len],
                    &mut mgf_mismatch[..db_len],
                );
                mgf_mismatch[0] &= 0x7f;
                invalid.push(mgf_mismatch);

                for encoded in invalid {
                    let signature = sign_encoded_message(&private, &encoded);
                    let parsed = rsa::pss::Signature::try_from(signature.as_slice()).unwrap();
                    assert!(!verify_pss(key, $algorithm, message, &signature));
                    assert!(verifier.verify(message, &parsed).is_err());
                    assert!(!openssl_verify(&directory, $name, $hash_len, &signature,));
                }
            }};
        }

        exercise_hash!(sha2::Sha256, HashAlgorithm::Sha256, "sha256", 32);
        exercise_hash!(sha2::Sha384, HashAlgorithm::Sha384, "sha384", 48);
        exercise_hash!(sha2::Sha512, HashAlgorithm::Sha512, "sha512", 64);
        let _ = std::fs::remove_dir_all(directory);
    }

    fn sign_encoded_message(private: &RsaPrivateKey, encoded: &[u8]) -> std::vec::Vec<u8> {
        use rsa::traits::PrivateKeyParts as _;

        let signature = rsa::BigUint::from_bytes_be(encoded)
            .modpow(private.d(), private.n())
            .to_bytes_be();
        let mut padded = std::vec![0; private.size()];
        let offset = padded.len() - signature.len();
        padded[offset..].copy_from_slice(&signature);
        padded
    }

    #[test]
    fn malformed_pkcs1_signatures_are_rejected_by_all_three_verifiers() {
        use rand_core::SeedableRng as _;

        let message = b"adversarial PKCS1 encoded message";
        let mut rng = ChaCha20Rng::from_seed([0x6e; 32]);
        let private = RsaPrivateKey::new(&mut rng, 2_048).unwrap();
        let public = RustCryptoPublicKey::from(&private);
        let modulus = public.n().to_bytes_be();
        let key = RsaPublicKey { modulus: &modulus };
        let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public.clone());
        let directory = std::env::temp_dir().join(format!(
            "tailfeather-pkcs1-adversarial-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("public.der"),
            public.to_public_key_der().unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::write(directory.join("message.bin"), message).unwrap();

        let valid = encode_pkcs1_sha256(message);
        let digest_info = RSA_2048_BYTES - 32 - 19;
        let mut shortened_padding = valid;
        shortened_padding[digest_info - 2] = 0;
        let mut altered_oid = valid;
        altered_oid[digest_info + 14] ^= 1;
        let mut trailing_data = valid;
        trailing_data[digest_info + 1] -= 1;

        for encoded in [shortened_padding, altered_oid, trailing_data] {
            let signature = sign_encoded_message(&private, &encoded);
            let parsed = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
            assert!(!verify_pkcs1(
                key,
                HashAlgorithm::Sha256,
                message,
                &signature,
            ));
            assert!(verifier.verify(message, &parsed).is_err());
            assert!(!openssl_verify_pkcs1(&directory, "sha256", &signature));
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    fn encode_pss(hash: HashAlgorithm, message: &[u8]) -> [u8; RSA_2048_BYTES] {
        let hash_len = hash.output_len();
        let db_len = RSA_2048_BYTES - hash_len - 1;
        let delimiter = db_len - hash_len - 1;
        let mut encoded = [0u8; RSA_2048_BYTES];
        encoded[delimiter] = 1;
        encoded[delimiter + 1..db_len].fill(0x5a);
        let mut message_hash = [0u8; 64];
        digest(hash, &[message], &mut message_hash);
        let mut encoded_hash = [0u8; 64];
        digest(
            hash,
            &[
                &[0u8; 8],
                &message_hash[..hash_len],
                &encoded[delimiter + 1..db_len],
            ],
            &mut encoded_hash,
        );
        encoded[db_len..db_len + hash_len].copy_from_slice(&encoded_hash[..hash_len]);
        mgf1_xor(hash, &encoded_hash[..hash_len], &mut encoded[..db_len]);
        encoded[0] &= 0x7f;
        encoded[RSA_2048_BYTES - 1] = 0xbc;
        encoded
    }

    fn mutate_db(
        hash: HashAlgorithm,
        encoded: &mut [u8; RSA_2048_BYTES],
        mutate: impl FnOnce(&mut [u8]),
    ) {
        let hash_len = hash.output_len();
        let db_len = RSA_2048_BYTES - hash_len - 1;
        let mut encoded_hash = [0u8; 64];
        encoded_hash[..hash_len].copy_from_slice(&encoded[db_len..db_len + hash_len]);
        mgf1_xor(hash, &encoded_hash[..hash_len], &mut encoded[..db_len]);
        encoded[0] &= 0x7f;
        mutate(&mut encoded[..db_len]);
        mgf1_xor(hash, &encoded_hash[..hash_len], &mut encoded[..db_len]);
        encoded[0] &= 0x7f;
    }

    #[test]
    fn rsa_public_key_parser_rejects_bad_exponents_and_moduli() {
        let mut modulus = [0x80u8; RSA_2048_BYTES];
        modulus[RSA_2048_BYTES - 1] = 1;
        let valid = pkcs1_key(&modulus, &[1, 0, 1]);
        assert!(parse_public_key(&valid).is_ok());

        let exponent = pkcs1_key(&modulus, &[3]);
        assert!(parse_public_key(&exponent).is_err());
        modulus[RSA_2048_BYTES - 1] = 0;
        assert!(parse_public_key(&pkcs1_key(&modulus, &[1, 0, 1])).is_err());
        assert!(parse_public_key(&pkcs1_key(&modulus[1..], &[1, 0, 1])).is_err());
    }

    fn pkcs1_key(modulus: &[u8], exponent: &[u8]) -> std::vec::Vec<u8> {
        fn length(output: &mut std::vec::Vec<u8>, length: usize) {
            if length < 128 {
                output.push(length as u8);
            } else {
                output.extend_from_slice(&[0x82, (length >> 8) as u8, length as u8]);
            }
        }
        let integer_len = modulus.len() + 1;
        let body_len = 1 + 3 + integer_len + 2 + exponent.len();
        let mut result = std::vec![0x30];
        length(&mut result, body_len);
        result.push(0x02);
        length(&mut result, integer_len);
        result.push(0);
        result.extend_from_slice(modulus);
        result.push(0x02);
        result.push(exponent.len() as u8);
        result.extend_from_slice(exponent);
        result
    }
}
