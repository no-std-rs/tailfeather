//! Synthetic vectors embedded in the internal testkit.

use sha2::{Digest, Sha256};

pub struct Vector {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}

const HEALTH: &[u8] = include_bytes!("../fixtures/health.json");

pub static ALL: &[Vector] = &[Vector {
    name: "health",
    bytes: HEALTH,
    sha256: "c0b2cedfd8c94f54fc8f089589d07b2c3a238d5e18aae57453c57a6873cd8b79",
}];

pub fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write;
        write!(out, "{byte:02x}").unwrap();
    }
    out
}
