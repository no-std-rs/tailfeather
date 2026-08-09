//! The Tailscale control-plane messages, encoded without an allocator.
//!
//! [`crate::noise`] gets a node as far as an authenticated channel to the server.
//! This crate is what it says over it: registration now, and the map request as
//! the netmap parser arrives.
//!
//! Everything here is sans-io — documents in and out of caller-supplied buffers
//! — so the same code runs on the host, on the harness, and on the device.

#![forbid(unsafe_code)]

pub mod hostinfo;
pub mod json;
pub mod map;
pub mod register;

pub use hostinfo::{EXIT_NODE_ROUTES, Hostinfo};
pub use json::{JsonError, Writer};
pub use map::MapRequest;
pub use register::{RegisterRequest, RegisterResponse};

/// The capability version this client speaks, taken from [`crate::noise`] so the
/// registration body and the Noise prologue cannot disagree.
///
/// They must match: the prologue binds the version into the handshake, and a
/// body claiming a different one describes a client the server did not
/// authenticate.
pub const CAPABILITY_VERSION: u16 = crate::noise::CAPABILITY_VERSION;

#[cfg(test)]
mod tests {
    #[test]
    fn the_capability_version_is_the_one_the_handshake_bound() {
        assert_eq!(super::CAPABILITY_VERSION, crate::noise::CAPABILITY_VERSION);
    }
}
