//! A Tailscale node's identity: three keys, their wire encoding, and the blob
//! that carries them across a reboot.
//!
//! # Three keys, three jobs
//!
//! A node holds three X25519 keypairs, and conflating them is a design error
//! rather than an optimisation. The **machine key** authenticates the device to
//! the coordination server and never appears on the data plane. The **node key**
//! is the WireGuard identity peers encrypt to, and is rotated on logout without
//! the machine ceasing to be the same machine. The **disco key** signs path
//! discovery messages, which travel over the same UDP socket as WireGuard but
//! outside the tunnel, so it must not be able to impersonate the node key.
//!
//! Keeping them distinct is what lets a node key be rotated, revoked, or made
//! ephemeral while the machine's registration survives.
//!
//! # Why the types are separate
//!
//! All three are 32 bytes of X25519, so the compiler is the only thing that can
//! stop one being passed where another belongs — and that mistake is invisible
//! at runtime, because every one of them produces a perfectly valid handshake
//! with the wrong identity. Hence three newtypes with no conversions between
//! them.

#![forbid(unsafe_code)]

pub mod encoding;
pub mod store;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use encoding::{DecodeError, decode_prefixed, encode_prefixed};
pub use store::{Blob, StoreError};

/// Every key here is X25519.
pub const KEY_LEN: usize = 32;

/// A source of cryptographically secure random bytes.
///
/// Deliberately not `rand_core::RngCore`, for the same reason `wirefeather::Rng` is
/// not: a crate this low in the tree should not pin a `rand_core` major version
/// onto every consumer, and the ESP32's hardware generator has nothing else in
/// common with a host test's.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// Declares a keypair type: a secret that zeroizes, its public half, and the
/// textual prefix the control protocol writes it with.
macro_rules! key_type {
    (
        $(#[$secret_doc:meta])* $secret:ident,
        $(#[$public_doc:meta])* $public:ident,
        $prefix:literal
    ) => {
        $(#[$secret_doc])*
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $secret(StaticSecret);

        impl $secret {
            /// Generate a fresh key.
            pub fn generate(rng: &mut impl Rng) -> Self {
                let mut bytes = [0u8; KEY_LEN];
                rng.fill_bytes(&mut bytes);
                let key = Self::from_bytes(bytes);
                bytes.zeroize();
                key
            }

            /// `StaticSecret::from` clamps, so any 32 bytes are a valid key.
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(StaticSecret::from(bytes))
            }

            pub fn to_bytes(&self) -> [u8; KEY_LEN] {
                self.0.to_bytes()
            }

            pub fn public(&self) -> $public {
                $public(PublicKey::from(&self.0))
            }

            /// The underlying secret, for the Diffie-Hellman a handshake needs.
            pub fn secret(&self) -> &StaticSecret {
                &self.0
            }
        }

        impl core::fmt::Debug for $secret {
            /// Prints nothing but the type name.
            ///
            /// A secret key that reaches a log is compromised, and the most
            /// common way that happens is a `#[derive(Debug)]` on a struct that
            /// contains one.
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($secret), "(redacted)"))
            }
        }

        $(#[$public_doc])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $public(PublicKey);

        impl $public {
            /// The textual prefix the control protocol writes this key with.
            pub const PREFIX: &'static str = $prefix;

            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(PublicKey::from(bytes))
            }

            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                self.0.as_bytes()
            }

            pub fn as_public(&self) -> &PublicKey {
                &self.0
            }

            /// Parse the `prefix:hex` form the server uses.
            pub fn parse(text: &str) -> Result<Self, DecodeError> {
                decode_prefixed(Self::PREFIX, text).map(Self::from_bytes)
            }

            /// Write the `prefix:hex` form into `out`, returning the length.
            pub fn encode<'o>(&self, out: &'o mut [u8]) -> Result<&'o str, DecodeError> {
                encode_prefixed(Self::PREFIX, self.as_bytes(), out)
            }
        }

        impl core::fmt::Display for $public {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(Self::PREFIX)?;
                f.write_str(":")?;
                for byte in self.as_bytes() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl core::fmt::Debug for $public {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}

key_type!(
    /// Authenticates this device to the coordination server. Used only for the
    /// ts2021 Noise handshake, never on the data plane.
    MachinePrivate,
    /// A machine key's public half, written `mkey:…`.
    ///
    /// The server publishes its own in this form at `/key`, which is where the
    /// encoding is pinned: whatever it emits is what we must both parse and
    /// produce.
    MachinePublic,
    "mkey"
);

key_type!(
    /// The WireGuard identity peers encrypt to. Rotated on logout, which is why
    /// it is not the machine key.
    NodePrivate,
    /// A node key's public half, written `nodekey:…`.
    NodePublic,
    "nodekey"
);

key_type!(
    /// Signs path-discovery messages, which travel outside the tunnel on the
    /// same UDP socket as WireGuard.
    DiscoPrivate,
    /// A disco key's public half, written `discokey:…`.
    DiscoPublic,
    "discokey"
);

/// A node's complete identity.
///
/// Generated once and persisted. Regenerating it makes the node a stranger to
/// the server: it re-registers as a new machine, and on a real tailnet that
/// means a fresh entry appearing on every reboot.
#[derive(Clone, Debug)]
pub struct Identity {
    pub machine: MachinePrivate,
    pub node: NodePrivate,
    pub disco: DiscoPrivate,
}

impl Identity {
    pub fn generate(rng: &mut impl Rng) -> Self {
        Self {
            machine: MachinePrivate::generate(rng),
            node: NodePrivate::generate(rng),
            disco: DiscoPrivate::generate(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u8);

    impl Rng for Counter {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn the_three_keys_of_an_identity_are_distinct() {
        // A generator that returned the same bytes three times would produce an
        // identity whose machine key is also its node key, which authenticates
        // the data plane with the control-plane credential.
        let identity = Identity::generate(&mut Counter(1));
        let machine = *identity.machine.public().as_bytes();
        let node = *identity.node.public().as_bytes();
        let disco = *identity.disco.public().as_bytes();
        assert_ne!(machine, node);
        assert_ne!(node, disco);
        assert_ne!(machine, disco);
    }

    #[test]
    fn each_key_writes_its_own_prefix() {
        assert_eq!(MachinePublic::PREFIX, "mkey");
        assert_eq!(NodePublic::PREFIX, "nodekey");
        assert_eq!(DiscoPublic::PREFIX, "discokey");
    }

    #[test]
    fn a_secret_key_does_not_print_itself() {
        // The most common way a key reaches a log is a derived Debug on a struct
        // that happens to contain one.
        struct Sink([u8; 128], usize);
        impl Write for Sink {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let n = s.len().min(self.0.len() - self.1);
                self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
                self.1 += n;
                Ok(())
            }
        }
        use core::fmt::Write;

        let identity = Identity::generate(&mut Counter(7));
        let mut sink = Sink([0; 128], 0);
        write!(sink, "{:?}", identity.machine).unwrap();
        let printed = core::str::from_utf8(&sink.0[..sink.1]).unwrap();
        assert_eq!(printed, "MachinePrivate(redacted)");

        // And the bytes really are absent, not merely unlikely to appear.
        let secret = identity.machine.to_bytes();
        assert!(!sink.0[..sink.1].windows(4).any(|w| w == &secret[..4]));
    }

    #[test]
    fn a_public_key_round_trips_through_its_text_form() {
        let identity = Identity::generate(&mut Counter(3));
        let public = identity.node.public();
        let mut buffer = [0u8; 128];
        let text = public.encode(&mut buffer).unwrap();
        assert!(text.starts_with("nodekey:"));
        assert_eq!(NodePublic::parse(text).unwrap(), public);
    }
}
