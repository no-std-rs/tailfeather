//! Allocation-free protocol components and a cooperative mesh [`Node`].
//!
//! The protocol modules are public so applications can use the individual
//! codecs, while [`Node`] is the preferred integration boundary. `Node` owns
//! protocol state but no sockets, executor, clock, random source, or storage.
//!
//! ```
//! use tailfeather::{Node, keys::{Identity, Rng}};
//!
//! struct Fixed;
//! impl Rng for Fixed {
//!     fn fill_bytes(&mut self, out: &mut [u8]) { out.fill(7); }
//! }
//!
//! let identity = Identity::generate(&mut Fixed);
//! let node = Node::<4>::factory_reset(identity, 1);
//! assert!(node.requires_persistence());
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod control;
pub mod derp;
pub mod disco;
pub mod keys;
pub mod netmap;
pub mod node;
pub mod noise;

pub use micro_h2 as http2;
pub use node::{
    ControlCommand, ControlEvent, ControlSession, DerpCommand, DerpEvent, DerpSession, Endpoint,
    Node, NodeAction, NodeError, NodeStatus, PersistState, RegistrationState, SecretBuffer,
    Transport,
};
pub use wirefeather as tunnel;
