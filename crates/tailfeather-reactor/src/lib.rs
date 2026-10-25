//! Executor-independent asynchronous building blocks for Tailfeather adapters.
//!
//! Routing, scheduling and queue semantics are identical on hosts and devices.
//! Optional `std` and `embassy` features supply platform I/O adapters and clocks.
//! The runtime does not select an executor or a global time driver.

#![no_std]
#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "embassy")]
pub mod embassy;
pub mod exec;
#[cfg(feature = "std")]
pub mod native;
pub mod queue;
pub mod routing;
pub mod runtime;
pub mod tcp;
pub mod tcp_async;

// Reexport exact dependency instances for platform implementors.
#[cfg(feature = "embassy")]
pub use embassy_net;
pub use embedded_io_async;
pub use tailfeather;
