//! Shared ICMP and checksum helpers used by the bare WireGuard harness.
//!
//! The firmware and harness deliberately call the same allocation-free packet
//! implementation so kernel interoperability cannot drift from the ESP path.

pub use tailfeather_gateway::icmp_echo_reply;
