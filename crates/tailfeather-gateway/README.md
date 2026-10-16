# tailfeather-gateway

An allocation-free IPv4 gateway core shared by Tailfeather's ESP32-C6 firmware
and Linux interoperability harness. It owns no sockets, clock, or executor.

The crate provides fixed-capacity TCP/UDP NAT, IPv4 packet construction and
checksums, ICMP echo replies, route policy, and a bounded peer API. Callers own
network I/O and supply packets and time to the protocol state.

This is experimental software. See the [Tailfeather repository](https://github.com/no-std-rs/tailfeather)
for integration, testing, and firmware instructions.

Dual-licensed under MIT or Apache-2.0.
