# tailfeather-gateway

An allocation-free IPv4 and IPv6 gateway core shared by Tailfeather's ESP32-C6 firmware
and Linux interoperability harness. It owns no sockets, clock, or executor.

The crate provides fixed-capacity TCP/UDP NAT, IPv4 packet construction and
checksums, ICMP echo replies, route policy, and a bounded peer API. Callers own
network I/O and supply packets and time to the protocol state.

The IPv6 module forwards UDP, TCP and ICMPv6 echo with endpoint-dependent
source translation through 32 fixed flow slots. It validates transport
checksums, binds sources to authenticated peer addresses, decrements hop limits,
clamps TCP MSS to the 1280-byte tunnel MTU, and reverses validated ICMPv6 error
quotations. Time Exceeded and Packet Too Big replies are bounded and rate limited.
Firmware and the bare harness use this same implementation; namespace tests
exercise real kernel IPv6 UDP, multi-packet TCP/TLS, echo and expired hop limits.

IPv6 extension headers, fragments, jumbograms and subnet routing are currently
unsupported and rejected. Forwarding is unicast only; link-local, multicast,
loopback and IPv4-mapped destinations do not cross the tunnel. The parser never
reassembles packets or skips unknown headers. The packet and error contracts
follow [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) and
[RFC 4443](https://www.rfc-editor.org/rfc/rfc4443).

This is experimental software. See the [Tailfeather repository](https://github.com/no-std-rs/tailfeather)
for integration, testing, and firmware instructions.

Dual-licensed under MIT or Apache-2.0.
