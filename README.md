# tailfeather

Allocation-free Rust building blocks for a Tailscale-compatible mesh node, plus
ESP32-C6 firmware for a small IPv4 WireGuard exit gateway.

The portable crates implement WireGuard, the ts2021 control transport, HTTP/2,
netmap parsing, disco, and DERP without `std` or `alloc`. The same code runs in a
bare Linux harness, where it can be tested against real reference implementations
before it is wired into the device.

> **Experimental:** this is protocol and embedded-systems work, not an audited
> VPN appliance. The complete control plane works in the harness; the firmware
> currently contains the WireGuard and TCP/UDP forwarding path.

## Status

| Where | What works today |
|---|---|
| ESP32-C6 | WiFi STA + DHCP, WireGuard responder, IPv4 UDP/TCP forwarding and NAT |
| Bare Linux harness | WireGuard in both roles, ts2021, registration, netmaps, disco, DERP, exit-route advertisement, and TLS against the local lab |
| Local conformance lab | Committed 34/34 baseline against Headscale v0.29.3 and tailscaled 1.94.2 |

Hosted Tailscale has not passed end to end yet. Its measured certificate chain
needs `embedded-tls`'s `p384` support and a trust-anchor model that can stop
before the topmost presented certificate. We also still need to verify that the
hosted service accepts a `MapRequest` without zstd compression; the local
Headscale lab does.

The next substantial step is integration: move the control-plane path that
already runs in the harness onto the ESP32 firmware.

## Try it

Run the portable crate tests and the conformance matrix backed by committed
reference vectors:

```sh
cargo test
scripts/conformance.sh
```

Run the full local lab against a real Headscale and a real `tailscaled`:

```sh
tests/lab/lab.sh up
tests/lab/lab.sh reference
tests/lab/tls.sh up
scripts/conformance.sh
```

Some lab and WireGuard interop steps need root, containers, network namespaces,
or a local Tailscale installation. `tests/lab/lab.sh doctor` reports what is
available. See [`tests/README.md`](tests/README.md) for the model, statuses, and
capture workflow.

## Architecture

| Path | Purpose |
|---|---|
| `crates/wg-core` | Sans-I/O WireGuard: handshakes, transport, replay protection, and timers |
| `crates/ts-keys` | Machine, node, and disco identities plus persistence |
| `crates/ts-noise` | ts2021 Noise IK transport and controlbase framing |
| `crates/micro-h2` | Minimal bounded HTTP/2 client and HPACK decoder |
| `crates/ts-control` | Registration, Hostinfo, and map requests |
| `crates/ts-netmap` | Streaming full and delta `MapResponse` parser |
| `crates/ts-disco` | NaCl-boxed path-discovery pings and pongs |
| `crates/ts-derp` | DERP v2 relay client |
| `harness` | No-`std`, no-libc Linux runtime for reference interop |
| `firmware` | ESP32-C6 WiFi, tunnel, NAT, and forwarding |
| `tests` / `crates/ts-conformance` | Live lab, captured vectors, baselines, and compatibility matrix |

The protocol crates know nothing about sockets. They operate on caller-owned
buffers and use `embedded-io-async` or `embedded-nal-async` at the edges, so the
firmware and harness drive the same implementations.

## Design constraints

- **No allocation in project code.** Buffers are fixed-size and collections are
  `heapless`. `esp-alloc` exists only for the ESP radio C blob's private heap.
- **No host-shaped test double.** The harness targets
  `x86_64-unknown-linux-none`: Linux syscalls, but no libc, `std`, allocator,
  threads, or hidden runtime.
- **Bounded memory.** Protocol limits and buffer sizes are explicit constants;
  netmaps are streamed rather than collected into one large document.
- **Reference implementations decide.** WireGuard is checked against the Linux
  kernel, and the control plane against Headscale and `tailscaled`, or against
  bytes captured from them.

That last rule catches bugs self-tests cannot. For example, tailfeather once
sealed and opened its own disco packets perfectly while a real Tailscale client
rejected them: NaCl puts its authentication tag before the ciphertext, unlike
the other AEAD layouts used here.

## Verification

```sh
cargo test                                  # host unit and differential tests
scripts/no-alloc-guard.sh                   # source scan + bare harness build
sudo scripts/interop-wireguard.sh           # std example vs kernel WireGuard
sudo scripts/interop-wireguard.sh harness   # bare harness as responder
sudo scripts/interop-wireguard.sh initiator # bare harness starts the handshake
```

The interop script creates a network namespace and requires both a completed
handshake and a successful in-tunnel ping. In `initiator` mode the kernel peer
has no endpoint, so a handshake proves tailfeather started it.

The conformance score is deliberately not a claim of universal compatibility.
Each `PASS` is tied to a live reference implementation or committed external
evidence, skipped checks do not count, and CI compares the full status matrix
with a baseline so a vanished measurement cannot masquerade as success.

## Run it on an ESP32-C6

Configuration is compiled into the firmware. Copy the example, fill in the WiFi
and WireGuard values, then build and flash:

```sh
cp .env.example .env
scripts/flash.sh
```

With a device on the network, the helper scripts can configure a kernel peer
and exercise forwarding:

```sh
sudo scripts/device-peer.sh up <device-lan-ip>
sudo scripts/bench-exit.sh <device-lan-ip>
sudo scripts/test-http.sh <device-lan-ip>
sudo scripts/device-peer.sh down
```

For the peer helpers, also add `LAPTOP_PRIVATE_KEY_B64` and
`DEVICE_PUBLIC_KEY_B64` to `.env`.

UDP uses ordinary station-side sockets. TCP is translated segment by segment
through a raw socket, with RFC 1624 checksum updates and MSS clamping for the
1280-byte tunnel MTU.

## Measured on hardware

One ESP32-C6 on 2.4 GHz WiFi produced the following results; they describe that
setup, not a general performance guarantee.

| Workload | Observed result |
|---|---|
| UDP, 1024-byte payloads | 4.3 Mbit/s peak; 3.85 Mbit/s sustained below 5% loss |
| HTTP through the exit path | 2.6–3.4 Mbit/s for a 2 MiB body |

The current path handles one packet from decrypt through reply encryption
before starting the next, so latency and WiFi round trips dominate. Pipelining
the two directions is the obvious next performance improvement.

## Current limits

- hosted Tailscale support is incomplete
- the control plane is not yet integrated into the firmware
- forwarding is IPv4-only, with MTU 1280 and no fragmentation
- firmware WireGuard is responder-only, although `wg-core` supports both roles
- WireGuard cookies / `mac2` DoS protection are not implemented
- throughput is a few Mbit/s on the tested hardware and radio setup

## References

- Tailscale's `controlbase`, `tailcfg.go`, and `disco.go`
- Headscale's `hscontrol/noise.go` and `hscontrol/poll.go`
- [tailscale/tailscale-rs](https://github.com/tailscale/tailscale-rs) for wire formats
- [MicroLink](https://github.com/CamM2325/microlink) for an ESP32 implementation in C

## License

Dual-licensed under MIT or Apache-2.0, at your option.
