# tailfeather

A [Tailscale](https://tailscale.com)-compatible mesh node in Rust, with no allocator, no libc
and no operating system underneath it — and an ESP32-C6 firmware that uses it to act as an
**exit node**: WireGuard data plane, ts2021 control plane, and NAT out the WiFi station uplink.

The protocol lives in `crates/`, each piece independently publishable and none of them aware of
a socket. `harness/` runs those same crates on `x86_64-unknown-linux-none` — the Linux syscall
ABI and nothing else — so every claim below is made by a binary with the firmware's
constraints rather than by a `std` test that could lean on the host.

The target is compatibility with **both** hosted Tailscale and self-hosted
[Headscale](https://headscale.net), at their current versions. Those are different problems —
Headscale on a LAN accepts plain HTTP and tolerates a client that never relays, while
`controlplane.tailscale.com` requires TLS and DERP — so compatibility with one is not evidence
about the other, and the test framework reports them separately.

## Why this is possible

- **MicroLink** ([CamM2325/microlink](https://github.com/CamM2325/microlink), MIT) already does
  the full thing in C on an ESP32-C3 — ts2021 + disco + DERP + WireGuard. It is our de facto
  protocol specification.
- **alfs/tailscale-iot** demonstrates Headscale working without DERP on a LAN, where peers
  disco-ping each other directly.
- Every cryptographic primitive WireGuard and ts2021 need exists as a `no_std` Rust crate
  (`x25519-dalek`, `chacha20poly1305`, `blake2`, `crypto_box`). What does *not* exist is a
  published `no_std` WireGuard implementation, so `crates/wg-core` is ours.

## Compatibility

`tests/` holds a framework that measures this project against real Headscale and a real
Tailscale client rather than against our own assumptions. It enumerates every behaviour a
compatible node must exhibit and gives each one a status, so the gap is explicit and
countable rather than vague.

```sh
tests/lab/lab.sh up && tests/lab/lab.sh reference   # a real Headscale and a real client
tests/lab/tls.sh up                                 # a TLS front, for the TLS client
scripts/conformance.sh                              # the matrix
scripts/conformance.sh --capture                    # re-capture ground truth first
```

**Currently 34 of 34 behaviours verified against Headscale v0.29.3 and tailscaled 1.94.2.**

What that does and does not mean. Every check is answered either by a reference implementation
during the run — Headscale, a real `tailscaled`, the Linux kernel's WireGuard — or by bytes
captured from one. Nothing counts as passing because our code agrees with itself; that rule has
paid for itself repeatedly, most recently when disco sealed and opened its own NaCl boxes
perfectly and a real client answered "failed to open naclbox (wrong rcpt?)", because NaCl puts
the Poly1305 tag before the ciphertext and every other AEAD in this tree appends it.

The measurement is against the **lab**. Two things stand between here and hosted Tailscale, and
both are named in the checks that touch them rather than hidden. The first is the certificate
chain: `controlplane.tailscale.com` serves ECDSA to a client offering ECDSA signature
algorithms — measured, and recorded in `tests/vectors/hosted_tls.json` — so what is needed is
embedded-tls's `p384` feature for the `ecdsa-with-SHA384` chain signatures, which unlike its
`rsa` feature does not pull in an allocator, plus a trust-anchor model that can stop before the
topmost presented certificate. This README previously said the chain was RSA-PSS-only and
therefore out of reach without an allocation-free RSA verifier; that was wrong, and it stood as
a roadmap blocker until someone measured it. The second is that whether the hosted service
honours a `MapRequest` that omits `Compress` is still unknown, which matters because every zstd
decoder in Rust needs a heap. See `tests/README.md` for what else the framework has established about the real
servers — including that Headscale v0.29.3 rejects any client advertising a capability version
below 113.

## Layout

```
firmware/         ESP32-C6 binary: WiFi STA, embassy-net, tunnel, NAT
tests/            compatibility framework: reference lab, ground-truth vectors
crates/ts-conformance  the compatibility matrix
crates/wg-core    sans-io no_std no-alloc WireGuard core (handshake, transport, timers)
crates/ts-keys    machine/node/disco keys, their wire encoding, and persistence
crates/ts-noise   ts2021 transport: Noise IK, controlbase framing, the HTTP/1.1 upgrade
crates/micro-h2   minimal no-alloc HTTP/2 client: framing, HPACK, a few streams
crates/ts-control control-plane messages: registration, Hostinfo, no-alloc JSON
crates/ts-netmap streaming MapResponse parser: peers, deltas, DERP map
crates/ts-disco   path discovery: NaCl-boxed pings on the WireGuard socket
crates/ts-derp    DERP v2 client: relaying when no direct path exists
harness/          no_std binary for x86_64-unknown-linux-none: runs the SAME library
                  crates against real wg-quick / Headscale on the dev machine, no ESP32
```

## Design rules

**No allocation.** No project code uses `alloc` — no `Box`, `Vec`, or `String` in our modules.
Buffers are static (`static_cell`), collections are `heapless`. The single exception is
`esp-alloc`, kept solely as the private heap the esp-radio WiFi C blob mallocs from; if a future
esp-radio release drops that requirement, `esp-alloc` goes too.

**Build on embedded async traits.** Everything above the HAL is generic over
`embedded-io-async` (byte streams) and `embedded-nal-async` (TCP/UDP) rather than concrete
embassy-net types. embassy-net sockets already implement these traits, so every layer is
host-testable on std and reusable off the ESP32.

**Reuse before writing.** Before starting any crate, look for an existing near-miss with an
active maintainer and prefer contributing or forking over rewriting. Specifically:
[reqwless](https://github.com/drogue-iot/reqwless) for the HTTP/2 work, and
[rustyguard](https://github.com/conradludgate/rustyguard) — which is `no_std` sans-io and
exactly the right shape, but currently unpublished and unlicensed — for WireGuard. Never
hand-roll a cryptographic primitive.

**Memory budget.** The C6 has 512 KB HP SRAM (~448 KB usable) and the radio blob's heap takes
64–96 KB of it. Every buffer size is a named constant in a per-crate budget module, and the
x86 harness uses the *same* constants so it cannot silently rely on space the C6 lacks. Working
targets: WireGuard sessions ≤ 8 KB, tunnel UDP buffers ~8 KB, NAT table ≤ 8 KB (~256 entries),
HTTP/2 frame + HPACK ≤ 20 KB, netmap staging ≤ 32 KB (streamed, never fully buffered),
embassy-net resources ~24 KB. `.data + .bss` is capped at 200 KB and checked after every
milestone.

## Testing without hardware

`harness/` targets `x86_64-unknown-linux-none` (tier 3: Linux syscall ABI, no libc, no std). It
supplies its own `_start`, reaches the kernel through `rustix` with `default-features = false`,
and runs the identical library crates against a real `wg-quick` peer on the development machine.
On top of that sits a small reactor — one `poll` call, no allocator, no threads — which is what
the async control plane will be built on. The firmware stays on stable Rust; only the harness
needs nightly, for `-Z build-std`.

```sh
cargo test                                     # host unit tests for every crates/* library
harness/…/harness selftest /tmp/harness-state  # the runtime itself: reactor, sockets, storage
sudo scripts/interop-wireguard.sh              # M2 against real kernel WireGuard (std example)
sudo scripts/interop-wireguard.sh harness      # the same, via the no_std no-libc harness
sudo scripts/interop-wireguard.sh initiator    # the harness starts the handshake; kernel answers
tests/lab/tls.sh up                            # a TLS front for the lab, for the TLS client
```

The interop script creates a network namespace, configures a real kernel WireGuard interface
inside it, and requires both a completed handshake and a successful in-tunnel ping. In
`initiator` mode the kernel peer is configured with *no* endpoint, so it cannot start a
handshake — a completed one proves ours was accepted. Testing against the reference
implementation rather than against ourselves is what caught the one protocol detail we had wrong
— see `crates/wg-core/README.md`.

## Milestones

| ID | Goal | Verified by |
|----|------|-------------|
| M1 ✅ | WiFi STA + DHCP | device gets an IP, answers `ping` |
| M2 ✅ | WireGuard responder + in-tunnel ICMP | `wg show` reports a handshake; `ping 10.99.0.1` |
| M3a ✅ | NAT out the uplink (UDP) | echo server sees the device's own IP; 4.3 Mbit/s |
| M3 ✅ | TCP forwarding | `curl` and `https://` through the tunnel from the device's IP |
| M3b | `Driver` shim (only if raw sockets prove insufficient) | 30 min soak |
| P0 | Headscale lab over plain HTTP, pcap ground truth | captured `/ts2021` session as test vectors ✅ |
| P1 | Machine/node/disco keys + Noise IK + controlbase | the harness completes a real `/ts2021` handshake ✅ |
| P2 | `micro-h2` + `RegisterRequest` with a preauth key | node appears in `headscale nodes list` ✅ |
| P3 | `MapRequest` long-poll + streaming netmap parse | a live netmap configures WireGuard peers ✅ |
| P4 | Disco on the shared WireGuard socket | a real `tailscaled` answers our probe, and we answer its ✅ |
| P5 | Exit-node advertisement + route approval | the server serves both default routes for us ✅ |

Every one of these is done in the **harness** — the `no_std`, no-libc, no-allocator binary that
runs the same library crates the firmware does. What remains is wiring them into the firmware
itself, which is composition rather than protocol work.

M1 and M2 are complete and verified on real hardware: an ESP32-C6 joins the WiFi network, takes
a DHCP lease, and completes a WireGuard handshake with the Linux kernel's implementation, which
then pings it through the tunnel. The same code passes the same test on the host and in the
harness.

## Running it on a device

Configuration reaches the firmware through `env!`, and `firmware/.cargo/config.toml` holds only
placeholders. Real values live in a gitignored `.env` at the repository root — copy
`.env.example` and fill it in.

```sh
scripts/flash.sh                               # build and flash, then monitor
sudo scripts/device-peer.sh up 192.168.6.163   # this machine becomes the peer; pings the tunnel
sudo scripts/device-peer.sh down               # remove the interface again
sudo scripts/bench-exit.sh 192.168.6.163       # UDP exit-node throughput benchmark
sudo scripts/test-http.sh 192.168.6.163        # HTTP/HTTPS forwarding through the device
```

The firmware still only responds; it never starts a handshake, so whatever sits on the other end
must be able to initiate. `wg-core` itself now does both roles — `Device::set_initiating` turns a
peer from one this device only answers into one it will start handshakes with, which is what a
mesh needs — and `scripts/interop-wireguard.sh initiator` verifies that half against the kernel.

## Forwarding

Both UDP and TCP are forwarded out of the WiFi uplink from the device's own address, so it works
as a general exit node: a client whose default route points into the tunnel resolves names,
fetches HTTP, and completes TLS handshakes, all appearing to the outside world as the ESP32.

The two protocols are translated differently. A UDP flow gets an ordinary `UdpSocket` on the
station interface, so the stack writes the outer headers itself and no checksum fixup is needed.
TCP cannot work that way — a `TcpSocket` would terminate the connection on the device instead of
passing it through — so segments are translated individually over a raw socket, with incremental
checksum updates (RFC 1624) and MSS clamping to the tunnel's MTU.

The plan expected TCP to need a custom `Driver` shim, on the theory that smoltcp would answer
forwarded segments with its own RST. It does not: smoltcp suppresses the RST for any packet a
raw socket consumes, so the shim turned out to be unnecessary.

MSS clamping matters more than it looks. Without it a connection opens normally and then hangs
the instant it carries a full-size segment, because that segment exceeds the tunnel MTU and is
silently dropped.

## Measured throughput

`scripts/bench-exit.sh` measures UDP.
`scripts/bench-exit.sh` runs a client in a network namespace so its traffic genuinely takes the
tunnel, and an echo server that reports the source address it observes — which is the actual
proof of translation, and reads as the device's LAN address rather than the tunnel client's.

With 1024-byte payloads on 2.4 GHz WiFi: **4.3 Mbit/s peak** through the device (2.16 Mbit/s of
payload in each direction, 264 packets/s), and 3.85 Mbit/s sustained below 5% loss.

HTTP downloads through the same path run at **2.6–3.4 Mbit/s** (a 2 MiB body in 5–6 s),
measured by `scripts/test-http.sh`.

The limit is not the cryptography. Sweeping payload size shows a fixed cost of roughly 2.3 ms
per packet on top of a much smaller per-byte cost, which is the signature of a serialized path:
the tunnel task handles one packet from end to end — decrypt, forward, await the reply, encrypt
— before starting the next, so throughput tracks the WiFi round trip rather than the CPU.
Splitting the two directions into separate tasks so they pipeline is the obvious next
optimisation, and is where any real gain lives.

## Scope limits (v1)

IPv4 only. MTU 1280 on the client side, no fragmentation. The firmware is WireGuard responder-only — the peer
always initiates, and rekeying works by expiring the session so the peer re-initiates. No
cookie/mac2 DoS machinery (the replay window *is* implemented). Throughput of a few Mbps.

## References

- `tailscale.com/control/controlbase`, `tailcfg.go`, `disco.go`
- `headscale` `hscontrol/noise.go`, `hscontrol/poll.go`
- [tailscale/tailscale-rs](https://github.com/tailscale/tailscale-rs) for wire formats

## License

Dual-licensed under MIT or Apache-2.0, at your option. Each `crates/*` library is written to be
independently publishable under the same terms.
