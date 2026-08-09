# tailfeather

Allocation-free Rust for a small Tailscale-compatible mesh node, plus an
ESP32-C6 IPv4 exit gateway and a no-libc Linux interoperability harness.

This is experimental protocol and embedded-systems software. It is not audited,
not a general-purpose Tailscale client, and not ready to publish as `0.1.0` until
the external release gates below have current evidence.

## Quick start

```sh
cargo test --workspace --all-targets
cargo run -p tailfeather-testkit -- check --json
scripts/no-alloc-guard.sh
```

The harness and firmware are sibling workspaces because each pins a different
bare target:

```sh
(cd harness && cargo build --release)
(cd firmware && cargo build --release)
```

## What works now

| Environment | Current implementation |
|---|---|
| Portable crates | WireGuard initiator/responder, ts2021 Noise, bounded HTTP/2, registration messages, streaming netmaps, disco, DERP, and the cooperative `Node<PEERS>` API |
| Linux harness | No libc, allocator, threads, or hidden runtime; drives live Headscale control, TLS, HTTP/2, registration, maps, disco, DERP, and both WireGuard roles. Netmaps are reconciled through `Node` |
| ESP32-C6 | One `Node<32>` actor owns the tunnel state; Wi-Fi/DHCP, static fallback peer configuration through a transactional map lease, IPv4 UDP/TCP forwarding, and NAT build for the device |
| Offline testkit | Published std-only synthetic-fixture checks with human, JSON, and exact-baseline output |

The ESP firmware does **not** yet run the full hosted control/DERP task set,
trusted-time bootstrap, two-slot flash store, or dynamic route installation.
Hosted Tailscale, pinned Headscale, and the complete physical-device suite must
therefore remain release blockers. The committed captures prove specific codec
behaviour; they are not evidence that a current hosted run passed.

## Crates

| Package | Purpose | Runtime |
|---|---|---|
| [`tailfeather`](crates/tailfeather/README.md) | Public `Node` plus keys, Noise, control, netmap, disco, and DERP; reexports `wirefeather` as `tunnel` and `micro-h2` as `http2` | `no_std`, no allocation |
| [`wirefeather`](crates/wirefeather/README.md) | Sans-I/O WireGuard-compatible handshake, transport, replay, and timers | `no_std`, no allocation |
| [`micro-h2`](crates/micro-h2/README.md) | Bounded client-side HTTP/2 and HPACK | `no_std`, no allocation |
| [`tailfeather-testkit`](crates/tailfeather-testkit/README.md) | Portable offline vectors, replay, reports, and CLI | `std` |

`ts-conformance` remains unpublished and owns privileged/live compatibility
orchestration and repo-only captures.

## Design constraints

- `Node` owns identity, live netmap, tunnel sessions, paths, DERP choice,
  registration state, and deadlines, but owns no transport, clock, executor,
  RNG, or store.
- Control and DERP sessions own their streams and emit decoded events. Node
  actions explicitly request direct sends, control/DERP work, IPv4 delivery,
  persistence, or status changes.
- Maps are applied transactionally with one exclusively borrowed staging lease.
  Unchanged peer keys retain tunnel sessions; removed or rotated keys do not.
- Persistent blobs are versioned and zeroized, include the three identities and
  nondecreasing trusted-time floor, and exclude auth keys, maps, and session
  keys. A new identity is created only by explicit factory reset.
- Project runtime code does not allocate. Fixed bounds are errors, never silent
  truncation. The radio C blob alone has a 64 KiB heap.
- The data plane is IPv4-only with a 1280-byte inner MTU. WireGuard cookies /
  `mac2` are not implemented.

## Verification and release gates

Automatic checks cover formatting, workspace tests, clippy, rustdoc warnings,
the no-allocation harness, firmware release builds, fixture provenance, resource
limits, and package contents. The compatibility suite is pinned to Headscale
v0.29.3 and tailscaled 1.94.2; its exact baselines are authoritative, not a
handwritten pass count.

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
scripts/conformance.sh
scripts/release-gates.sh
```

A release also needs fresh same-commit evidence for hosted Tailscale, pinned
Headscale, physical-device/adversarial tests, stack headroom, resource limits,
cleanup, fixture audit, and both trademark reviews. Hosted integrated checks
must be live `pass`; `todo`, `skip`, `fail`, or unlinked `external` results block
release. Hosted map compression is a hard blocker unless the server accepts an
uncompressed response.

The future publication order is `wirefeather`, `micro-h2`, `tailfeather`, then
`tailfeather-testkit`. Nothing in this repository preparation publishes a crate
or transfers the repository.

## Trademark and repository status

The package name remains `wirefeather`. Publication is blocked until written
authorization records the exact permitted descriptive WireGuard compatibility
wording, acknowledgment, policy link, and non-affiliation disclaimer. Tailscale
wording requires a separate review. WireGuard and Tailscale are marks of their
respective owners; this project is not affiliated with or endorsed by either.

Metadata intentionally retains the current repository URL. After the owner
transfers it, update every package and documentation link to
`https://github.com/no-std-rs/tailfeather`, verify links, and repeat all package
checks.

## References and license

Protocol references include Tailscale's `controlbase`, `tailcfg.go`, and
`disco.go`; Headscale's `hscontrol/noise.go` and `hscontrol/poll.go`; the Noise
and WireGuard specifications; and RFC 7540/RFC 7541.

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.
