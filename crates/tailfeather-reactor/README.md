# Tailfeather async reactor

A shared userspace mesh client for native applications and allocation-free
Embassy applications. `tailfeather` retains protocol state and codecs;
`tailfeather-reactor` owns asynchronous control, DERP, direct WireGuard, and
inner IPv4 TCP scheduling. Both adapters run the same `runtime::Runtime`.

The crate is an independent Cargo workspace, like `hosted/` and `firmware/`,
so platform dependencies do not enter the portable library's Bazel closure.
It currently requires Rust 1.91, matching smoltcp 0.13's requirement.

| Feature | Effect |
| --- | --- |
| default (empty) | Executor-independent, allocation-free core and TCP APIs |
| `embassy` | Embassy-net sockets, verified embedded TLS, Embassy clock |
| `std` | Tokio sockets, verified rustls TLS, filesystem state, owned TCP storage |
| `alloc` | Optional owned TCP buffers without selecting an executor |
| `fast-curve25519`, `peer-names`, `hosted-policy` | Explicit core performance/metadata/policy budgets |
| `accelerated-crypto` | CPU-dispatched fused AEAD on supported native targets; portable fallback elsewhere |

`std` and `embassy` can coexist for host testing. `embassy` does not enable
`std`, `alloc`, a global time driver, a timer-queue size, or a HAL. Applications
choose their Embassy time driver, network runner, critical sections, and DNS
capacity. The allocation-free probe instantiates the complete runtime in an
Embassy executor task on `riscv32imac-unknown-none-elf` without an allocator.

## Application ownership

Applications supply a `Node<PEERS>`, `tcp::Storage<N, BUFFER>`, a
`runtime::Buffers<PEERS>`, configuration strings/CA bytes, and durable `State`.
Place these arenas in application-owned static storage on embedded targets.
`Network` supplies a monotonic clock, a trusted wall clock, cryptographic RNG,
verified TLS streams, and a single bound UDP socket. The Embassy adapter takes
an existing `embassy_net::Stack`, UDP socket, HAL RNG factory, and `TlsClock`.
The application continues running its Embassy network runner.

The shared runtime provides enrollment and authority-bound identity restoration,
streaming maps and endpoint updates, two cancellable DERP workers, STUN discovery
on the data socket, direct-path discovery, WireGuard rekeys, TCP connect/listen,
half-closes, and acknowledged drain. Oversized policies/maps stop the client;
source ownership and ingress ACL checks apply before delivering plaintext TCP.
Both modes expose the same runtime and `embedded_io_async` stream API. Peer,
socket, packet, and byte budgets are explicit configuration choices.

Create the platform objects, then drive the runtime alongside application work:

```rust,ignore
use embedded_io_async::Write;

let mut node = runtime::restore::<_, _, 32>(&config, &network, &state)?;
let client = runtime::Runtime::<_, _, 32, 8>::new(
    config, &mut node, &network, &state,
)?;
let mut arena = tcp::Storage::<8, 8192>::new();
let sockets = tcp_async::Tcp::new(
    tcp::NetStack::<8, 8>::with_storage(1, &mut arena),
);
let mut links = runtime::Buffers::<32>::new();
embassy_futures::select::select(client.run(&sockets, &mut links), async {
    client.ready().await?;
    let mut stream = client.connect(&sockets, peer_ipv4, 2222, 49152).await?;
    stream.write_all(b"hello").await.map_err(|_| "TCP write")?;
    stream.shutdown().map_err(|_| "TCP shutdown")?; // preserve the response reader
    // Read the response, then drop streams/listeners before sockets.drain(...).
    Ok::<_, &'static str>(())
}).await;
```

`Network::receive` must be cancellation-safe. `State` must enforce exclusive
identity ownership and atomic durable replacement. A timestamp reservation is
committed before emitting an initiation; idle polling performs no timestamp
writes. Reloading starts above the persisted reservation after clock rollback.
The native `FileState` holds an exclusive directory lock, including on Android.
The application supplies durable embedded storage; the compile probe's fixture
state and deterministic RNG are for compilation only.

`Tcp::run` keeps RX progressing while TX is backpressured. It drains bounded
bursts without moving the packet arena, wakes on application work, and sleeps
until TCP deadlines when idle. Listener backlogs survive simultaneous SYNs and
failed handshakes. Handles include a generation so reused slots reject stale
handles. Use a new stack ID when replacing a stack whose raw handles may survive.

## CPU acceleration and packet backends

The portable RustCrypto implementation already dispatches SIMD on x86. The
optional accelerated provider reuses ring's fused ChaCha20-Poly1305 assembly and
runtime CPU dispatch on little-endian native x86_64/AArch64 targets. It preserves
WireGuard's algorithm, nonce layout, tags, and replay checks. Authentication
failure clears the output buffer on both providers. Bare-metal and WebAssembly
targets retain the portable provider, including when the feature is unified by
a larger dependency graph.

`native::CpuCapabilities::detect()` reports the configured AEAD provider and
available CPU extensions. Detection does not force instructions unsupported by
the CPU or OS. Run `cargo run --features std,accelerated-crypto --example cpu`
from this directory to inspect it. `hosted/` enables acceleration for native
applications; it reuses this crate's TCP, routing, queues, clocks, sockets, TLS,
filesystem storage, and RNG adapters while retaining its thread/duplex-stream API.

`PacketIo::send_batch` and `Network::send_batch` are burst submission hooks for
alternative userspace packet engines. The default preserves ordering and
backpressure using individual sends. A DPDK/ring adapter can implement the hook
without changing the protocol or TCP implementation. This crate does not include
a DPDK driver.

## Verification and local throughput

```sh
cargo test --locked --features std,embassy,accelerated-crypto
cargo test --locked --no-default-features --features embassy
cargo clippy --locked --all-targets --features std,embassy,accelerated-crypto -- -D warnings
cargo build --locked --manifest-path probe/Cargo.toml --target riscv32imac-unknown-none-elf
```

The same bidirectional TCP/half-close/drain contract runs with caller-owned and
owned buffers and Tokio/Embassy clocks. Real Headscale tests run the common
runtime with either storage strategy, verified private-CA TLS, DERP, direct UDP
with control/DERP offline, durable reconnect without a key, and rejected enrollment:

```sh
TAILFEATHER_FIXTURE_RUNTIME=reactor-fixed python3 hosted/tools/test-headscale.py
TAILFEATHER_FIXTURE_RUNTIME=reactor-owned python3 hosted/tools/test-headscale.py
```

Run those commands from the repository root. The fixture uses a disposable
container, private credential files, and automatically selected loopback ports.

The release benchmark transfers complete TCP flows through bounded in-memory
packet rings. The default transport case measures TCP with optional WireGuard
sessions and replay checks. `--mesh` runs the complete shared runtime, including
cold handshakes, direct discovery, routing, source ownership, ingress policy,
actor queues, and TCP. Its trusted fixture map grants the peer TCP port 2222.
Timings exclude connection/handshake setup and include both endpoints on one
worker. It prints three JSON samples after warmup and checks received length
and checksum.

```sh
cargo bench --locked --no-default-features --features embassy --bench throughput -- --buffers fixed
cargo bench --locked --no-default-features --features embassy,accelerated-crypto --bench throughput -- --buffers fixed
cargo bench --locked --features std,embassy,accelerated-crypto --bench throughput -- --buffers owned
```

Add `--mesh` to any command to measure the full runtime. To build and measure
all six buffer/feature combinations sequentially and save the samples plus CPU
and compiler metadata, run `python3 tools/benchmark.py --output results.json`
from this crate. On Linux, `--cpu N` pins each measurement to one CPU.

Compare payload Gbit/s, packet rate, and the active provider. Packet-rate figures
include ACKs; packet-byte figures include inner headers and WireGuard padding/tags.
These local measurements establish packet-engine CPU capacity and exclude NIC,
outer UDP/IP/Ethernet, kernel socket, coordinator, and DERP service costs.

A local Ryzen 9 7900 run (Rust 1.95.0, generic release target, fat LTO, CPU 10,
64 MiB, median of three samples) produced these payload Gbit/s values:

| Mode | Buffers | Full runtime, portable | Full runtime, accelerated | TCP + WG, accelerated | TCP alone |
| --- | --- | ---: | ---: | ---: | ---: |
| `no_std` | fixed | 1.10 | 2.37 | 4.58 | 9.84 |
| `std` | fixed | 1.01 | 1.47 | 2.92 | 6.36 |
| `std` | owned | 1.06 | 1.70 | 3.71 | 7.84 |

[Raw samples and environment](benchmarks/ryzen-7900.json) include both endpoints
on one worker. The faster no-std results also use an Embassy clock, while std
uses Tokio; code generation and host load can affect these comparisons. These
measurements support gigabit-class local packet processing, not a physical NIC
wirespeed claim or a 10 Gbit/s guarantee. Use the complete-runtime figures when
budgeting SDK throughput; transport-only numbers omit routing and actor work.
