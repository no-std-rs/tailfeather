# Tailfeather hosted runtime

`tailfeather-hosted` embeds the portable Tailfeather node in native Windows,
macOS, Linux and Android applications. Tokio sockets carry control TLS/Noise, DERP and
UDP; smoltcp provides userspace IPv4 TCP inside authenticated WireGuard tunnels.
It requires no TUN device, driver, administrator rights or installed VPN client.
The no-std core remains independent of this adapter.

```rust,no_run
# async fn example() -> std::io::Result<()> {
use tailfeather_hosted::{Client, Config};
let session = tempfile::tempdir()?;
let node = Client::start(Config {
    directory: session.path().into(),
    control_url: "https://headscale.example".into(),
    hostname: "my-session".into(),
    auth_key: std::env::var("FIXTURE_AUTH_KEY").unwrap(),
    control_ca_der: Vec::new(), // optional private root CA in DER format
    relay_only: false,
    ephemeral: true,
})?;
let own_address = node.ready().await?;
// Obtain the target's current address from your application's approved device
// directory (for example the rzero backend), rather than using own_address.
let peer_address = "100.64.0.2".parse().unwrap();
let stream = node.connect(peer_address, 2222).await?;
# Ok(()) }
```

Each independent session uses its own state directory. An ephemeral provider key
and `ephemeral: true` register a disposable node on either Tailscale or Headscale;
the coordinator controls offline node removal timing. The same identity is kept
across reconnects during that session. Keep the temporary directory alive until
all client clones and streams have been dropped. Persistent consumers can set
`ephemeral: false` and reuse their private directory without a new auth key.
State is bound to the HTTPS control origin, replaced atomically, and protected by
an exclusive directory lock. Corrupt or mismatched state fails closed.
Android uses rustix file locking because the standard library's file locking
methods are unsupported there. Build Android applications against Android libc
when they need the platform DNS resolver.
WireGuard timestamp ranges are reserved ahead in a private atomic sidecar, so
reusing an identity after a clock rollback cannot repeat earlier initiations.
The reservation avoids writing on every packet-driver iteration.

`listen(port)` accepts tunnel-only streams after control ACL and cryptographic
source checks. The runtime bounds TCP sockets to 16, listeners to 4, pending
commands to 16 and packet queues to 128. TCP buffers are 64 KiB per direction.
Each listener reserves up to four sockets before polling packets so simultaneous
SYNs can complete without waiting for the application to accept the first stream.
Established connections retain their sockets when the total capacity is reached.
`TAILFEATHER_NET_TRACE=1` prints TCP states and queue sizes without packet contents.
Dropping the last client shuts down the node. Dropping a listener stops new
acceptance. This adapter exposes IPv4 TCP, not system-wide networking or UDP
application sockets. Hosted peer capacity is 128; the core's embedded default remains 32. Hosted
clients enable the `hosted-policy` feature: each of the 32 ACL rules can retain
256 source and 256 destination networks, so provider-expanded device tags do
not overflow the firmware's eight-address budget. Oversized policies still
fail closed; no ACL entries are truncated. Embedded builds retain their small
defaults. The hosted worker reserves a 64 MiB stack for the larger bounded map
and its async staging frames (virtual address space, committed as used).
TCP write shutdown preserves the response reader. Fully dropped streams release
half-closed sockets after acknowledging queued data and FIN, with bounded close
deadlines even when the peer stops responding. Call `Client::drain().await` after
dropping application streams and before dropping the client to retain final writes.
Drain rejects live listeners and returns an error if a close is reset, fails,
or its 15-second deadline expires. FIN acknowledgement is tracked from the
validated TCP flow rather than inferred from an empty send queue.
Directional ACLs govern incoming connection attempts; TCP continuation packets
still require cryptokey source validation and the TCP stack's sequence checks.

Run `cargo test --manifest-path hosted/Cargo.toml --locked` and strict Clippy for
all targets. `examples/headscale.rs` additionally runs registration, private-CA
TLS, real DERP TCP exchange and reconnects against a local Headscale fixture at
`https://localhost:18443`. It takes a directory containing `ca.der` and a private
`keys.json` array of two fixture-only preauth keys; `--ephemeral` exercises
ephemeral registration on both ends. It never accepts keys as command arguments.

Direct mode advertises the bound UDP port on the control connection's local
interface and validates STUN replies received on that same data socket before
publishing reflexive candidates. `relay_only` omits these candidates. TCP races
up to 16 distinct IPv4 DNS answers within a 15-second total connection deadline.
Custom CA DER is validated before the runtime starts. DERP protocol handshakes
have a 20-second deadline and disconnect commands cancel pending handshakes;
valid large extension frames are drained without growing buffers. Invalid or
over-capacity netmaps stop the node, including during endpoint publication, so
an older ACL cannot remain active after an unsupported policy update.

The Headscale fixture runner also accepts `--direct --offline-direct`. After it
prints `READY`, stop the fixture and create `continue` in its directory. It then
establishes a new TCP connection and transfers 1 MiB using direct UDP while both
control and DERP are offline, skipping the reconnect tests that need the server.

A new discovery cycle replaces previous candidates, and changed candidates
restart bounded hole-punch announcements for active peers. NAT discovery refreshes
at control heartbeats after a 30-second interval; changed endpoints are published
even when the preferred relay stays the same. Stateful actor
commands keep FIFO order and bypass backpressured packet sends. Relay writes
have a 15-second deadline; tunnel TCP connection establishment allows 90 seconds
for relay failover, independently of the native TCP dial deadline.

Dropping the final client signals cancellation and joins its worker before the
identity lock is released to the caller. Cancellation does not wait for detached
OS DNS lookups. The Headscale fixture restarts the same identity immediately,
without a timing sleep. Silent established DERP sessions expire 90 seconds after
the last received frame, including when outbound notifications continue.

`python3 hosted/tools/test-headscale.py` runs both production-path scenarios
against a digest-pinned disposable Headscale container with a generated CA.
It needs Docker (or `CONTAINER_ENGINE=podman`) and OpenSSL; the runner selects
free loopback ports automatically. Linux CI runs it after the native tests; fixture keys never leave
its private temporary directory. This includes the 1 MiB transfer regression
and immediate no-key reconnect without a restart sleep.


The userspace TCP stack, routing/source checks, bounded action mailbox, clocks,
outer sockets, TLS and file storage are shared with `tailfeather-reactor`.
That companion crate also exposes an allocation-free Embassy runtime with
caller-owned arenas and the same control/DERP/WireGuard/TCP behavior. Native
hosted applications enable its CPU-dispatched fused AEAD provider. See
[`tailfeather-reactor`](../crates/tailfeather-reactor/README.md) for the feature
matrix, CPU capability diagnostics, and local packet-engine benchmarks.
