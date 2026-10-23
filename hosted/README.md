# Tailfeather hosted runtime

`tailfeather-hosted` embeds the portable Tailfeather node in native Windows,
macOS and Linux applications. Tokio sockets carry control TLS/Noise, DERP and
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

`listen(port)` accepts tunnel-only streams after control ACL and cryptographic
source checks. The runtime bounds TCP sockets to 16, listeners to 4, pending
commands to 16 and packet queues to 128. TCP buffers are 64 KiB per direction.
Dropping the last client shuts down the node. Dropping a listener stops new
acceptance. This adapter exposes IPv4 TCP, not system-wide networking or UDP
application sockets. Peer capacity follows the core's 32-peer limit.

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
valid large extension frames are drained without growing buffers.

The Headscale fixture runner also accepts `--direct --offline-direct`. After it
prints `READY`, stop the fixture and create `continue` in its directory. It then
establishes a new TCP connection and transfers 1 MiB using direct UDP while both
control and DERP are offline, skipping the reconnect tests that need the server.

A new discovery cycle replaces previous candidates, and changed candidates
restart bounded hole-punch announcements for active peers. Stateful actor
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
It needs Docker (or `CONTAINER_ENGINE=podman`), OpenSSL and free loopback ports
18443/13478. Linux CI runs it after the native tests; fixture keys never leave
its private temporary directory. This includes the 1 MiB transfer regression
and immediate no-key reconnect without a restart sleep.
