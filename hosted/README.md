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
let address = node.ready().await?;
let stream = node.connect(address, 2222).await?;
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
