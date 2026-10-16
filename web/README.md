# tailfeather in the browser

Open **<https://no-std-rs.github.io/tailfeather/>** to run the browser client.
Join your tailnet with the Tailscale sign-in link or an auth key, then choose
a peer and open an SSH terminal. On first use, choose an account on that device;
later connections reuse it automatically.

A web page that joins a Tailscale tailnet **as its own node** and opens tabbed
SSH terminals to peers. Connections keep their own output and authentication
prompts when switching tabs. Network details (node keys, endpoints, DERP map,
and logs) are available in the diagnostics drawer. All networking is tailfeather compiled to
`wasm32-unknown-unknown`; the browser supplies only WebSockets, `fetch`,
timers, randomness, `localStorage`, and the DOM.

```
web/
  client/          the page: Rust crate `tailfeather-web` (its own Cargo workspace),
    src/           wasm-bindgen API + runtime
    www/           index.html, app.js, style.css (no framework)
    e2e/           Playwright scripts (credential-free checks, full SSH run)
    build.sh       cargo -> wasm-bindgen -> web/dist
  relay/           optional Cloudflare Worker WebSocket relay (separate)
  dist/            build output (gitignored)
```

## How it works

```
 xterm.js ── russh ──(tokio duplex)── smoltcp TCP ── tailfeather Node ── WireGuard ── DERP over WebSocket ── peer
                                                        │
                                                        └── control: fetch /key, ts2021 (Noise + HTTP/2) over WebSocket
```

- **Control.** `GET https://controlplane.tailscale.com/key?v=131` with
  `fetch()` (it is CORS-enabled). The Noise IK initiation is computed first
  (`tailfeather::control::transport::initiate`) and sent in the WebSocket URL,
  `wss://controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=<base64>`,
  subprotocol `tailscale-control-protocol`, because a browser cannot set
  request headers on a WebSocket. The server's Noise response is the first
  thing on the socket (`transport::complete`). Over WebSocket the server sends
  nothing more until the client's HTTP/2 preface, so the optional early
  payload is read after HTTP/2 starts (`DeferredNoiseStream`). From there the
  registration, streaming map, and endpoint update are tailfeather's existing
  `Http2`/`MapStream`/`send_endpoint_update`.
- **Registration.** With an auth key the node registers directly. Without one
  the server answers with an `AuthURL`; the page shows it as a link and the
  client repeats the request with `Followup: <AuthURL>` (a long poll) until the
  node is approved. After the first successful registration the node persists
  "enrolled", reconnects, and never sends the auth key again — exactly the
  firmware's state machine.
- **Identity.** The node's `PersistState` blob is kept base64-encoded in
  `localStorage["tailfeather.state"]`, acknowledged through
  `Node::persistence_result`. `Date.now()` is the trusted clock.
- **Data plane.** A page has no UDP, so the node runs in tailfeather's
  relay-only mode (`Node::set_direct_paths(false)`): no disco probes, no direct
  transmits, every WireGuard packet through DERP, disco pings that arrive over
  DERP answered over DERP. The node publishes no endpoints and a preferred DERP
  region (by default the SSH target's home region; overridable), so peers reach
  it there. `Node::set_initiate_on_demand(true)` makes it handshake only with
  peers it has traffic for, instead of every peer in the netmap.
- **DERP.** `wss://<derp host>/derp`, subprotocol `derp`; the server-key frame
  follows the upgrade directly. `tailfeather::derp::Client` does the handshake
  and framing; pings are answered, `PeerGone` clears the learned relay.
- **TCP and SSH.** smoltcp (`Medium::Ip`, this node's tailnet /32, MTU 1280)
  hands every transmitted packet to `Node::encapsulate_ipv4` for the peer that
  owns the destination; decrypted packets are accepted only if their source is
  one of the sender's addresses (WireGuard cryptokey routing). russh runs over
  a `tokio::io::duplex` bridged to the smoltcp socket; its keepalive and
  inactivity timers are off because there is no Tokio runtime in a page.
- **SSH trust.** Host keys are trust-on-first-use: the SHA-256 fingerprint is
  shown and stored per `ip:port` in `localStorage`; a changed key is refused
  with a warning ("Forget host key" clears it). Authentication tries `none`
  (what Tailscale SSH accepts when the ACL allows the tailnet identity; its
  "check" mode prints a login link as a banner), then keyboard-interactive,
  password (prompted in the terminal), then a pasted OpenSSH private key.

Library changes this needed, all unit-tested and allocation-free:
`transport::{initiate, complete}` (the ts2021 handshake split; `establish` is
composed from the same pieces and unchanged on the wire),
`RegisterRequest::write_followup`, relay-only mode and on-demand initiation in
`Node`, and a `peer-names` Cargo feature (off by default, so firmware RAM is
unchanged) that keeps each peer's MagicDNS short name.

## Build

Needs Rust with the `wasm32-unknown-unknown` target, Node.js/npm, and a clang
that can target wasm32 (ring compiles C). `build.sh` uses
`$CC_wasm32_unknown_unknown`, else `clang` on `PATH` if it lists wasm32, else
Homebrew's `/home/linuxbrew/.linuxbrew/opt/llvm@21/bin/clang`. It installs the
`wasm-bindgen` CLI version pinned by `Cargo.lock` into `web/client/.tools`.

```sh
cd web/client
./build.sh                 # -> web/dist (index.html, app.js, pkg/, vendor/)
./build.sh --static        # static hosting without the Worker-only auth-key link
cargo test                 # host tests: pure logic, and a relay-only data-plane loopback
```

## Run

The `Publish web client` GitHub Actions workflow builds and tests the static
client, then deploys `web/dist` to GitHub Pages on every push to `main`.
It can also be run manually. Assets use relative URLs so the application works
under the `/tailfeather/` project path. GitHub Pages serves the browser client;
the Cloudflare Worker described below is optional.

Any static server works if it serves `.wasm` as `application/wasm`:

```sh
node web/client/e2e/serve.mjs 8000        # or: cd web/dist && python3 -m http.server 8000
# open http://127.0.0.1:8000/
```

Fill in a hostname, optionally an auth key, and **Connect**. Without a key,
open the login link that appears. When the netmap shows this node's address,
pick a peer and **Open terminal**. Tailscale authenticates the connection, while
the destination still needs a local OS account. The page asks for that account
once per device and port, and reuses it on later connections. With **Remember**
on, the choice survives a reload. Change it, or enter a manual address, port,
or private key, under **SSH options** in the Tailnet drawer.

The deployed site at <https://tailfeather-web.pawelchcki.workers.dev> has a third
way in: <https://tailfeather-web.pawelchcki.workers.dev/connect>. That path is
behind Cloudflare Access. After you log in, the Worker mints a single-use,
ephemeral, untagged key and redirects to `/#tskey=…`. The page removes the key from
the URL, connects with it once, and never stores it. See
[`relay/README.md`](relay/README.md#one-time-keys-get-connect).

The optional **Relay** setting (Advanced) routes both WebSockets through the
`web/relay` Worker: `wss://<relay>/relay/control/<control host>/ts2021?…` and
`wss://<relay>/relay/derp/<derp host>`.

Each SSH connection opens a new tab. Disconnect ends that connection and keeps
its output; closing the tab removes it. Stopping or reconnecting the browser
node disconnects all its SSH sessions. Connection tabs share one browser node;
the existing lock still prevents two separate browser tabs from running the
same saved node identity.

SSH tabs use `user@hostname` from the Tailscale peer map, with a fuller name or
the IP to distinguish duplicate names. The browser title follows the selected
SSH tab. Ctrl+/ sends Ctrl+_ to the terminal; on mobile, tap Ctrl and type `/`.

HTTP(S) links are clickable in the terminal. **Links in this terminal** also
lists the most recent 20 URLs as native links, so they can be tapped on mobile.
A Tailscale SSH approval URL from a server banner or terminal output gets an
**Approve Tailscale SSH** button in its connection tab. Detection handles split
SSH messages, ANSI colors and terminal wrapping. Approval opens in a new browser
tab only when you tap the link; the SSH connection continues waiting. Terminal
output and detected links are kept in memory only, and disappear with the tab.
Dismiss the approval notice once finished; it also hides when SSH closes. The
URL remains available in that tab's links list.

Focus mode expands the workspace to the viewport. Fullscreen uses the browser
API when available, with focus mode as the fallback. Mobile controls provide
Ctrl, Esc, Tab, arrow keys and keyboard focus for the active connection.

## Tests

```sh
cd web/client
npm ci && ./build.sh
npm run test:e2e           # credential-free, against the real Tailscale service
npm run test:e2e -- --local # browser/UI and local SSH checks without live DERP/control checks
npm run test:links         # streaming URL and trusted Tailscale origin checks
npm run test:labels        # hostname selection and duplicate peer names
npm run test:pages         # after ./build.sh --static: app at /tailfeather/
npm run test:pages -- https://no-std-rs.github.io/tailfeather/ --live
```

`e2e/run.mjs` runs headless Chromium (playwright-core 1.60.0 = Chromium 1223,
found in `~/.cache/ms-playwright`; `CHROMIUM_PATH` overrides). It checks that

- the page loads with `application/wasm` and no CSP violations;
- the browser's SSH client works: russh (ring crypto, key exchange), host-key
  trust on first use and pinning (a changed key is refused), `none` and
  keyboard-interactive authentication with a banner, a PTY shell and its exit
  status — against a local `ssh2` server reached through a WebSocket
  byte-stream bridge on the page's origin (`sshOverWebSocket`, a diagnostic
  entry point that bypasses the tailnet);
- a DERP handshake over WebSocket completes with a hosted region
  (`DERP_REGION`, default `waw`);
- the production control plane answers the registration with an `AuthURL`
  (printed, never opened).

`RELAY=https://…` runs the DERP and control checks through a relay.

The host test `loopback_tests` joins two relay-only, on-demand nodes through
an in-memory DERP relay and carries a TCP connection over smoltcp and
WireGuard from a cold start, using the page's routing and cryptokey checks.

### Full SSH test (needs tailnet approval)

```sh
cd web/client
TS_AUTHKEY=tskey-auth-… npm run test:ssh       # or without TS_AUTHKEY: approve the printed link
```

`e2e/ssh.mjs` keeps a persistent Chromium profile (`TF_E2E_PROFILE`, default
`web/client/e2e/.profile`, gitignored) and a fixed origin
(`http://127.0.0.1:8765`, `TF_E2E_PORT`) so the node identity and remembered
settings survive between runs. It connects (auth key typed into the form, never
printed; "remember" on), prints the `AuthURL` and waits up to
`TF_AUTH_WAIT_MIN` (default 10) minutes if approval is needed, then opens SSH
to `TF_SSH_HOST` (default `100.113.109.28`) as `TF_SSH_USER` (default `pawel`),
runs `echo TAILFEATHER_E2E_OK; uname -n`, and asserts the output is the marker
followed by `TF_EXPECT_HOST` (default `bazzite`). If Tailscale SSH is in check
mode, the terminal output (with its login link) is printed while it waits.
The tailnet policy must allow this node to reach the target on port 22 and
permit Tailscale SSH for the user.

## Security notes

- The auth key is a credential. It is never logged or sent anywhere but the
  control plane, and after the first enrollment it is not sent at all.
- With **Remember** on (the default), the page stores its settings in
  `localStorage["tailfeather.settings"]`, *including the auth key, the SSH user
  and any pasted private key*, so they are prefilled next time. Anyone with
  access to this browser profile can read them. Turn Remember off to keep
  secrets in memory only. **Forget this browser node** deletes the node
  identity and every saved setting and secret (remembered SSH host keys are
  kept; "Forget host key" clears one).
- The node identity (machine, node and disco private keys) is in
  `localStorage["tailfeather.state"]`; treat the profile as the node.
- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src
  'self' https: wss:`. `style-src` also allows `'unsafe-inline'` because
  xterm.js injects `<style>` elements for its renderer (with `style-src 'self'`
  alone Chromium blocks them). xterm is served from the vendored npm copy, not
  a CDN.
- Decrypted packets whose source is not an address of the sending peer are
  dropped. There is no Tailscale packet filter beyond that: nothing listens on
  this node, and smoltcp resets unsolicited connections.

## Limitations

- DERP only: every packet is relayed, so throughput and latency are those of
  the relay path. IPv4 only.
- One control server (`controlplane.tailscale.com`); no Headscale setting.
- The CSP allows `wss:` but not plain `ws:` to other origins, so a relay must
  be HTTPS (or share the page's origin).
- Tailnets larger than 32 peers are truncated (the netmap says so).
- An expired node key is reported, not rotated: forget the node and log in
  again.
- If `localStorage` is unavailable the node refuses to connect, since it cannot
  keep its identity.
- In a sandboxed headless Chromium with no usable fonts, xterm's cell metrics
  are zero; the scripts therefore read terminal output from the byte stream,
  not the screen.
