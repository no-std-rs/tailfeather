# Remote loopback links and OAuth

Tailfeather can open a remote SSH host's `localhost`, `127.0.0.1`, or `[::1]`
HTTP(S) links on your browser device. Choose **Open remote host:port** in
**Links in this terminal**, or activate the link inside the terminal. The action
belongs to that SSH connection. Other HTTP(S) links, including Tailscale SSH
approval links, open normally.

This requires desktop Firefox and a local Node.js 22+ companion on Linux or
macOS. An ordinary web page cannot bind an OS TCP listener. The companion binds
the original URL's loopback address and port on your browser device. The Firefox
extension relays its TCP bytes to the page, and the page opens `direct-tcpip`
channels through that terminal's existing authenticated, host-key-checked SSH
connection. The SSH server must permit local TCP forwarding to the destination.
Tailscale SSH servers or policies that reject `direct-tcpip` cannot use this
feature; the page reports the refusal.

HTTPS stays end-to-end between your browser and the remote service: the companion
does not terminate TLS. The remote service still needs a certificate your browser
accepts for its original loopback hostname.

## Install

Use a trusted local checkout or the `loopback/` directory included in the built
web-client artifact. The companion has no npm dependencies.

```sh
node web/loopback/install.mjs
```

The explicit installer copies the host under
`~/.local/lib/tailfeather-loopback/` and registers
`org.tailfeather.loopback` with Firefox's per-user native-messaging manifest
directory. The manifest permits only extension ID
`loopback@tailfeather.no-std-rs` and pins your Node executable's absolute path.
On macOS the manifest lives under
`~/Library/Application Support/Mozilla/NativeMessagingHosts/`; on Linux it is
`~/.mozilla/native-messaging-hosts/`.

In Firefox, open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
Add-on**, and select `web/loopback/extension/manifest.json`. Reload Tailfeather
after loading the extension. This developer installation lasts until Firefox
restarts; load it again after restarting. No signed persistent add-on is
distributed yet. The shipped extension allows only the official GitHub Pages
client and the documented Cloudflare Worker client. Forwarded loopback service
pages and OAuth callback pages receive no extension bridge; they use ordinary
browser TCP connections to the listener opened by your Tailfeather terminal.
For a private deployment, use a separate manifest copy with its exact trusted
HTTPS application URL pattern in `matches` before loading.

Local development requires an explicit opt-in: copy `extension/` to a temporary
directory, add your local application's match pattern to that copy's `matches`,
and load only the copy in an isolated throwaway Firefox profile. Local patterns
also trust any remote service pages matching those patterns. Keep that developer
copy out of your normal browser. The automated acceptance runner makes this
temporary opt-in copy itself; the distributed manifest stays HTTPS-only.

Sandboxed/Flatpak Firefox must be able to execute the installed Node binary and
read the native-host manifest; use a desktop Firefox installation with native
messaging access. This integration does not support Android/iOS browsers or
Chromium. On those devices use a native SSH client with local forwarding or
rclone's separate-device authorization procedure.

## Rclone Google Drive authorization

1. In a Tailfeather SSH terminal, run
   `rclone authorize drive --auth-no-open-browser` with your configured OAuth
   desktop client. Rclone must listen on a loopback address on that SSH host.
2. Open **Links in this terminal** and choose **Open remote 127.0.0.1:53682**
   (or the printed hostname and port). Allow the user-initiated browser popup.
3. Sign in with Google in the opened tab and approve the requested permissions.
   Google's original registered loopback redirect, such as
   `http://127.0.0.1:53682/`, now reaches the local companion. Its new TCP
   connection traverses the same SSH session to the original remote rclone
   listener. Rclone validates its original state and finishes authorization.
4. Keep the SSH terminal and Tailfeather page open until rclone finishes. Close
   or disconnect that terminal afterward to release the local listener.

Neither the initial URL nor the OAuth `redirect_uri` is rewritten. No remote
listener is published on the internet. If the browser device already uses that
port, including a forward from another terminal, setup fails; stop that owner
first. Two terminals cannot silently share a callback listener. `localhost`
binds both `127.0.0.1` and `::1`; a system without IPv6 loopback support must use
a URL with an explicit available numeric loopback address.

## Lifetime and data handling

Each SSH tab has its own extension port, native process, listeners, and SSH
channels. Closing/disconnecting the terminal, stopping its browser node, closing
the page, or losing the extension/native process releases the forwarding
resources. Closing only the authorization popup leaves forwarding active until
the SSH terminal ends. The companion limits listeners to eight per terminal and
active TCP streams to 32, with bounded 32 KiB transfer frames and backpressure.
Idle TCP streams expire after two minutes; listeners remain until disconnect.

OAuth states, codes, tokens, raw TCP data, and detected URLs stay in memory. They
are not written to Tailfeather logs, extension storage, native stdout diagnostics,
or persistent settings. Native stdout is solely the private Firefox protocol.
As with `ssh -L`, other local applications can reach an explicitly enabled local
forward, so stop it when finished. The remote application must validate OAuth
state and enforce its own authorization.

## Verification

```sh
cd web/client
npm run test:links
./build.sh --static
npm run test:e2e -- --local
```

For the actual Firefox extension/native-messaging acceptance test on Linux with
`bwrap` installed, install Playwright's Firefox into a temporary browser cache
and run:

```sh
cd web/client
PLAYWRIGHT_BROWSERS_PATH=/tmp/tailfeather-firefox-browsers npx --no-install playwright-core install firefox
PLAYWRIGHT_BROWSERS_PATH=/tmp/tailfeather-firefox-browsers npm run test:firefox-loopback
```

To also exercise **real rclone authorization and token exchange**, provide the
pinned rclone v1.75.2 executable through `RCLONE_TEST_BINARY`. For Linux amd64,
download the official release and verify the pinned archive checksum:

```sh
curl --fail --location --output /tmp/tailfeather-rclone.zip https://github.com/rclone/rclone/releases/download/v1.75.2/rclone-v1.75.2-linux-amd64.zip
printf '%s  %s\n' 349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702 /tmp/tailfeather-rclone.zip | sha256sum --check -
unzip -p /tmp/tailfeather-rclone.zip rclone-v1.75.2-linux-amd64/rclone > /tmp/tailfeather-rclone
chmod 700 /tmp/tailfeather-rclone
RCLONE_TEST_BINARY=/tmp/tailfeather-rclone PLAYWRIGHT_BROWSERS_PATH=/tmp/tailfeather-firefox-browsers npm run test:firefox-loopback
```

The real-rclone test uses Drive's documented
[`auth_url` and `token_url` overrides](https://rclone.org/drive/#drive-auth-url)
to point exclusively at a local mock OAuth provider. Real rclone runs in a
private network namespace, modeling the remote SSH host's independent loopback
interface. Private Unix sockets transport raw TCP to the SSH fixture and local
provider; no service is exposed publicly. Rclone prints its own initial auth URL,
the browser returns to its unchanged registered `http://127.0.0.1:53682/`, and
rclone exchanges the code and exits successfully with verified mock access and
refresh tokens. The command uses `--config /dev/null`; its token output stays
in memory and is never emitted in test diagnostics. This uses rclone's supported
OAuth-only [authorize implementation](https://github.com/rclone/rclone/blob/v1.75.2/fs/config/authorize.go),
with dummy client values, no Google requests, and no real account credentials.

This runner uses Firefox's WebDriver BiDi temporary-add-on installation API. It
first installs the shipped extension and verifies that local service/callback
pages cannot create native companion listeners. It then installs a temporary
extension copy explicitly permitting the local test application and runs the
OAuth/forwarding fixture. It creates its own temporary profile and native
manifest. Bubblewrap mounts a fresh
home overlay with only the required source, dependencies, and browser cache
readable; the user's actual home and Firefox profile are not modified. The
temporary profile and manifest are removed afterward.

The `ssh-loopback` browser test runs the actual WASM SSH client, a real local
SSH server enforcing `direct-tcpip`, the shipped extension content script, and
the native companion's real TCP listeners. It replaces Firefox's extension
runtime API with an in-process test bridge. A mock OAuth provider requires a
sign-in action and returns the unchanged registered loopback callback, whose
state/code reach the simulated remote rclone listener. It verifies port
collision isolation between terminal tabs, server forwarding-policy rejection,
secret-free logs/storage, and port reuse after disconnect. Separate tests cover
the native messaging frame parser, loopback-only binds, resource teardown, and
streamed URL recognition.

The same OAuth fixture was also exercised locally with an actual isolated
desktop Firefox installation, its installed temporary extension, and native
messaging to the companion. Firefox's profile and native-host manifests were
isolated in temporary directories; no real browser profile was modified.
The mock flow also round-trips a 256 KiB binary request/response across frame
boundaries. CI uses the Chromium runtime shim described above.

The pinned real-rclone acceptance test also completed locally through the actual
Firefox extension/native companion and SSH transport, including rclone's token
exchange and successful exit. The OAuth provider and tokens are local test
fixtures. Live Google account sign-in remains a manual acceptance step requiring
the user's OAuth credentials; the sequence above describes that procedure.

To uninstall, remove the extension, its `org.tailfeather.loopback.json` manifest,
and `~/.local/lib/tailfeather-loopback/`.
