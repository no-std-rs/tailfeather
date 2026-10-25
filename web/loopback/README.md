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
distributed yet. The extension allows the official GitHub Pages client, the
documented Cloudflare Worker client, and local development pages. For a private
deployment, add its exact HTTPS URL pattern to the manifest's `matches` list
before loading. Treat permitted pages as trusted clients of the companion.

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

This verifies the complete routing and callback mechanism with a simulated
provider. It does not claim live Google account authorization, real rclone
completion, or an installed Firefox native-messaging session has been exercised
in CI. Those require a desktop installation and the user's OAuth credentials;
the manual sequence above is the acceptance procedure.

To uninstall, remove the extension, its `org.tailfeather.loopback.json` manifest,
and `~/.local/lib/tailfeather-loopback/`.
