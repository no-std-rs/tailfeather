# tailfeather-web relay

A Cloudflare Worker that does two things for the browser build of tailfeather:

1. **Hosts the static site**: the output of `web/client/build.sh` in `web/dist/`,
   served through the `ASSETS` binding.
2. **Relays WebSockets** to Tailscale control and DERP servers. This is optional.
   Browsers can already connect to both directly, so the relay is only for networks
   or servers where direct WebSockets fail.

It is plain ES-module JavaScript with no runtime dependencies. Wrangler is a pinned
dev dependency (`4.120.1`, the version the deployment system uses).

## Contract

| Request (with `Upgrade: websocket`) | Required subprotocol | Upstream |
| --- | --- | --- |
| `GET /relay/control/<host>/ts2021?X-Tailscale-Handshake=<v>` | `tailscale-control-protocol` | `wss://<host>/ts2021?X-Tailscale-Handshake=<v>` |
| `GET /relay/derp/<host>` | `derp` | `wss://<host>/derp` |
| any path outside `/relay/` | – | static assets (`env.ASSETS.fetch(request)`) |

- Every request reaches the Worker first (`run_worker_first: true`). A path under
  `/relay/` never falls through to assets. Unknown relay paths get `404`.
- The control handshake value is forwarded exactly as received. Every other
  query parameter is dropped, and so is the entire DERP query.
- The relay only ever connects to `https://<host>` on port 443, sending
  `Upgrade: websocket` and the same subprotocol. The response is `101` with
  `Sec-WebSocket-Protocol` set to the subprotocol the upstream negotiated.
- Frames are piped both ways as binary with no extra buffering. A text frame
  closes both sides with `1003`. Close codes and reasons are passed through in both
  directions, except that the reserved code `1005` becomes `1000` and `1006`,
  `1015` and other codes the API rejects become `1011`. An error on either
  side closes both sides with `1011`.

Rejections are checked in this order, and all of them happen before any upstream
connection is opened:

| Status | When |
| --- | --- |
| 404 | malformed `/relay/...` path |
| 405 | method is not `GET` |
| 403 | `Origin` is not in `ALLOWED_ORIGINS`, when that list is set |
| 403 | the host is not a strictly valid DNS name or is not on the allowlist |
| 426 | no `Upgrade: websocket` |
| 400 | the required subprotocol was not offered |
| 414 / 400 | control query is longer than 1 KiB, or does not have exactly one well-formed `X-Tailscale-Handshake` |
| 502 | upstream is unreachable, refused the upgrade, or did not negotiate the subprotocol (the upstream body is never echoed) |
| 500 | invalid allowlist configuration (the Worker refuses all relay requests) |

## One-time keys: `GET /connect`

`/connect` gives the page a Tailscale auth key without copying one by hand. The
path is behind a Cloudflare Access application that allows only the owner's email
(my-infra `tofu/cloudflare/tailfeather-web`). The page and the relay stay public.

1. Access sends the browser to the team login, then forwards the request with
   `Cf-Access-Jwt-Assertion`.
2. The Worker verifies that JWT itself: RS256 against
   `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs`, the issuer, the audience,
   expiry, and an email equal to `AUTHKEY_OWNER_EMAIL`.
3. It creates a **single-use, ephemeral, pre-approved, untagged** key that
   expires in 10 minutes, using the `TS_API_TOKEN` secret.
4. It answers `303` to `/#tskey=<key>` with `no-store` and `no-referrer`. The page
   removes the fragment from the URL and history, connects with the key once, and
   never stores or logs it.

The key is untagged on purpose. It creates a node owned by the token's user, and
the tailnet's `autogroup:self` SSH rule covers that node. Tailscale SSH does not let
tagged nodes reach user-owned devices. Unless every one of `ACCESS_TEAM_DOMAIN`,
`ACCESS_AUD`, `AUTHKEY_OWNER_EMAIL` and the `TS_API_TOKEN` secret is set,
`/connect` returns `404`. The endpoint never echoes a Tailscale error body.

## Configuration (`vars` in `wrangler.jsonc`)

| Var | Default | Meaning |
| --- | --- | --- |
| `CONTROL_HOSTS` | `controlplane.tailscale.com` | Comma-separated exact control host names. An empty value allows none. |
| `DERP_HOST_PATTERN` | `^derp\d+[a-z]?\.tailscale\.com$` | Regex for DERP host names. The Worker always anchors it. An empty value allows none. The default matches every hosted DERP server in the current DERP map. |
| `ALLOWED_ORIGINS` | *(empty)* | Comma-separated exact origins, such as `https://tailfeather-web.example.workers.dev`. An empty value allows any Origin. |
| `ACCESS_TEAM_DOMAIN` | `chcki.cloudflareaccess.com` | Access team domain whose keys sign the `/connect` JWT. |
| `ACCESS_AUD` | the `/connect` application's audience tag | Public. It is the `connect_access_aud` output of my-infra `tofu/cloudflare/tailfeather-web`. |
| `AUTHKEY_OWNER_EMAIL` | `pawelchcki@gmail.com` | The one person allowed to mint keys, and it must be the owner of `TS_API_TOKEN`: every key enrolls a node as that user, with that user's tailnet access. A list turns the endpoint off. Access to `/connect` must be restricted to the same person. |
| `TS_API_TOKEN` (secret) | – | Tailscale API access token used to mint keys. Set with `wrangler secret put`; it is never in the config. |

Before any allowlist is consulted, the host must be a lowercase DNS name: no port,
userinfo, IP literal, percent-escape or trailing dot. That means a permissive
pattern still cannot turn the Worker into an open proxy.

**Origin tradeoff.** The Tailscale upstreams accept any Origin, so the relay adds
no protection by checking it, and the default allows any. With the default, any
web page can use your relay and your Worker's bandwidth to reach the allowlisted
Tailscale hosts, and nothing else. Setting `ALLOWED_ORIGINS` limits browser use to
your own site, and requests without an `Origin` header are then rejected. It does
not stop non-browser clients, which can send any `Origin`.

## Local development

```sh
cd web/relay
npm ci
npm test         # node --test unit tests; no network needed
npm run check    # wrangler deploy --dry-run --outdir <tmp>; uploads nothing
npm run dev      # wrangler dev on http://localhost:8787
npm run smoke    # live check through a local wrangler dev (needs network)
```

If `web/dist` has not been built yet, `check`, `dev` and `smoke` pass Wrangler a
throwaway placeholder assets directory. The relay works without the site.

`npm run smoke` starts `wrangler dev` on a free local port and then checks:

- that a few requests are rejected (`403`, `426`, `404`),
- that a DERP WebSocket through the relay to `derp1f.tailscale.com` negotiates
  `derp` and gets a first frame that is the DERP server key: type `0x01`, then the
  magic `44 45 52 50 f0 9f 94 91` ("DERP🔑"),
- that a control WebSocket with a deliberately invalid handshake is upgraded and
  then closed by the upstream with `1008`, which shows close codes are
  propagated.

To test an instance that is already running, set `RELAY_URL`, for example
`RELAY_URL=https://tailfeather-web.<account>.workers.dev npm run smoke`.

In `wrangler dev`, workerd may log `Uncaught Error: Network connection lost.` when
a Tailscale upstream drops TCP right after a close handshake. The close has
already been relayed at that point, so the message is harmless.

## Deployment

The Worker is currently deployed with `wrangler deploy` from this directory. Build
the static site into `web/dist` first (`web/client/build.sh`), because
`assets.directory` is `../dist`. Moving to the **my-infra Runnerless** deployment
system requires enrolling a `tailfeather-web` project in its saved policy first;
until then the host refuses the submit with `403`. After enrollment, Runnerless
must be the only publisher of this Worker. There is intentionally no `deploy`
npm script.

Runnerless parses the Wrangler config strictly and rejects unknown fields. Keep
`wrangler.jsonc` limited to:

- plain top-level fields: `$schema`, `name`, `main`, `compatibility_date`,
  `workers_dev`, `preview_urls`, `assets`, `vars`,
- `assets` with only `directory`, `binding` and a **boolean** `run_worker_first`.
  The array form is rejected.

Do not add routes, observability, limits, named `env` sections, other bindings or
secrets. The root config is deployed as the default environment.
