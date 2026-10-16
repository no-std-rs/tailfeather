// Cloudflare Worker: WebSocket relay to Tailscale control/DERP plus the static
// host for the tailfeather web client (web/dist via the ASSETS binding).
//
//   GET /relay/control/<host>/ts2021?X-Tailscale-Handshake=...  -> wss://<host>/ts2021?...
//   GET /relay/derp/<host>                                      -> wss://<host>/derp
//   anything else                                               -> env.ASSETS.fetch(request)

import { handleConnect } from "./authkey.js";
import { ConfigError, bridge, configFromEnv, isValidHostname, parseRoute, planRelay } from "./relay.js";

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
};

function runtimeDeps() {
  return {
    fetch: (url, init) => fetch(url, init),
    createPair: () => {
      const pair = new WebSocketPair();
      return [pair[0], pair[1]];
    },
    upgradeResponse: (webSocket, protocol) =>
      new Response(null, { status: 101, webSocket, headers: { "Sec-WebSocket-Protocol": protocol } }),
  };
}

function log(fields) {
  // Never log URLs or query strings: the control handshake travels in the query.
  console.log(JSON.stringify({ relay: true, ...fields }));
}

function textResponse(status, reason, headers = {}) {
  return new Response(`${status} ${reason}\n`, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

export async function handleRequest(request, env, deps = runtimeDeps()) {
  const url = new URL(request.url);
  if (url.pathname === "/connect") return handleConnect(request, env, { fetch: deps.fetch, log });
  const route = parseRoute(url.pathname);
  if (route === null) return env.ASSETS.fetch(request);

  const logHost = isValidHostname(route.host) ? route.host : "(invalid)";
  let config;
  try {
    config = configFromEnv(env);
  } catch (err) {
    log({ kind: route.kind, status: 500, error: err instanceof ConfigError ? err.message : "config" });
    return textResponse(500, "relay misconfigured");
  }

  const plan = planRelay(
    { route, method: request.method, headers: request.headers, search: url.search },
    config,
  );
  if (plan.status) {
    log({ kind: route.kind, host: logHost, status: plan.status });
    return textResponse(plan.status, plan.reason, plan.headers);
  }
  return connectUpstream(plan, deps);
}

async function connectUpstream({ kind, host, protocol, upstreamUrl }, deps) {
  const fail = (reason, extra = {}) => {
    log({ kind, host, status: 502, ...extra });
    return textResponse(502, reason);
  };

  let response;
  try {
    response = await deps.fetch(upstreamUrl, {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": protocol },
    });
  } catch (err) {
    return fail("upstream connection failed", { error: err?.name ?? "error" });
  }

  const upstream = response.webSocket;
  if (!upstream) {
    // Do not echo the upstream body; just release it.
    try {
      await response.body?.cancel();
    } catch {
      // Body already consumed or unavailable; nothing to release.
    }
    return fail(`upstream did not upgrade (HTTP ${response.status})`, { upstreamStatus: response.status });
  }

  const negotiated = response.headers.get("Sec-WebSocket-Protocol");
  if (negotiated === null || negotiated.trim() !== protocol) {
    upstream.accept();
    upstream.close(1002, "relay: subprotocol not negotiated");
    return fail("upstream did not negotiate the subprotocol");
  }

  const [client, server] = deps.createPair();
  bridge(server, upstream, ({ by, code }) => log({ kind, host, event: "close", by, code }));
  server.accept();
  upstream.accept();
  log({ kind, host, status: 101 });
  return deps.upgradeResponse(client, protocol);
}
