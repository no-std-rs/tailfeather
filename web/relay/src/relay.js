// Pure relay logic: routing, validation, upstream URL construction, close-code
// mapping and the WebSocket bridge. No Workers-only globals are touched here so
// everything can be unit-tested under plain Node (`node --test`).

export const PROTOCOLS = Object.freeze({
  control: "tailscale-control-protocol",
  derp: "derp",
});

export const UPSTREAM_PATHS = Object.freeze({
  control: "/ts2021",
  derp: "/derp",
});

export const DEFAULT_CONTROL_HOSTS = "controlplane.tailscale.com";
export const DEFAULT_DERP_HOST_PATTERN = "^derp\\d+[a-z]?\\.tailscale\\.com$";
export const MAX_QUERY_LENGTH = 1024;
export const HANDSHAKE_PARAM = "X-Tailscale-Handshake";

const RELAY_PREFIX = "/relay/";
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Percent-encoded (or raw) base64 / base64url; never `&`, `#`, spaces or quotes.
const HANDSHAKE_VALUE_RE = /^[A-Za-z0-9%._~+/=-]+$/;
const MAX_CLOSE_REASON_BYTES = 123;

export class ConfigError extends Error {}

/**
 * Map a request path to a relay route.
 * Returns null for non-relay paths (serve static assets),
 * `{ kind: "unknown" }` for malformed paths under /relay/ (never assets),
 * or `{ kind: "control" | "derp", host }`.
 */
export function parseRoute(pathname) {
  if (pathname !== "/relay" && !pathname.startsWith(RELAY_PREFIX)) return null;
  const parts = pathname.slice(RELAY_PREFIX.length).split("/");
  if (parts.length === 3 && parts[0] === "control" && parts[2] === "ts2021") {
    return { kind: "control", host: parts[1] };
  }
  if (parts.length === 2 && parts[0] === "derp") {
    return { kind: "derp", host: parts[1] };
  }
  return { kind: "unknown" };
}

/**
 * Strict DNS host name check: lowercase LDH labels, at least two labels, no
 * trailing dot, no port/userinfo/percent-escapes, and a last label starting
 * with a letter (rules out IPv4 literals in every WHATWG-parsed form).
 */
export function isValidHostname(host) {
  if (typeof host !== "string" || host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (!labels.every((label) => LABEL_RE.test(label))) return false;
  return /^[a-z]/.test(labels[labels.length - 1]);
}

function parseList(value, { lowercase = true } = {}) {
  return String(value)
    .split(",")
    .map((entry) => (lowercase ? entry.trim().toLowerCase() : entry.trim()))
    .filter((entry) => entry.length > 0);
}

/**
 * Build the relay configuration from Worker vars. Unset vars use the safe
 * defaults; an explicitly empty CONTROL_HOSTS / DERP_HOST_PATTERN denies all.
 * Throws ConfigError on invalid values (the Worker then fails closed).
 */
export function configFromEnv(env = {}) {
  const controlHosts = parseList(env.CONTROL_HOSTS ?? DEFAULT_CONTROL_HOSTS);
  for (const host of controlHosts) {
    if (!isValidHostname(host)) throw new ConfigError(`invalid CONTROL_HOSTS entry: ${host}`);
  }
  const pattern = String(env.DERP_HOST_PATTERN ?? DEFAULT_DERP_HOST_PATTERN).trim();
  let derpHostPattern = null;
  if (pattern.length > 0) {
    try {
      // Always anchor, so an unanchored operator pattern cannot match a substring.
      derpHostPattern = new RegExp(`^(?:${pattern})$`);
    } catch {
      throw new ConfigError("invalid DERP_HOST_PATTERN");
    }
  }
  const allowedOrigins = parseList(env.ALLOWED_ORIGINS ?? "");
  return { controlHosts, derpHostPattern, allowedOrigins, maxQueryLength: MAX_QUERY_LENGTH };
}

export function isAllowedHost(kind, host, config) {
  if (!isValidHostname(host)) return false;
  if (kind === "control") return config.controlHosts.includes(host);
  if (kind === "derp") return config.derpHostPattern !== null && config.derpHostPattern.test(host);
  return false;
}

/** Empty allowlist allows any Origin; otherwise the Origin must be listed. */
export function isOriginAllowed(origin, allowedOrigins) {
  if (allowedOrigins.length === 0) return true;
  if (typeof origin !== "string" || origin.length === 0) return false;
  return allowedOrigins.includes(origin.trim().toLowerCase());
}

/** True if the Upgrade header asks for websocket (case-insensitive token). */
export function wantsWebSocket(upgradeHeader) {
  if (typeof upgradeHeader !== "string") return false;
  return upgradeHeader.split(",").some((token) => token.trim().toLowerCase() === "websocket");
}

/** True if the exact protocol is among the offered Sec-WebSocket-Protocol values. */
export function offersProtocol(protocolHeader, protocol) {
  if (typeof protocolHeader !== "string") return false;
  return protocolHeader.split(",").some((token) => token.trim() === protocol);
}

/**
 * Reduce the control query to exactly one X-Tailscale-Handshake parameter,
 * forwarded byte-for-byte. `search` is URL.search ("" or "?...").
 * Returns `{ query }` (with leading "?") or `{ status, reason }`.
 */
export function controlQuery(search, maxLength = MAX_QUERY_LENGTH) {
  const raw = search.startsWith("?") ? search.slice(1) : search;
  if (raw.length > maxLength) return { status: 414, reason: "query too long" };
  const values = [];
  for (const pair of raw.split("&")) {
    const eq = pair.indexOf("=");
    const name = eq === -1 ? pair : pair.slice(0, eq);
    if (name === HANDSHAKE_PARAM) values.push(eq === -1 ? "" : pair.slice(eq + 1));
  }
  if (values.length !== 1) return { status: 400, reason: `exactly one ${HANDSHAKE_PARAM} required` };
  const value = values[0];
  if (!HANDSHAKE_VALUE_RE.test(value) || /%(?![0-9A-Fa-f]{2})/.test(value)) {
    return { status: 400, reason: `malformed ${HANDSHAKE_PARAM}` };
  }
  return { query: `?${HANDSHAKE_PARAM}=${value}` };
}

/**
 * Build the upstream URL. Only ever https://<validated host>:443/<fixed path>;
 * re-parses the result and refuses anything the URL parser would alter.
 */
export function buildUpstreamUrl(kind, host, query = "") {
  const path = UPSTREAM_PATHS[kind];
  if (!path || !isValidHostname(host)) throw new Error("refusing to build upstream URL");
  const href = `https://${host}${path}${query}`;
  const url = new URL(href);
  if (
    url.href !== href ||
    url.protocol !== "https:" ||
    url.hostname !== host ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== path
  ) {
    throw new Error("refusing to build upstream URL");
  }
  return href;
}

/**
 * Validate a relay request before any upstream connection is opened.
 * Returns `{ status, reason, headers? }` to reject, or
 * `{ kind, host, protocol, upstreamUrl }` to proceed.
 */
export function planRelay({ route, method, headers, search }, config) {
  if (route.kind !== "control" && route.kind !== "derp") {
    return { status: 404, reason: "unknown relay route" };
  }
  if (method !== "GET") return { status: 405, reason: "method not allowed", headers: { Allow: "GET" } };
  if (!isOriginAllowed(headers.get("Origin"), config.allowedOrigins)) {
    return { status: 403, reason: "origin not allowed" };
  }
  if (!isAllowedHost(route.kind, route.host, config)) return { status: 403, reason: "host not allowed" };
  if (!wantsWebSocket(headers.get("Upgrade"))) {
    return { status: 426, reason: "websocket upgrade required", headers: { Upgrade: "websocket" } };
  }
  const protocol = PROTOCOLS[route.kind];
  if (!offersProtocol(headers.get("Sec-WebSocket-Protocol"), protocol)) {
    return { status: 400, reason: `subprotocol ${protocol} required` };
  }
  let query = "";
  if (route.kind === "control") {
    const result = controlQuery(search, config.maxQueryLength);
    if (result.status) return result;
    query = result.query;
  }
  return {
    kind: route.kind,
    host: route.host,
    protocol,
    upstreamUrl: buildUpstreamUrl(route.kind, route.host, query),
  };
}

/**
 * Map a received close code to one WebSocket.close() accepts. 1005 (no status)
 * becomes 1000; 1006/1015/1004 and anything out of range become 1011.
 */
export function mapCloseCode(code) {
  if (code === undefined || code === null || code === 1005) return 1000;
  if (!Number.isInteger(code)) return 1011;
  if (code >= 1000 && code <= 1003) return code;
  if (code >= 1007 && code <= 1014) return code;
  if (code >= 3000 && code <= 4999) return code;
  return 1011;
}

/** Truncate a close reason to the 123-byte UTF-8 limit on a code point boundary. */
export function truncateReason(reason) {
  const text = typeof reason === "string" ? reason : "";
  const encoder = new TextEncoder();
  if (encoder.encode(text).length <= MAX_CLOSE_REASON_BYTES) return text;
  let out = "";
  let bytes = 0;
  for (const ch of text) {
    const size = encoder.encode(ch).length;
    if (bytes + size > MAX_CLOSE_REASON_BYTES) break;
    out += ch;
    bytes += size;
  }
  return out;
}

const WS_CLOSED = 3;

function closeQuietly(ws, code, reason) {
  // The runtime auto-replies to a peer's close frame, leaving the socket CLOSED;
  // closing again would only queue a write on a connection that is going away.
  if (ws.readyState === WS_CLOSED) return;
  try {
    ws.close(code, reason);
  } catch {
    // Raced with the peer closing; nothing left to do.
  }
}

/**
 * Pipe binary messages both ways between two WebSockets (call before accept())
 * and propagate close/error. Text frames are a protocol violation for both
 * upstreams and close both sides with 1003. `onClose({ by, code })` is called
 * once.
 */
export function bridge(client, upstream, onClose = () => {}) {
  // Recent compatibility dates follow the standard default binaryType "blob";
  // a Blob cannot be passed to send(), so ask for ArrayBuffers explicitly.
  client.binaryType = "arraybuffer";
  upstream.binaryType = "arraybuffer";
  let done = false;
  const shutdown = (by, code, reason) => {
    if (done) return;
    done = true;
    const mapped = mapCloseCode(code);
    const text = truncateReason(reason);
    closeQuietly(client, mapped, text);
    closeQuietly(upstream, mapped, text);
    onClose({ by, code: mapped });
  };
  const wire = (from, to, name) => {
    from.addEventListener("message", (event) => {
      if (done) return;
      if (!(event.data instanceof ArrayBuffer || ArrayBuffer.isView(event.data))) {
        shutdown(name, 1003, "relay: binary frames only");
        return;
      }
      try {
        to.send(event.data);
      } catch {
        shutdown(name, 1011, "relay: forward failed");
      }
    });
    from.addEventListener("close", (event) => shutdown(name, event.code, event.reason));
    from.addEventListener("error", () => shutdown(name, 1011, `relay: ${name} error`));
  };
  wire(client, upstream, "client");
  wire(upstream, client, "upstream");
}
