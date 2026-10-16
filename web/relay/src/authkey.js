// GET /connect: mint a single-use Tailscale auth key for a Cloudflare Access
// user and hand it to the page in the URL fragment.
//
// Cloudflare Access gates the path; this module verifies the Access JWT itself
// as well, so a request that reaches the Worker any other way, or a forged
// header, gets nothing. The key is minted with the operator's own Tailscale API
// access token, so the browser node is owned by that user and is covered by the
// tailnet's ordinary SSH rules (tagged nodes cannot Tailscale-SSH into
// user-owned devices). Keys are single-use, ephemeral, pre-approved and expire
// in ten minutes. Nothing here is logged except outcome and status.

const TAILSCALE_KEYS_URL = "https://api.tailscale.com/api/v2/tailnet/-/keys";
export const KEY_EXPIRY_SECONDS = 600;
const JWKS_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_S = 60;

/**
 * Everything must be configured, or the endpoint does not exist.
 *
 * Exactly one person may mint keys: the owner of `TS_API_TOKEN`. Every key is
 * created with that token, so the node it enrolls belongs to the token's owner
 * and gets that user's tailnet access (including `autogroup:self` SSH). Letting
 * anyone else mint one would hand them the owner's identity, so there is no
 * list here, and a value that looks like one turns the endpoint off.
 */
export function authkeyConfig(env = {}) {
  const teamDomain = String(env.ACCESS_TEAM_DOMAIN ?? "").trim().toLowerCase();
  const aud = String(env.ACCESS_AUD ?? "").trim();
  const owner = String(env.AUTHKEY_OWNER_EMAIL ?? "").trim().toLowerCase();
  const token = env.TS_API_TOKEN;
  if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(teamDomain) || !aud) return null;
  if (!/^[^\s,@]+@[^\s,@]+$/.test(owner)) return null;
  if (typeof token !== "string" || token.length === 0) return null;
  return { teamDomain, aud, owner, token };
}

function base64UrlBytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function base64UrlJson(text) {
  return JSON.parse(new TextDecoder().decode(base64UrlBytes(text)));
}

let jwksCache = { url: "", keys: [], fetchedAt: 0 };

/** For tests. */
export function resetJwksCache() {
  jwksCache = { url: "", keys: [], fetchedAt: 0 };
}

async function signingKeys(teamDomain, fetchImpl, now, force) {
  const url = `https://${teamDomain}/cdn-cgi/access/certs`;
  if (!force && jwksCache.url === url && now - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;
  const response = await fetchImpl(url);
  if (!response.ok) throw new Error(`certs ${response.status}`);
  const body = await response.json();
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  jwksCache = { url, keys, fetchedAt: now };
  return keys;
}

/**
 * Verify a Cloudflare Access JWT: RS256 signature from the team's published
 * keys, issuer, audience, expiry and not-before. Returns the claims or null.
 */
export async function verifyAccessJwt(token, { teamDomain, aud, fetch: fetchImpl, now = Date.now() }) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header;
  let claims;
  let signature;
  try {
    header = base64UrlJson(parts[0]);
    claims = base64UrlJson(parts[1]);
    signature = base64UrlBytes(parts[2]);
  } catch {
    return null;
  }
  if (header?.alg !== "RS256" || typeof header.kid !== "string") return null;

  let jwk;
  for (const force of [false, true]) {
    const keys = await signingKeys(teamDomain, fetchImpl, now, force);
    jwk = keys.find((key) => key.kid === header.kid && key.kty === "RSA");
    if (jwk) break;
  }
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed))) return null;

  const seconds = Math.floor(now / 1000);
  if (claims?.iss !== `https://${teamDomain}`) return null;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(aud)) return null;
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_S < seconds) return null;
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_S > seconds) return null;
  if (typeof claims.email !== "string") return null;
  return claims;
}

/**
 * The Tailscale API request for one user-owned, single-use browser key. The
 * description allows only letters, digits, hyphens and spaces, so the user's
 * email stays out of it.
 */
export function mintRequest(token) {
  return {
    url: TAILSCALE_KEYS_URL,
    init: {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        capabilities: { devices: { create: { reusable: false, ephemeral: true, preauthorized: true } } },
        expirySeconds: KEY_EXPIRY_SECONDS,
        description: "tailfeather-web browser",
      }),
    },
  };
}

function text(status, reason) {
  return new Response(`${status} ${reason}\n`, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function handleConnect(request, env, { fetch: fetchImpl, log }) {
  if (request.method !== "GET") return text(405, "method not allowed");
  const config = authkeyConfig(env);
  if (!config) return text(404, "not configured");

  let claims = null;
  try {
    claims = await verifyAccessJwt(request.headers.get("Cf-Access-Jwt-Assertion"), {
      teamDomain: config.teamDomain,
      aud: config.aud,
      fetch: fetchImpl,
    });
  } catch {
    log({ route: "connect", status: 503, error: "access-certs" });
    return text(503, "cannot verify access");
  }
  const email = claims?.email?.toLowerCase();
  if (!email || email !== config.owner) {
    log({ route: "connect", status: 403 });
    return text(403, "forbidden");
  }

  const { url, init } = mintRequest(config.token);
  let key;
  try {
    const response = await fetchImpl(url, init);
    if (!response.ok) {
      // Never echo the body: it can describe the tailnet or the token.
      try {
        await response.body?.cancel();
      } catch {
        // Nothing to release.
      }
      log({ route: "connect", status: 502, upstreamStatus: response.status });
      return text(502, `tailscale refused the key request (HTTP ${response.status})`);
    }
    key = (await response.json())?.key;
  } catch {
    log({ route: "connect", status: 502, error: "tailscale" });
    return text(502, "tailscale unavailable");
  }
  if (typeof key !== "string" || !/^tskey-auth-[A-Za-z0-9-]+$/.test(key)) {
    log({ route: "connect", status: 502, error: "unexpected key" });
    return text(502, "tailscale returned an unexpected key");
  }
  log({ route: "connect", status: 303 });
  return new Response(null, {
    status: 303,
    headers: {
      // A fragment never reaches a server or a Referer; the page strips it.
      Location: `/#tskey=${encodeURIComponent(key)}`,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}
