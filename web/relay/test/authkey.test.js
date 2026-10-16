import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { KEY_EXPIRY_SECONDS, authkeyConfig, handleConnect, resetJwksCache, verifyAccessJwt } from "../src/authkey.js";
import { handleRequest } from "../src/index.js";

const TEAM = "chcki.cloudflareaccess.com";
const AUD = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN = "tskey-api-SECRET-TOKEN-VALUE";
const KEY = "tskey-auth-kAbCdEf1CNTRL-0123456789abcdef";
const ENV = {
  ACCESS_TEAM_DOMAIN: TEAM,
  ACCESS_AUD: AUD,
  AUTHKEY_OWNER_EMAIL: "pawelchcki@gmail.com",
  TS_API_TOKEN: TOKEN,
};

const { privateKey, publicKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const otherKey = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const JWK = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1", alg: "RS256", use: "sig" };

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

async function jwt(claims, { kid = "k1", alg = "RS256", key = privateKey } = {}) {
  const head = b64url(JSON.stringify({ alg, kid, typ: "JWT" }));
  const body = b64url(JSON.stringify(claims));
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(new Uint8Array(signature))}`;
}

function goodClaims(extra = {}) {
  return { iss: `https://${TEAM}`, aud: [AUD], email: "pawelchcki@gmail.com", exp: now() + 300, iat: now(), ...extra };
}

function fakeFetch({ mint = () => Response.json({ key: KEY, expires: "later" }) } = {}) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url) === `https://${TEAM}/cdn-cgi/access/certs`) return Response.json({ keys: [JWK] });
    if (String(url) === "https://api.tailscale.com/api/v2/tailnet/-/keys") return mint(init);
    throw new Error(`unexpected fetch ${url}`);
  };
  return { fetch, calls };
}

function request(token, method = "GET") {
  const headers = new Headers();
  if (token !== undefined) headers.set("Cf-Access-Jwt-Assertion", token);
  return new Request("https://tailfeather-web.example/connect", { method, headers });
}

describe("authkeyConfig", () => {
  it("is off unless every setting is present", () => {
    assert.ok(authkeyConfig(ENV));
    for (const missing of ["ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "AUTHKEY_OWNER_EMAIL", "TS_API_TOKEN"]) {
      assert.equal(authkeyConfig({ ...ENV, [missing]: "" }), null, missing);
    }
    assert.equal(authkeyConfig({ ...ENV, ACCESS_TEAM_DOMAIN: "evil.example.com" }), null);
  });

  it("allows only the token owner: a list of emails turns the endpoint off", () => {
    // Keys are minted with the owner's token, so a second person would get the
    // owner's tailnet identity.
    assert.equal(authkeyConfig({ ...ENV, AUTHKEY_OWNER_EMAIL: "pawelchcki@gmail.com,friend@example.com" }), null);
    assert.equal(authkeyConfig({ ...ENV, AUTHKEY_OWNER_EMAIL: "not-an-email" }), null);
    assert.equal(authkeyConfig({ ...ENV, AUTHKEY_OWNER_EMAIL: " PawelChcki@Gmail.com " }).owner, "pawelchcki@gmail.com");
  });
});

describe("verifyAccessJwt", () => {
  beforeEach(resetJwksCache);
  const verify = async (token, fetch = fakeFetch().fetch) => verifyAccessJwt(token, { teamDomain: TEAM, aud: AUD, fetch });

  it("accepts a valid token", async () => {
    assert.equal((await verify(await jwt(goodClaims()))).email, "pawelchcki@gmail.com");
  });

  it("rejects wrong issuer, audience, expiry, not-before and missing email", async () => {
    for (const claims of [
      goodClaims({ iss: "https://evil.cloudflareaccess.com" }),
      goodClaims({ aud: ["someone-else"] }),
      goodClaims({ exp: now() - 3600 }),
      goodClaims({ nbf: now() + 3600 }),
      goodClaims({ email: undefined }),
    ]) {
      assert.equal(await verify(await jwt(claims)), null, JSON.stringify(claims));
    }
  });

  it("rejects a bad signature, unknown kid, other algorithms and garbage", async () => {
    assert.equal(await verify(await jwt(goodClaims(), { key: otherKey.privateKey })), null);
    assert.equal(await verify(await jwt(goodClaims(), { kid: "nope" })), null);
    assert.equal(await verify(await jwt(goodClaims(), { alg: "none" })), null);
    const valid = await jwt(goodClaims());
    const [head, , sig] = valid.split(".");
    const forged = b64url(JSON.stringify(goodClaims({ email: "attacker@example.com" })));
    assert.equal(await verify(`${head}.${forged}.${sig}`), null);
    for (const junk of [undefined, "", "a.b", "a.b.c", "!!.??.**"]) assert.equal(await verify(junk), null);
  });

  it("caches the team keys and refetches once for an unknown kid", async () => {
    const { fetch, calls } = fakeFetch();
    await verify(await jwt(goodClaims()), fetch);
    await verify(await jwt(goodClaims()), fetch);
    assert.equal(calls.length, 1);
    await verify(await jwt(goodClaims(), { kid: "rotated" }), fetch);
    assert.equal(calls.length, 2);
  });
});

describe("handleConnect", () => {
  beforeEach(resetJwksCache);
  const logs = [];
  const log = (entry) => logs.push(entry);

  it("mints a single-use, ephemeral, pre-approved key and redirects with it in the fragment", async () => {
    const { fetch, calls } = fakeFetch();
    const response = await handleConnect(request(await jwt(goodClaims())), ENV, { fetch, log });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("Location"), `/#tskey=${encodeURIComponent(KEY)}`);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");

    const mint = calls.find((call) => call.url.startsWith("https://api.tailscale.com/"));
    assert.equal(mint.init.method, "POST");
    assert.equal(mint.init.headers.Authorization, `Bearer ${TOKEN}`);
    const body = JSON.parse(mint.init.body);
    assert.deepEqual(body.capabilities.devices.create, { reusable: false, ephemeral: true, preauthorized: true });
    assert.equal(body.capabilities.devices.create.tags, undefined, "user-owned: never tagged");
    assert.equal(body.expirySeconds, KEY_EXPIRY_SECONDS);
    assert.match(body.description, /^[A-Za-z0-9 -]{1,50}$/);
  });

  it("is a 404 when not configured and refuses other methods", async () => {
    const { fetch, calls } = fakeFetch();
    assert.equal((await handleConnect(request(await jwt(goodClaims())), {}, { fetch, log })).status, 404);
    assert.equal((await handleConnect(request(await jwt(goodClaims()), "POST"), ENV, { fetch, log })).status, 405);
    assert.equal(calls.length, 0);
  });

  it("refuses without a valid Access JWT or for another email, before touching Tailscale", async () => {
    const { fetch, calls } = fakeFetch();
    for (const token of [undefined, "junk", await jwt(goodClaims({ email: "someone@example.com" }))]) {
      assert.equal((await handleConnect(request(token), ENV, { fetch, log })).status, 403);
    }
    assert.ok(calls.every((call) => !call.url.startsWith("https://api.tailscale.com/")));
  });

  it("does not echo a Tailscale error body and never logs secrets", async () => {
    logs.length = 0;
    const { fetch } = fakeFetch({ mint: () => new Response(`{"message":"${TOKEN} is bad"}`, { status: 401 }) });
    const response = await handleConnect(request(await jwt(goodClaims())), ENV, { fetch, log });
    assert.equal(response.status, 502);
    const text = await response.text();
    assert.ok(!text.includes(TOKEN));
    const logged = JSON.stringify(logs);
    assert.ok(!logged.includes(TOKEN) && !logged.includes(KEY) && !logged.includes("pawelchcki"));
  });

  it("rejects an unexpected key shape", async () => {
    const { fetch } = fakeFetch({ mint: () => Response.json({ key: "javascript:alert(1)" }) });
    assert.equal((await handleConnect(request(await jwt(goodClaims())), ENV, { fetch, log })).status, 502);
  });

  it("is routed by the Worker before static assets", async () => {
    const { fetch } = fakeFetch();
    const env = { ...ENV, ASSETS: { fetch: async () => new Response("asset") } };
    const response = await handleRequest(request(await jwt(goodClaims())), env, { fetch });
    assert.equal(response.status, 303);
  });
});
