import assert from "node:assert/strict";
import { beforeEach, describe, it, mock } from "node:test";

import { handleRequest } from "../src/index.js";
import { bridge } from "../src/relay.js";

const HANDSHAKE = "SECRETHANDSHAKE%2Bvalue%3D%3D";

class FakeSocket extends EventTarget {
  constructor() {
    super();
    this.readyState = 1;
    this.accepted = false;
    this.sent = [];
    this.closedWith = null;
    this.binaryType = "blob";
  }
  accept() {
    this.accepted = true;
  }
  send(data) {
    this.sent.push(data);
  }
  close(code, reason) {
    if (this.readyState === 3) throw new Error("already closed");
    this.closedWith = { code, reason };
    this.readyState = 2;
  }
  emit(type, props = {}) {
    this.dispatchEvent(Object.assign(new Event(type), props));
  }
}

function makeDeps(upstreamResponse) {
  const calls = [];
  const pair = [new FakeSocket(), new FakeSocket()];
  const deps = {
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (upstreamResponse instanceof Error) throw upstreamResponse;
      return upstreamResponse;
    },
    createPair: () => pair,
    upgradeResponse: (webSocket, protocol) => ({ status: 101, webSocket, protocol }),
  };
  return { deps, calls, pair };
}

function makeEnv(vars = {}) {
  const assetCalls = [];
  return {
    env: {
      ...vars,
      ASSETS: {
        fetch: async (request) => {
          assetCalls.push(request);
          return new Response("asset");
        },
      },
    },
    assetCalls,
  };
}

const wsHeaders = (protocol, extra = {}) => ({ Upgrade: "websocket", "Sec-WebSocket-Protocol": protocol, ...extra });
const req = (path, headers = {}, init = {}) => new Request(`https://relay.example${path}`, { headers, ...init });

let logs;
beforeEach(() => {
  logs = [];
  mock.method(console, "log", (line) => logs.push(String(line)));
});

describe("handleRequest routing", () => {
  it("serves non-relay paths from ASSETS", async () => {
    const { env, assetCalls } = makeEnv();
    const { deps, calls } = makeDeps(new Error("unused"));
    for (const path of ["/", "/index.html", "/pkg/tailfeather_bg.wasm", "/relayx"]) {
      const request = req(path);
      const res = await handleRequest(request, env, deps);
      assert.equal(await res.text(), "asset");
      assert.equal(assetCalls.at(-1), request);
    }
    assert.equal(calls.length, 0);
  });

  it("never falls through to ASSETS for /relay paths and never connects on rejection", async () => {
    const { env, assetCalls } = makeEnv();
    const { deps, calls } = makeDeps(new Error("unused"));
    const cases = [
      ["/relay", {}, 404],
      ["/relay/", {}, 404],
      ["/relay/nope", wsHeaders("derp"), 404],
      ["/relay/derp/derp1.tailscale.com.evil.com", wsHeaders("derp"), 403],
      ["/relay/derp/evil.com#.tailscale.com", wsHeaders("derp"), 403],
      ["/relay/derp/DERP1.TAILSCALE.COM", wsHeaders("derp"), 403],
      ["/relay/derp/derp1.tailscale.com:8443", wsHeaders("derp"), 403],
      ["/relay/derp/127.0.0.1", wsHeaders("derp"), 403],
      ["/relay/derp/%64erp1.tailscale.com", wsHeaders("derp"), 403],
      ["/relay/derp/", wsHeaders("derp"), 403],
      [`/relay/derp/${"a".repeat(300)}.com`, wsHeaders("derp"), 403],
      ["/relay/derp/derp1.tailscale.com", {}, 426],
      ["/relay/derp/derp1.tailscale.com", wsHeaders("tailscale-control-protocol"), 400],
      ["/relay/control/controlplane.tailscale.com/ts2021", wsHeaders("tailscale-control-protocol"), 400],
      [`/relay/control/controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=${"A".repeat(1100)}`, wsHeaders("tailscale-control-protocol"), 414],
    ];
    for (const [path, headers, status] of cases) {
      const res = await handleRequest(req(path, headers), env, deps);
      assert.equal(res.status, status, path);
      assert.match(await res.text(), new RegExp(`^${status} `));
    }
    const post = await handleRequest(req("/relay/derp/derp1.tailscale.com", wsHeaders("derp"), { method: "POST" }), env, deps);
    assert.equal(post.status, 405);
    assert.equal(assetCalls.length, 0);
    assert.equal(calls.length, 0);
  });

  it("fails closed with 500 on invalid configuration", async () => {
    const { env } = makeEnv({ DERP_HOST_PATTERN: "(" });
    const { deps, calls } = makeDeps(new Error("unused"));
    const res = await handleRequest(req("/relay/derp/derp1.tailscale.com", wsHeaders("derp")), env, deps);
    assert.equal(res.status, 500);
    assert.equal(calls.length, 0);
  });

  it("applies ALLOWED_ORIGINS", async () => {
    const { env } = makeEnv({ ALLOWED_ORIGINS: "https://tailfeather.example" });
    const { deps, calls } = makeDeps(new Error("unused"));
    const res = await handleRequest(
      req("/relay/derp/derp1.tailscale.com", wsHeaders("derp", { Origin: "https://evil.example" })),
      env,
      deps,
    );
    assert.equal(res.status, 403);
    assert.equal(calls.length, 0);
  });
});

describe("handleRequest upstream", () => {
  const upgraded = (protocol, socket = new FakeSocket()) => ({
    status: 101,
    headers: new Headers({ "Sec-WebSocket-Protocol": protocol }),
    webSocket: socket,
  });

  it("relays DERP: fetches https://<host>/derp, accepts and bridges both sides", async () => {
    const { env } = makeEnv();
    const upstream = new FakeSocket();
    const { deps, calls, pair } = makeDeps(upgraded("derp", upstream));
    const res = await handleRequest(req("/relay/derp/derp1f.tailscale.com?x=1", wsHeaders("derp")), env, deps);
    assert.deepEqual(res, { status: 101, webSocket: pair[0], protocol: "derp" });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://derp1f.tailscale.com/derp");
    assert.deepEqual(calls[0].init, { headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "derp" } });
    const server = pair[1];
    assert.ok(server.accepted && upstream.accepted);
    const frame = new Uint8Array([0x01, 0x00]).buffer;
    upstream.emit("message", { data: frame });
    assert.equal(server.sent[0], frame);
    upstream.emit("close", { code: 1006, reason: "" });
    assert.deepEqual(server.closedWith, { code: 1011, reason: "" });
  });

  it("relays control with only the handshake param and never logs it", async () => {
    const { env } = makeEnv();
    const { deps, calls } = makeDeps(upgraded("tailscale-control-protocol"));
    const path = `/relay/control/controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=${HANDSHAKE}&extra=1`;
    const res = await handleRequest(req(path, wsHeaders("tailscale-control-protocol")), env, deps);
    assert.equal(res.status, 101);
    assert.equal(res.protocol, "tailscale-control-protocol");
    assert.equal(calls[0].url, `https://controlplane.tailscale.com/ts2021?X-Tailscale-Handshake=${HANDSHAKE}`);
    assert.ok(logs.length > 0);
    for (const line of logs) {
      assert.doesNotMatch(line, /SECRETHANDSHAKE|X-Tailscale-Handshake|\?/);
      JSON.parse(line);
    }
  });

  it("returns 502 without echoing the body when upstream does not upgrade", async () => {
    const { env } = makeEnv();
    const upstreamRes = new Response("upstream secret body", { status: 403 });
    const { deps } = makeDeps(upstreamRes);
    const res = await handleRequest(req("/relay/derp/derp1.tailscale.com", wsHeaders("derp")), env, deps);
    assert.equal(res.status, 502);
    const body = await res.text();
    assert.doesNotMatch(body, /secret/);
    assert.match(body, /HTTP 403/);
    assert.equal(upstreamRes.bodyUsed, true, "upstream body should be cancelled, not left open");
  });

  it("returns 502 when the upstream connection fails", async () => {
    const { env } = makeEnv();
    const { deps } = makeDeps(new TypeError("connect failed https://controlplane.tailscale.com/ts2021?secret"));
    const res = await handleRequest(req("/relay/derp/derp1.tailscale.com", wsHeaders("derp")), env, deps);
    assert.equal(res.status, 502);
    assert.doesNotMatch(logs.join("\n"), /secret/);
  });

  it("returns 502 and closes upstream if the subprotocol was not negotiated", async () => {
    const { env } = makeEnv();
    for (const negotiated of [null, "other"]) {
      const upstream = new FakeSocket();
      const response = { status: 101, headers: new Headers(negotiated ? { "Sec-WebSocket-Protocol": negotiated } : {}), webSocket: upstream };
      const { deps, pair } = makeDeps(response);
      const res = await handleRequest(req("/relay/derp/derp1.tailscale.com", wsHeaders("derp")), env, deps);
      assert.equal(res.status, 502);
      assert.equal(upstream.closedWith.code, 1002);
      assert.equal(pair[1].accepted, false);
    }
  });
});

describe("bridge", () => {
  function setup() {
    const client = new FakeSocket();
    const upstream = new FakeSocket();
    const closes = [];
    bridge(client, upstream, (info) => closes.push(info));
    return { client, upstream, closes };
  }

  it("requests ArrayBuffer delivery on both sockets", () => {
    const { client, upstream } = setup();
    assert.equal(client.binaryType, "arraybuffer");
    assert.equal(upstream.binaryType, "arraybuffer");
  });

  it("forwards binary messages both ways without copying", () => {
    const { client, upstream } = setup();
    const a = new ArrayBuffer(4);
    const b = new Uint8Array([1, 2, 3]);
    client.emit("message", { data: a });
    upstream.emit("message", { data: b });
    assert.equal(upstream.sent[0], a);
    assert.equal(client.sent[0], b);
  });

  it("closes both sides with 1003 on a text frame", () => {
    const { client, upstream, closes } = setup();
    client.emit("message", { data: "hello" });
    assert.equal(client.closedWith.code, 1003);
    assert.equal(upstream.closedWith.code, 1003);
    assert.equal(upstream.sent.length, 0);
    assert.deepEqual(closes, [{ by: "client", code: 1003 }]);
  });

  it("propagates close codes and reasons, mapping reserved codes", () => {
    for (const [code, expected] of [
      [1008, 1008],
      [4001, 4001],
      [1005, 1000],
      [1006, 1011],
      [1015, 1011],
    ]) {
      const { client, upstream, closes } = setup();
      upstream.readyState = 3; // runtime already answered the peer's close frame
      upstream.emit("close", { code, reason: "why" });
      assert.deepEqual(client.closedWith, { code: expected, reason: "why" });
      assert.equal(upstream.closedWith, null, "must not re-close a CLOSED socket");
      assert.deepEqual(closes, [{ by: "upstream", code: expected }]);
    }
  });

  it("propagates client close to upstream once", () => {
    const { client, upstream, closes } = setup();
    client.emit("close", { code: 1000, reason: "bye" });
    upstream.emit("close", { code: 1000, reason: "bye" });
    assert.deepEqual(upstream.closedWith, { code: 1000, reason: "bye" });
    assert.equal(closes.length, 1);
  });

  it("closes both sides with 1011 on error or failed send, then ignores traffic", () => {
    const errored = setup();
    errored.upstream.emit("error");
    assert.equal(errored.client.closedWith.code, 1011);
    assert.equal(errored.upstream.closedWith.code, 1011);
    errored.client.emit("message", { data: new ArrayBuffer(1) });
    assert.equal(errored.upstream.sent.length, 0);

    const failing = setup();
    failing.upstream.send = () => {
      throw new Error("boom");
    };
    failing.client.emit("message", { data: new ArrayBuffer(1) });
    assert.equal(failing.client.closedWith.code, 1011);
    assert.deepEqual(failing.closes, [{ by: "client", code: 1011 }]);
  });

  it("truncates overlong close reasons", () => {
    const { client, upstream } = setup();
    upstream.emit("close", { code: 4000, reason: "r".repeat(500) });
    assert.equal(client.closedWith.reason.length, 123);
  });
});
