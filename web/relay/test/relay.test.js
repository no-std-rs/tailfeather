import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ConfigError,
  buildUpstreamUrl,
  configFromEnv,
  controlQuery,
  isAllowedHost,
  isOriginAllowed,
  isValidHostname,
  mapCloseCode,
  offersProtocol,
  parseRoute,
  planRelay,
  truncateReason,
  wantsWebSocket,
} from "../src/relay.js";

const config = configFromEnv({});
const HS = "X-Tailscale-Handshake";

describe("parseRoute", () => {
  it("leaves non-relay paths to assets", () => {
    for (const p of ["/", "/index.html", "/relayx", "/relays/derp/x", "/Relay/derp/x", "/a/relay/derp/x"]) {
      assert.equal(parseRoute(p), null, p);
    }
  });
  it("parses control and derp routes", () => {
    assert.deepEqual(parseRoute("/relay/control/controlplane.tailscale.com/ts2021"), {
      kind: "control",
      host: "controlplane.tailscale.com",
    });
    assert.deepEqual(parseRoute("/relay/derp/derp1f.tailscale.com"), { kind: "derp", host: "derp1f.tailscale.com" });
    assert.deepEqual(parseRoute("/relay/derp/"), { kind: "derp", host: "" });
  });
  it("marks every other /relay path unknown (never assets)", () => {
    for (const p of [
      "/relay",
      "/relay/",
      "/relay/nope",
      "/relay/control/controlplane.tailscale.com",
      "/relay/control/controlplane.tailscale.com/ts2021/",
      "/relay/control/controlplane.tailscale.com/key",
      "/relay/control//ts2021/x",
      "/relay/derp/derp1.tailscale.com/derp",
      "/relay/derp/derp1.tailscale.com/",
      "/relay/DERP/derp1.tailscale.com",
    ]) {
      assert.deepEqual(parseRoute(p), { kind: "unknown" }, p);
    }
  });
  it("sees hostile hosts exactly as the URL parser leaves them", () => {
    const host = (raw) => parseRoute(new URL(`https://relay.example${raw}`).pathname)?.host;
    assert.equal(host("/relay/derp/evil.com#.tailscale.com"), "evil.com");
    assert.equal(host("/relay/derp/%64erp1.tailscale.com"), "%64erp1.tailscale.com");
    assert.equal(host("/relay/derp/derp1.tailscale.com:8443"), "derp1.tailscale.com:8443");
    assert.equal(host("/relay/derp/DERP1.TAILSCALE.COM"), "DERP1.TAILSCALE.COM");
    assert.equal(parseRoute(new URL("https://relay.example/relay/derp/../../index.html").pathname), null);
  });
});

describe("isValidHostname", () => {
  it("accepts lowercase DNS names", () => {
    for (const h of ["derp1.tailscale.com", "derp1f.tailscale.com", "controlplane.tailscale.com", "a.b", "xn--dp-2ka.example"]) {
      assert.equal(isValidHostname(h), true, h);
    }
  });
  it("rejects hostile or malformed input", () => {
    const hostile = [
      "",
      "evil.com#.tailscale.com",
      "DERP1.TAILSCALE.COM",
      "Derp1.tailscale.com",
      "derp1.tailscale.com:8443",
      "derp1.tailscale.com:443",
      "127.0.0.1",
      "127.1",
      "0x7f.1",
      "1.2.3.0x4",
      "10.0.0.1.",
      "::1",
      "[::1]",
      "[2001:db8::1]",
      "%64erp1.tailscale.com",
      "derp1%2etailscale.com",
      "derp1.tailscale.com.",
      ".derp1.tailscale.com",
      "derp1..tailscale.com",
      "-derp1.tailscale.com",
      "derp1-.tailscale.com",
      "user@derp1.tailscale.com",
      "user:pw@derp1.tailscale.com",
      "derp1.tailscale.com/",
      "derp1.tailscale.com\\",
      "derp1.tailscale.com?x",
      "derp1.tailscale.com ",
      " derp1.tailscale.com",
      "derp1.tailscale.com\n",
      "derp1.tail\tscale.com",
      "derp1_x.tailscale.com",
      "dеrp1.tailscale.com", // Cyrillic "е"
      "localhost",
      "com",
      `${"a".repeat(64)}.com`,
      `${"a.".repeat(126)}com`, // 255 chars
      undefined,
      null,
      42,
    ];
    for (const h of hostile) assert.equal(isValidHostname(h), false, JSON.stringify(h));
  });
  it("enforces the 253-char and 63-char label limits exactly", () => {
    assert.equal(isValidHostname(`${"a".repeat(63)}.com`), true);
    const at253 = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
    assert.equal(at253.length, 253);
    assert.equal(isValidHostname(at253), true);
    assert.equal(isValidHostname(`a${at253}`), false);
  });
});

describe("isAllowedHost (default allowlists)", () => {
  it("allows hosted DERP names and the control plane", () => {
    for (const h of ["derp1.tailscale.com", "derp1f.tailscale.com", "derp28.tailscale.com", "derp10a.tailscale.com"]) {
      assert.equal(isAllowedHost("derp", h, config), true, h);
    }
    assert.equal(isAllowedHost("control", "controlplane.tailscale.com", config), true);
  });
  it("denies everything else", () => {
    const derpDenied = [
      "derp1.tailscale.com.evil.com",
      "evil.com#.tailscale.com",
      "DERP1.TAILSCALE.COM",
      "derp1.tailscale.com:8443",
      "127.0.0.1",
      "%64erp1.tailscale.com",
      "derp1.tailscale.com.",
      "",
      "derp.tailscale.com",
      "derp1ff.tailscale.com",
      "xderp1.tailscale.com",
      "evil.derp1.tailscale.com",
      "derp1.tailscalexcom.com",
      "derp1.tailscale.co",
      "controlplane.tailscale.com",
      `derp${"1".repeat(300)}.tailscale.com`,
    ];
    for (const h of derpDenied) assert.equal(isAllowedHost("derp", h, config), false, h);
    for (const h of ["derp1.tailscale.com", "login.tailscale.com", "controlplane.tailscale.com.evil.com", "CONTROLPLANE.TAILSCALE.COM"]) {
      assert.equal(isAllowedHost("control", h, config), false, h);
    }
    assert.equal(isAllowedHost("other", "controlplane.tailscale.com", config), false);
  });
});

describe("configFromEnv", () => {
  it("uses safe defaults", () => {
    assert.deepEqual(config.controlHosts, ["controlplane.tailscale.com"]);
    assert.deepEqual(config.allowedOrigins, []);
    assert.equal(config.maxQueryLength, 1024);
  });
  it("parses lists and treats explicitly empty allowlists as deny-all", () => {
    const c = configFromEnv({
      CONTROL_HOSTS: " controlplane.tailscale.com , Headscale.Example.org,, ",
      DERP_HOST_PATTERN: "",
      ALLOWED_ORIGINS: "https://Tailfeather.example, http://localhost:8787",
    });
    assert.deepEqual(c.controlHosts, ["controlplane.tailscale.com", "headscale.example.org"]);
    assert.deepEqual(c.allowedOrigins, ["https://tailfeather.example", "http://localhost:8787"]);
    assert.equal(isAllowedHost("derp", "derp1.tailscale.com", c), false);
    assert.equal(isAllowedHost("control", "controlplane.tailscale.com", configFromEnv({ CONTROL_HOSTS: "" })), false);
  });
  it("always anchors the DERP pattern", () => {
    const c = configFromEnv({ DERP_HOST_PATTERN: "derp\\d+\\.example\\.com" });
    assert.equal(isAllowedHost("derp", "derp1.example.com", c), true);
    assert.equal(isAllowedHost("derp", "derp1.example.com.evil.com", c), false);
    assert.equal(isAllowedHost("derp", "xderp1.example.com", c), false);
    const alt = configFromEnv({ DERP_HOST_PATTERN: "a\\.example|b\\.example" });
    assert.equal(isAllowedHost("derp", "a.example.evil.com", alt), false);
  });
  it("fails closed on invalid values", () => {
    assert.throws(() => configFromEnv({ DERP_HOST_PATTERN: "(" }), ConfigError);
    assert.throws(() => configFromEnv({ CONTROL_HOSTS: "controlplane.tailscale.com:443" }), ConfigError);
    assert.throws(() => configFromEnv({ CONTROL_HOSTS: "10.0.0.1" }), ConfigError);
  });
});

describe("isOriginAllowed", () => {
  it("allows any origin when the list is empty", () => {
    assert.equal(isOriginAllowed(null, []), true);
    assert.equal(isOriginAllowed("https://anything.example", []), true);
  });
  it("requires an exact listed origin otherwise", () => {
    const list = ["https://tailfeather.example"];
    assert.equal(isOriginAllowed("https://tailfeather.example", list), true);
    assert.equal(isOriginAllowed("HTTPS://TAILFEATHER.EXAMPLE", list), true);
    for (const o of [null, "", "null", "https://tailfeather.example.evil.com", "http://tailfeather.example", "https://evil.example"]) {
      assert.equal(isOriginAllowed(o, list), false, String(o));
    }
  });
});

describe("header checks", () => {
  it("wantsWebSocket", () => {
    assert.equal(wantsWebSocket("websocket"), true);
    assert.equal(wantsWebSocket("WebSocket"), true);
    assert.equal(wantsWebSocket("h2c, websocket"), true);
    for (const v of [null, undefined, "", "websocketx", "h2c"]) assert.equal(wantsWebSocket(v), false, String(v));
  });
  it("offersProtocol matches exact tokens only", () => {
    assert.equal(offersProtocol("derp", "derp"), true);
    assert.equal(offersProtocol("foo, derp", "derp"), true);
    assert.equal(offersProtocol("tailscale-control-protocol", "tailscale-control-protocol"), true);
    for (const v of [null, "", "Derp", "derpx", "foo", "derp-foo", "tailscale-control-protocol"]) {
      assert.equal(offersProtocol(v, "derp"), false, String(v));
    }
  });
});

describe("controlQuery", () => {
  it("forwards only the handshake parameter, verbatim", () => {
    assert.deepEqual(controlQuery(`?${HS}=AB%2Bcd%2F%3D%3D`), { query: `?${HS}=AB%2Bcd%2F%3D%3D` });
    assert.deepEqual(controlQuery(`?a=1&${HS}=abc&b=2`), { query: `?${HS}=abc` });
    assert.deepEqual(controlQuery(`?${HS}=a-b_c.d~e+f/g=`), { query: `?${HS}=a-b_c.d~e+f/g=` });
  });
  it("rejects missing, duplicate, empty or malformed handshakes", () => {
    for (const s of [
      "",
      "?",
      "?foo=bar",
      `?${HS}`,
      `?${HS}=`,
      `?${HS}=a&${HS}=b`,
      `?x-tailscale-handshake=abc`,
      `?${HS}=abc%`,
      `?${HS}=abc%2`,
      `?${HS}=%zz`,
      `?${HS}=a'b`,
      `?${HS}=a"b`,
      `?${HS}=a<b`,
      `?${HS}=a;b`,
    ]) {
      assert.equal(controlQuery(s).status, 400, s);
    }
  });
  it("caps the query length", () => {
    const prefix = `${HS}=`;
    const exact = `?${prefix}${"A".repeat(1024 - prefix.length)}`;
    assert.ok(controlQuery(exact).query);
    assert.equal(controlQuery(`${exact}A`).status, 414);
  });
});

describe("buildUpstreamUrl", () => {
  it("builds https URLs on port 443 with fixed paths", () => {
    assert.equal(buildUpstreamUrl("derp", "derp1f.tailscale.com"), "https://derp1f.tailscale.com/derp");
    assert.equal(
      buildUpstreamUrl("control", "controlplane.tailscale.com", `?${HS}=abc`),
      `https://controlplane.tailscale.com/ts2021?${HS}=abc`,
    );
  });
  it("refuses invalid hosts, kinds and URL-altering queries", () => {
    assert.throws(() => buildUpstreamUrl("derp", "evil.com#.tailscale.com"));
    assert.throws(() => buildUpstreamUrl("derp", "derp1.tailscale.com:8443"));
    assert.throws(() => buildUpstreamUrl("other", "derp1.tailscale.com"));
    assert.throws(() => buildUpstreamUrl("control", "controlplane.tailscale.com", "?a b"));
    assert.throws(() => buildUpstreamUrl("control", "controlplane.tailscale.com", "/../x"));
  });
});

describe("planRelay", () => {
  const derp = { kind: "derp", host: "derp1f.tailscale.com" };
  const control = { kind: "control", host: "controlplane.tailscale.com" };
  const ws = (protocol, extra = {}) => new Headers({ Upgrade: "websocket", "Sec-WebSocket-Protocol": protocol, ...extra });
  const plan = (route, headers, { method = "GET", search = "", cfg = config } = {}) =>
    planRelay({ route, method, headers, search }, cfg);

  it("plans DERP and control upgrades", () => {
    assert.deepEqual(plan(derp, ws("derp"), { search: "?ignored=1" }), {
      kind: "derp",
      host: "derp1f.tailscale.com",
      protocol: "derp",
      upstreamUrl: "https://derp1f.tailscale.com/derp",
    });
    assert.deepEqual(plan(control, ws("foo, tailscale-control-protocol"), { search: `?${HS}=abc&v=1` }), {
      kind: "control",
      host: "controlplane.tailscale.com",
      protocol: "tailscale-control-protocol",
      upstreamUrl: `https://controlplane.tailscale.com/ts2021?${HS}=abc`,
    });
  });
  it("rejects with the documented statuses", () => {
    assert.equal(plan({ kind: "unknown" }, ws("derp")).status, 404);
    const post = plan(derp, ws("derp"), { method: "POST" });
    assert.equal(post.status, 405);
    assert.equal(post.headers.Allow, "GET");
    assert.equal(plan({ kind: "derp", host: "derp1.tailscale.com.evil.com" }, ws("derp")).status, 403);
    assert.equal(plan({ kind: "control", host: "derp1.tailscale.com" }, ws("tailscale-control-protocol")).status, 403);
    const noUpgrade = plan(derp, new Headers({ "Sec-WebSocket-Protocol": "derp" }));
    assert.equal(noUpgrade.status, 426);
    assert.equal(noUpgrade.headers.Upgrade, "websocket");
    assert.equal(plan(derp, new Headers({ Upgrade: "websocket" })).status, 400);
    assert.equal(plan(derp, ws("tailscale-control-protocol")).status, 400);
    assert.equal(plan(control, ws("derp"), { search: `?${HS}=abc` }).status, 400);
    assert.equal(plan(control, ws("tailscale-control-protocol")).status, 400);
    assert.equal(plan(control, ws("tailscale-control-protocol"), { search: `?${HS}=${"A".repeat(2000)}` }).status, 414);
  });
  it("checks the host before anything upgrade-related", () => {
    assert.equal(plan({ kind: "derp", host: "evil.example" }, new Headers()).status, 403);
  });
  it("enforces ALLOWED_ORIGINS when set", () => {
    const cfg = configFromEnv({ ALLOWED_ORIGINS: "https://tailfeather.example" });
    assert.equal(plan(derp, ws("derp", { Origin: "https://evil.example" }), { cfg }).status, 403);
    assert.equal(plan(derp, ws("derp"), { cfg }).status, 403);
    assert.equal(plan(derp, ws("derp", { Origin: "https://tailfeather.example" }), { cfg }).protocol, "derp");
  });
});

describe("mapCloseCode", () => {
  it("passes through codes close() accepts", () => {
    for (const c of [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 4000, 4999]) {
      assert.equal(mapCloseCode(c), c);
    }
  });
  it("maps reserved and invalid codes", () => {
    assert.equal(mapCloseCode(1005), 1000);
    assert.equal(mapCloseCode(undefined), 1000);
    assert.equal(mapCloseCode(null), 1000);
    for (const c of [1004, 1006, 1015, 1016, 2999, 999, 0, -1, 5000, 65535, 1000.5, NaN, "1000"]) {
      assert.equal(mapCloseCode(c), 1011, String(c));
    }
  });
});

describe("truncateReason", () => {
  it("keeps short reasons and drops non-strings", () => {
    assert.equal(truncateReason("bye"), "bye");
    assert.equal(truncateReason(undefined), "");
  });
  it("truncates to 123 UTF-8 bytes on a code point boundary", () => {
    assert.equal(truncateReason("x".repeat(200)), "x".repeat(123));
    const emoji = truncateReason("🔑".repeat(40));
    assert.equal(new TextEncoder().encode(emoji).length, 120);
    assert.equal(emoji, "🔑".repeat(30));
  });
});
