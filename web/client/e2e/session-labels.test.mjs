import assert from "node:assert/strict";
import { test } from "node:test";
import { connectionLabel, hostLabel } from "../www/session-labels.js";

test("unique Tailscale names use the short hostname", () => {
  const peers = [{ ip: "100.64.0.1", name: "workstation.tailnet.ts.net." }, { ip: "100.64.0.2", name: "server" }];
  assert.equal(connectionLabel({ ip: "100.64.0.1", user: "alice", port: 22 }, peers), "alice@workstation");
  assert.equal(connectionLabel({ ip: "100.64.0.2", user: "root", port: 2222 }, peers), "root@server:2222");
});

test("colliding short names use the distinguishing full name", () => {
  const peers = [{ ip: "100.64.0.1", name: "server.home.ts.net." }, { ip: "100.64.0.2", name: "SERVER.work.ts.net." }];
  assert.equal(hostLabel("100.64.0.1", peers), "server.home.ts.net");
  assert.equal(hostLabel("100.64.0.2", peers), "SERVER.work.ts.net");
});

test("duplicate names include the IP rather than misidentifying a peer", () => {
  const peers = [{ ip: "100.64.0.1", name: "server" }, { ip: "100.64.0.2", name: "Server" }];
  assert.equal(hostLabel("100.64.0.1", peers), "server (100.64.0.1)");
  assert.equal(hostLabel("100.64.0.2", peers), "Server (100.64.0.2)");
});

test("missing peer names fall back to the destination address", () => {
  assert.equal(hostLabel("100.64.0.1", [{ ip: "100.64.0.1", name: "" }]), "100.64.0.1");
  assert.equal(hostLabel("100.64.0.2"), "100.64.0.2");
});

test("WebSocket diagnostics keep their actual endpoint", () => {
  assert.equal(connectionLabel({ ip: "100.64.0.1", user: "tester", url: "ws://localhost:8080/ssh" }), "tester@localhost:8080");
});
