import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer, connect } from "node:net";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import { LoopbackHost, nativeMain } from "../native.mjs";
import { LoopbackForwarding } from "../../client/www/loopback-forwarding.js";

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test("native host rejects public targets, binds exclusive loopback and releases port", async () => {
  const replies = [];
  const first = new LoopbackHost((value) => replies.push(value));
  const secondReplies = [];
  const second = new LoopbackHost((value) => secondReplies.push(value));
  const port = await freePort();
  try {
    for (const host of ["0.0.0.0", "::", "127.0.0.2", "example.org", "localhost.evil"]) {
      await first.receive({ type: "listen", id: "invalid", request: "invalid", host, port });
      assert.equal(first.listeners.size, 0);
    }
    await first.receive({ type: "listen", id: "first", request: "1", host: "127.0.0.1", port });
    assert.deepEqual(replies.at(-1), { type: "reply", request: "1", ok: true });
    assert.equal(first.listeners.get("first").servers[0].address().address, "127.0.0.1");
    await second.receive({ type: "listen", id: "second", request: "2", host: "127.0.0.1", port });
    assert.deepEqual(secondReplies.at(-1), { type: "reply", request: "2", ok: false });
    first.close();
    await second.receive({ type: "listen", id: "second", request: "3", host: "127.0.0.1", port });
    assert.deepEqual(secondReplies.at(-1), { type: "reply", request: "3", ok: true });
  } finally { first.close(); second.close(); }
});

test("native messaging parses fragmented frames and shuts down on EOF/oversized frames", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const host = nativeMain(input, output);
  const port = await freePort();
  const message = Buffer.from(JSON.stringify({ type: "listen", id: "one", request: "1", host: "127.0.0.1", port }));
  const header = Buffer.alloc(4);
  header.writeUInt32LE(message.length);
  const reply = once(output, "data");
  input.write(header.subarray(0, 2));
  input.write(Buffer.concat([header.subarray(2), message]));
  const [frame] = await reply;
  assert.equal(JSON.parse(frame.subarray(4)).ok, true);
  input.end();
  await once(input, "end");
  assert.equal(host.listeners.size, 0);
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32LE(1024 * 1024);
  const badInput = new PassThrough();
  const bad = nativeMain(badInput, new PassThrough());
  badInput.write(oversized);
  assert.equal(bad.closed, true);
});

test("localhost reserves both loopback families and explicit IPv6 stays loopback-only", async () => {
  const replies = [];
  const host = new LoopbackHost((message) => replies.push(message));
  const port = await freePort();
  try {
    await host.receive({ type: "listen", id: "both", request: "1", host: "localhost", port });
    assert.equal(replies.at(-1).ok, true);
    assert.deepEqual(host.listeners.get("both").servers.map((server) => server.address().address), ["127.0.0.1", "::1"]);
    host.stop("both");
    await host.receive({ type: "listen", id: "v6", request: "2", host: "::1", port });
    assert.equal(replies.at(-1).ok, true);
    assert.equal(host.listeners.get("v6").servers[0].address().address, "::1");
  } finally { host.close(); }
});

test("partial localhost bind failure releases its IPv4 listener and listener budget is reusable", async () => {
  const blocker = createServer();
  blocker.listen({ port: 0, host: "::1", ipv6Only: true });
  await once(blocker, "listening");
  const port = blocker.address().port;
  const replies = [];
  const host = new LoopbackHost((reply) => replies.push(reply));
  try {
    await host.receive({ type: "listen", id: "partial", request: "1", host: "localhost", port });
    assert.equal(replies.at(-1).ok, false);
    assert.equal(host.listeners.size, 0);
    const reused = createServer();
    reused.listen(port, "127.0.0.1");
    await once(reused, "listening");
    await new Promise((resolve) => reused.close(resolve));
    for (let index = 0; index < 8; index++) {
      await host.receive({ type: "listen", id: `listener-${index}`, request: "2", host: "127.0.0.1", port: await freePort() });
      assert.equal(replies.at(-1).ok, true);
    }
    const ninth = { type: "listen", id: "ninth", request: "3", host: "127.0.0.1", port: await freePort() };
    await host.receive(ninth);
    assert.equal(replies.at(-1).ok, false);
    assert.equal(host.listeners.size, 8);
    host.stop("listener-0");
    await host.receive(ninth);
    assert.equal(replies.at(-1).ok, true);
    assert.equal(host.listeners.size, 8);
  } finally {
    host.close();
    await new Promise((resolve) => blocker.close(resolve));
  }
});

class Page {
  location = { origin: "https://no-std-rs.github.io" };
  listeners = new Set();
  addEventListener(_type, fn) { this.listeners.add(fn); }
  removeEventListener(_type, fn) { this.listeners.delete(fn); }
  postMessage(message) { this.outbound(message); }
  emit(message, override = {}) {
    for (const fn of this.listeners) fn({ source: this, origin: this.location.origin, data: message, ...override });
  }
}

test("disconnect rejects pending hello/listen/write requests and stale sessions cannot answer a successor", async () => {
  for (const phase of ["hello", "listen", "write"]) {
    const page = new Page();
    const controller = new LoopbackForwarding(() => ({}), { window: page });
    page.outbound = (message) => {
      if (phase !== "hello" && message.type === "hello") queueMicrotask(() => page.emit({
        source: "tailfeather-loopback-extension", session: controller.session, type: "hello",
      }));
    };
    const pending = phase === "write" ? controller.request({ type: "write", socket: "1", data: "" })
      : controller.listen("http://127.0.0.1:53682/auth");
    const rejected = assert.rejects(pending, /disconnected/);
    await new Promise((resolve) => setImmediate(resolve));
    controller.dispose();
    await rejected;
    assert.equal(controller.pending.size, 0);
    assert.equal(controller.listeners.size, 0);
    assert.equal(page.listeners.size, 0);
    const next = new LoopbackForwarding(() => ({}), { window: page });
    try {
      const current = next.request({ type: "write", socket: "1", data: "" });
      page.emit({ source: "tailfeather-loopback-extension", session: controller.session, type: "reply", request: "1", ok: true });
      assert.equal(next.pending.size, 1);
      page.emit({ source: "tailfeather-loopback-extension", session: next.session, type: "reply", request: "1", ok: true });
      await current;
      assert.equal(next.pending.size, 0);
    } finally { next.dispose(); }
  }
});

test("failure accepting a native connection closes its already opened SSH pipe", async () => {
  const page = new Page();
  let closed = 0;
  const ssh = { async open_forward() { return { close() { closed++; } }; } };
  const controller = new LoopbackForwarding(() => ssh, { window: page });
  page.outbound = (message) => {
    if (message.type === "hello") queueMicrotask(() => page.emit({
      source: "tailfeather-loopback-extension", session: controller.session, type: "hello",
    }));
  };
  controller.request = async ({ type }) => { if (type === "accept") throw Error("native accept timed out"); };
  try {
    await controller.listen("http://127.0.0.1:53682/auth");
    const entry = [...controller.listeners.values()][0];
    await controller.receive({ type: "connection", id: entry.id, socket: "1" });
    assert.equal(controller.pipes.size, 0);
    assert.equal(closed, 1);
  } finally { controller.dispose(); }
});

test("page controller isolates sessions, backpressures bytes, and drops native/SSH resources", async () => {
  const page = new Page();
  let host;
  let controller;
  let closed = 0;
  const forwarded = [];
  const ssh = { async open_forward(host, port, write, close) {
    forwarded.push({ host, port });
    return {
      async send(bytes) { await write(bytes); },
      async eof() { close(); },
      close() { closed++; },
    };
  } };
  controller = new LoopbackForwarding(() => ssh, { window: page });
  const reply = (message) => page.emit({ ...message, source: "tailfeather-loopback-extension", session: controller.session });
  host = new LoopbackHost(reply);
  page.outbound = (message) => {
    if (message.type === "hello") queueMicrotask(() => reply({ type: "hello" }));
    else if (message.type === "disconnect") host.close();
    else void host.receive(message);
  };
  const port = await freePort();
  try {
    const url = `http://127.0.0.1:${port}/auth?state=kept-in-memory`;
    assert.equal(await controller.listen(url), url);
    page.emit({ source: "tailfeather-loopback-extension", session: "wrong", type: "connection" });
    assert.deepEqual(forwarded, []);
    const socket = connect(port, "127.0.0.1");
    await once(socket, "connect");
    socket.write("opaque-TLS-or-HTTP-bytes");
    const [data] = await once(socket, "data");
    assert.equal(data.toString(), "opaque-TLS-or-HTTP-bytes");
    assert.deepEqual(forwarded, [{ host: "127.0.0.1", port }]);
    const payload = Buffer.from(Uint8Array.from({ length: 256 * 1024 }, (_unused, index) => index % 251));
    const chunks = [];
    let length = 0;
    await new Promise((resolve, reject) => {
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        length += chunk.length;
        if (length >= payload.length) resolve();
      });
      socket.once("close", () => { if (length < payload.length) reject(Error("large transfer reset")); });
      socket.write(payload);
    });
    assert.deepEqual(Buffer.concat(chunks), payload);
    controller.dispose();
    await once(socket, "close");
    assert.equal(closed, 1);
    assert.equal(page.listeners.size, 0);
    assert.equal(host.listeners.size, 0);
  } finally { controller.dispose(); host.close(); }
});
