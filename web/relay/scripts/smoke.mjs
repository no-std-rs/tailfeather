// Live smoke test for the relay (needs network access to Tailscale).
//
//   npm run smoke                        # starts `wrangler dev` on a free local port
//   RELAY_URL=https://host npm run smoke # tests an already running instance instead
//
// Checks: a few rejections (403/426/404), a DERP WebSocket through the relay to
// derp1f.tailscale.com whose first frame is the DERP server key (type 0x01 +
// magic "DERP🔑"), and a control WebSocket that the upstream accepts and then
// closes because the handshake is deliberately invalid (close code propagation).

import { createServer } from "node:net";
import { assetsOverride, spawnWrangler } from "./wrangler.mjs";

const DERP_HOST = process.env.SMOKE_DERP_HOST ?? "derp1f.tailscale.com";
const CONTROL_HOST = process.env.SMOKE_CONTROL_HOST ?? "controlplane.tailscale.com";
const MAGIC = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];
const FRAME_SERVER_KEY = 0x01;

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForServer(base, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fetch(`${base}/relay/`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error(`wrangler dev did not come up within ${timeoutMs} ms`);
}

async function expectStatus(base, path, expected, headers = {}) {
  const res = await fetch(`${base}${path}`, { headers });
  await res.arrayBuffer();
  if (res.status !== expected) throw new Error(`GET ${path}: expected ${expected}, got ${res.status}`);
  console.log(`ok  GET ${path} -> ${res.status}`);
}

function openSocket(url, protocol, onOpen, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, [protocol]);
    ws.binaryType = "arraybuffer";
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`timeout on ${url.replace(/\?.*/, "?…")}`));
    }, timeoutMs);
    const finish = (fn, value) => {
      clearTimeout(timer);
      fn(value);
    };
    ws.addEventListener("error", () => finish(reject, new Error("websocket error (connection refused or upgrade failed)")));
    ws.addEventListener("open", () => {
      if (ws.protocol !== protocol) {
        ws.close();
        finish(reject, new Error(`negotiated protocol ${JSON.stringify(ws.protocol)}, want ${protocol}`));
        return;
      }
      onOpen(ws, (value) => finish(resolve, value), (err) => finish(reject, err));
    });
  });
}

function checkDerp(wsBase) {
  const url = `${wsBase}/relay/derp/${DERP_HOST}`;
  return openSocket(url, "derp", (ws, done, fail) => {
    const bytes = [];
    ws.addEventListener("message", (event) => {
      if (typeof event.data === "string") return fail(new Error("unexpected text frame"));
      bytes.push(...new Uint8Array(event.data));
      if (bytes.length < 5 + MAGIC.length) return;
      const head = bytes.slice(0, 13);
      const hex = head.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      ws.close(1000, "smoke done");
      if (head[0] !== FRAME_SERVER_KEY || !MAGIC.every((b, i) => head[5 + i] === b)) {
        return fail(new Error(`first frame is not a DERP server key: ${hex}`));
      }
      done(hex);
    });
    ws.addEventListener("close", (event) => fail(new Error(`closed early: ${event.code} ${event.reason}`)));
  });
}

function checkControl(wsBase) {
  // "!!!" is not valid base64, so the control server accepts the WebSocket and
  // then closes it with a policy-violation code that must survive the relay.
  const url = `${wsBase}/relay/control/${CONTROL_HOST}/ts2021?X-Tailscale-Handshake=%21%21%21`;
  return openSocket(url, "tailscale-control-protocol", (ws, done) => {
    ws.addEventListener("close", (event) => done({ code: event.code, reason: event.reason }));
  });
}

async function main() {
  let base = process.env.RELAY_URL?.replace(/\/+$/, "");
  let child = null;
  let assets = null;
  if (!base) {
    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    assets = assetsOverride();
    child = spawnWrangler(
      ["dev", "--ip", "127.0.0.1", "--port", String(port), "--show-interactive-dev-session=false", ...assets.args],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    child.on("exit", (code) => {
      if (code) console.error(`wrangler dev exited with ${code}`);
    });
  }
  const wsBase = base.replace(/^http/, "ws");
  try {
    await waitForServer(base, 60000);
    await expectStatus(base, `/relay/derp/${DERP_HOST}.evil.com`, 403);
    await expectStatus(base, `/relay/derp/${DERP_HOST}`, 426);
    await expectStatus(base, "/relay/nope", 404);
    const hex = await checkDerp(wsBase);
    console.log(`ok  DERP via relay: first bytes ${hex} (frameServerKey + "DERP🔑")`);
    const closed = await checkControl(wsBase);
    console.log(`ok  control via relay: upgraded, upstream closed ${closed.code} ${JSON.stringify(closed.reason)}`);
    console.log("smoke: PASS");
  } catch (err) {
    console.error(`smoke: FAIL: ${err.message}`);
    process.exitCode = 1;
  } finally {
    if (child) child.kill("SIGTERM");
    assets?.cleanup();
  }
}

await main();
