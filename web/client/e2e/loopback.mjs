// Real browser/WASM/russh/direct-tcpip + native loopback sockets. The Firefox
// runtime API is shimmed; the shipped content script is executed unchanged.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createServer as tcpServer } from "node:net";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { serve } from "./serve.mjs";
import { startLocalSsh } from "./local-ssh.mjs";
import { openPage, check } from "./browser.mjs";
import { LoopbackHost } from "../../loopback/native.mjs";

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

export async function loopbackTest(context, { nativeExtension = false } = {}) {
  const reservation = tcpServer();
  const port = await listen(reservation);
  await new Promise((resolve) => reservation.close(resolve));
  const original = `http://127.0.0.1:${port}/auth?state=fixture-state`;
  const callback = `http://127.0.0.1:${port}/`;
  let finished = false;
  const provider = createServer((request, response) => {
    const url = new URL(request.url, "http://provider.test");
    if (url.pathname === "/favicon.ico") { response.writeHead(204).end(); return; }
    assert.equal(url.searchParams.get("redirect_uri"), callback);
    assert.equal(url.searchParams.get("state"), "fixture-state");
    if (url.pathname === "/authorize") {
      response.writeHead(200, { "Content-Type": "text/html" });
      response.end(`<form action="/approve"><input type="hidden" name="redirect_uri" value="${callback}"><input type="hidden" name="state" value="fixture-state"><button>Sign in to test provider</button></form>`);
    } else {
      response.writeHead(302, { Location: `${callback}?code=fixture-code&state=fixture-state` }).end();
    }
  });
  const providerPort = await listen(provider);
  const remote = createServer((request, response) => {
    const url = new URL(request.url, callback);
    if (url.pathname === "/favicon.ico") { response.writeHead(204).end(); return; }
    if (url.pathname === "/auth") {
      assert.equal(url.searchParams.get("state"), "fixture-state");
      response.writeHead(302, { Location: `http://127.0.0.1:${providerPort}/authorize?redirect_uri=${encodeURIComponent(callback)}&state=fixture-state` }).end();
    } else {
      assert.equal(url.searchParams.get("code"), "fixture-code");
      assert.equal(url.searchParams.get("state"), "fixture-state");
      finished = true;
      response.writeHead(200, { "Content-Type": "text/plain" }).end("Authorization complete");
    }
  });
  const backingPort = await listen(remote);
  const { server, url } = await serve();
  const forwards = [];
  const ssh = await startLocalSsh(server, { forwardTarget: { port, backingPort }, onForward: (info) => forwards.push(info) });
  const hosts = new Map();
  let page;
  try {
    if (!nativeExtension) {
      await context.exposeBinding("__loopbackNative", async ({ page: owner }, message) => {
        if (!hosts.has(message.session)) hosts.set(message.session, new LoopbackHost((reply) => {
          void owner.evaluate(({ session, reply }) => window.__nativePorts.get(session)?.emit(reply),
            { session: message.session, reply }).catch(() => {});
        }));
        await hosts.get(message.session).receive(message);
      });
      await context.exposeBinding("__loopbackDisconnect", (_source, session) => hosts.get(session)?.close());
      await context.addInitScript(() => {
        window.__nativePorts = new Map();
        window.browser = { runtime: { connect() {
          const messages = [];
          const disconnects = [];
          let session;
          let disconnected = false;
          const port = {
            onMessage: { addListener(fn) { messages.push(fn); } },
            onDisconnect: { addListener(fn) { disconnects.push(fn); } },
            postMessage(message) {
              session = message.session;
              window.__nativePorts.set(session, port);
              void window.__loopbackNative(message);
            },
            emit(message) { if (!disconnected) for (const fn of messages) fn(message); },
            disconnect() {
              if (disconnected) return;
              disconnected = true;
              void window.__loopbackDisconnect(session);
              for (const fn of disconnects) fn();
            },
          };
          return port;
        } } };
      });
      await context.addInitScript({ path: fileURLToPath(new URL("../../loopback/extension/content.js", import.meta.url)) });
    }
    const opened = await openPage(context, url, "loopback");
    page = opened.page;
    const ws = url.replace(/^http/, "ws") + "ssh";
    const openTerminal = async () => {
      await page.evaluate((url) => window.tailfeather.ssh({ url, user: "tester" }), ws);
      await page.waitForFunction(() => window.tailfeather.terminalText.includes("welcome to e2e-sshd"));
      await page.evaluate((text) => window.tailfeather.session.send(new TextEncoder().encode(`echo ${text}\r`)), original);
      await page.waitForSelector(".pane:not([hidden]) .ssh-loopback-link", { state: "attached" });
    };
    await openTerminal();
    const firstTab = await page.evaluate(() => window.tailfeather.sessions[0].id);
    const popupReady = page.waitForEvent("popup");
    await page.locator(".pane:not([hidden]) .ssh-link-list").evaluate((details) => { details.open = true; });
    await page.click(".pane:not([hidden]) .ssh-loopback-link");
    const popup = await popupReady;
    await popup.waitForSelector("button");
    // Server policy rejection is preserved by the existing authenticated session.
    const denied = await page.evaluate(async (port) => {
      try { await window.tailfeather.session.open_forward("127.0.0.1", port, () => {}, () => {}); return false; }
      catch { return true; }
    }, port === 65535 ? port - 1 : port + 1);
    check(denied, "server forwarding policy was bypassed");

    await openTerminal();
    await page.locator(".pane:not([hidden]) .ssh-link-list").evaluate((details) => { details.open = true; });
    await page.click(".pane:not([hidden]) .ssh-loopback-link");
    await page.waitForFunction(() => document.querySelector(".pane:not([hidden]) .ssh-forwarding-status").textContent.includes("refused"));
    await page.evaluate(() => window.tailfeather.closeTab(window.tailfeather.sessions[1].id));

    await popup.click("button");
    await popup.waitForURL(`${callback}?code=fixture-code&state=fixture-state`);
    check(await popup.textContent("body") === "Authorization complete" && finished, "OAuth callback did not reach original remote listener");
    check(forwards.length >= 1 && forwards.every((info) => info.destIP === "127.0.0.1" && info.destPort === port), "forwarding changed the remote destination");
    const secretState = await page.evaluate(() => ({ stored: JSON.stringify({ ...localStorage }), logs: window.tailfeather.logs.join("\n") }));
    check(!/fixture-state|fixture-code/.test(secretState.stored + secretState.logs), "OAuth values escaped into logs/storage");
    await page.evaluate((id) => window.tailfeather.closeTab(id), firstTab);
    await popup.close();
    await page.waitForTimeout(100);
    check([...hosts.values()].every((host) => host.listeners.size === 0 && host.sockets.size === 0), "closed terminals retained native resources");
    const reused = tcpServer();
    reused.listen(port, "127.0.0.1");
    await once(reused, "listening");
    await new Promise((resolve) => reused.close(resolve));
    check(opened.problems.length === 0, opened.problems.join("\n"));
    console.log("  original loopback OAuth redirect/callback over authenticated SSH; policy, tab isolation and cleanup verified");
  } finally {
    for (const host of hosts.values()) host.close();
    await page?.close();
    ssh.close();
    server.close();
    remote.closeAllConnections();
    remote.close();
    provider.closeAllConnections();
    provider.close();
  }
}
