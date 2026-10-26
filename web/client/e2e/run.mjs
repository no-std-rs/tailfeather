// Credential-free end-to-end tests against the real Tailscale service.
//
//   npm run test:e2e        (after ./build.sh)
//
// 1. control: the built page, started without an auth key, reaches the point
//    where the production control plane returns an AuthURL. That proves the
//    /key fetch, ts2021 over WebSocket, Noise, HTTP/2 and RegisterRequest.
//    The URL is printed and never visited.
// 2. derp: the page opens a DERP WebSocket to a hosted region (DERP_REGION,
//    default "waw", bazzite's home) and completes the DERP handshake with a
//    throwaway key.
// 3. page: xterm mounts, and the page raised no CSP violations or errors.
// 4. ssh-local: the browser's russh client (ring crypto, key exchange, host
//    key trust-on-first-use and pinning, `none` and keyboard-interactive auth
//    with an auth banner, PTY shell, exit status) against a local ssh2 server
//    reached through a WebSocket byte-stream bridge on the page's origin.
//
// RELAY=https://relay.example repeats the control and DERP checks through a
// deployed relay.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { DIST, serve } from "./serve.mjs";
import { check, launch, openPage, stripAnsi } from "./browser.mjs";
import { startLocalSsh } from "./local-ssh.mjs";
import { workspaceTest } from "./workspace.mjs";
import { accountsTest } from "./accounts.mjs";
import { loopbackTest } from "./loopback.mjs";

const relay = process.env.RELAY ?? "";
const derpRegion = process.env.DERP_REGION ?? "waw";

async function derpHost(code) {
  // Test-harness side only: the page itself cannot read this (no CORS).
  const response = await fetch("https://login.tailscale.com/derpmap/default");
  const map = await response.json();
  const region = Object.values(map.Regions).find((region) => region.RegionCode === code);
  check(region, `no DERP region ${code} in the default map`);
  const node = region.Nodes.find((node) => !node.STUNOnly);
  return { id: region.RegionID, host: node.HostName };
}

async function controlTest(context, url) {
  const { page, problems } = await openPage(context, url, "control");
  await page.fill("#hostname", `tailfeather-e2e-${Date.now().toString(36)}`);
  await page.fill("#auth-key", "");
  await page.evaluate(() => {
    document.querySelector("#connect-form details").open = true;
  });
  await page.fill("#relay", relay);
  await page.uncheck("#remember");
  await page.click("#connect-button");
  try {
    await page.waitForFunction(() => window.tailfeather.authUrl !== "", null, { timeout: 90_000 });
  } finally {
    const logs = await page.evaluate(() => window.tailfeather.logs);
    console.log(logs.map((line) => `    ${line}`).join("\n"));
  }
  const authUrl = await page.evaluate(() => window.tailfeather.authUrl);
  check(/^https:\/\/login\.tailscale\.com\//.test(authUrl), `unexpected AuthURL ${authUrl}`);
  const shown = await page.textContent("#auth-link");
  check(shown === authUrl, "the AuthURL is not shown in the page");
  console.log(`  AuthURL returned by production control (not visited): ${authUrl}`);
  await page.evaluate(() => window.tailfeather.client.stop());
  check(problems.length === 0, problems.join("\n"));
  await page.close();
}

async function derpTest(context, url) {
  const { id, host } = await derpHost(derpRegion);
  const { page, problems } = await openPage(context, url, "derp");
  const serverKey = await page.evaluate(
    ([host, relay]) => window.tailfeather.derpProbe(host, relay),
    [host, relay],
  );
  check(/^nodekey:[0-9a-f]{8}/.test(serverKey), `unexpected DERP server key ${serverKey}`);
  console.log(`  DERP region ${id} (${derpRegion}) ${host}: handshake complete, server key ${serverKey}`);
  check(problems.length === 0, problems.join("\n"));
  await page.close();
}

async function pageTest(context, url) {
  const { page, problems } = await openPage(context, url, "page");
  // Pixel sizes are not checked: a sandboxed headless Chromium may have no
  // usable fonts, which leaves xterm's cell metrics at zero.
  const terminal = await page.evaluate(() => ({
    mounted: document.querySelector("#terminal .xterm .xterm-screen") !== null,
    cols: window.tailfeather.terminal.cols,
  }));
  check(terminal.mounted && terminal.cols > 0, "xterm did not mount");
  const disabled = await page.isDisabled("#ssh-button");
  check(disabled, "SSH should wait for a tailnet address");

  // Remembered settings restore cleared fields as empty, not as page defaults.
  await page.evaluate(() =>
    localStorage.setItem("tailfeather.settings", JSON.stringify({ remember: true, sshHost: "", target: "", sshUser: "alice" })),
  );
  await page.reload();
  await page.waitForFunction(() => document.body.dataset.ready === "true", null, { timeout: 30_000 });
  const restored = await page.evaluate(() => ({
    sshHost: document.querySelector("#ssh-host").value,
    target: document.querySelector("#target").value,
    sshUser: document.querySelector("#ssh-user").value,
  }));
  check(restored.sshHost === "" && restored.target === "", `cleared fields came back: ${JSON.stringify(restored)}`);
  check(restored.sshUser === "alice", "a remembered value was not restored");
  check(problems.length === 0, problems.join("\n"));
  console.log("  page loads with no CSP violations; xterm mounts; cleared settings stay cleared");
  await page.close();
}

async function sessionLabelsTest(context, url) {
  const { page, problems } = await openPage(context, url, "session-labels");
  const initialTitle = await page.title();
  await page.evaluate(() => {
    const api = window.tailfeather;
    api.netmap = { peers: [
      { ip: "100.64.0.1", name: "workstation" },
      { ip: "100.64.0.2", name: "server" },
      { ip: "100.64.0.3", name: "server" },
    ] };
    // Test label rendering without opening a connection to a real tailnet.
    api.client = { ssh: (_options, callbacks) => ({
      resize() {}, send() {}, close() { callbacks.closed("test complete"); },
    }) };
    api.ssh({ user: "alice", ip: "100.64.0.1" });
  });
  check(await page.locator(".tab-label").textContent() === "alice@workstation", "SSH tab still shows an IP instead of its peer name");
  check(await page.title() === "alice@workstation · tailfeather", "browser title still shows an IP instead of its peer name");
  await page.evaluate(() => {
    const api = window.tailfeather;
    api.netmap.peers[0].name = "renamed-workstation";
    api.ssh({ user: "root", ip: "100.64.0.2" });
  });
  const labels = await page.locator(".tab-label").allTextContents();
  check(labels[0] === "alice@renamed-workstation", "an existing tab did not pick up the new peer name");
  check(labels[1] === "root@server (100.64.0.2)", "a duplicate peer name lost its distinguishing IP");
  await page.evaluate(() => window.tailfeather.selectTab(window.tailfeather.sessions[0].id));
  check(await page.title() === "alice@renamed-workstation · tailfeather", "browser title did not follow a renamed SSH tab");
  await page.evaluate(() => {
    const api = window.tailfeather;
    for (const tab of api.sessions) api.closeTab(tab.id);
    api.client = null;
  });
  check(await page.title() === initialTitle, "closing every SSH tab did not restore the idle browser title");
  check(problems.length === 0, problems.join("\n"));
  console.log("  SSH and browser tabs use peer names, distinguish duplicates, and update after renaming");
  await page.close();
}

async function terminalMatches(page, pattern, what, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const text = stripAnsi(await page.evaluate(() => window.tailfeather.terminalText));
    if (pattern.test(text)) return text;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}; terminal:\n${text}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

async function closedWith(page, pattern, what) {
  await page.waitForFunction(() => window.tailfeather.lastClose, null, { timeout: 20_000 });
  const reason = await page.evaluate(() => window.tailfeather.lastClose);
  check(pattern.test(reason), `${what}: closed with "${reason}"`);
  return reason;
}

async function localSshTest(context, url) {
  const { page, problems } = await openPage(context, url, "ssh-local");
  const wsUrl = `${url.replace(/^http/, "ws")}ssh`;
  const open = (user) =>
    page.evaluate(([url, user]) => window.tailfeather.ssh({ url, user }), [wsUrl, user]);
  const send = (text) =>
    page.evaluate((text) => window.tailfeather.session.send(new TextEncoder().encode(text)), text);

  // auth "none", first use of the host key, a shell, and the exit status.
  await open("tester");
  await terminalMatches(page, /Permanently added .* \(SHA256:[A-Za-z0-9+/]+\)/, "the host key");
  await terminalMatches(page, /welcome to e2e-sshd/, "the shell");
  await send("echo TAILFEATHER_E2E_OK; uname -n\r");
  await terminalMatches(page, /(^|\n)TAILFEATHER_E2E_OK\r?\ne2e-sshd\r?\n/, "the command output");
  await send("exit\r");
  await closedWith(page, /exit status 0/, "exit");
  console.log("  none auth, TOFU host key, PTY shell, command output, exit status 0");

  // keyboard-interactive, answered in the terminal, after a banner; the
  // host key is now remembered.
  await open("kbd");
  await terminalMatches(page, /matches the remembered one/, "the pinned host key");
  await terminalMatches(page, /e2e-sshd banner: authorized testing only/, "the auth banner");
  await terminalMatches(page, /Code: $/, "the keyboard-interactive prompt");
  await page.evaluate(() => window.tailfeather.terminal.input("1234\r"));
  await terminalMatches(page, /welcome to e2e-sshd/, "the shell after keyboard-interactive");
  await send("exit\r");
  await closedWith(page, /exit status 0/, "exit");
  console.log("  auth banner, keyboard-interactive prompt answered in the terminal");

  // Disconnect while authentication waits at a prompt: setup must stop rather
  // than wait for an answer that will never come.
  await open("kbd");
  await terminalMatches(page, /Code: $/, "a prompt to abandon");
  await page.click("#ssh-close");
  await closedWith(page, /before the session started|authentication cancelled/, "disconnect during authentication");
  console.log("  disconnect during authentication ends the session");

  // Opening another tab while authentication waits leaves both independent.
  await open("kbd");
  await terminalMatches(page, /Code: $/, "the prompt of the background session");
  const backgroundId = await page.evaluate(() => window.tailfeather.activeTabId);
  await open("tester");
  await terminalMatches(page, /welcome to e2e-sshd/, "the second tab's shell");
  await page.evaluate((id) => window.tailfeather.closeTab(id), backgroundId);
  await page.waitForTimeout(500);
  check(await page.evaluate(() => window.tailfeather.session !== null), "closing the background prompt cleared the active session");
  await send("echo STILL_OPEN\r");
  await terminalMatches(page, /(^|\n)STILL_OPEN\r?\n/, "input to the replacement session");
  await send("exit\r");
  await closedWith(page, /exit status 0/, "exit of the replacement");
  console.log("  closing a background authentication prompt leaves the active session alone");

  // Connecting again replaces the tailnet client; a terminal attached to the
  // old one's network stack must be closed, not left waiting forever.
  await open("tester");
  await terminalMatches(page, /welcome to e2e-sshd/, "a shell to strand");
  await page.evaluate(() => {
    document.querySelector("#auth-key").value = "";
    document.querySelector("#remember").checked = false;
  });
  await page.click("#connect-button");
  await closedWith(page, /closed/i, "the terminal when reconnecting");
  check(await page.evaluate(() => window.tailfeather.session === null), "the terminal outlived its client");
  // A reconnect that fails to start must not leave the stopped client in use.
  await page.evaluate(() => {
    document.querySelector("#connect-form details").open = true;
    document.querySelector("#relay").value = "ftp://not-a-relay.example";
  });
  await page.click("#connect-button");
  await page.waitForFunction(() => window.tailfeather.logs.some((line) => /Could not start/.test(line)), null, {
    timeout: 10_000,
  });
  check(await page.evaluate(() => window.tailfeather.client === null), "a failed reconnect kept the stopped client");
  check(await page.isDisabled("#ssh-button"), "SSH stayed enabled without a client");
  await page.evaluate(() => {
    document.querySelector("#relay").value = "";
  });
  console.log("  reconnecting closes the terminal of the replaced client; a failed start leaves no client");

  // A different remembered key is refused.
  await page.evaluate((slot) => localStorage.setItem(slot, "SHA256:not-this-key"), `tailfeather.hostkey.${wsUrl}`);
  await open("tester");
  await terminalMatches(page, /REMOTE HOST IDENTIFICATION HAS CHANGED/, "the host key warning");
  await closedWith(page, /HAS CHANGED/, "a changed host key");
  console.log("  a changed host key is refused");
  check(problems.length === 0, problems.join("\n"));
  await page.close();
}

// /connect hands over a minted key in the fragment. The page must take it out
// of the URL, connect with it, and never write it to the input or storage.
async function mintedKeyTest(context, url) {
  const key = "tskey-auth-kE2EfragmentCNTRL-0000deadbeef";
  const { page, problems } = await openPage(context, `${url}#tskey=${key}`, "minted-key");
  await page.waitForFunction(() => window.tailfeather.client !== null, null, { timeout: 10_000 });
  const state = await page.evaluate(() => ({
    hash: location.hash,
    input: document.querySelector("#auth-key").value,
    storage: JSON.stringify({ ...localStorage }),
    logs: window.tailfeather.logs.join("\n"),
  }));
  await page.evaluate(() => window.tailfeather.client.stop());
  check(state.hash === "", `the fragment was left in the URL: ${state.hash}`);
  check(state.input === "", "the minted key was put in the auth key field");
  check(!state.storage.includes(key), "the minted key was persisted");
  check(!state.logs.includes(key), "the minted key was logged");
  check(/single-use auth key from \/connect/.test(state.logs), "the page did not connect with the key");
  check(problems.length === 0, problems.join("\n"));
  await page.close();

  // Even when the WebAssembly module never loads, the key leaves the URL.
  const failing = await context.newPage();
  await failing.route("**/*.wasm", (route) => route.abort());
  await failing.goto(`${url}#tskey=${key}`);
  await failing.waitForFunction(() => location.hash === "", null, { timeout: 10_000 });
  await failing.close();
  console.log("  #tskey is consumed, stripped from the URL (even if the wasm fails), used once, never stored or logged");
}

// Two tabs of one origin share the persisted node identity; only one may run it.
async function oneTabTest(context, url) {
  const first = await openPage(context, url, "tab-1");
  const second = await openPage(context, url, "tab-2");
  const connect = async (page) => {
    await page.evaluate(() => {
      document.querySelector("#auth-key").value = "";
      document.querySelector("#remember").checked = false;
    });
    await page.click("#connect-button");
  };
  await connect(first.page);
  await first.page.waitForFunction(() => window.tailfeather.client !== null, null, { timeout: 10_000 });
  await connect(second.page);
  await second.page.waitForFunction(
    () => window.tailfeather.logs.some((line) => /already running in another tab/.test(line)),
    null,
    { timeout: 10_000 },
  );
  check(await second.page.evaluate(() => window.tailfeather.client === null), "the second tab started the node");
  await first.page.evaluate(() => window.tailfeather.client?.stop());
  check(first.problems.length === 0 && second.problems.length === 0, [...first.problems, ...second.problems].join("\n"));
  await first.page.close();
  await second.page.close();
  console.log("  a second tab refuses to run the node that another tab is running");
}

check(existsSync(join(DIST, "pkg", "tailfeather_web_bg.wasm")), "run ./build.sh first");
const { server, url } = await serve();
const localSsh = await startLocalSsh(server);
const browser = await launch();
let failed = 0;
for (const [name, test] of [
  ["page", pageTest],
  ["session-labels", sessionLabelsTest],
  ["accounts", accountsTest],
  ["accounts-mobile", accountsTest],
  ["minted-key", mintedKeyTest],
  ["one-tab", oneTabTest],
  ["ssh-local", localSshTest],
  ["ssh-loopback", loopbackTest],
  ["workspace", workspaceTest],
  ["workspace-mobile", workspaceTest],
  ["derp", derpTest],
  ["control", controlTest],
].filter(([name]) => !process.argv.includes("--local") || !["derp", "control"].includes(name))) {
  const context = await browser.newContext(name.endsWith("-mobile") ?
    { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } : {});
  console.log(`${name}${relay ? ` (relay ${relay})` : ""}:`);
  try {
    await test(context, url);
    console.log(`PASS ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL ${name}: ${error.message}`);
  }
  await context.close();
}
await browser.close();
localSsh.close();
server.close();
process.exit(failed ? 1 : 0);
