// Full SSH end-to-end test: browser node -> tailnet -> SSH to a real peer.
//
//   TS_AUTHKEY=tskey-auth-... npm run test:ssh      (auth key optional)
//
// Uses a persistent Chromium profile so the node identity saved in
// localStorage survives between runs. Without an auth key (and without a
// saved, still-authorized identity) it prints the login URL and waits for
// someone to approve the node; it never opens that URL itself.
//
// Environment (all optional):
//   TS_AUTHKEY            auth key, typed into the form; never printed
//   TF_E2E_PROFILE        profile directory (default web/client/e2e/.profile)
//   TF_E2E_PORT           fixed port for the page origin (default 8765); the
//                         origin must stay the same for localStorage to persist
//   TF_SSH_HOST           default 100.113.109.28 (bazzite)
//   TF_SSH_USER           default pawel
//   TF_EXPECT_HOST        expected `uname -n`, default bazzite
//   TF_AUTH_WAIT_MIN      minutes to wait for approval (default 10)
//   TF_EPHEMERAL          "0" registers a non-ephemeral node (default ephemeral)
//   RELAY                 relay origin, e.g. https://relay.example
//   HEADED=1              show the browser

import { existsSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DIST, serve } from "./serve.mjs";
import { check, launchPersistent, stripAnsi, watch } from "./browser.mjs";

const profile = resolve(
  process.env.TF_E2E_PROFILE ?? fileURLToPath(new URL("./.profile", import.meta.url)),
);
const port = Number(process.env.TF_E2E_PORT ?? 8765);
const host = process.env.TF_SSH_HOST ?? "100.113.109.28";
const user = process.env.TF_SSH_USER ?? "pawel";
const expectHost = process.env.TF_EXPECT_HOST ?? "bazzite";
const authWaitMs = Number(process.env.TF_AUTH_WAIT_MIN ?? 10) * 60_000;
const relay = process.env.RELAY ?? "";
const marker = "TAILFEATHER_E2E_OK";

const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

async function pollUntil(page, what, timeoutMs, predicate, onTick) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = await page.evaluate(() => ({
      status: window.tailfeather.status,
      authUrl: window.tailfeather.authUrl,
      ip: window.tailfeather.netmap?.self?.ip ?? null,
      netmap: window.tailfeather.netmap,
      logText: window.tailfeather.logs.join("\n"),
      terminal: window.tailfeather.terminalText,
      session: window.tailfeather.session !== null,
      lastClose: window.tailfeather.lastClose ?? null,
    }));
    if (onTick) await onTick(state);
    if (predicate(state)) return state;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what} (status: ${state.status})`);
    await sleep(1000);
  }
}

check(existsSync(join(DIST, "pkg", "tailfeather_web_bg.wasm")), "run ./build.sh first");
mkdirSync(profile, { recursive: true });
const { server, url } = await serve(port);
const context = await launchPersistent(profile);
const page = context.pages()[0] ?? (await context.newPage());
const problems = watch(page, "ssh");
let printedLogs = 0;
async function printNewLogs() {
  const logs = await page.evaluate(() => window.tailfeather?.logs ?? []);
  for (const line of logs.slice(printedLogs)) console.log(`  | ${line}`);
  printedLogs = logs.length;
}

let exitCode = 1;
try {
  await page.goto(url);
  await page.waitForFunction(() => document.body.dataset.ready === "true", null, { timeout: 30_000 });
  console.log(`page ${url} (profile ${profile})`);

  // This script specifies a manual destination and account through SSH options.
  await page.evaluate(() => {
    document.querySelector("#connect-form details").open = true;
    document.querySelector("#ssh-options").open = true;
  });
  if (!await page.locator("#drawer").isVisible()) await page.click("#drawer-toggle");
  if (process.env.TS_AUTHKEY) {
    // Typed into the password field; never echoed. "Remember" stores it in
    // this profile's localStorage for later runs.
    await page.fill("#auth-key", process.env.TS_AUTHKEY);
    console.log("auth key: provided through TS_AUTHKEY");
  } else {
    const remembered = await page.inputValue("#auth-key");
    console.log(`auth key: ${remembered ? "remembered in the profile" : "none (interactive login)"}`);
  }
  await page.fill("#relay", relay);
  await page.fill("#target", host);
  await page.fill("#ssh-host", host);
  await page.fill("#ssh-user", user);
  if (process.env.TF_EPHEMERAL === "0") await page.uncheck("#ephemeral");
  await page.check("#remember");
  await page.click("#connect-button");

  let shownAuthUrl = "";
  await pollUntil(
    page,
    "a tailnet address",
    authWaitMs,
    (state) => state.ip !== null,
    async (state) => {
      await printNewLogs();
      if (state.authUrl && state.authUrl !== shownAuthUrl) {
        shownAuthUrl = state.authUrl;
        console.log(`\n>>> Approve this node within ${authWaitMs / 60_000} minutes: ${state.authUrl}\n`);
      }
    },
  );
  const state = await pollUntil(
    page,
    `${host} in the netmap`,
    60_000,
    (state) => state.netmap?.peers?.some((peer) => peer.ip === host),
    printNewLogs,
  );
  const peer = state.netmap.peers.find((peer) => peer.ip === host);
  console.log(`node address ${state.ip}; target ${peer.name || host} home DERP ${peer.homeDerp}, online=${peer.online}`);

  await page.evaluate(({ host, user }) => window.tailfeather.ssh({ ip: host, user }), { host, user });
  let printedTerminal = 0;
  const showTerminal = async (state) => {
    await printNewLogs();
    const text = stripAnsi(state.terminal);
    if (text.length > printedTerminal) {
      process.stdout.write(text.slice(printedTerminal).replace(/^/gm, "  > "));
      process.stdout.write("\n");
      printedTerminal = text.length;
    }
    if (/password:|passphrase/i.test(text)) throw new Error("the server asked for a password; this test expects Tailscale SSH");
  };
  // Tailscale SSH "check" mode prints a login link in the terminal and waits.
  await pollUntil(
    page,
    "an authenticated SSH session",
    authWaitMs,
    (state) => state.lastClose !== null || /SSH: authenticated/.test(state.logText),
    showTerminal,
  );
  const closed = await page.evaluate(() => window.tailfeather.lastClose ?? null);
  check(closed === null, `SSH closed early: ${closed}`);
  await sleep(1500);
  await page.evaluate((command) => {
    window.tailfeather.session.send(new TextEncoder().encode(command));
  }, `echo ${marker}; uname -n\r`);
  const done = await pollUntil(
    page,
    "the command output",
    60_000,
    (state) => new RegExp(`(^|\\n)${marker}\\r?\\n${expectHost}\\r?\\n`).test(stripAnsi(state.terminal)),
    showTerminal,
  );
  check(done.session, "the SSH session ended before the check");
  console.log(`\noutput contains "${marker}" followed by "${expectHost}"`);
  await page.evaluate(() => window.tailfeather.session.send(new TextEncoder().encode("exit\r")));
  await pollUntil(page, "the session to close", 30_000, (state) => !state.session, showTerminal);
  const reason = await page.evaluate(() => window.tailfeather.lastClose);
  console.log(`closed: ${reason}`);
  check(problems.length === 0, problems.join("\n"));
  console.log("PASS ssh");
  exitCode = 0;
} catch (error) {
  await printNewLogs().catch(() => {});
  console.log(`FAIL ssh: ${error.message}`);
} finally {
  await page.evaluate(() => window.tailfeather?.client?.stop()).catch(() => {});
  await context.close();
  server.close();
}
process.exit(exitCode);
