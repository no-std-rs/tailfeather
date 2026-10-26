// Real pinned rclone, local mock OAuth, unchanged registered loopback URI.
// A private network namespace models the SSH host's independent loopback.
import { createServer as httpServer } from "node:http";
import { createServer as tcpServer, connect } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { serve } from "./serve.mjs";
import { startLocalSsh } from "./local-ssh.mjs";
import { openPage, check } from "./browser.mjs";

const VERSION = "1.75.2";
const CALLBACK = "http://127.0.0.1:53682/";
const CLIENT = "tailfeather-local-test-client";
const SECRET = "tailfeather-local-test-secret";
const CODE = "tailfeather-local-test-code";
const TOKEN = "tailfeather-local-test-access";
const REFRESH = "tailfeather-local-test-refresh";
const COMMAND = "rclone authorize drive --auth-no-open-browser";

async function listen(server, address) {
  server.listen(address);
  await once(server, "listening");
  return server;
}

function bridge(socket, upstream) {
  socket.pipe(upstream).pipe(socket);
  const close = () => { socket.destroy(); upstream.destroy(); };
  socket.on("error", close);
  upstream.on("error", close);
  socket.on("close", () => upstream.destroy());
  upstream.on("close", () => socket.destroy());
}

async function namespaceHost(binary, directory, providerPort) {
  const emit = (message) => process.stdout.write(JSON.stringify(message) + "\n");
  let state = "";
  let exchanged = false;
  const sockets = new Set();
  const provider = httpServer(async (request, response) => {
    try {
      const url = new URL(request.url, `http://127.0.0.1:${providerPort}`);
      if (url.pathname === "/authorize") {
        check(url.searchParams.get("redirect_uri") === CALLBACK, "rclone changed the registered loopback URI");
        check(url.searchParams.get("client_id") === CLIENT && url.searchParams.get("response_type") === "code", "unexpected mock OAuth request");
        state = url.searchParams.get("state");
        check(state?.length > 10, "rclone did not provide OAuth state");
        const approve = "/approve?" + new URLSearchParams({ state });
        response.writeHead(200, { "Content-Type": "text/html" }).end(
          `<!doctype html><a href="${approve.replaceAll("&", "&amp;")}">Authorize local test account</a>`);
      } else if (url.pathname === "/approve") {
        check(state && url.searchParams.get("state") === state, "mock OAuth state mismatch");
        response.writeHead(302, { Location: CALLBACK + "?" + new URLSearchParams({ state, code: CODE }) }).end();
      } else if (url.pathname === "/token" && request.method === "POST") {
        let body = "";
        for await (const chunk of request) {
          body += chunk;
          check(body.length < 65536, "oversized mock token request");
        }
        const form = new URLSearchParams(body);
        const basic = "Basic " + Buffer.from(`${CLIENT}:${SECRET}`).toString("base64");
        check(request.headers.authorization === basic ||
          (form.get("client_id") === CLIENT && form.get("client_secret") === SECRET), "wrong mock OAuth client");
        check(form.get("grant_type") === "authorization_code" && form.get("code") === CODE &&
          form.get("redirect_uri") === CALLBACK, "wrong mock token exchange");
        exchanged = true;
        response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({
          access_token: TOKEN, refresh_token: REFRESH, token_type: "Bearer", expires_in: 3600,
        }));
      } else response.writeHead(404).end();
    } catch {
      response.writeHead(400).end("Invalid local test OAuth request");
    }
  });
  await listen(provider, { port: providerPort, host: "127.0.0.1" });
  const proxies = [];
  for (const [name, port] of [["provider.sock", providerPort], ["rclone.sock", 53682]]) {
    const proxy = tcpServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      bridge(socket, connect(port, "127.0.0.1"));
    });
    await listen(proxy, join(directory, name));
    proxies.push(proxy);
  }
  const child = spawn(binary, ["authorize", "drive", CLIENT, SECRET, "--auth-no-open-browser",
    "--drive-auth-url", `http://127.0.0.1:${providerPort}/authorize`,
    "--drive-token-url", `http://127.0.0.1:${providerPort}/token`, "--config", "/dev/null"],
  { env: { LANG: "C.UTF-8" }, stdio: ["ignore", "pipe", "pipe"] });
  // OAuth values and final token JSON are inspected only in memory, never logged.
  let output = "";
  let announced = false;
  const capture = (data) => {
    output += data.toString("utf8");
    if (output.length > 512 * 1024) { child.kill(); return; }
    const url = /http:\/\/127\.0\.0\.1:53682\/auth\?state=[^\s]+\r?\n/.exec(output)?.[0].trim();
    if (url && !announced) { announced = true; emit({ type: "url", url }); }
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("error", () => emit({ type: "error" }));
  child.on("close", (code) => {
    let token;
    try { token = JSON.parse(/--->\s*\n([^\n]+)\n<---End paste/.exec(output)?.[1]); } catch {}
    emit({ type: "complete", success: code === 0 && exchanged &&
      token?.access_token === TOKEN && token?.refresh_token === REFRESH });
    output = "";
    state = "";
  });
  const stop = () => {
    child.kill();
    for (const socket of sockets) socket.destroy();
    for (const proxy of proxies) proxy.close();
    provider.closeAllConnections();
    provider.close();
  };
  process.stdin.resume();
  process.stdin.on("end", stop);
  process.on("SIGTERM", stop);
}

export async function realRcloneTest(context, binary) {
  const version = spawnSync(binary, ["version"], { encoding: "utf8", env: { LANG: "C.UTF-8" } });
  check(version.status === 0 && version.stdout.startsWith(`rclone v${VERSION}\n`), `Expected pinned rclone v${VERSION}`);
  const directory = await mkdtemp(join(tmpdir(), "tailfeather-rclone-"));
  const providerProxy = await listen(tcpServer((socket) => bridge(socket, connect(join(directory, "provider.sock")))), { port: 0, host: "127.0.0.1" });
  const { server, url } = await serve();
  let namespace;
  let page;
  let resolveUrl, rejectUrl, resolveDone, rejectDone;
  const authUrl = new Promise((resolve, reject) => { resolveUrl = resolve; rejectUrl = reject; });
  const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
  // Attach immediately; startup failures must not create unhandled rejections.
  void authUrl.catch(() => {});
  void done.catch(() => {});
  const ssh = await startLocalSsh(server, {
    forwardTarget: { port: 53682, backingSocket: join(directory, "rclone.sock") },
    onShellCommand(command, stream) {
      if (command !== COMMAND) return false;
      check(!namespace, "rclone test command was started twice");
      namespace = spawn("bwrap", ["--unshare-net", "--unshare-pid", "--die-with-parent",
        "--ro-bind", "/", "/", "--bind", directory, directory,
        "--dev-bind", "/dev", "/dev", "--proc", "/proc",
        process.execPath, fileURLToPath(import.meta.url), "--namespace", binary, directory, String(providerProxy.address().port)],
      { stdio: ["pipe", "pipe", "pipe"] });
      stream.once("close", () => namespace.stdin.end());
      stream.on("error", () => namespace.stdin.end());
      let pending = "";
      namespace.stdout.on("data", (data) => {
        pending += data.toString("utf8");
        for (;;) {
          const newline = pending.indexOf("\n");
          if (newline < 0) break;
          const message = JSON.parse(pending.slice(0, newline));
          pending = pending.slice(newline + 1);
          if (message.type === "url") {
            if (!stream.destroyed) stream.write(`${message.url}\r\n`);
            resolveUrl(message.url);
          } else if (message.type === "complete" && message.success) {
            if (!stream.destroyed) stream.write("rclone local authorization complete\r\n$ ");
            resolveDone();
          } else {
            rejectUrl(Error("Local rclone authorization failed"));
            rejectDone(Error("Local rclone authorization failed"));
          }
        }
      });
      // Do not dump process output on failure; it may contain OAuth values.
      namespace.stderr.resume();
      namespace.on("error", () => { rejectUrl(Error("Cannot start isolated rclone")); rejectDone(Error("Cannot start isolated rclone")); });
      namespace.on("close", () => { rejectUrl(Error("Isolated rclone host exited")); rejectDone(Error("Isolated rclone host exited")); });
      return true;
    },
  });
  const deadline = setTimeout(() => { rejectUrl(Error("Local rclone startup timed out")); rejectDone(Error("Local rclone authorization timed out")); }, 30_000);
  try {
    const opened = await openPage(context, url, "real-rclone");
    page = opened.page;
    await page.evaluate((url) => window.tailfeather.ssh({ url, user: "tester" }), url.replace(/^http/, "ws") + "ssh");
    await page.waitForFunction(() => window.tailfeather.terminalText.includes("welcome to e2e-sshd"));
    await page.evaluate((command) => window.tailfeather.session.send(new TextEncoder().encode(command + "\r")), COMMAND);
    const initial = await authUrl;
    check(initial.startsWith(CALLBACK + "auth?state="), "rclone printed an unexpected loopback URL");
    await page.waitForSelector(".ssh-loopback-link", { state: "attached" });
    await page.locator(".ssh-link-list").evaluate((details) => { details.open = true; });
    const popupReady = page.waitForEvent("popup");
    await page.click(".ssh-loopback-link");
    const popup = await popupReady;
    await popup.getByText("Authorize local test account").click();
    await done;
    check(new URL(popup.url()).origin + "/" === CALLBACK, "rclone callback origin was rewritten");
    const saved = await page.evaluate(() => JSON.stringify({ storage: { ...localStorage }, logs: window.tailfeather.logs }));
    check(![CODE, TOKEN, REFRESH, new URL(initial).searchParams.get("state")].some((secret) => saved.includes(secret)), "rclone OAuth values escaped into logs/storage");
    check(opened.problems.length === 0, opened.problems.join("\n"));
    await page.evaluate(() => window.tailfeather.closeTab(window.tailfeather.sessions[0].id));
    await popup.close();
    console.log(`PASS real rclone v${VERSION} completed local OAuth/token exchange through Firefox/native/SSH with unchanged callback`);
  } finally {
    clearTimeout(deadline);
    await page?.close();
    namespace?.stdin.end();
    if (namespace && namespace.exitCode === null) {
      const kill = setTimeout(() => namespace.kill("SIGKILL"), 2000);
      await once(namespace, "close");
      clearTimeout(kill);
    }
    ssh.close();
    server.close();
    providerProxy.close();
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[2] === "--namespace") {
  try { await namespaceHost(process.argv[3], process.argv[4], Number(process.argv[5])); }
  catch (error) {
    process.stdout.write(JSON.stringify({ type: "error", stage: "namespace setup", code: error.code ?? "FAILED" }) + "\n");
    process.exitCode = 1;
  }
}
