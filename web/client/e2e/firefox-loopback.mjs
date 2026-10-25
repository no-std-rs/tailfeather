// Actual Firefox + installed temporary WebExtension + native messaging.
// Bubblewrap overlays the native-manifest directory and isolates the profile:
// nothing is installed in the user's home or existing Firefox profile.
import { firefox } from "playwright-core";
import { mkdtemp, mkdir, writeFile, rm, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { loopbackTest } from "./loopback.mjs";

const script = fileURLToPath(import.meta.url);
const root = fileURLToPath(new URL("../../../", import.meta.url));

async function runFirefox(scratch) {
  const reserve = createServer();
  reserve.listen(0, "127.0.0.1");
  await once(reserve, "listening");
  const port = reserve.address().port;
  await new Promise((resolve) => reserve.close(resolve));
  const context = await firefox.launchPersistentContext(join(scratch, "profile"), {
    headless: true,
    args: ["--remote-debugging-port", String(port)],
    firefoxUserPrefs: { "remote.experimental.enabled": true },
  });
  let socket;
  const pending = new Map();
  try {
    socket = new WebSocket(`ws://127.0.0.1:${port}/session`);
    await once(socket, "open");
    let sequence = 0;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      clearTimeout(request.timer);
      if (message.error) request.reject(Error(`Firefox BiDi: ${message.error}`));
      else request.resolve(message.result);
    });
    const send = (method, params) => new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(Error(`Firefox BiDi timed out: ${method}`));
      }, 15_000);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params }));
    });
    await send("session.new", { capabilities: { alwaysMatch: {} } });
    const installed = await send("webExtension.install", {
      extensionData: { type: "path", path: join(root, "web", "loopback", "extension") },
    });
    if (installed.extension !== "loopback@tailfeather.no-std-rs") throw Error("Firefox did not install the expected extension");
    await loopbackTest(context, { nativeExtension: true });
    console.log("PASS actual Firefox extension/native messaging OAuth and binary forwarding");
  } finally {
    for (const { timer } of pending.values()) clearTimeout(timer);
    socket?.close();
    await context.close();
  }
}

if (process.argv[2] === "--inside") {
  await runFirefox(process.argv[3]);
} else {
  if (process.platform !== "linux") throw Error("The isolated Firefox acceptance runner requires Linux and bubblewrap.");
  const scratch = await mkdtemp(join(tmpdir(), "tailfeather-firefox-"));
  try {
    const mozilla = join(scratch, "mozilla");
    const manifests = join(mozilla, "native-messaging-hosts");
    await mkdir(manifests, { recursive: true });
    await mkdir(join(scratch, "cache"));
    const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
    const launcher = join(scratch, "native-host");
    await writeFile(launcher,
      `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(root, "web", "loopback", "native.mjs"))} "$@"\n`, { mode: 0o700 });
    await writeFile(join(manifests, "org.tailfeather.loopback.json"), JSON.stringify({
      name: "org.tailfeather.loopback", description: "Isolated Tailfeather acceptance test",
      path: launcher, type: "stdio", allowed_extensions: ["loopback@tailfeather.no-std-rs"],
    }));
    const home = await realpath(homedir());
    const dependencies = await realpath(join(root, "web", "client", "node_modules"));
    const browserCache = dirname(dirname(dirname(firefox.executablePath())));
    const result = spawnSync("bwrap", [
      "--ro-bind", "/", "/", "--bind", "/tmp", "/tmp",
      // A fresh empty home is a mount overlay, never a new HOME environment.
      "--tmpfs", home,
      "--ro-bind", root, root,
      "--ro-bind", dependencies, dependencies,
      "--ro-bind", dirname(dirname(process.execPath)), dirname(dirname(process.execPath)),
      "--ro-bind", browserCache, browserCache,
      "--bind", mozilla, join(home, ".mozilla"),
      "--dev-bind", "/dev", "/dev", "--proc", "/proc", "--unshare-pid", "--die-with-parent",
      "--setenv", "XDG_CACHE_HOME", join(scratch, "cache"),
      process.execPath, script, "--inside", scratch,
    ], { stdio: "inherit", env: process.env });
    if (result.error) throw result.error;
    if (result.status !== 0) throw Error(`Firefox acceptance exited ${result.status ?? result.signal}`);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
