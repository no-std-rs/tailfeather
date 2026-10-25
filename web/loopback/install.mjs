#!/usr/bin/env node
// Explicit user-run Linux/macOS Firefox native-host installation.
import { mkdir, copyFile, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

if (!["linux", "darwin"].includes(process.platform)) throw Error("This installer supports Linux and macOS Firefox.");
const home = homedir();
const destination = join(home, ".local", "lib", "tailfeather-loopback");
const manifests = process.platform === "darwin"
  ? join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts")
  : join(home, ".mozilla", "native-messaging-hosts");
await mkdir(destination, { recursive: true, mode: 0o700 });
await mkdir(manifests, { recursive: true, mode: 0o700 });
await copyFile(join(dirname(fileURLToPath(import.meta.url)), "native.mjs"), join(destination, "native.mjs"));
const quote = (text) => "'" + text.replaceAll("'", "'\\''") + "'";
const executable = join(destination, "tailfeather-loopback");
await writeFile(executable, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(destination, "native.mjs"))} "$@"\n`, { mode: 0o700 });
await chmod(executable, 0o700);
await writeFile(join(manifests, "org.tailfeather.loopback.json"), JSON.stringify({
  name: "org.tailfeather.loopback",
  description: "Tailfeather loopback forwarding companion",
  path: executable,
  type: "stdio",
  allowed_extensions: ["loopback@tailfeather.no-std-rs"],
}, null, 2) + "\n", { mode: 0o600 });
console.log("Installed Firefox native host. Load extension/manifest.json through about:debugging to enable it.");
