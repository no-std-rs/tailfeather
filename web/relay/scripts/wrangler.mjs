// Run the pinned Wrangler for local dev / dry-run checks.
//
//   node scripts/wrangler.mjs check        -> wrangler deploy --dry-run --outdir <tmp>
//   node scripts/wrangler.mjs dev [args]   -> wrangler dev [args]
//
// If the static site has not been built into ../dist yet, a throwaway
// placeholder directory is passed via --assets so the Worker can still be
// checked and run. Nothing is ever deployed from here.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const RELAY_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const WRANGLER_JS = join(RELAY_DIR, "node_modules", "wrangler", "bin", "wrangler.js");
const DIST_DIR = join(RELAY_DIR, "..", "dist");

/** Returns extra wrangler args (placeholder --assets when ../dist is missing) and a cleanup. */
export function assetsOverride() {
  if (existsSync(DIST_DIR)) return { args: [], cleanup: () => {} };
  const dir = mkdtempSync(join(tmpdir(), "tailfeather-relay-assets-"));
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>tailfeather placeholder</title>\n");
  console.error(`[relay] ${DIST_DIR} not built; using placeholder assets at ${dir}`);
  return { args: ["--assets", dir], cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** Spawn wrangler with the given args (cwd = web/relay). */
export function spawnWrangler(args, options = {}) {
  return spawn(process.execPath, [WRANGLER_JS, ...args], { cwd: RELAY_DIR, stdio: "inherit", ...options });
}

function main(argv) {
  const [mode, ...rest] = argv;
  const cleanups = [];
  let args;
  if (mode === "check") {
    const outdir = mkdtempSync(join(tmpdir(), "tailfeather-relay-out-"));
    cleanups.push(() => rmSync(outdir, { recursive: true, force: true }));
    args = ["deploy", "--dry-run", "--outdir", outdir, ...rest];
  } else if (mode === "dev") {
    args = ["dev", ...rest];
  } else {
    console.error("usage: node scripts/wrangler.mjs check|dev [wrangler args...]");
    process.exit(2);
  }
  const assets = assetsOverride();
  cleanups.push(assets.cleanup);
  const child = spawnWrangler([...args, ...assets.args]);
  const forward = (signal) => child.kill(signal);
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  child.on("exit", (code, signal) => {
    for (const cleanup of cleanups) cleanup();
    process.exit(code ?? (signal ? 1 : 0));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
