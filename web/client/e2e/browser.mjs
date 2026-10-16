// Shared Playwright helpers for the end-to-end scripts.
//
// playwright-core is pinned to 1.60.0, whose bundled Chromium is revision
// 1223; it finds that browser in ~/.cache/ms-playwright on its own. Set
// CHROMIUM_PATH to use a different Chromium binary.

import { chromium } from "playwright-core";

export function launchOptions() {
  const options = { headless: process.env.HEADED !== "1" };
  if (process.env.CHROMIUM_PATH) options.executablePath = process.env.CHROMIUM_PATH;
  return options;
}

export async function launch() {
  return chromium.launch(launchOptions());
}

export async function launchPersistent(profile) {
  return chromium.launchPersistentContext(profile, launchOptions());
}

/// Collect console output and CSP violations, and fail on uncaught errors.
export function watch(page, label = "page") {
  const problems = [];
  page.on("console", (message) => {
    const text = message.text();
    if (/Content Security Policy|Refused to/i.test(text)) problems.push(`CSP: ${text}`);
    if (message.type() === "error") console.log(`[${label} console.error] ${text}`);
  });
  page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
  return problems;
}

export async function openPage(context, url, label) {
  const page = await context.newPage();
  const problems = watch(page, label);
  const wasm = page.waitForResponse((response) => response.url().endsWith(".wasm"));
  await page.goto(url);
  const response = await wasm;
  const type = response.headers()["content-type"];
  if (type !== "application/wasm") throw new Error(`wasm served as ${type}`);
  await page.waitForFunction(() => document.body.dataset.ready === "true", null, { timeout: 30_000 });
  return { page, problems };
}

export function stripAnsi(text) {
  // CSI and OSC sequences, then any stray escapes.
  return text
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-_]/g, "");
}

export function check(condition, message) {
  if (!condition) throw new Error(message);
}
