// Exercise the built application under a project path, as on GitHub Pages.
// Pass a deployed URL to check the real site instead. --live also checks the
// credential-free Tailscale sign-in flow; it never follows the returned URL.
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { check, launch, openPage } from "./browser.mjs";
import { DIST, serve } from "./serve.mjs";

const remote = process.argv.slice(2).find((arg) => !arg.startsWith("--"));
let root;
let server;
let browser;
try {
  let url = remote;
  if (!url) {
    root = await mkdtemp(join(tmpdir(), "tailfeather-pages-"));
    await cp(DIST, join(root, "tailfeather"), { recursive: true });
    const local = await serve(0, root);
    server = local.server;
    url = `${local.url}tailfeather/`;
  }
  browser = await launch();
  const context = await browser.newContext();
  const { page, problems } = await openPage(context, url, "pages");
  check(await page.locator("#terminal .xterm-screen").count() === 1, "terminal did not mount");
  check(await page.isDisabled("#ssh-button"), "SSH enabled before joining a tailnet");
  check(!await page.locator("#worker-auth a").isVisible(), "static site offers a Worker-only /connect link");
  check(new URL(page.url()).pathname === new URL(url).pathname, "the project path changed");
  console.log(`PASS Pages path, WebAssembly MIME type, terminal, and static login UI: ${url}`);

  if (process.argv.includes("--live")) {
    await page.fill("#hostname", `tailfeather-pages-${Date.now().toString(36)}`);
    await page.fill("#auth-key", "");
    await page.uncheck("#remember");
    await page.click("#connect-button");
    await page.waitForFunction(() => window.tailfeather.authUrl !== "", null, { timeout: 90_000 });
    const authUrl = new URL(await page.evaluate(() => window.tailfeather.authUrl));
    check(authUrl.protocol === "https:" && authUrl.hostname === "login.tailscale.com", "unexpected Tailscale sign-in URL");
    check(await page.locator("#auth-link").isVisible(), "sign-in link is not visible");
    await page.evaluate(() => window.tailfeather.client?.stop());
    console.log("PASS Tailscale returned a sign-in link; no credentials or tailnet approval used");
  }
  check(problems.length === 0, problems.join("\n"));
  await context.close();
} finally {
  await browser?.close();
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (root) await rm(root, { recursive: true, force: true });
}
