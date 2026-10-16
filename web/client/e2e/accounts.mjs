import { check, openPage } from "./browser.mjs";

export async function accountsTest(context, url) {
  const { page, problems } = await openPage(context, url, "accounts");
  const installPeers = () => page.evaluate(() => {
    const api = window.tailfeather;
    api.netmap = { self: { ip: "100.64.0.254" }, peers: [
      { ip: "100.64.0.1", name: "workstation" },
      { ip: "100.64.0.2", name: "server" },
    ] };
    window.accountAttempts = [];
    api.client = { stop() {}, ssh: (options, callbacks) => {
      window.accountAttempts.push({ ip: options.ip, user: options.user });
      return { resize() {}, send() {}, close() { callbacks.closed("test complete"); } };
    } };
    const select = document.getElementById("peer-select");
    select.replaceChildren(new Option("Pick a peer…", ""),
      ...api.netmap.peers.map((peer) => new Option(peer.name, peer.ip)),
      new Option("Enter another device address…", "manual"));
    select.disabled = false;
    document.getElementById("ssh-button").disabled = false;
  });
  const closeDrawer = async () => {
    if (await page.locator("#drawer").isVisible()) await page.click("#drawer-close");
  };
  const open = async (ip) => {
    await closeDrawer();
    if (!await page.locator("#peer-select").isVisible()) await page.click("#new-tab");
    await page.selectOption("#peer-select", ip);
    await page.click("#ssh-button");
  };
  const choose = async (name) => {
    await page.waitForSelector("#ssh-account-dialog[open]");
    await page.fill("#ssh-account-name", name);
    await page.press("#ssh-account-name", "Enter");
  };
  const attempts = () => page.evaluate(() => window.accountAttempts);
  await installPeers();
  await open("100.64.0.1");
  check((await attempts()).length === 0, "SSH started before an account was selected");
  check(await page.locator("#ssh-account-host").textContent() === "workstation", "account prompt does not identify the device");
  await page.fill("#ssh-account-name", "   ");
  await page.locator('#ssh-account-dialog button[value="connect"]').click();
  check(await page.locator("#ssh-account-dialog").evaluate((el) => el.open), "a blank account dismissed the prompt");
  const width = await page.evaluate(() => innerWidth);
  await page.screenshot({ path: `/tmp/tailfeather-account-${width}.png` });
  await choose("alice");
  await page.waitForFunction(() => window.accountAttempts.length === 1);
  check(!await page.locator("#ssh-user").isVisible(), "the account field still clutters the connection bar");
  await open("100.64.0.2");
  await choose("bob");
  await page.waitForFunction(() => window.accountAttempts.length === 2);
  await open("100.64.0.1");
  await page.waitForFunction(() => window.accountAttempts.length === 3);
  check(!(await page.locator("#ssh-account-dialog").evaluate((el) => el.open)), "a saved device prompted again");
  check(JSON.stringify(await attempts()) === JSON.stringify([
    { ip: "100.64.0.1", user: "alice" },
    { ip: "100.64.0.2", user: "bob" },
    { ip: "100.64.0.1", user: "alice" },
  ]), "accounts leaked from one device to another");

  // An explicit override applies only to this destination.
  await page.click("#drawer-toggle");
  await page.locator("#ssh-options").evaluate((el) => { el.open = true; });
  await page.fill("#ssh-user", "carol");
  await page.reload();
  await page.waitForFunction(() => document.body.dataset.ready === "true");
  await installPeers();
  await open("100.64.0.1");
  await page.waitForFunction(() => window.accountAttempts.length === 1);
  check((await attempts())[0].user === "carol", "the saved per-device override was not restored");
  await open("100.64.0.2");
  await page.waitForFunction(() => window.accountAttempts.length === 2);
  check((await attempts())[1].user === "bob", "overriding one device changed another's account");

  await page.click("#drawer-toggle");
  await page.uncheck("#remember");
  await page.reload();
  await page.waitForFunction(() => document.body.dataset.ready === "true");
  await installPeers();
  await open("100.64.0.1");
  await choose("alice");
  await page.waitForFunction(() => window.accountAttempts.length === 1);
  check(await page.evaluate(() => JSON.stringify(JSON.parse(localStorage.getItem("tailfeather.settings"))) === '{"remember":false}'),
    "an account was persisted with Remember off");
  await page.evaluate(() => window.tailfeather.forget());
  await installPeers();
  await open("100.64.0.1");
  await page.waitForSelector("#ssh-account-dialog[open]");
  await page.keyboard.press("Escape");
  await page.waitForSelector("#ssh-account-dialog:not([open])", { state: "attached" });
  check((await attempts()).length === 0, "canceling the account prompt opened SSH");
  if (!await page.locator("#peer-select").isVisible()) await page.click("#new-tab");
  await page.selectOption("#peer-select", "manual");
  check(await page.locator("#ssh-host").isVisible(), "manual addressing cannot be reached through the peer picker");
  check(problems.length === 0, problems.join("\n"));
  console.log("  first-use account choice, per-device reuse and overrides, Remember off, Forget, and Escape cancellation");
  await page.close();
}
