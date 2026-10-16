import { check, openPage } from "./browser.mjs";

export async function workspaceTest(context, url) {
  const { page, problems } = await openPage(context, url, "workspace");
  const wsUrl = `${url.replace(/^http/, "ws")}ssh`;
  const open = async (user) => page.evaluate(([url, user]) => {
    window.tailfeather.ssh({ url, user });
    return window.tailfeather.activeTabId;
  }, [wsUrl, user]);
  const send = async (id, text) => page.evaluate(([id, text]) => {
    window.tailfeather.sessions.find((tab) => tab.id === id).session.send(new TextEncoder().encode(text));
  }, [id, text]);
  const waitText = (id, text) => page.waitForFunction(([id, text]) =>
    window.tailfeather.sessions.find((tab) => tab.id === id)?.terminalText.includes(text), [id, text], { timeout: 20_000 });

  const first = await open("tester");
  await waitText(first, "welcome to e2e-sshd");
  const second = await open("tester");
  await waitText(second, "welcome to e2e-sshd");
  const titleFor = (id) => page.evaluate((id) => `${window.tailfeather.sessions.find((tab) => tab.id === id).label} · tailfeather`, id);
  check(await page.title() === await titleFor(second), "browser title does not identify the selected SSH tab");
  await send(first, "echo FIRST_ONLY\r");
  await send(second, "echo SECOND_ONLY\r");
  await waitText(first, "FIRST_ONLY\r\n");
  await waitText(second, "SECOND_ONLY\r\n");
  check(await page.evaluate(([first, second]) => {
    const tabs = window.tailfeather.sessions;
    return tabs.length === 2 && !tabs.find((tab) => tab.id === first).terminalText.includes("SECOND_ONLY") &&
      !tabs.find((tab) => tab.id === second).terminalText.includes("FIRST_ONLY");
  }, [first, second]), "connection tabs mixed their output");

  await page.evaluate((id) => window.tailfeather.selectTab(id), first);
  check(await page.title() === await titleFor(first), "browser title did not follow the selected SSH tab");
  await page.click("#drawer-toggle"); // Close the initially visible settings.
  await send(first, "links\r");
  await page.waitForFunction((id) =>
    window.tailfeather.sessions.find((tab) => tab.id === id).sshAuthUrl.endsWith("/a/browser-example"), first);
  const authLink = page.locator(".ssh-auth-link:visible");
  check(await authLink.getAttribute("href") === "https://login.tailscale.com/a/browser-example", "split SSH approval URL was not promoted");
  check(await authLink.getAttribute("rel") === "noopener noreferrer", "approval link lacks opener protection");
  // Clicking the native link opens a separate tab and leaves both sessions
  // running. Intercept the test URL so no real login page is contacted.
  await context.route("https://login.tailscale.com/**", (route) => route.fulfill({ body: "Test approval page" }));
  const popupPromise = page.waitForEvent("popup");
  if (await page.evaluate(() => matchMedia("(pointer: coarse)").matches)) await authLink.tap();
  else await authLink.click();
  const popup = await popupPromise;
  await popup.waitForLoadState("domcontentloaded");
  check(await popup.evaluate(() => window.opener === null), "approval tab can access its opener");
  await popup.close();
  check(await page.evaluate(() => window.tailfeather.sessions.every((tab) => tab.session)), "approval link disconnected SSH");

  await page.locator(".ssh-link-list:visible summary").click();
  check(await page.locator('.ssh-link-list:visible a[href="https://example.org/osc-link"]').count() === 1,
    "OSC link is missing from the mobile links list");
  check(await page.locator('.ssh-link-list:visible a[href^="https://example.org/documentation/"]').count() === 1,
    "wrapped URL is missing from the mobile links list");
  await page.locator(".ssh-link-list:visible summary").click();

  // Clicking a web URL directly in xterm exercises the addon too. The native
  // list above handles touch; this coordinate check applies to a mouse.
  if (!await page.evaluate(() => matchMedia("(pointer: coarse)").matches)) {
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const point = await page.evaluate(() => {
      const terminal = window.tailfeather.terminal;
      const buffer = terminal.buffer.active;
      const screen = terminal.element.querySelector(".xterm-screen").getBoundingClientRect();
      for (let row = 0; row < terminal.rows; row++) {
        const line = buffer.getLine(buffer.viewportY + row)?.translateToString();
        const col = line?.indexOf("https://example.org/documentation/") ?? -1;
        if (col >= 0) return { x: screen.x + (col + 3.5) * screen.width / terminal.cols,
          y: screen.y + (row + 0.5) * screen.height / terminal.rows };
      }
      return null;
    });
    check(point, "terminal URL was not visible for clicking");
    await context.route("https://example.org/**", (route) => route.fulfill({ body: "Test documentation" }));
    await page.mouse.move(point.x, point.y);
    await page.waitForFunction(() => document.querySelector(".xterm-cursor-pointer"), null, { timeout: 5000 });
    const linked = page.waitForEvent("popup", { timeout: 5000 });
    await page.mouse.click(point.x, point.y);
    await (await linked).close();
  }

  await page.click("#focus-button");
  check(await page.evaluate(() => document.body.classList.contains("focus-mode")), "focus mode did not activate");
  check(await authLink.isVisible(), "focus mode hides SSH approval");
  const layout = await page.evaluate(() => {
    const panel = document.querySelector("#terminal-panel").getBoundingClientRect();
    return { width: innerWidth, height: innerHeight, panelHeight: panel.height,
      scrollWidth: document.documentElement.scrollWidth };
  });
  check(layout.scrollWidth <= layout.width + 1, "workspace overflows the mobile viewport horizontally");
  check(layout.panelHeight > layout.height * 0.8, "focus mode leaves too little terminal space");
  await page.screenshot({ path: `/tmp/tailfeather-focus-${layout.width}.png` });
  await page.setViewportSize({ width: layout.width, height: 420 });
  await page.waitForTimeout(200);
  const bottom = await page.locator("#terminal-panel").evaluate((el) => el.getBoundingClientRect().bottom);
  check(bottom <= 421, "workspace does not resize when the viewport shrinks");
  await page.setViewportSize({ width: layout.width, height: layout.height });
  await page.click("#focus-button");
  await page.click("#fullscreen-button");
  await page.waitForFunction(() => document.body.classList.contains("focus-mode"));
  check(await authLink.isVisible(), "fullscreen hides SSH approval");
  if (await page.evaluate(() => !!document.fullscreenElement)) {
    await page.evaluate(() => document.exitFullscreen());
    await page.waitForFunction(() => !document.body.classList.contains("focus-mode"));
  } else {
    await page.click("#focus-button");
  }
  await page.evaluate(() => Object.defineProperty(document, "fullscreenEnabled", { value: false, configurable: true }));
  await page.click("#fullscreen-button");
  check(await page.evaluate(() => document.body.classList.contains("focus-mode") && !document.fullscreenElement),
    "fullscreen fallback did not enter focus mode");
  await page.click("#fullscreen-button");
  check(await page.evaluate(() => !document.body.classList.contains("focus-mode")), "fullscreen fallback did not restore the layout");
  await page.evaluate(() => { delete document.fullscreenEnabled; });

  // A present fullscreen API can still be refused by browser policy. The
  // same button must let the user leave the resulting focus layout.
  await page.evaluate(() => {
    Object.defineProperty(document, "fullscreenEnabled", { value: true, configurable: true });
    document.documentElement.requestFullscreen = () => Promise.reject(new Error("Fullscreen denied"));
  });
  await page.click("#fullscreen-button");
  await page.waitForFunction(() => document.querySelector("#fullscreen-button").getAttribute("aria-pressed") === "true");
  check(await page.evaluate(() => document.body.classList.contains("focus-mode") && !document.fullscreenElement),
    "rejected fullscreen did not enter focus mode");
  await page.click("#fullscreen-button");
  check(await page.evaluate(() => !document.body.classList.contains("focus-mode")),
    "rejected fullscreen fallback could not be exited with its button");
  await page.evaluate(() => {
    delete document.fullscreenEnabled;
    delete document.documentElement.requestFullscreen;
  });

  await page.evaluate(() => {
    const handle = window.tailfeather.session;
    const send = handle.send.bind(handle);
    window.e2ePhysicalKeys = [];
    window.e2eRestorePhysicalSend = () => { handle.send = send; };
    handle.send = (bytes) => window.e2ePhysicalKeys.push([...bytes]);
    window.tailfeather.terminal.focus();
  });
  await page.keyboard.press("Control+/");
  const physicalKeys = await page.evaluate(() => window.e2ePhysicalKeys);
  check(JSON.stringify(physicalKeys) === "[[31]]", `Ctrl+/ did not send exactly one Ctrl+_: ${JSON.stringify(physicalKeys)}`);
  await page.evaluate(() => {
    window.e2eRestorePhysicalSend();
    delete window.e2eRestorePhysicalSend;
    delete window.e2ePhysicalKeys;
  });

  if (await page.evaluate(() => matchMedia("(pointer: coarse)").matches)) {
    await page.evaluate(() => {
      const handle = window.tailfeather.session;
      const send = handle.send.bind(handle);
      window.e2eKeyInput = [];
      handle.send = (bytes) => window.e2eKeyInput.push([...bytes]);
      window.e2eRestoreSend = () => { handle.send = send; };
    });
    await page.locator('[data-key="ctrl"]').tap();
    await page.evaluate(() => window.tailfeather.terminal.input("c"));
    await page.locator('[data-key="ctrl"]').tap();
    await page.evaluate(() => window.tailfeather.terminal.input("/"));
    await page.locator('[data-key="esc"]').tap();
    await page.locator('[data-key="tab"]').tap();
    await page.locator('[data-key="up"]').tap();
    const keys = await page.evaluate(() => window.e2eKeyInput);
    check(JSON.stringify(keys) === JSON.stringify([[3], [31], [27], [9], [27, 91, 65]]),
      `mobile helper keys produced unexpected bytes: ${JSON.stringify(keys)}`);
    await page.evaluate(() => document.activeElement.blur());
    await page.locator('[data-key="keyboard"]').tap();
    check(await page.evaluate(() => document.activeElement.classList.contains("xterm-helper-textarea")),
      "mobile keyboard button did not focus the active terminal");
    await page.evaluate(() => {
      window.e2eRestoreSend();
      delete window.e2eRestoreSend;
      delete window.e2eKeyInput;
    });
    await page.setViewportSize({ width: layout.width, height: 300 });
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const keybarBottom = await page.locator("#keybar").evaluate((el) => el.getBoundingClientRect().bottom);
    check(keybarBottom <= 301, `mobile keyboard controls are covered in a short viewport (${keybarBottom})`);
    await page.click("#new-tab");
    await page.waitForTimeout(200);
    const formLayout = await page.evaluate(() => {
      const box = (id) => document.getElementById(id).getBoundingClientRect();
      return { formBottom: box("ssh-form").bottom, tabsTop: box("tabbar").top,
        keysBottom: box("keybar").bottom, viewportBottom: visualViewport.height + visualViewport.offsetTop };
    });
    check(formLayout.keysBottom <= formLayout.viewportBottom + 1,
      `opening the SSH form covers mobile controls: ${JSON.stringify(formLayout)}`);
    check(formLayout.formBottom <= formLayout.tabsTop, "the SSH form overlaps connection tabs");
    await page.locator("#ssh-button").scrollIntoViewIfNeeded();
    const buttonBox = await page.locator("#ssh-button").boundingBox();
    check(buttonBox.y >= 0 && buttonBox.y + buttonBox.height <= 301, "Open terminal cannot be reached with the keyboard open");
    check(await page.locator("#ssh-button").evaluate((button) => {
      const box = button.getBoundingClientRect();
      return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === button;
    }), "the scrolled Open terminal button is clipped or covered");
    await page.click("#new-tab");
    await page.setViewportSize({ width: layout.width, height: layout.height });
  }

  await page.evaluate((id) => window.tailfeather.selectTab(id), second);
  await page.click("#ssh-close");
  await page.waitForFunction((id) => window.tailfeather.sessions.find((tab) => tab.id === id).lastClose, second);
  check(await page.evaluate((id) => window.tailfeather.sessions.find((tab) => tab.id === id).terminalText.includes("SECOND_ONLY"), second),
    "Disconnect discarded the closed tab's output");
  await send(first, "echo STILL_CONNECTED\r");
  await waitText(first, "STILL_CONNECTED\r\n");
  await page.evaluate((id) => window.tailfeather.closeTab(id), second);
  check(await page.evaluate((id) => window.tailfeather.sessions.length === 1 && window.tailfeather.activeTabId === id, first),
    "closing a tab failed to select the remaining connection");
  check(await page.title() === await titleFor(first), "closing the selected tab did not restore the remaining tab's title");

  // Removing a middle duplicate must not give the next tab an existing name.
  const duplicate = await open("tester");
  await waitText(duplicate, "welcome to e2e-sshd");
  const third = await open("tester");
  await waitText(third, "welcome to e2e-sshd");
  await page.evaluate((id) => window.tailfeather.closeTab(id), duplicate);
  const replacement = await open("tester");
  await waitText(replacement, "welcome to e2e-sshd");
  const labels = await page.locator(".tab-select").allTextContents();
  check(new Set(labels).size === labels.length, "reopening a duplicate connection reused an existing tab label");
  await page.evaluate(([third, replacement]) => {
    window.tailfeather.closeTab(third);
    window.tailfeather.closeTab(replacement);
  }, [third, replacement]);

  // An authentication prompt stays attached to its own background tab.
  const pending = await open("kbd");
  await waitText(pending, "Code: ");
  await page.evaluate((id) => window.tailfeather.selectTab(id), first);
  await send(first, "echo PROMPT_ISOLATED\r");
  await waitText(first, "PROMPT_ISOLATED\r\n");
  await page.evaluate((id) => window.tailfeather.closeTab(id), pending);
  await send(first, "exit\r");
  await page.waitForFunction((id) => window.tailfeather.sessions.find((tab) => tab.id === id).lastClose, first);
  const live = await open("tester");
  await waitText(live, "welcome to e2e-sshd");
  const interrupted = await open("kbd");
  await waitText(interrupted, "Code: ");
  // Even a failed reconnect must end every old connection and prompt. An
  // invalid relay fails locally before contacting a control server.
  await page.evaluate(async () => {
    try { await window.tailfeather.connect({ relay: "ftp://invalid-relay.example" }); }
    catch { /* Expected local validation failure. */ }
  });
  await page.waitForFunction(() => window.tailfeather.sessions.every((tab) => !tab.session && tab.lastClose));
  check(await page.evaluate(() => window.tailfeather.client === null), "failed reconnect kept the previous client");
  await page.evaluate((id) => window.tailfeather.selectTab(id), first);
  check(await page.locator(".ssh-auth-link:visible").count() === 0, "a closed SSH session still claims approval is pending");
  check(problems.length === 0, problems.join("\n"));
  await page.screenshot({ path: `/tmp/tailfeather-workspace-${layout.width}.png` });
  console.log("  independent SSH tabs, clickable URLs, mobile approval links, focus/resize, isolated prompts and close");
  await page.close();
}
