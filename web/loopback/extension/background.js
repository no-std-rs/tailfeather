// One native process per SSH tab. No shared listener, routing table, or storage.
browser.runtime.onConnect.addListener((page) => {
  if (page.name !== "tailfeather-loopback" || !page.sender.tab) return page.disconnect();
  const native = browser.runtime.connectNative("org.tailfeather.loopback");
  page.onMessage.addListener((message) => native.postMessage(message));
  native.onMessage.addListener((message) => page.postMessage(message));
  page.onDisconnect.addListener(() => native.disconnect());
  native.onDisconnect.addListener(() => {
    try { page.postMessage({ type: "disconnected" }); } catch {}
    page.disconnect();
  });
});
