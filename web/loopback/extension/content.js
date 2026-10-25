const sessions = new Map();
window.addEventListener("message", (event) => {
  const message = event.data;
  if (event.source !== window || event.origin !== location.origin ||
      message?.source !== "tailfeather-loopback-page" ||
      typeof message.session !== "string" || !/^[a-zA-Z0-9-]{1,80}$/.test(message.session)) return;
  let port = sessions.get(message.session);
  if (message.type === "disconnect") {
    port?.disconnect();
    sessions.delete(message.session);
    return;
  }
  if (!port) {
    if (message.type !== "hello" || sessions.size >= 16) return;
    port = browser.runtime.connect({ name: "tailfeather-loopback" });
    sessions.set(message.session, port);
    port.onMessage.addListener((data) => window.postMessage({
      ...data, source: "tailfeather-loopback-extension", session: message.session,
    }, location.origin));
    port.onDisconnect.addListener(() => {
      sessions.delete(message.session);
      window.postMessage({ source: "tailfeather-loopback-extension", session: message.session, type: "disconnected" }, location.origin);
    });
    window.postMessage({ source: "tailfeather-loopback-extension", session: message.session, type: "hello" }, location.origin);
    return;
  }
  port.postMessage(message);
});
window.addEventListener("pagehide", () => {
  for (const port of sessions.values()) port.disconnect();
  sessions.clear();
});
