import { WebLinksAddon } from "./vendor/addon-web-links.mjs";
import { TerminalUrlScanner, safeWebUrl, isTailscaleAuthUrl, loopbackDestination } from "./terminal-url-scanner.js";
import { LoopbackForwarding } from "./loopback-forwarding.js";

function anchor(url, label = url) {
  const link = document.createElement("a");
  link.href = url;
  link.textContent = label;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

export function installTerminalLinks({ terminal, container, onAuthUrl = () => {}, getSession = () => null }) {
  let ended = false;
  const forwardingStatus = document.createElement("div");
  forwardingStatus.className = "ssh-forwarding-status";
  forwardingStatus.setAttribute("role", "status");
  const forwarding = new LoopbackForwarding(getSession, { onError: (message) => { forwardingStatus.textContent = message; } });
  async function openLink(event, text) {
    const url = safeWebUrl(text);
    if (!url) return;
    if (!loopbackDestination(url)) { window.open(url, "_blank", "noopener,noreferrer"); return; }
    event?.preventDefault();
    if (ended || !getSession()) { forwardingStatus.textContent = "This SSH connection has closed."; return; }
    // Reserve a user-initiated browser tab before asynchronous native setup.
    const popup = window.open("about:blank", "_blank");
    if (!popup) { forwardingStatus.textContent = "Allow a popup to open the remote loopback service."; return; }
    popup.opener = null;
    try {
      const original = await forwarding.listen(url);
      if (ended) { popup.close(); return; }
      popup.location.replace(original);
      forwardingStatus.textContent = "Remote loopback forwarding is active. Keep this SSH terminal open until authorization finishes.";
    } catch (error) {
      popup.close();
      forwardingStatus.textContent = error.message;
      if (!ended) forwardingStatus.append(" ", anchor(
        "https://github.com/no-std-rs/tailfeather/blob/main/web/loopback/README.md", "Setup instructions"));
    }
  }
  function terminalLink(url) {
    const destination = loopbackDestination(url);
    if (!destination) return anchor(url);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ssh-loopback-link";
    button.textContent = `Open remote ${destination.host}:${destination.port}`;
    button.addEventListener("click", (event) => { void openLink(event, url); });
    return button;
  }
  const addon = new WebLinksAddon(openLink);
  terminal.loadAddon(addon);
  // OSC 8 hyperlinks are part of xterm itself, rather than the web-links
  // addon. Apply the same scheme check and opener protection to them.
  terminal.options.linkHandler = { activate: openLink };
  container.classList.add("terminal-links");
  const banner = document.createElement("div");
  banner.className = "ssh-auth-banner";
  banner.hidden = true;
  banner.setAttribute("role", "status");
  const details = document.createElement("details");
  details.className = "ssh-link-list";
  details.hidden = true;
  const summary = document.createElement("summary");
  const list = document.createElement("ul");
  details.append(summary, list);
  container.replaceChildren(banner, forwardingStatus, details);
  const urls = [];
  let authUrl = "";
  let disposed = false;

  const scanner = new TerminalUrlScanner((url) => {
    if (disposed) return;
    if (isTailscaleAuthUrl(url) && authUrl !== url) {
      authUrl = url;
      const message = document.createElement("span");
      message.textContent = "Tailscale SSH needs approval. ";
      const link = anchor(url, "Approve Tailscale SSH");
      link.className = "ssh-auth-link";
      const dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "ssh-auth-dismiss";
      dismiss.textContent = "×";
      dismiss.setAttribute("aria-label", "Dismiss SSH approval notice");
      dismiss.addEventListener("click", () => { banner.hidden = true; });
      banner.replaceChildren(message, link, dismiss);
      banner.hidden = false;
      onAuthUrl(url);
    }
    if (urls.includes(url)) return;
    urls.push(url);
    if (urls.length > 20) urls.shift();
    summary.textContent = `Links in this terminal (${urls.length})`;
    list.replaceChildren(...urls.map((value) => {
      const item = document.createElement("li");
      item.append(terminalLink(value));
      return item;
    }));
    details.hidden = false;
  });

  return {
    write(text) { if (!disposed) scanner.write(text); },
    finish() {
      if (disposed) return;
      scanner.finish();
      ended = true;
      forwarding.dispose();
      forwardingStatus.textContent = "";
      banner.hidden = true;
    },
    dispose() {
      disposed = true;
      ended = true;
      forwarding.dispose();
      addon.dispose();
      container.replaceChildren();
    },
  };
}
