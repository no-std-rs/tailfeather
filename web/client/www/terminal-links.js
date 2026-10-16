import { WebLinksAddon } from "./vendor/addon-web-links.mjs";
import { TerminalUrlScanner, safeWebUrl, isTailscaleAuthUrl } from "./terminal-url-scanner.js";

function openLink(_event, text) {
  const url = safeWebUrl(text);
  if (url) window.open(url, "_blank", "noopener,noreferrer");
}

function anchor(url, label = url) {
  const link = document.createElement("a");
  link.href = url;
  link.textContent = label;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

export function installTerminalLinks({ terminal, container, onAuthUrl = () => {} }) {
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
  container.replaceChildren(banner, details);
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
      item.append(anchor(value));
      return item;
    }));
    details.hidden = false;
  });

  return {
    write(text) { if (!disposed) scanner.write(text); },
    finish() {
      if (disposed) return;
      scanner.finish();
      banner.hidden = true;
    },
    dispose() {
      disposed = true;
      addon.dispose();
      container.replaceChildren();
    },
  };
}
