// Recognize URLs in remote output, independently of terminal line wrapping.
// Keep incomplete URLs/ANSI sequences across SSH messages; never scan local
// password input. No output or URLs are persisted.
export function safeWebUrl(text) {
  try {
    const url = new URL(text);
    if (!/^https?:$/.test(url.protocol) || !url.hostname || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

export function isTailscaleAuthUrl(text) {
  const safe = safeWebUrl(text);
  if (!safe) return false;
  const url = new URL(safe);
  return url.protocol === "https:" && url.hostname === "login.tailscale.com" && !url.port &&
    /^\/a\/[A-Za-z0-9_-]+\/?$/.test(url.pathname);
}

function trimPunctuation(text, prefix) {
  // Keep balanced parentheses in a URL, but drop a surrounding sentence's
  // closing punctuation, e.g. '(https://example.org/page)'.
  for (const [open, close] of [["(", ")"], ["[", "]"], ["{", "}"]]) {
    if (!prefix.includes(open)) continue;
    const beforeProse = text.replace(/[.,;:!?]+$/, "");
    if (beforeProse.endsWith(close) && beforeProse.split(close).length > beforeProse.split(open).length) {
      text = beforeProse;
    }
    while (text.endsWith(close) && text.split(close).length > text.split(open).length) {
      text = text.slice(0, -1);
    }
  }
  return text;
}

export class TerminalUrlScanner {
  constructor(onUrl) {
    this.onUrl = onUrl;
    this.token = "";
    this.mode = "text";
    this.osc = "";
    this.oscOverflow = false;
    this.overflow = false;
  }

  emit(text, prefix = "") {
    const url = safeWebUrl(prefix ? trimPunctuation(text, prefix) : text);
    if (url) this.onUrl(url);
  }

  flushToken() {
    if (!this.overflow) {
      for (const match of this.token.matchAll(/https?:\/\/[^\s<>"'`]+/gi)) this.emit(match[0], this.token.slice(0, match.index));
    }
    this.token = "";
    this.overflow = false;
  }

  finishOsc() {
    // OSC 8 hyperlinks have `8;params;URI`. Other OSC sequences (titles,
    // clipboard, etc.) must never become links.
    const match = !this.oscOverflow && /^8;[^;]*;(https?:\/\/.*)$/i.exec(this.osc);
    if (match) this.emit(match[1]);
    this.osc = "";
    this.oscOverflow = false;
    this.mode = "text";
  }

  write(text) {
    for (const ch of text) {
      if (this.mode === "escape") {
        this.mode = ch === "[" ? "csi" : ch === "]" ? "osc" : "text";
        continue;
      }
      if (this.mode === "csi") {
        if (ch >= "@" && ch <= "~") this.mode = "text";
        continue;
      }
      if (this.mode === "osc" || this.mode === "osc-escape") {
        if (ch === "\x07" || (this.mode === "osc-escape" && ch === "\\")) this.finishOsc();
        else if (ch === "\x1b") this.mode = "osc-escape";
        else {
          if (this.osc.length < 4096) this.osc += ch;
          else this.oscOverflow = true;
          this.mode = "osc";
        }
        continue;
      }
      if (ch === "\x1b") {
        this.mode = "escape";
      } else if (ch === "\x9b") {
        this.mode = "csi";
      } else if (/[\s<>"'`\x00-\x1f\x7f]/.test(ch)) {
        this.flushToken();
      } else if (this.token.length < 4096) {
        this.token += ch;
      } else {
        this.overflow = true;
      }
    }
  }

  finish() {
    this.flushToken();
  }
}
