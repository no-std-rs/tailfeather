// The page around the tailfeather wasm client: a connect form, the netmap,
// and xterm.js terminals, one per SSH connection tab. No framework; the
// client does all networking.

import init, {
  TailnetClient,
  derpProbe,
  forgetHostKey,
  forgetNode,
  sshOverWebSocket,
} from "./pkg/tailfeather_web.js";
import { Terminal } from "./vendor/xterm.mjs";
import { FitAddon } from "./vendor/addon-fit.mjs";
import { installTerminalLinks } from "./terminal-links.js";
import { connectionLabel } from "./session-labels.js";

const SETTINGS_KEY = "tailfeather.settings";
const LOG_LINES = 600;
const TERMINAL_TEXT_LIMIT = 65536;
const NOTICE_MS = 12_000;
const DEFAULT_TITLE = document.title;

// The drawer docks beside the terminal from this width; below it, it covers
// the workspace. Coarse pointers get the key row and larger targets.
const WIDE = window.matchMedia("(min-width: 900px)");
const COARSE = window.matchMedia("(pointer: coarse)");
const NARROW = window.matchMedia("(max-width: 599px)");

const $ = (id) => document.getElementById(id);

// Connection tabs, in display order, and the one shown.
const tabs = [];
let activeTab = null;
let tabSeq = 0;

// State shared with end-to-end scripts through window.tailfeather. The
// terminal fields describe the active tab.
const api = {
  client: null,
  status: "idle",
  authUrl: "",
  netmap: null,
  logs: [],
  connect,
  ssh: openTab,
  selectTab: (id) => selectTab(findTab(id), { focus: true }),
  closeTab: (id) => closeTab(findTab(id)),
  derpProbe: (host, relay) => derpProbe(host, relay || undefined),
  forget,
};
Object.defineProperties(api, {
  terminal: { get: () => (activeTab ?? idle).terminal, enumerable: true },
  session: { get: () => activeTab?.handle ?? null, enumerable: true },
  terminalText: { get: () => activeTab?.text ?? "", enumerable: true },
  lastClose: { get: () => activeTab?.lastClose ?? null, enumerable: true },
  activeTabId: { get: () => activeTab?.id ?? null, enumerable: true },
  sessions: { get: () => tabs.map((tab) => tab.view), enumerable: true },
});
window.tailfeather = api;

// ---- settings ------------------------------------------------------------

function readSettings() {
  try {
    return JSON.parse(localStorage.getItem(SETTINGS_KEY) || "null");
  } catch {
    return null;
  }
}

function formSettings() {
  return {
    hostname: $("hostname").value,
    authKey: $("auth-key").value,
    ephemeral: $("ephemeral").checked,
    relay: $("relay").value,
    target: $("target").value,
    homeDerp: $("home-derp").value,
    sshHost: $("ssh-host").value,
    sshPort: $("ssh-port").value,
    sshUser: $("ssh-user").value,
    sshKey: $("ssh-key").value,
  };
}

// Secrets (the auth key and a pasted private key) are stored only when
// "remember" is on, and never logged.
function saveSettings() {
  if (!$("remember").checked) {
    // Remember only the choice not to remember.
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ remember: false }));
    return;
  }
  localStorage.setItem(SETTINGS_KEY, JSON.stringify({ remember: true, ...formSettings() }));
}

function applySettings(settings) {
  if (!settings) return;
  const fields = {
    hostname: "hostname",
    authKey: "auth-key",
    relay: "relay",
    target: "target",
    homeDerp: "home-derp",
    sshHost: "ssh-host",
    sshPort: "ssh-port",
    sshUser: "ssh-user",
    sshKey: "ssh-key",
  };
  // An empty string is a value the user chose (a cleared field); only a
  // missing property means "keep the page default".
  for (const [key, id] of Object.entries(fields)) {
    if (typeof settings[key] === "string") $(id).value = settings[key];
  }
  if (typeof settings.ephemeral === "boolean") $("ephemeral").checked = settings.ephemeral;
  $("remember").checked = settings.remember !== false;
}

// ---- status, log, notices, netmap ----------------------------------------

function setStatus(text) {
  api.status = text;
  const status = $("status");
  status.textContent = text;
  status.dataset.phase = text;
  status.title = text;
}

function log(line) {
  const stamp = new Date().toLocaleTimeString([], { hour12: false });
  const entry = `${stamp}  ${line}`;
  api.logs.push(entry);
  if (api.logs.length > LOG_LINES) api.logs.splice(0, api.logs.length - LOG_LINES);
  const pre = $("log");
  const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
  pre.textContent = api.logs.join("\n");
  if (stick) pre.scrollTop = pre.scrollHeight;
}

// The log lives in the drawer, so failures the user caused are also shown
// next to the terminal.
let noticeTimer = 0;

function showNotice(text) {
  const notice = $("notice");
  notice.textContent = text;
  notice.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(clearNotice, NOTICE_MS);
}

function clearNotice() {
  clearTimeout(noticeTimer);
  $("notice").hidden = true;
  $("notice").textContent = "";
}

function showAuthUrl(url) {
  api.authUrl = url;
  $("auth").hidden = !url;
  const link = $("auth-link");
  if (url && /^https:\/\//.test(url)) {
    link.href = url;
    link.textContent = url;
  } else {
    link.removeAttribute("href");
    link.textContent = url;
  }
}

function cell(row, text, className) {
  const td = row.insertCell();
  td.textContent = text ?? "";
  if (className) td.className = className;
  return td;
}

function renderNetmap(json) {
  let netmap;
  try {
    netmap = JSON.parse(json);
  } catch {
    return;
  }
  api.netmap = netmap;
  refreshTabLabels();
  const regions = new Map(netmap.derp.map((region) => [region.id, region]));
  const regionText = (id) => (id ? `${id}${regions.get(id) ? ` ${regions.get(id).code}` : ""}` : "—");

  const self = $("self").tBodies[0];
  self.replaceChildren();
  const rows = [
    ["Name", netmap.self.name || $("hostname").value],
    ["Tailnet IPv4", netmap.self.ip || "—"],
    ["Node key", netmap.self.nodeKey],
    ["Home DERP", regionText(netmap.self.homeDerp)],
    ["Status", netmap.self.status],
  ];
  for (const [name, value] of rows) {
    const row = self.insertRow();
    cell(row, name, "label");
    cell(row, value);
  }

  $("peer-count").textContent = `(${netmap.peers.length}${netmap.truncated ? ", truncated" : ""})`;
  const peers = $("peers").tBodies[0];
  peers.replaceChildren();
  for (const peer of netmap.peers) {
    const row = peers.insertRow();
    cell(row, peer.name || peer.nodeKey);
    cell(row, peer.ip || "—", "mono");
    cell(row, peer.online ? "yes" : "no", peer.online ? "online" : "offline");
    cell(row, peer.endpoints.join(" ") || "—", "mono small");
    cell(row, regionText(peer.homeDerp));
    const actions = row.insertCell();
    if (peer.ip) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "SSH";
      button.addEventListener("click", () => {
        $("ssh-host").value = peer.ip;
        syncPeerPicker();
        if ($("ssh-user").value) {
          openFromUi();
        } else {
          setDrawer(false, { focus: false });
          revealSshForm();
          $("ssh-user").focus();
        }
      });
      actions.append(button);
    }
  }
  renderPeerPicker(netmap.peers);

  const derp = $("derp").tBodies[0];
  derp.replaceChildren();
  for (const region of netmap.derp) {
    const row = derp.insertRow();
    cell(row, String(region.id));
    cell(row, region.code);
    cell(
      row,
      region.nodes.map((node) => `${node.host}:${node.port}${node.stunPort ? ` (stun ${node.stunPort})` : ""}`).join(", "),
      "mono small",
    );
    const state = [region.home ? "home" : "", region.connected ? "connected" : region.connecting ? "connecting" : ""]
      .filter(Boolean)
      .join(", ");
    cell(row, state || "—", region.connected ? "online" : "");
  }
  $("ssh-button").disabled = !netmap.self.ip;
}

// A plain peer picker beside the SSH fields, so choosing a host never needs
// the diagnostics. Rebuilt only when the list changes: netmaps arrive often
// and replacing the options would close an open picker.
let peerPickerKey = "";

function renderPeerPicker(peers) {
  const usable = peers
    .filter((peer) => peer.ip)
    .sort((a, b) => Number(b.online) - Number(a.online) || (a.name || a.ip).localeCompare(b.name || b.ip));
  const key = JSON.stringify(usable.map((peer) => [peer.ip, peer.name, peer.online]));
  if (key === peerPickerKey) return;
  peerPickerKey = key;
  const select = $("peer-select");
  const options = [new Option(usable.length ? "Pick a peer…" : "No peers", "")];
  for (const peer of usable) {
    const name = peer.name || peer.ip;
    options.push(new Option(`${name}${peer.online ? "" : " (offline)"} — ${peer.ip}`, peer.ip));
  }
  select.replaceChildren(...options);
  select.disabled = usable.length === 0;
  syncPeerPicker();
}

function syncPeerPicker() {
  const select = $("peer-select");
  const host = $("ssh-host").value.trim();
  select.value = [...select.options].some((option) => option.value === host) ? host : "";
}

// ---- connect -------------------------------------------------------------

// One tab runs this browser's node at a time. Two tabs would restore the same
// persisted keys and appear as one node connected twice, each replacing the
// other's control, DERP and WireGuard sessions. The lock is taken on the first
// connect and held until the tab closes.
let nodeLock = null;

function holdNodeLock() {
  if (!navigator.locks) return Promise.resolve(true);
  if (!nodeLock) {
    nodeLock = new Promise((resolve) => {
      navigator.locks.request("tailfeather.node", { ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        // Returning a promise that never settles keeps the lock for the tab's life.
        return lock ? new Promise(() => {}) : undefined;
      });
    }).then((held) => {
      if (!held) nodeLock = null;
      return held;
    });
  }
  return nodeLock;
}

async function connect(overrides = {}) {
  // Stop the old client, and end its terminals' sessions, which belong to
  // that client's network stack, before anything below can throw. A failed
  // start then leaves no stopped client behind for the page to keep using.
  stop();
  if (!(await holdNodeLock())) {
    throw new Error("this browser's node is already running in another tab; use that tab or close it first");
  }
  const settings = { ...formSettings(), ...overrides };
  saveSettings();
  const homeDerp = Number.parseInt(settings.homeDerp, 10);
  const client = TailnetClient.start(
    {
      hostname: settings.hostname,
      authKey: settings.authKey,
      ephemeral: settings.ephemeral,
      relay: settings.relay,
      target: settings.target,
      homeDerp: Number.isFinite(homeDerp) ? homeDerp : undefined,
    },
    { status: setStatus, log, authUrl: showAuthUrl, netmap: renderNetmap },
  );
  api.client = client;
  $("stop-button").disabled = false;
  syncClientControls();
  return client;
}

function stop() {
  for (const tab of tabs) endSession(tab);
  if (api.client) api.client.stop();
  api.client = null;
  $("stop-button").disabled = true;
  $("ssh-button").disabled = true;
  syncClientControls();
  updateControls();
}

function forget() {
  stop();
  forgetNode();
  localStorage.removeItem(SETTINGS_KEY);
  $("auth-key").value = "";
  $("ssh-key").value = "";
  showAuthUrl("");
  log("Forgot this browser's node identity and saved settings.");
}

function syncClientControls() {
  $("quick-connect").hidden = api.client !== null;
}

function startFromUi(overrides) {
  clearNotice();
  connect(overrides).catch((error) => {
    log(`Could not start: ${error.message ?? error}`);
    showNotice(`Could not start: ${error.message ?? error}`);
  });
}

// ---- terminals -----------------------------------------------------------

function makeTerminal(host, extra = {}) {
  const terminal = new Terminal({
    convertEol: false,
    cursorBlink: true,
    fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace',
    fontSize: NARROW.matches ? 13 : 14,
    scrollback: 5000,
    theme: { background: "#101418", foreground: "#d8dee4" },
    ...extra,
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(host);
  return { terminal, fit };
}

function element(tag, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

// Resizing any terminal box refits whichever terminal is shown.
const resizer = new ResizeObserver(() => scheduleRefit());

// Shown while there are no tabs, so the page always has a mounted terminal.
// It takes no input and has no session.
const idle = (() => {
  const pane = element("div", "pane idle");
  pane.setAttribute("aria-label", "No connection");
  const host = element("div", "xterm-host");
  pane.append(host);
  $("terminal").append(pane);
  const { terminal, fit } = makeTerminal(host, { cursorBlink: false, disableStdin: true });
  terminal.write("\x1b[2mNo connection. Pick a peer or type a host and user, then Open terminal.\x1b[0m\r\n");
  resizer.observe(host);
  return { pane, host, terminal, fit };
})();

// Size a terminal to its box. Proposals are checked because xterm reports
// nonsense (zero-sized cells, so infinite columns) before fonts are usable,
// and while its pane is hidden. Only a live session hears about the change.
function fitTerminal(view, handle) {
  if (view.pane.hidden) return;
  const size = view.fit.proposeDimensions();
  if (!size || !Number.isFinite(size.cols) || !Number.isFinite(size.rows)) return;
  const cols = Math.min(Math.max(size.cols, 20), 500);
  const rows = Math.min(Math.max(size.rows, 5), 200);
  if (cols === view.terminal.cols && rows === view.terminal.rows) return;
  view.terminal.resize(cols, rows);
  if (handle) handle.resize(cols, rows);
}

function refit() {
  if (activeTab) fitTerminal(activeTab, activeTab.handle);
  else fitTerminal(idle, null);
}

let refitFrame = 0;
function scheduleRefit() {
  if (refitFrame) return;
  refitFrame = requestAnimationFrame(() => {
    refitFrame = 0;
    refit();
  });
}

// ---- connection tabs -----------------------------------------------------

function findTab(id) {
  return tabs.find((tab) => tab.id === id) ?? null;
}

function tabLabel(options) {
  const base = connectionLabel(options, api.netmap?.peers);
  const used = new Set(tabs.filter((tab) => tab.baseLabel === base).map((tab) => tab.label));
  let suffix = 1;
  let label = base;
  while (used.has(label)) label = `${base} (${++suffix})`;
  return { base, label };
}

function refreshTabLabels() {
  const used = new Set();
  for (const tab of tabs) {
    const base = connectionLabel(tab.destination, api.netmap?.peers);
    let label = tab.baseLabel === base ? tab.label : base;
    let suffix = 1;
    while (used.has(label)) label = `${base} (${++suffix})`;
    used.add(label);
    tab.baseLabel = base;
    tab.label = label;
    tab.name.textContent = label;
    tab.close.setAttribute("aria-label", `Close ${label}`);
    updateTab(tab);
  }
  updateControls();
}

// Each tab owns its terminal, decoder, SSH handle, prompt, output copy,
// close reason and link controller. `disposed` makes every late callback of a
// removed tab a no-op.
function createTab({ base, label }, { ip, port, user, url }) {
  const id = `ssh-${++tabSeq}`;

  const pane = element("div", "pane");
  pane.id = `pane-${id}`;
  pane.hidden = true;
  pane.setAttribute("role", "tabpanel");
  pane.setAttribute("aria-labelledby", `tab-${id}`);
  const links = element("div", "term-links");
  const host = element("div", "xterm-host");
  pane.append(links, host);
  $("terminal").append(pane);
  const { terminal, fit } = makeTerminal(host);

  const item = element("div", "tab");
  item.setAttribute("role", "presentation");
  const button = element("button", "tab-select");
  button.type = "button";
  button.id = `tab-${id}`;
  button.tabIndex = -1;
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", "false");
  button.setAttribute("aria-controls", pane.id);
  const dot = element("span", "dot");
  dot.setAttribute("aria-hidden", "true");
  const name = element("span", "tab-label");
  name.textContent = label;
  const state = element("span", "visually-hidden");
  button.append(dot, name, state);
  const close = element("button", "tab-close");
  close.type = "button";
  close.textContent = "×";
  close.title = "Close tab";
  close.setAttribute("aria-label", `Close ${label}`);
  item.append(button, close);
  $("tabs").append(item);

  const tab = {
    id,
    baseLabel: base,
    label,
    destination: { ip, port, user, url },
    pane,
    host,
    terminal,
    fit,
    decoder: new TextDecoder(),
    links: null,
    handle: null,
    prompt: null,
    text: "",
    lastClose: null,
    sshAuthUrl: "",
    disposed: false,
    item,
    button,
    name,
    close,
    state,
  };
  // What scripts see: no options, keys or passwords.
  tab.view = Object.freeze(
    Object.defineProperties(
      {},
      {
        id: { value: id, enumerable: true },
        label: { get: () => tab.label, enumerable: true },
        terminalText: { get: () => tab.text, enumerable: true },
        session: { get: () => tab.handle, enumerable: true },
        lastClose: { get: () => tab.lastClose, enumerable: true },
        sshAuthUrl: { get: () => tab.sshAuthUrl, enumerable: true },
      },
    ),
  );
  tab.links = installTerminalLinks({
    terminal,
    container: links,
    onAuthUrl: (url) => {
      if (!tab.disposed) tab.sshAuthUrl = url;
    },
  });
  terminal.onData((data) => routeInput(tab, applyCtrl(data)));
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.type !== "keydown" || !event.ctrlKey || event.altKey || event.metaKey || event.isComposing || event.key !== "/") return true;
    event.preventDefault();
    setCtrl(false);
    routeInput(tab, "\u001f");
    return false;
  });
  button.addEventListener("click", () => selectTab(tab, { focus: "auto" }));
  close.addEventListener("click", () => {
    if (tab.handle && !confirm(`Close the connection to ${tab.label}?`)) return;
    closeTab(tab);
    // The button that had focus is gone; keep keyboard users in the tab bar.
    if (document.activeElement === document.body || !document.activeElement) {
      (activeTab ? activeTab.button : $("new-tab")).focus();
    }
  });
  resizer.observe(host);
  tabs.push(tab);
  refreshTabLabels();
  return tab;
}

function updateTab(tab) {
  const live = tab.handle !== null;
  tab.item.classList.toggle("live", live);
  tab.state.textContent = live ? "" : " (disconnected)";
  tab.button.title = tab.lastClose ? `${tab.label} — ${tab.lastClose}` : tab.label;
}

function updateControls() {
  $("ssh-close").disabled = !activeTab?.handle;
  $("terminal-panel").classList.toggle("has-tabs", tabs.length > 0);
  document.title = activeTab ? `${activeTab.label} · tailfeather` : DEFAULT_TITLE;
}

function selectTab(tab, { focus = false } = {}) {
  if (!tab || tab.disposed) return false;
  // Was the user typing? Then keep typing in the newly shown terminal; on a
  // touch screen, do not raise the keyboard otherwise.
  const typing = Boolean(document.activeElement?.closest?.(".xterm"));
  activeTab = tab;
  for (const other of tabs) {
    const shown = other === tab;
    other.pane.hidden = !shown;
    other.item.classList.toggle("active", shown);
    other.button.setAttribute("aria-selected", String(shown));
    other.button.tabIndex = shown ? 0 : -1;
  }
  idle.pane.hidden = true;
  fitTerminal(tab, tab.handle);
  if (focus === true || (focus === "auto" && (typing || !COARSE.matches))) tab.terminal.focus();
  revealTab(tab);
  updateControls();
  return true;
}

// Scroll the tab strip only; scrollIntoView would also scroll the page frame.
function revealTab(tab) {
  const strip = $("tabs");
  const start = tab.item.offsetLeft;
  const end = start + tab.item.offsetWidth;
  if (start < strip.scrollLeft) strip.scrollLeft = start;
  else if (end > strip.scrollLeft + strip.clientWidth) strip.scrollLeft = end - strip.clientWidth;
}

// End a tab's session but keep the tab and its output. The session still
// reports how it ended through `closed`.
function endSession(tab) {
  const handle = tab.handle;
  tab.handle = null;
  cancelPrompt(tab);
  if (handle) handle.close();
  updateTab(tab);
}

function closeTab(tab) {
  if (!tab || tab.disposed) return false;
  const index = tabs.indexOf(tab);
  const wasActive = tab === activeTab;
  endSession(tab);
  tab.disposed = true;
  tab.links.dispose();
  resizer.unobserve(tab.host);
  tab.terminal.dispose();
  tab.pane.remove();
  tab.item.remove();
  tabs.splice(index, 1);
  if (wasActive) {
    activeTab = null;
    const next = tabs[index] ?? tabs[index - 1];
    if (next) {
      selectTab(next, { focus: "auto" });
    } else {
      idle.pane.hidden = false;
      fitTerminal(idle, null);
    }
  }
  updateControls();
  return true;
}

// `overrides.url` (a ws:// URL carrying a raw TCP stream) bypasses the tailnet;
// the end-to-end tests use it against a local SSH server. Every call opens and
// selects a new tab.
function openTab(overrides = {}) {
  if (!api.client && !overrides.url) throw new Error("connect to the tailnet first");
  saveSettings();
  const options = {
    url: overrides.url,
    ip: overrides.ip ?? $("ssh-host").value.trim(),
    port: Number.parseInt(overrides.port ?? $("ssh-port").value, 10) || 22,
    user: overrides.user ?? $("ssh-user").value.trim(),
    privateKey: overrides.privateKey ?? ($("ssh-key").value.trim() || undefined),
  };
  const tab = createTab(tabLabel(options), options);
  // Shown and fitted first, so the PTY starts at the terminal's real size.
  selectTab(tab, { focus: true });
  const live = () => !tab.disposed;
  const open = options.url ? sshOverWebSocket : (...args) => api.client.ssh(...args);
  try {
    tab.handle = open(
      { ...options, cols: tab.terminal.cols, rows: tab.terminal.rows },
      {
        write: (bytes) => {
          if (!live()) return;
          tab.terminal.write(bytes);
          const text = tab.decoder.decode(bytes, { stream: true });
          record(tab, text);
          tab.links.write(text);
        },
        // A session that was ended (or a tailnet that was stopped) gets no
        // more prompts; Rust treats null as cancelled.
        prompt: (label, echo) => (live() && tab.handle ? promptInTerminal(tab, label, echo) : Promise.resolve(null)),
        closed: (reason) => {
          if (!live()) return;
          const rest = tab.decoder.decode();
          if (rest) {
            record(tab, rest);
            tab.links.write(rest);
          }
          tab.handle = null;
          tab.lastClose = reason;
          cancelPrompt(tab);
          tab.links.finish();
          updateTab(tab);
          updateControls();
        },
      },
    );
  } catch (error) {
    closeTab(tab);
    throw error;
  }
  updateTab(tab);
  updateControls();
  return tab.handle;
}

// A form submit, peer button or picker: the user wants the terminal, so the
// settings drawer and the transient form get out of the way.
function openFromUi() {
  clearNotice();
  try {
    openTab();
  } catch (error) {
    log(`SSH: ${error.message ?? error}`);
    showNotice(`SSH: ${error.message ?? error}`);
    return;
  }
  setDrawer(false, { focus: false });
  $("terminal-panel").classList.remove("form-open");
}

// A bounded plain-text copy for scripted checks.
function record(tab, text) {
  tab.text = (tab.text + text).slice(-TERMINAL_TEXT_LIMIT);
}

// Local output (prompts and their echo) goes to the screen and the copy, but
// never to the link scanner.
function localWrite(tab, text) {
  tab.terminal.write(text);
  record(tab, text);
}

// ---- input ---------------------------------------------------------------

// While a prompt is active, keystrokes answer it instead of reaching SSH.
function promptInTerminal(tab, label, echo) {
  cancelPrompt(tab);
  return new Promise((resolve) => {
    const text = label.replace(/\n/g, "\r\n");
    localWrite(tab, text);
    // The label comes from the server (keyboard-interactive instructions can
    // carry a link); what the user types never does.
    tab.links.write(text);
    tab.prompt = { echo, buffer: "", resolve };
    if (tab === activeTab) tab.terminal.focus();
  });
}

function cancelPrompt(tab) {
  const prompt = tab.prompt;
  tab.prompt = null;
  if (prompt) prompt.resolve(null);
}

function answerPrompt(tab, data) {
  const prompt = tab.prompt;
  for (const ch of data) {
    if (ch === "\r" || ch === "\n") {
      localWrite(tab, "\r\n");
      tab.prompt = null;
      prompt.resolve(prompt.buffer);
      return;
    }
    if (ch === "\u0003" || ch === "\u0004") {
      localWrite(tab, "^C\r\n");
      tab.prompt = null;
      prompt.resolve(null);
      return;
    }
    if (ch === "\u007f" || ch === "\b") {
      if (prompt.buffer.length > 0) {
        prompt.buffer = prompt.buffer.slice(0, -1);
        if (prompt.echo) localWrite(tab, "\b \b");
      }
      continue;
    }
    if (ch >= " ") {
      prompt.buffer += ch;
      if (prompt.echo) localWrite(tab, ch);
    }
  }
}

// Cursor keys and other escape sequences mean nothing to a prompt; without
// this an arrow would leave "[A" in a password.
const ESCAPE_SEQUENCE = /\x1b(?:\[[0-?]*[ -/]*[@-~]|O[@-~]|[@-Z\\-_])?/g;

const encoder = new TextEncoder();
function routeInput(tab, data) {
  if (tab.disposed || !data) return;
  if (tab.prompt) {
    answerPrompt(tab, data.replace(ESCAPE_SEQUENCE, ""));
  } else if (tab.handle) {
    tab.handle.send(encoder.encode(data));
  }
}

// The key row's Ctrl applies to the next key only, typed or tapped.
let ctrlArmed = false;

function setCtrl(on) {
  ctrlArmed = on;
  document.querySelector('#keybar [data-key="ctrl"]').setAttribute("aria-pressed", String(on));
}

function applyCtrl(data) {
  if (!ctrlArmed || !data) return data;
  setCtrl(false);
  const ch = data[0];
  let control = null;
  if (/[a-z]/i.test(ch)) control = String.fromCharCode(ch.toUpperCase().charCodeAt(0) - 64);
  else if ("@[\\]^_".includes(ch)) control = String.fromCharCode(ch.charCodeAt(0) - 64);
  else if (ch === " ") control = "\u0000";
  else if (ch === "?") control = "\u007f";
  else if (ch === "/") control = "\u001f";
  return control === null ? data : control + data.slice(1);
}

const ARROWS = { up: "A", down: "B", right: "C", left: "D" };

function pressKey(key) {
  if (key === "ctrl") {
    setCtrl(!ctrlArmed);
    return;
  }
  const tab = activeTab;
  if (key === "keyboard") {
    if (!tab) return;
    if (document.activeElement === tab.terminal.textarea) tab.terminal.textarea.blur();
    else tab.terminal.focus();
    return;
  }
  const ctrl = ctrlArmed;
  setCtrl(false);
  if (!tab) return;
  let data;
  if (key in ARROWS) {
    const final = ARROWS[key];
    if (ctrl) data = `\x1b[1;5${final}`;
    else data = tab.terminal.modes.applicationCursorKeysMode ? `\x1bO${final}` : `\x1b[${final}`;
  } else {
    data = key === "esc" ? "\x1b" : "\t";
  }
  tab.terminal.scrollToBottom();
  routeInput(tab, data);
}

// ---- layout: drawer, focus mode, fullscreen, viewport --------------------

function setDrawer(open, { focus = true } = {}) {
  const drawer = $("drawer");
  if (drawer.hidden === !open) return;
  drawer.hidden = !open;
  $("drawer-toggle").setAttribute("aria-expanded", String(open));
  if (focus) (open ? $("drawer-title") : $("drawer-toggle")).focus();
  scheduleRefit();
}

function isFocusMode() {
  return document.body.classList.contains("focus-mode");
}

function canFullscreen() {
  return Boolean(document.fullscreenEnabled && document.documentElement.requestFullscreen);
}

// Fullscreen started focus mode, so leaving fullscreen leaves it too.
let fullscreenOwnsFocus = false;
let fullscreenFallback = false;

function setFocusMode(on) {
  document.body.classList.toggle("focus-mode", on);
  const button = $("focus-button");
  button.setAttribute("aria-pressed", String(on));
  button.querySelector(".label").textContent = on ? "Exit focus" : "Focus";
  if (!canFullscreen() || fullscreenFallback) $("fullscreen-button").setAttribute("aria-pressed", String(on));
  // The drawer is hidden in focus mode; leaving it "open" would make Escape
  // close something invisible.
  if (on) setDrawer(false, { focus: false });
  if (!on) {
    fullscreenFallback = false;
    fullscreenOwnsFocus = false;
    $("terminal-panel").classList.remove("form-open");
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  }
  scheduleRefit();
}

async function toggleFullscreen() {
  if (document.fullscreenElement) {
    await document.exitFullscreen().catch(() => {});
    return;
  }
  // iPhone Safari has no element fullscreen: the focus layout is the fallback.
  if (!canFullscreen() || fullscreenFallback) {
    setFocusMode(!isFocusMode());
    return;
  }
  const already = isFocusMode();
  setFocusMode(true);
  try {
    await document.documentElement.requestFullscreen({ navigationUI: "hide" });
    fullscreenOwnsFocus = !already;
  } catch {
    // Refused (no user activation, policy): the focus layout stays.
    fullscreenFallback = true;
    $("fullscreen-button").setAttribute("aria-pressed", "true");
  }
}

function onFullscreenChange() {
  const on = Boolean(document.fullscreenElement);
  if (on) fullscreenFallback = false;
  const button = $("fullscreen-button");
  button.setAttribute("aria-pressed", String(on));
  button.querySelector(".label").textContent = on ? "Exit fullscreen" : "Fullscreen";
  if (!on && fullscreenOwnsFocus) setFocusMode(false);
  scheduleRefit();
}

// The form hides while terminals use a small screen or focus mode; "+"
// brings it back for the next connection.
function revealSshForm() {
  $("terminal-panel").classList.add("form-open");
}

function toggleSshForm() {
  const panel = $("terminal-panel");
  const form = $("ssh-form");
  if (getComputedStyle(form).display === "none") {
    revealSshForm();
  } else if (panel.classList.contains("form-open")) {
    panel.classList.remove("form-open");
    return;
  }
  ($("ssh-user").value ? $("ssh-host") : $("ssh-user")).focus();
}

// Follow the visual viewport, which shrinks when a mobile keyboard opens
// (iOS does not resize the layout viewport). Pinch zoom is left alone.
function syncViewport() {
  const viewport = window.visualViewport;
  if (viewport && Math.abs(viewport.scale - 1) > 0.01) return;
  const style = document.documentElement.style;
  style.setProperty("--vv-height", `${Math.round(viewport ? viewport.height : window.innerHeight)}px`);
  style.setProperty("--vv-top", `${Math.round(viewport ? viewport.offsetTop : 0)}px`);
}

let viewportFrame = 0;
function scheduleViewport() {
  if (viewportFrame) return;
  viewportFrame = requestAnimationFrame(() => {
    viewportFrame = 0;
    syncViewport();
    refit();
  });
}

syncViewport();
window.visualViewport?.addEventListener("resize", scheduleViewport);
window.visualViewport?.addEventListener("scroll", scheduleViewport);
window.addEventListener("resize", scheduleViewport);

// Escape belongs to the remote program while a terminal has focus. Elsewhere
// it closes the drawer or the transient form, or leaves focus mode.
function onEscape(event) {
  if (event.key !== "Escape" || event.defaultPrevented || event.isComposing) return;
  const target = event.target instanceof Element ? event.target : null;
  if (target?.closest(".xterm")) return;
  const drawer = $("drawer");
  if (!drawer.hidden && (!WIDE.matches || drawer.contains(target))) {
    event.preventDefault();
    setDrawer(false);
    return;
  }
  const panel = $("terminal-panel");
  if (panel.classList.contains("form-open") && $("ssh-form").contains(target)) {
    event.preventDefault();
    panel.classList.remove("form-open");
    activeTab?.terminal.focus();
    return;
  }
  if (isFocusMode()) {
    event.preventDefault();
    setFocusMode(false);
  }
}

// Tablist keys (only while a tab has focus): arrows, Home and End.
function onTabKey(event) {
  const index = tabs.findIndex((tab) => tab.button === event.target);
  if (index < 0) return;
  const moves = {
    ArrowRight: tabs[(index + 1) % tabs.length],
    ArrowLeft: tabs[(index - 1 + tabs.length) % tabs.length],
    Home: tabs[0],
    End: tabs[tabs.length - 1],
  };
  const next = moves[event.key];
  if (!next) return;
  event.preventDefault();
  selectTab(next);
  next.button.focus();
}

// ---- wiring --------------------------------------------------------------

// /connect (behind Cloudflare Access) redirects here with a freshly minted,
// single-use auth key in the fragment. Take it out of the address bar and
// history at once; it is used for this connection only and never remembered.
function takeMintedKey() {
  const key = new URLSearchParams(location.hash.slice(1)).get("tskey");
  if (key === null) return null;
  history.replaceState(null, "", location.pathname + location.search);
  return /^tskey-auth-[A-Za-z0-9-]+$/.test(key) ? key : null;
}

function wireLayout(saved) {
  // Neither form may ever submit natively: that would put its fields, the
  // auth key included, into the URL. Their real handlers attach once the
  // WebAssembly module is loaded.
  for (const id of ["connect-form", "ssh-form"]) {
    $(id).addEventListener("submit", (event) => event.preventDefault());
  }
  // Setup is open where it fits beside the terminal, and on a first visit.
  setDrawer(WIDE.matches || !saved, { focus: false });
  $("drawer-toggle").addEventListener("click", () => setDrawer($("drawer").hidden));
  $("drawer-close").addEventListener("click", () => setDrawer(false));
  $("quick-connect").addEventListener("click", () => $("connect-form").requestSubmit());
  $("new-tab").addEventListener("click", toggleSshForm);
  $("focus-button").addEventListener("click", () => setFocusMode(!isFocusMode()));
  $("fullscreen-button").addEventListener("click", () => toggleFullscreen());
  document.addEventListener("fullscreenchange", onFullscreenChange);
  document.addEventListener("keydown", onEscape);
  $("tabs").addEventListener("keydown", onTabKey);
  // Taps on the tab bar and key row must not take focus from the terminal
  // (on a phone that would drop the keyboard). Keyboard focus still works.
  for (const id of ["tabbar", "keybar"]) {
    $(id).addEventListener("mousedown", (event) => {
      if (event.target instanceof Element && event.target.closest("button")) event.preventDefault();
    });
  }
  $("keybar").addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest("button[data-key]") : null;
    if (button) pressKey(button.dataset.key);
  });
  $("peer-select").addEventListener("change", () => {
    const ip = $("peer-select").value;
    if (!ip) return;
    $("ssh-host").value = ip;
    if (!$("ssh-user").value) $("ssh-user").focus();
  });
  $("ssh-host").addEventListener("input", syncPeerPicker);
}

async function main() {
  // Take a minted key out of the address bar before anything asynchronous, so
  // it is gone even if loading the WebAssembly module fails.
  const minted = takeMintedKey();
  const saved = readSettings();
  wireLayout(saved);
  updateControls();
  await init();
  applySettings(saved);
  syncPeerPicker();
  syncClientControls();
  $("connect-form").addEventListener("submit", (event) => {
    event.preventDefault();
    startFromUi();
  });
  $("stop-button").addEventListener("click", stop);
  $("forget-button").addEventListener("click", () => {
    if (confirm("Delete this browser's node identity and every saved setting and secret?")) forget();
  });
  $("remember").addEventListener("change", saveSettings);
  $("ssh-form").addEventListener("submit", (event) => {
    event.preventDefault();
    openFromUi();
  });
  $("ssh-close").addEventListener("click", () => {
    if (activeTab) endSession(activeTab);
    updateControls();
  });
  $("hostkey-forget").addEventListener("click", () => {
    const host = $("ssh-host").value.trim();
    const port = Number.parseInt($("ssh-port").value, 10) || 22;
    try {
      forgetHostKey(host, port);
      log(`Forgot the remembered host key of ${host}:${port}.`);
    } catch (error) {
      log(`Forget host key: ${error.message ?? error}`);
    }
  });
  api.ready = true;
  document.body.dataset.ready = "true";
  if (minted) {
    log("Received a single-use auth key from /connect; connecting.");
    startFromUi({ authKey: minted });
  }
}

api.loaded = main();
