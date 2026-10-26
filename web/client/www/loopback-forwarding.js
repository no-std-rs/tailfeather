import { loopbackDestination } from "./terminal-url-scanner.js";

const bytesToBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
const base64ToBytes = (data) => Uint8Array.from(atob(data), (value) => value.charCodeAt(0));

// No URL, credential, or TCP byte is persisted or sent to a logging API.
export class LoopbackForwarding {
  constructor(getSession, { window: page = window, onError = () => {} } = {}) {
    this.page = page;
    this.getSession = getSession;
    this.onError = onError;
    this.session = crypto.randomUUID();
    this.pending = new Map();
    this.listeners = new Map();
    this.pipes = new Map();
    this.disposed = false;
    this.sequence = 0;
    this.onMessage = (event) => {
      if (event.source !== this.page || event.origin !== this.page.location.origin ||
          event.data?.source !== "tailfeather-loopback-extension" || event.data.session !== this.session) return;
      void this.receive(event.data);
    };
    page.addEventListener("message", this.onMessage);
  }

  post(message) {
    if (this.disposed) throw Error("This SSH connection has closed.");
    this.page.postMessage({ ...message, source: "tailfeather-loopback-page", session: this.session }, this.page.location.origin);
  }

  async connect() {
    if (this.connected) return;
    if (!this.connecting) {
      this.connecting = new Promise((resolve, reject) => {
        this.hello = resolve;
        this.helloReject = reject;
        this.helloTimer = setTimeout(() => {
          this.hello = null;
          this.helloReject = null;
          reject(Error("Install the Tailfeather Loopback Firefox extension and native companion; see web/loopback/README.md."));
        }, 2000);
        this.post({ type: "hello" });
      }).catch((error) => { this.connecting = null; throw error; });
    }
    await this.connecting;
  }

  request(message) {
    const request = String(++this.sequence);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(request);
        reject(Error("Loopback companion timed out."));
      }, 15_000);
      this.pending.set(request, { resolve, reject, timer });
      try { this.post({ ...message, request }); }
      catch (error) { clearTimeout(timer); this.pending.delete(request); reject(error); }
    });
  }

  async listen(text) {
    const destination = loopbackDestination(text);
    if (!destination || !this.getSession()) throw Error("Open a loopback link from a connected SSH terminal.");
    await this.connect();
    const key = `${destination.host}:${destination.port}`;
    if (!this.listeners.has(key)) {
      const id = crypto.randomUUID();
      const entry = { ...destination, id };
      this.listeners.set(key, entry);
      entry.ready = this.request({ type: "listen", id, host: destination.host, port: destination.port });
      try { await entry.ready; }
      catch (error) {
        this.listeners.delete(key);
        if (!this.disposed) this.post({ type: "stop", id });
        throw error;
      }
    }
    await this.listeners.get(key)?.ready;
    return destination.url;
  }

  async receive(message) {
    if (this.disposed) return;
    if (message.type === "hello") {
      this.connected = true;
      clearTimeout(this.helloTimer);
      this.hello?.();
      this.hello = null;
      this.helloReject = null;
      return;
    }
    if (message.type === "disconnected") { this.dispose(); return; }
    if (message.type === "reply") {
      const pending = this.pending.get(message.request);
      if (!pending) return;
      this.pending.delete(message.request);
      clearTimeout(pending.timer);
      if (message.ok) pending.resolve();
      else pending.reject(Error("Loopback companion refused the operation. Check installation or whether another terminal/application owns this port."));
      return;
    }
    if (message.type === "connection") {
      const entry = [...this.listeners.values()].find((value) => value.id === message.id);
      if (!entry || !this.getSession()) {
        this.post({ type: "close", socket: message.socket });
        return;
      }
      const socket = message.socket;
      const record = { pipe: null, closed: false };
      this.pipes.set(socket, record);
      try {
        const pipe = await this.getSession().open_forward(entry.host, entry.port,
          (bytes) => this.request({ type: "write", socket, data: bytesToBase64(bytes) }),
          () => this.request({ type: "eof", socket }),
          () => {
            record.closed = true;
            this.pipes.delete(socket);
            if (!this.disposed) this.post({ type: "close", socket });
          });
        if (record.closed || this.disposed) { pipe.close(); return; }
        record.pipe = pipe;
        await this.request({ type: "accept", socket });
      } catch {
        record.pipe?.close();
        this.pipes.delete(socket);
        this.onError("SSH forwarding was refused or disconnected. Check the server's forwarding policy.");
        if (!this.disposed) this.post({ type: "close", socket });
      }
      return;
    }
    const record = this.pipes.get(message.socket);
    if (!record) return;
    if (message.type === "closed") {
      record.closed = true;
      record.pipe?.close();
      this.pipes.delete(message.socket);
      return;
    }
    try {
      if (message.type === "data") {
        await record.pipe.send(base64ToBytes(message.data));
        if (!this.disposed) this.post({ type: "ack", socket: message.socket });
      } else if (message.type === "eof") await record.pipe.eof();
    } catch {
      record.pipe?.close();
      if (!this.disposed) this.post({ type: "close", socket: message.socket });
    }
  }

  dispose() {
    if (this.disposed) return;
    this.post({ type: "disconnect" });
    this.disposed = true;
    clearTimeout(this.helloTimer);
    this.helloReject?.(Error("SSH loopback forwarding disconnected."));
    this.helloReject = null;
    this.page.removeEventListener("message", this.onMessage);
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(Error("SSH loopback forwarding disconnected."));
    }
    this.pending.clear();
    for (const record of this.pipes.values()) record.pipe?.close();
    this.pipes.clear();
    this.listeners.clear();
  }
}
