#!/usr/bin/env node
// Firefox native-messaging host. Never log protocol payloads: TCP contains OAuth secrets.
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const MAX_FRAME = 128 * 1024;
const MAX_CHUNK = 32768;
const validId = (id) => typeof id === "string" && /^[a-zA-Z0-9-]{1,80}$/.test(id);

export class LoopbackHost {
  constructor(send) {
    this.send = send;
    this.listeners = new Map();
    this.sockets = new Map();
    this.nextSocket = 0;
    this.closed = false;
  }

  async receive(message) {
    const { type, request } = message ?? {};
    try {
      if (this.closed) throw Error();
      if (type === "listen") {
        const { id, host, port } = message;
        if (!validId(id) || this.listeners.has(id) || this.listeners.size >= 8 ||
            !["localhost", "127.0.0.1", "::1"].includes(host) ||
            !Number.isInteger(port) || port < 1 || port > 65535) throw Error();
        const entry = { servers: [], sockets: new Set() };
        this.listeners.set(id, entry);
        try {
          for (const address of host === "localhost" ? ["127.0.0.1", "::1"] : [host]) {
            const server = createServer({ allowHalfOpen: true, highWaterMark: MAX_CHUNK }, (socket) => {
              if (this.closed || this.sockets.size >= 32) return socket.destroy();
              const socketId = String(++this.nextSocket);
              entry.sockets.add(socketId);
              this.sockets.set(socketId, socket);
              socket.pause();
              socket.setTimeout(120_000, () => socket.destroy());
              socket.on("data", (data) => {
                socket.pause();
                // readable highWaterMark ensures bounded chunks, still validate explicitly.
                if (data.length > MAX_CHUNK) return socket.destroy();
                this.send({ type: "data", id, socket: socketId, data: data.toString("base64") });
              });
              socket.on("end", () => this.send({ type: "eof", id, socket: socketId }));
              socket.on("error", () => {});
              socket.on("close", () => {
                this.sockets.delete(socketId);
                entry.sockets.delete(socketId);
                this.send({ type: "closed", id, socket: socketId });
              });
              this.send({ type: "connection", id, socket: socketId });
            });
            // Only the requested numeric loopback address, never wildcard/DNS binding.
            server.on("error", () => {});
            entry.servers.push(server);
            await new Promise((ready, failed) => {
              server.once("error", failed);
              server.listen({ host: address, port, ipv6Only: true, exclusive: true }, () => {
                server.off("error", failed);
                ready();
              });
            });
            if (this.closed || this.listeners.get(id) !== entry) {
              server.close();
              throw Error();
            }
          }
          if (this.closed) throw Error();
        } catch {
          this.stop(id);
          throw Error();
        }
      } else if (type === "stop") {
        this.stop(message.id);
      } else if (type === "close") {
        this.sockets.get(message.socket)?.destroy();
      } else {
        const socket = this.sockets.get(message.socket);
        if (!socket) throw Error();
        if (type === "accept" || type === "ack") socket.resume();
        else if (type === "eof") socket.end();
        else if (type === "write") {
          if (typeof message.data !== "string" || message.data.length > 43692 ||
              !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.data)) throw Error();
          const data = Buffer.from(message.data, "base64");
          if (data.length > MAX_CHUNK) throw Error();
          await new Promise((ready, failed) => {
            socket.write(data, (error) => error ? failed(error) : ready());
          });
        } else throw Error();
      }
      if (validId(request)) this.send({ type: "reply", request, ok: true });
    } catch {
      // Fixed message; never include URLs, bytes, or native exception strings.
      if (validId(request)) this.send({ type: "reply", request, ok: false });
    }
  }

  stop(id) {
    const entry = this.listeners.get(id);
    if (!entry) return;
    this.listeners.delete(id);
    for (const server of entry.servers) server.close();
    for (const socket of entry.sockets) this.sockets.get(socket)?.destroy();
  }

  close() {
    this.closed = true;
    for (const id of this.listeners.keys()) this.stop(id);
  }
}

export function nativeMain(input = process.stdin, output = process.stdout) {
  let pending = Buffer.alloc(0);
  const host = new LoopbackHost((message) => {
    if (host.closed) return;
    const body = Buffer.from(JSON.stringify(message));
    const header = Buffer.alloc(4);
    header.writeUInt32LE(body.length);
    if (output.writableLength > 4 * MAX_FRAME) {
      host.close();
      input.destroy();
      output.end();
      return;
    }
    output.write(Buffer.concat([header, body]));
  });
  input.on("data", (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 4) {
      const length = pending.readUInt32LE(0);
      if (length > MAX_FRAME) { host.close(); input.destroy(); return; }
      if (pending.length < length + 4) return;
      const frame = pending.subarray(4, length + 4);
      pending = pending.subarray(length + 4);
      try { void host.receive(JSON.parse(frame.toString("utf8"))); }
      catch { host.close(); input.destroy(); return; }
    }
  });
  input.on("end", () => host.close());
  input.on("error", () => host.close());
  output.on("error", () => host.close());
  return host;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) nativeMain();
