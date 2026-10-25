// A throwaway SSH server (ssh2) behind a websockify-style WebSocket bridge on
// the page's own origin, so the browser's russh client can be exercised
// without a tailnet.
//
// Accepts user "tester" with auth "none", and user "kbd" through
// keyboard-interactive (answer "1234") after an auth banner. The "shell"
// understands `echo …`, `uname -n` (answers "e2e-sshd") and `exit`.

import { createServer as createTcpServer, connect } from "node:net";
import ssh2 from "ssh2";
import { WebSocketServer, createWebSocketStream } from "ws";

const { Server, utils } = ssh2;

function shell(stream) {
  let line = "";
  stream.write("welcome to e2e-sshd\r\n$ ");
  stream.on("data", (data) => {
    for (const ch of data.toString("utf8")) {
      if (ch !== "\r" && ch !== "\n") {
        line += ch;
        stream.write(ch);
        continue;
      }
      stream.write("\r\n");
      const commands = line.split(";").map((command) => command.trim());
      line = "";
      for (const command of commands) {
        if (command === "exit") {
          stream.exit(0);
          stream.end();
          return;
        }
        if (command === "uname -n") stream.write("e2e-sshd\r\n");
        else if (command === "links") {
          // Separate SSH messages, formatting and a URI longer than a mobile
          // terminal row exercise the browser's actual output callback.
          stream.write("\x1b[32mhttps://login.tail");
          setTimeout(() => {
            stream.write("scale.com/a/browser-example\x1b[0m\r\n");
            stream.write("Docs: https://example.org/documentation/a-long-page-for-a-narrow-terminal?lang=en\r\n");
            stream.write("\x1b]8;;https://example.org/osc-link\x07OSC link\x1b]8;;\x07\r\n");
            stream.write("$ ");
          }, 20);
          return;
        }
        else if (command.startsWith("echo ")) stream.write(`${command.slice(5)}\r\n`);
        else if (command) stream.write(`unknown: ${command}\r\n`);
      }
      stream.write("$ ");
    }
  });
}

export async function startLocalSsh(httpServer, {
  forwardTarget = null, onForward = () => {}, forwardDelay = () => 0, onForwardClose = () => {},
} = {}) {
  const hostKey = utils.generateKeyPairSync("ed25519");
  const ssh = new Server(
    { hostKeys: [hostKey.private], banner: "e2e-sshd banner: authorized testing only\nApprove: https://login.tailscale.com/a/banner-example\n" },
    (client) => {
      client.on("authentication", (context) => {
        if (context.username === "tester" && context.method === "none") return context.accept();
        if (context.username === "kbd" && context.method === "keyboard-interactive") {
          return context.prompt([{ prompt: "Code: ", echo: true }], "e2e", "Enter the code.", (answers) => {
            if (answers[0] === "1234") context.accept();
            else context.reject(["keyboard-interactive"]);
          });
        }
        context.reject(context.username === "kbd" ? ["keyboard-interactive"] : ["none"]);
      });
      client.on("ready", () => {
        client.on("tcpip", (accept, reject, info) => {
          if (!forwardTarget || info.destPort !== forwardTarget.port || !["localhost", "127.0.0.1", "::1"].includes(info.destIP)) return reject();
          onForward(info);
          const delay = forwardDelay(info);
          // Emulate the remote namespace on a separate local backing port.
          const upstream = connect(forwardTarget.backingPort, "127.0.0.1");
          upstream.on("error", () => { try { reject(); } catch {} });
          upstream.on("connect", () => {
            const open = () => {
              const stream = accept();
              upstream.pipe(stream).pipe(upstream);
              stream.on("error", () => upstream.destroy());
              stream.on("close", () => { upstream.destroy(); onForwardClose(info); });
            };
            if (delay) setTimeout(open, delay);
            else open();
          });
        });
        client.on("session", (accept) => {
          const session = accept();
          session.on("pty", (acceptPty) => acceptPty && acceptPty());
          session.on("window-change", (acceptChange) => acceptChange && acceptChange());
          session.on("shell", (acceptShell) => shell(acceptShell()));
        });
      });
      client.on("error", () => {});
    },
  );
  const tcp = createTcpServer((socket) => ssh.injectSocket(socket));
  await new Promise((resolve) => tcp.listen(0, "127.0.0.1", resolve));
  const port = tcp.address().port;

  // websockify: each WebSocket is one TCP connection to the SSH server.
  const bridge = new WebSocketServer({
    noServer: true,
    handleProtocols: (protocols) => (protocols.has("binary") ? "binary" : false),
  });
  httpServer.on("upgrade", (request, socket, head) => {
    if (!request.url.startsWith("/ssh")) return socket.destroy();
    bridge.handleUpgrade(request, socket, head, (ws) => {
      const upstream = connect(port, "127.0.0.1");
      const stream = createWebSocketStream(ws);
      stream.pipe(upstream).pipe(stream);
      const close = () => {
        upstream.destroy();
        ws.terminate();
      };
      upstream.on("error", close);
      stream.on("error", close);
    });
  });
  return {
    close() {
      bridge.close();
      tcp.close();
    },
  };
}
