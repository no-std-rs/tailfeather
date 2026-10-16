// A minimal static server for web/dist with correct MIME types
// (`application/wasm` matters: streaming instantiation refuses anything else).
//
//   node e2e/serve.mjs [port]      # serves ../dist on http://127.0.0.1:<port>/

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const DIST = resolve(fileURLToPath(new URL("../../dist", import.meta.url)));

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".map": "application/json",
  ".json": "application/json",
};

export function serve(port = 0, root = DIST) {
  const server = createServer(async (request, response) => {
    const path = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    const file = normalize(join(root, path.endsWith("/") ? `${path}index.html` : path));
    if (file !== root && !file.startsWith(root + sep)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, {
        "Content-Type": TYPES[extname(file)] ?? "application/octet-stream",
        "Cache-Control": "no-store",
      });
      response.end(body);
    } catch {
      response.writeHead(404).end("not found");
    }
  });
  return new Promise((resolveListen) => {
    server.listen(port, "127.0.0.1", () => {
      resolveListen({ server, url: `http://127.0.0.1:${server.address().port}/` });
    });
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { url } = await serve(Number(process.argv[2] ?? 8000));
  console.log(`serving ${DIST} at ${url}`);
}
