import assert from "node:assert/strict";
import { test } from "node:test";
import { TerminalUrlScanner, safeWebUrl, isTailscaleAuthUrl, loopbackDestination } from "../www/terminal-url-scanner.js";

test("split SSH URLs and formatting sequences produce only complete links", () => {
  const urls = [];
  const scanner = new TerminalUrlScanner((url) => urls.push(url));
  scanner.write("Approve: \x1b[3");
  scanner.write("2mhttps://login.tail");
  scanner.write("scale.com/a/browser-");
  assert.deepEqual(urls, []);
  scanner.write("example\x1b[0m\r\n");
  scanner.write("Docs (https://example.org/docs?q=1&lang=en).\n");
  assert.deepEqual(urls, [
    "https://login.tailscale.com/a/browser-example",
    "https://example.org/docs?q=1&lang=en",
  ]);
});

test("OSC hyperlinks are detected without leaking other OSC contents", () => {
  const urls = [];
  const scanner = new TerminalUrlScanner((url) => urls.push(url));
  scanner.write("\x1b]0;https://example.org/title-only\x07");
  scanner.write("\x1b]8;;https://example.org/linked\x1b");
  scanner.write("\\click here\x1b]8;;\x07\n");
  scanner.write("https://example.org/end");
  assert.deepEqual(urls, ["https://example.org/linked"]);
  scanner.finish();
  assert.deepEqual(urls, ["https://example.org/linked", "https://example.org/end"]);
});

test("valid URL punctuation is preserved unless an unmatched prose bracket identifies a wrapper", () => {
  const urls = [];
  const scanner = new TerminalUrlScanner((url) => urls.push(url));
  scanner.write("https://example.org/reset?token=abc! https://example.org. https://example.org/closing)\n");
  scanner.write("(https://example.org/docs).\n");
  scanner.write("\x1b]8;;https://example.org/exact).\x07link\x1b]8;;\x07");
  assert.deepEqual(urls, [
    "https://example.org/reset?token=abc!",
    "https://example.org./",
    "https://example.org/closing)",
    "https://example.org/docs",
    "https://example.org/exact).",
  ]);
});

test("SSH approval identifies only the exact trusted HTTPS origin and auth route", () => {
  assert.ok(isTailscaleAuthUrl("https://login.tailscale.com/a/browser-example"));
  for (const url of [
    "http://login.tailscale.com/a/browser-example",
    "https://login.tailscale.com.evil.example/a/browser-example",
    "https://login.tailscale.com:8443/a/browser-example",
    "https://login.tailscale.com@evil.example/a/browser-example",
    "https://evil.example@login.tailscale.com/a/browser-example",
    "https://login.tailscale.com/docs",
    "javascript:alert(1)",
    "data:text/html,example",
  ]) assert.equal(isTailscaleAuthUrl(url), false, url);
  assert.equal(safeWebUrl("https://user:password@example.org/"), null);
  assert.equal(safeWebUrl("javascript:alert(1)"), null);
});

test("overlong remote tokens are discarded and the next URL still works", () => {
  const urls = [];
  const scanner = new TerminalUrlScanner((url) => urls.push(url));
  scanner.write(`https://example.org/${"x".repeat(6000)}\nhttps://example.org/ok\n`);
  assert.deepEqual(urls, ["https://example.org/ok"]);
});

test("loopback links preserve OAuth URLs and identify HTTP(S) hosts and ports", () => {
  for (const [url, host, port] of [
    ["http://127.0.0.1:53682/auth?state=opaque%2Bvalue", "127.0.0.1", 53682],
    ["https://localhost/callback", "localhost", 443],
    ["http://[::1]:53682/auth", "::1", 53682],
  ]) assert.deepEqual(loopbackDestination(url), { url, host, port });
  for (const url of ["https://localhost.evil/", "http://127.0.0.2:53682/", "https://example.org/", "javascript:localhost", "http://user:password@localhost/"]) {
    assert.equal(loopbackDestination(url), null);
  }
});
