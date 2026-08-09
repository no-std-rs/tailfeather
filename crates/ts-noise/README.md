# ts-noise

The allocation-free transport beneath Tailscale's HTTP/2 control plane, known
upstream as ts2021.

The protocol is a TCP connection carrying an HTTP/1.1 upgrade, a Noise IK
handshake, and then encrypted controlbase records. `ts-noise` implements those
layers; `micro-h2` handles the HTTP/2 inside them.

## What it owns

- `/key?v=…` and ts2021 HTTP upgrade request/response encoding
- the Noise IK handshake authenticated by machine keys
- early payloads sent before the server's HTTP/2 preface
- record framing, encryption, counters, and size checks

The public `CAPABILITY_VERSION` is used in the key request, handshake, and
control messages so those layers cannot advertise different clients.

## API shape

Nothing here opens a socket. The caller writes upgrade requests, feeds the
response into `Handshake`, and receives a `Session`. A session seals and opens
one bounded record at a time in caller-owned buffers. `EarlyReader` separates
the optional early payload from the HTTP/2 bytes that follow.

TLS, TCP buffering, HTTP/2, and reconnection policy remain outside this crate.

## Protocol details that matter

Controlbase record lengths and nonces are big-endian. WireGuard uses a
little-endian nonce, and both conventions produce the same first nonce, so a
mistake appears only on the second encrypted record. The crate makes those
formats separate instead of sharing a tempting generic helper.

## Verification

Constants and known-answer tests come from a captured tailscaled 1.94.2 session
against Headscale v0.29.3. Differential tests compare the Noise handshake with
the independent `snow` implementation.

See the [repository README](../../README.md) for the complete stack.

## License

MIT OR Apache-2.0, at your option.
