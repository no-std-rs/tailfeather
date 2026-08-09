# ts-control

Allocation-free request and response types for the Tailscale control plane.

`ts-noise` creates an authenticated channel and `micro-h2` carries HTTP. This
crate defines what a node says over that channel:

- `RegisterRequest` and `RegisterResponse` for joining a tailnet
- `Hostinfo`, including exit-node route advertisement
- `MapRequest` for starting the streaming network map
- a bounded JSON `Writer` that escapes untrusted strings

Every encoder writes into a caller-owned buffer and reports overflow instead of
allocating or truncating.

## Boundaries

This crate does not perform I/O, run HTTP/2, manage a Noise session, or parse a
netmap. It produces and consumes the small control messages around those layers;
`ts-netmap` owns the long-lived stream of map responses.

`CAPABILITY_VERSION` is re-exported from `ts-noise`, keeping the version in the
Noise prologue and JSON bodies identical.

## Compression

`MapRequest` deliberately omits `Compress`. The pinned Headscale lab responds
with plain JSON when compression is not requested, which preserves the
no-allocation design. Whether hosted Tailscale accepts the same request remains
an explicit compatibility question.

## Verification

Tests round-trip generated documents through a real JSON parser, exercise
hostile strings and undersized buffers, and compare control messages with
captured server behavior through `ts-conformance`.

See the [repository README](../../README.md) for the complete stack.

## License

MIT OR Apache-2.0, at your option.
