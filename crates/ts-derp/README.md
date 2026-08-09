# ts-derp

An allocation-free DERP v2 client core for relaying WireGuard packets when no
direct path exists.

DERP forwards opaque packets by destination node key. The relay cannot decrypt
the WireGuard payload; it only connects nodes that cannot currently reach each
other directly.

## What it handles

- the HTTP/1.1 upgrade to `/derp`
- server-key and client-info handshake frames
- authenticated node identity using NaCl `crypto_box`
- sending and receiving packets addressed by node key
- the preferred-relay notification
- bounded parsing and writing of DERP v2 frames

`Client` represents an established protocol session. Frame parsing remains
separate so a caller can feed bytes from any TCP implementation without this
crate owning a socket or receive buffer.

## Boundaries

The caller provides TCP or TLS, randomness, reconnection, keepalive policy, and
DERP-region selection. This crate does not discover direct routes; `ts-disco`
does that, with `CallMeMaybe` commonly traveling over the relay first.

Frames are capped at 4096 bytes. Oversized input and output buffers fail
explicitly rather than allocating or truncating.

## Verification

Unit tests cover the captured server-key shape, upgrade negotiation, handshake,
frame endianness, size bounds, preferred-relay messages, and packet exchange.
The conformance suite also exercises a real relay path through a reference
client.

See [`ts-disco`](../ts-disco/README.md) for direct-path discovery and the
[repository README](../../README.md) for the complete stack.

## License

MIT OR Apache-2.0, at your option.
