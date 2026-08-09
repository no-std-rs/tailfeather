# ts-disco

Tailscale's encrypted path-discovery messages for finding a direct UDP route to
a peer.

Disco probes candidate addresses learned from the network map. Pings and pongs
reveal which address currently reaches the peer; `CallMeMaybe` shares candidates
through DERP when no direct path exists yet.

## Shared-socket design

Disco and WireGuard use the same UDP socket because a NAT mapping is specific
to a port. `is_disco` recognizes the `TS💬` prefix so a caller can demultiplex
the two protocols before parsing either one.

Messages use NaCl `crypto_box` with the sender's disco identity. `seal` writes a
complete datagram into a caller-owned buffer; `open` authenticates it and
returns the verified sender plus the plaintext length for `Message::decode`.

## Boundaries

This crate owns message encoding, encryption, and the wire limits for pings,
pongs, and candidate lists. The caller owns timers, endpoint ranking, socket
I/O, and the decision to replace a WireGuard endpoint after a successful probe.

The implementation is `no_std`, allocation-free, and capped at `MAX_PACKET`.
Tests compare sealed packets with libsodium-compatible output and cover
tampering, wrong recipients, address forms, padding, and malformed messages.

See [`ts-derp`](../ts-derp/README.md) for the relay path and the
[repository README](../../README.md) for the complete stack.

## License

MIT OR Apache-2.0, at your option.
