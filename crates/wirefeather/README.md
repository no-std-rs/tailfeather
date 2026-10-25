# wirefeather

The default `fast-curve25519` feature retains precomputed basepoint tables.
Use `default-features = false` to trade key-operation speed for smaller code.
Another dependency enabling the tables re-enables them through Cargo feature
unification.

A sans-io [WireGuard](https://www.wireguard.com) protocol core: `no_std`,
allocation-free, and independent of any socket API.

`Device` never touches a socket, a clock, or a random number generator of its
own. You hand it received datagrams together with the current time and a source
of randomness; it hands back `Action`s describing what to send or deliver. The
same code therefore runs inside an Embassy task on a microcontroller and under
Bazel tests on a laptop.

```rust
use wirefeather::{Action, Device, Instant, Rng};

let mut device: Device<4> = Device::new(static_private_key);
let peer = device.add_peer(peer_public_key, None)?;

match device.handle_udp(&datagram, Instant(now_millis), &mut rng, &mut out)? {
    Action::Send { peer, data } => socket.send_to(data, endpoint_of(peer)),
    Action::Receive { peer, packet } => deliver(peer, packet),
    Action::None => {}
}
# Ok::<(), wirefeather::Error>(())
```

## Scope

Both handshake roles are implemented. Peers begin in responder mode;
`Device::set_initiating` enables active handshakes, retries, and rekeys for a
mesh peer. Current and previous session slots keep packets in flight alive
during a rekey.

Implemented: Noise IKpsk2 initiator and responder handshakes,
ChaCha20-Poly1305 transport, a 1024-packet replay window, passive keepalives,
handshake retries, rekeying, and session expiry.

Not implemented: cookies / `mac2`, roaming policy (the caller owns endpoints),
socket I/O, or anything above IP. A device-wide handshake rate limit protects
the expensive X25519 work after the cheap `mac1` screen.

## Verification

The handshake is checked against the reference implementation, not only against
itself. `scripts/interop-wireguard.sh` in the parent repository stands up a real
kernel WireGuard interface in a network namespace, points it at this crate, and
requires both a completed handshake and a successful in-tunnel ping. Its
`initiator` mode gives the kernel no endpoint, proving that this crate started
the accepted handshake. The in-process tests in `src/tests.rs` drive the same
ladder in CI without root.

One finding worth recording, because it costs an afternoon otherwise: the Noise
construction string is

```text
Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
```

with the cipher spelled `ChaChaPoly`, the short name from the Noise
specification — **not** `ChaCha20Poly1305`, which is how WireGuard's own paper
writes it in prose. The Linux kernel pins it as `static const u8
handshake_name[37]`, and 37 is the length of the short form. Getting this wrong
changes the initial chaining key, and the only symptom is that the first AEAD
tag check fails, a long way from the cause.

## Memory

Every buffer size is a named constant in `budget`, so the cost is auditable and
a host test cannot silently assume space the target does not have. A `Device`
holds `PEERS` peers; each peer costs two sessions of roughly 200 bytes. The
largest single buffer a caller must provide is `MAX_DATAGRAM_LEN` (1312 bytes),
enough for a full 1280-byte inner packet plus header, padding, and tag.

## Dependencies

Only cryptographic primitives and `heapless`, all `no_std`: `x25519-dalek`,
`chacha20poly1305`, `blake2`, `hmac`, `subtle`, `zeroize`. Nothing is
hand-rolled. `#![forbid(unsafe_code)]`.

Randomness is supplied through a local `Rng` trait rather than `rand_core`,
because depending on `rand_core` would pin a particular major version onto every
consumer, and a hardware RNG has nothing else in common with a test generator.

## License

MIT OR Apache-2.0, at your option.


The optional `accelerated-crypto` feature selects ring's fused, CPU-dispatched
ChaCha20-Poly1305 implementation on native little-endian x86_64/AArch64 systems.
Other targets retain the portable RustCrypto provider. Both providers preserve
ciphertext/tag formats and replay behavior; authentication failure clears the
output buffer. `crypto::aead_backend()` reports the configured provider. The
portable provider already uses runtime SIMD detection on x86. The feature is
forwarded by `tailfeather` and `tailfeather-reactor` and is enabled by the hosted
adapter. Differential tests cover both nonce conventions, packet/block boundaries,
AAD, and corrupted tags alongside the protocol conformance tests.
