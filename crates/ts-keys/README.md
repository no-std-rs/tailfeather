# ts-keys

Typed Tailscale identities, their wire encoding, and allocation-free
persistence.

A node has three X25519 identities with different jobs:

| Key | Role | Wire prefix |
|---|---|---|
| Machine | authenticates the device to the coordination server | `mkey:` |
| Node | WireGuard identity used by peers and DERP | `nodekey:` |
| Disco | authenticates path-discovery messages | `discokey:` |

Separate Rust types prevent a valid key from being used in the wrong protocol.
Private keys zeroize on drop and redact their `Debug` output; public keys parse
and emit the prefix-plus-hex form used on the wire.

## API shape

- `Identity::generate` creates all three keypairs from a caller-provided `Rng`.
- `MachinePublic`, `NodePublic`, and `DiscoPublic` provide typed parsing and
  encoding.
- `Blob` serializes a complete identity into a fixed-size, versioned record.
- `load_or_create` restores that record through a caller-provided `Store`, or
  creates and persists a fresh identity on first boot.

The crate does not choose a secure-storage backend or random-number generator.
Those are platform responsibilities: the ESP32 can use flash and its hardware
RNG, while tests can provide deterministic implementations of the same small
traits.

## Bounds and verification

Identity storage is a fixed `BLOB_LEN`; no variable-size document or collection
is allocated. Tests cover key separation, wire formats, secret redaction,
constant-time equality, corrupted records, and first-boot/reboot behavior.

See the [repository README](../../README.md) for the complete protocol stack.

## License

MIT OR Apache-2.0, at your option.
