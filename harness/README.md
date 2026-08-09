# harness

Runs the project's library crates on the development machine with no hardware
and no operating system underneath them.

The target is `x86_64-unknown-linux-none`: the Linux syscall ABI, but no libc,
no `std`, and no allocator. That combination is the whole point. The firmware's
library crates are `no_std` and allocation-free, and the only way to be
confident they *stay* that way — and that they behave identically off the chip —
is to run them somewhere just as bare. A `std` test binary would quietly hide an
accidental dependence on the hosted environment.

```
sudo ../scripts/interop-wireguard.sh harness
```

That stands up a real kernel WireGuard interface in a network namespace, points
it at this binary, and requires a completed handshake and a successful in-tunnel
ping. Running the same script without `harness` does the identical test against
the `std` `responder` example in `wirefeather`; both must pass, because both are the
same `wirefeather`.

## Layout

- `rt.rs` — raw syscalls via inline assembly: socket, bind, sendto, recvfrom,
  poll, clock_gettime, getrandom, write, exit. Also a `Console` and a `println!`
  that need no allocator.
- `inner.rs` — an ICMP echo responder, so the tunnel address answers `ping`.
- `main.rs` — `_start`, argument parsing off the initial stack, and the receive
  loop driving `wirefeather::Device`.

## Two things that will bite anyone extending this

**Build from inside this directory.** Cargo discovers `.cargo/config.toml` from
the working directory, not from `--manifest-path`. Building from the repository
root silently produces an ordinary linux-gnu binary, which then fails to link
because libc supplies its own `_start`.

**The binary must not be position-independent.** The target enables PIE by
default, which assumes something processes relocations before the program runs.
With no libc there is no such startup code, so every absolute address —
including string literals — is wrong, and the process dies before doing any real
work, with an empty log and no clue why. `-C relocation-model=static` in
`.cargo/config.toml` is what avoids this.

## Nightly

This is the only part of the project that needs nightly, and only because
`x86_64-unknown-linux-none` is tier 3 and has no prebuilt `core` to link
against, so `-Z build-std` must compile one. The firmware stays on stable.

## Status

The harness now includes the no-allocation reactor, TCP, atomic file storage,
TLS, ts2021, HTTP/2, registration, streamed netmaps, disco, DERP, and both
WireGuard roles. Netmaps are handed through the public `tailfeather::Node`
transactional lease API before peers are reported. Live results still depend on
the exact lab environment and baseline; a successful bare build alone is not an
interoperability claim.

Currently `inner.rs` duplicates the ICMP echo responder that the firmware also
needs. Once there is a third consumer, or the firmware's copy diverges, it
should move into a small shared crate under `crates/`.
