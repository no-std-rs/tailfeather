# no-libc harness

Build with:

```sh
bazel build //harness:harness
bazel test //:harness_elf_contract
```

The Bazel target uses supported `x86_64-unknown-linux-gnu` compiler artifacts
while retaining `#![no_std]`, `_start`, panic-abort, static relocation, no
startup files, and no default libraries. Small C-ABI memory and abort-only EH
shims are provided in-tree; no libc, allocator, interpreter, or dynamic
dependency reaches the ELF. The artifact contract checks those properties with
`readelf` and `nm`.

The harness contains the no-allocation reactor, TCP, atomic storage, TLS,
ts2021, HTTP/2, registration, streamed netmaps, disco, DERP, and both
WireGuard roles. Conformance tools receive it through the
`TS_CONFORMANCE_HARNESS` Bazel runfile rather than a target-directory path.

Kernel interoperability takes an explicit mode and responder runfile:

```sh
sudo scripts/interop-wireguard.sh harness-responder bazel-bin/harness/harness
sudo scripts/interop-wireguard.sh harness-initiator bazel-bin/harness/harness
sudo scripts/interop-wireguard.sh harness-rekey bazel-bin/harness/harness
sudo scripts/nostd-interop.sh bazel-bin/harness/harness
```
