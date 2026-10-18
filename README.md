# tailfeather

Allocation-free Rust for a small Tailscale-compatible mesh node, an ESP32-C6
IPv4 exit gateway, and a static no-libc Linux interoperability harness.

This is experimental protocol and embedded-systems software. It is not audited
and is not a general-purpose Tailscale client.

Try the [browser SSH client](https://no-std-rs.github.io/tailfeather/), or see
[`web/README.md`](web/README.md) to build and host it yourself.

## Build and test

Bazel 9.2.0 is selected by `.bazelversion`; Bzlmod pins Rust 1.95.0, LLVM
0.8.16, `rules_python` 2.2.0, and `rules_rs` 0.0.102. Cargo manifests and
lockfiles describe dependency closures only. Builds and tests never launch
Cargo.

```sh
bb login
bazel test //:format //:unit_tests
bazel test //:artifact_contract_tests --config=optimized
bazel build //:clippy //:docs //harness:harness //firmware:ci_image --config=optimized
bazel test //:offline_conformance --test_output=all
```

Ordinary actions use BuildBuddy Cloud RBE, the remote cache, and BES by default.
They retain a local execution branch when the remote executor is unavailable.
Use `--config=local` for deliberately local, cache-isolated work.

The stable root targets are `//:format`, `//:clippy`, `//:docs`,
`//:unit_tests`, `//:artifact_contract_tests`, `//:offline_conformance`, and
`//:privileged_lab`. The principal artifacts are `//harness:harness` and
`//firmware:ci_image`.

## Privileged lab

`bazel test //:privileged_lab` is routed only to the `linux-amd64-kvm`
BuildBuddy pool. It is uncached and has no local fallback. The test boots one
disposable 4-vCPU/2-GiB smolVM guest from checksum-pinned smolVM 1.7.4 and
Alpine 3.21.7 inputs, installs an offline checksum-pinned APK overlay, starts
Headscale 0.29.3 and Tailscale 1.94.2 with a real TUN device, enforces the full
lab baseline, and runs all three kernel WireGuard modes. Missing KVM, TUN,
namespace, veth, or kernel WireGuard support is a hard failure.

## Firmware device workflow

`//firmware:ci_image` receives harmless placeholders and can run on RBE. Real
credentials belong only in the gitignored `.env` file. Build and flash locally:

```sh
bazel run //firmware:flash --config=device
```

The device configuration disables the remote executor, cache, uploads, and BES
before credentials enter the Rust action environment. See
[`firmware/README.md`](firmware/README.md).

## Components

- `tailfeather`: bounded node, control, netmap, disco, DERP, keys, and state.
- `tailfeather-gateway`: allocation-free IPv4 routing and fixed-capacity NAT.
- `tailfeather-ssh`: small allocation-free SSH console with bounded Tailscale
  accept-policy enforcement; see [`crates/tailfeather-ssh/README.md`](crates/tailfeather-ssh/README.md).
- `wirefeather`: allocation-free WireGuard-compatible handshake and transport.
- `tailfeather-testkit`: std-only offline fixture and baseline checks.
- `ts-conformance`: offline and live compatibility measurement.
- `harness`: static `_start` executable using Linux syscalls without libc.
- `firmware`: ESP32-C6 application for `riscv32imac-unknown-none-elf`.
- `web`: a browser Tailscale node with an SSH terminal, built on tailfeather
  compiled to WebAssembly (its own Cargo workspace; see
  [`web/README.md`](web/README.md)).

HTTP/2 and HPACK come from the published
[`micro-h2`](https://github.com/no-std-rs/micro-h2) crate, pinned to `0.2.0`
in each Cargo workspace. Wirefeather remains part of this repository.

Runnerless releases `wirefeather`, `tailfeather`, and `tailfeather-gateway`
independently, with a version file and changelog in each crate. Testkit,
conformance tools, and the applications stay internal. See
[`docs/releases.md`](docs/releases.md) for the release PRs and publishing flow.

The [normal web URL](https://no-std-rs.github.io/tailfeather/) follows stable
Tailfeather releases; the [main preview](https://no-std-rs.github.io/tailfeather/main/)
and [`tailfeather-main` prerelease](https://github.com/no-std-rs/tailfeather/releases/tag/tailfeather-main)
follow tested main builds and Tailfeather release PRs.

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
