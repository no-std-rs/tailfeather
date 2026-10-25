# ESP32-C6 firmware

The CI artifact is built through a Bazel platform transition for
`riscv32imac-unknown-none-elf`:

```sh
bazel build //firmware:ci_image --config=optimized
```

CI uses non-secret placeholders. To build and flash a device, copy
`.env.example` to the gitignored `.env`, fill every value, install `espflash`,
then run:

```sh
bazel run //firmware:flash --config=device
```

`--config=device` composes optimized and fully local settings. It disables BES,
remote execution, remote caching, cache acceptance, and uploads before `.env`
is read. Never pass real device values to an ordinary remote invocation.

For a private Headscale/DERP PKI, set `TS_CONTROL_CA_DER` in `.env` to a
DER-encoded CA certificate. The local flash script validates it and embeds it
as the optional pinned root used by firmware TLS verification.

The first-party Cargo build script and directory-local toolchain configuration
have been replaced by Bazel linker flags, action environment, and the hermetic
Rust toolchain. Third-party generated build scripts remain in the Bazel graph.


The Wi-Fi uplink uses DHCPv4 and IPv6 SLAAC. IPv6 exit forwarding requires a
SLAAC address and IPv6 default gateway; `ipv6-exit-capable=true` and the selected
uplink configuration appear in the serial log. Only that capability advertises
`::/0`. A capability change restarts control bootstrap to refresh the advertised
routes. IPv4-only networks advertise only `0.0.0.0/0`; Tailscale clients that
require both default routes may therefore not offer this node as an exit.

IPv6 forwarding uses the shared bounded gateway core for UDP, TCP and ICMPv6
echo, with exact peer address ownership and control-plane ACL checks. See the
[gateway limits](../crates/tailfeather-gateway/README.md) for unsupported packet
forms. An IPv4 underlay can carry IPv6 inner packets; direct IPv6 underlay
endpoint discovery is separate from this feature.
