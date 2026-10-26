# ESP32-C6 firmware emulation

The `ESP32-C6 emulator` workflow boots the production Rust firmware in
[Espressif ESP-EMU](https://github.com/espressif/esp-emulator), using inert CI
provisioning. It checks Wi-Fi association, DHCP, IPv6 SLAAC and a default
gateway, first-boot identity persistence,
restoration after reboot, and recovery from an interrupted initial record write.
These checks execute the real ROM, bootloader, `esp-hal`, `esp-radio`, Embassy
tasks, and flash adapter. They require neither a board nor KVM/TUN privileges.

ESP-EMU 0.50.0 and espflash 4.4.0 release assets are pinned by SHA-256 in the
workflow. Install those versions locally and run:

```sh
bazel build --noannounce_rc --config=local --config=optimized //firmware:ci_image
python3 scripts/esp-emulator-smoke.py \
  --elf bazel-bin/firmware/esp_gateway_firmware \
  --require-ipv6 \
  --logs-dir /tmp/tailfeather-emulator-logs
```

Use `--esp-emu /path/to/esp-emu` and `--espflash /path/to/espflash` when the tools
are outside `PATH`. The image converter explicitly places the partition table
at `0x8000`, matching the embedded bootloader. Temporary flash images are
discarded after the test; only console logs are retained. The original ELF is
never modified and no physical serial device is opened.

CI requires a parsed non-link-local IPv6 address and a configured default
gateway on all three boots. Link-local traffic alone cannot satisfy this gate.
Restore runs wait for SLAAC rather than exiting at the identity-restored marker.

The emulator supplies a WPA2/WPA3 access point matching the CI Wi-Fi settings.
Its restricted user-mode network permits DHCP and DNS but blocks other outbound
connections. No real Tailscale authentication key or Wi-Fi password is needed.
Do not build this smoke test with device provisioning.

This suite checks firmware boot, persistence, and IPv6 configuration. It does not establish real
radio behavior, physical flash endurance, or end-to-end IPv6 exit forwarding.
Use the namespace interoperability suite for packet forwarding and hardware
acceptance for behavior specific to the physical board.
