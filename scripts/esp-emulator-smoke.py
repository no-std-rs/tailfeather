#!/usr/bin/env python3
"""Boot the real ESP32-C6 image and check Wi-Fi and flash recovery in ESP-EMU."""

import argparse
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.50.0"
SSID = "buildbuddy-ci-placeholder"
SLOTS = (0x370000, 0x371000)
SECTOR_SIZE = 4096


def ipv6_ready(text):
    for address, gateway in re.findall(
            r"IPv6 uplink:\s+(\S+)\s+gateway=Some\(([^)]+)\)", text):
        try:
            source = ipaddress.IPv6Interface(address).ip
            router = ipaddress.IPv6Address(gateway)
        except ValueError:
            continue
        if (not (source.is_unspecified or source.is_loopback or source.is_multicast
                 or source.is_link_local or source.ipv4_mapped is not None)
                and not (router.is_unspecified or router.is_loopback or router.is_multicast
                         or router.ipv4_mapped is not None)):
            return True
    return False


def boot(emulator, elf, image, log, seconds, expected, *, save=False, exit_on=None,
         require_ipv6=False):
    command = [
        str(emulator), "--chip", "esp32c6", "--firmware", str(image),
        "--elf", str(elf), "--wifi-ssid", SSID, "--wifi-password", SSID,
        "--net", "user,restrict=yes", "--console", "usb-jtag",
        "--timeout", f"{seconds}s", "--log-color", "never",
    ]
    if save:
        command.append("--save-state")
    if exit_on:
        command.extend(["--exit-on", exit_on])
    with log.open("w") as output:
        result = subprocess.run(
            command, stdout=output, stderr=subprocess.STDOUT, timeout=seconds + 30
        )
    text = log.read_text(errors="replace")
    missing = [marker for marker in expected if marker not in text]
    if require_ipv6 and not ipv6_ready(text):
        missing.append("non-link-local IPv6 SLAAC address and default gateway")
    failures = [marker for marker in (
        "panicked at", "Guru Meditation", "load partition table error",
        "could not verify both identity state slots", "Exception was unhandled",
    ) if marker in text]
    if result.returncode or missing or failures:
        raise RuntimeError(
            f"{log.name}: exit={result.returncode}, missing={missing}, failures={failures}; "
            f"see {log}"
        )
    print(f"PASS {log.stem}", flush=True)


def require_redundant_state(image):
    flash = image.read_bytes()
    records = [flash[base:base + SECTOR_SIZE] for base in SLOTS]
    if any(len(record) != SECTOR_SIZE or record[:4] != b"TFSL"
           or record[-4:] != b"COMT" for record in records):
        raise RuntimeError("firmware did not commit both persistent-state sectors")
    if records[0] != records[1]:
        raise RuntimeError("persistent-state sectors disagree after first boot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True,
                        help="ESP32-C6 ci_image ELF, built with inert CI settings")
    parser.add_argument("--esp-emu", type=Path, default=shutil.which("esp-emu"))
    parser.add_argument("--espflash", type=Path, default=shutil.which("espflash"))
    parser.add_argument("--logs-dir", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=15,
                        help="maximum emulation time per full boot (default: 15)")
    parser.add_argument("--require-ipv6", action="store_true",
                        help="require a non-link-local IPv6 address and default gateway on every boot")
    args = parser.parse_args()
    if not args.esp_emu or not args.espflash:
        parser.error("esp-emu and espflash must be installed or supplied explicitly")
    if not 5 <= args.seconds <= 60:
        parser.error("--seconds must be between 5 and 60")
    emulator, elf = args.esp_emu.resolve(), args.elf.resolve(strict=True)
    version = subprocess.check_output([str(emulator), "--version"], text=True)
    if version.strip() != f"esp-emu {VERSION}":
        parser.error(f"expected esp-emu {VERSION}, got {version.strip()!r}")
    args.logs_dir.mkdir(parents=True, exist_ok=True)
    # ESP-EMU --save-state mutates its image. Always use disposable copies,
    # and retain logs only: flash contains generated private identity keys.
    with tempfile.TemporaryDirectory(prefix="tailfeather-esp-smoke-") as directory:
        fresh = Path(directory) / "fresh.bin"
        subprocess.run([
            str(args.espflash), "save-image", "--chip", "esp32c6", "--merge",
            "--flash-size", "4mb", "--partition-table", str(ROOT / "firmware/partitions.csv"),
            "--partition-table-offset", "0x8000", "--target-app-partition", "factory",
            "--skip-update-check", str(elf), str(fresh),
        ], check=True)
        if len(fresh.read_bytes()) != 4 * 1024 * 1024:
            raise RuntimeError("expected a merged 4 MiB image")
        persisted = Path(directory) / "persisted.bin"
        shutil.copyfile(fresh, persisted)
        markers = [f"associated with {SSID}", "link_up = true", "DHCP lease:"]
        boot(emulator, elf, persisted, args.logs_dir / "first-boot.log", args.seconds,
             markers + ["state=identity-created reason=first-boot"], save=True,
             require_ipv6=args.require_ipv6)
        require_redundant_state(persisted)
        boot(emulator, elf, persisted, args.logs_dir / "restore.log", args.seconds,
             markers + ["state=identity-restored"],
             exit_on=None if args.require_ipv6 else "state=identity-restored",
             require_ipv6=args.require_ipv6)
        # Model power loss during the very first body write: one partial sector
        # beside an erased sector. The actual flash adapter must recover it.
        torn = Path(directory) / "torn-first-write.bin"
        flash = bytearray(fresh.read_bytes())
        flash[SLOTS[0]] = 0
        torn.write_bytes(flash)
        boot(emulator, elf, torn, args.logs_dir / "torn-first-write.log", args.seconds,
             markers + ["state=identity-created reason=first-boot"], save=True,
             require_ipv6=args.require_ipv6)
        require_redundant_state(torn)
    print("PASS ESP32-C6 firmware boot, Wi-Fi/DHCP, identity restore, and torn-write recovery")
    if args.require_ipv6:
        print("PASS IPv6 SLAAC address and default gateway on all three boots")


if __name__ == "__main__":
    main()
