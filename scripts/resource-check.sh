#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ELF="$ROOT/firmware/target/riscv32imac-unknown-none-elf/release/esp-gateway-firmware"

# Compile-time tests enforce Node<32> <= 64 KiB and Netmap<32> <= 32 KiB.
cargo test --manifest-path "$ROOT/crates/tailfeather/Cargo.toml" node::tests::default_node_fits_device_budget

[[ -f "$ELF" ]] || { echo "FAIL: build firmware release first: $ELF"; exit 1; }
SIZE_TOOL=""
for candidate in riscv32-unknown-elf-size llvm-size /usr/bin/size rust-size; do
    if command -v "$candidate" >/dev/null 2>&1; then SIZE_TOOL="$candidate"; break; fi
done
[[ -n "$SIZE_TOOL" ]] || { echo "FAIL: no ELF size tool found"; exit 1; }

read -r text aggregate_data _ _ < <("$SIZE_TOOL" "$ELF" | awk 'NR==2 {print $1, $2, $3, $4}')
[[ "$aggregate_data" =~ ^[0-9]+$ ]] || { echo "FAIL: could not parse $SIZE_TOOL output"; exit 1; }
section_hex() {
    readelf -SW "$ELF" | sed -nE "s/^ *\[[ 0-9]+\] $1 +[^ ]+ +[^ ]+ +[^ ]+ +([0-9a-fA-F]+).*/\1/p"
}
data_hex="$(section_hex '\.data')"
wifi_data_hex="$(section_hex '\.data\.wifi')"
bss_hex="$(section_hex '\.bss')"
radio_heap_hex="$(section_hex '\.dram2_uninit')"
[[ -n "$data_hex" && -n "$wifi_data_hex" && -n "$bss_hex" ]] || {
    echo "FAIL: could not read exact data/bss sections"; exit 1
}
data=$((16#$data_hex + 16#$wifi_data_hex))
bss=$((16#$bss_hex))
ram=$((data + bss))
image=$((text + data))
(( ram <= 204800 )) || { echo "FAIL: .data + .bss is $ram bytes (limit 204800)"; exit 1; }
(( image <= 1572864 )) || { echo "FAIL: loadable image is $image bytes (limit 1572864)"; exit 1; }
grep -Eq 'heap_allocator!.*size: 65536' "$ROOT/firmware/src/main.rs" || {
    echo "FAIL: radio-only heap is not pinned to 65536 bytes"; exit 1;
}
(( 16#$radio_heap_hex == 65536 )) || {
    echo "FAIL: linked radio heap is not 65536 bytes"; exit 1;
}
echo "PASS: RAM=$ram bytes; loadable image=$image bytes; radio heap=65536 bytes"
echo "NOTE: >=25% task-stack headroom remains a physical-suite evidence gate"
