#!/usr/bin/env bash
set -euo pipefail

ELF="$1"
SOURCE="$2"
READELF="$3"
SIZE_TOOL="$4"
RAM_BASELINE=296176
# Headroom over the image as built, not a round number: the previous limit was
# 0x300000 because that *was* the whole factory partition, so the check and the
# flash geometry were the same fact written twice and the image had already
# outgrown both. firmware/partitions.csv now gives factory 0x360000 (3,538,944)
# on the 8 MB part, and this sits 5% above the current image inside it -- so a
# failure here means the image grew, with room left to land the fix, rather than
# meaning it will not flash.
IMAGE_LIMIT=3499303
# .stack is whatever RAM is left after .data/.bss, so static growth silently
# eats stack headroom. Assert a floor so a regression fails CI instead of
# panicking mid-TLS-handshake on device: the control path peaks around 128 KiB,
# and 80bfa07 grew .bss until the 126,864-byte stack overflowed by 1,264 bytes.
STACK_FLOOR=129024
# The radio heap and .stack share one pool that must end at 0x4087e610 -- the
# 6,640 bytes above that are ROM scratch that ROM flash code reuses at runtime
# -- so stack headroom is bought 1:1 from the heap. Take only what the control
# path needs: at 58,896 the 10 MB benchmark could not finish inside 90 s, and at
# 52,240 esp-radio fails to start at all.
# Retaining the explicit DERP InsecureForTests bit and both delayed-self route
# approvals crosses the next 16-byte RAM alignment boundary. Shift that block
# from the 61.2 KiB radio arena into main RAM while preserving the measured
# 129 KiB control-TLS stack floor.
RADIO_HEAP=61184
# RTC-fast is the ESP32-C6's 16 KiB LP SRAM and cannot be grown -- that is the
# silicon. It holds the staged netmap, which grows whenever the netmap parser
# learns a new field, and it was already within a few hundred bytes of full.
# Adding DNSConfig grew it by 532 and the only symptom was three identical
# 'will not fit in region RTC_FAST' linker errors, which name no symbol and
# point at no commit. Fail here instead, while there is still room to decide
# whether the new field belongs in retained memory at all.
RTC_LIMIT=16128
test -f "$ELF" || { echo "missing firmware ELF: $ELF" >&2; exit 1; }
test -x "$READELF" || { echo "missing LLVM readelf: $READELF" >&2; exit 1; }
test -x "$SIZE_TOOL" || { echo "missing LLVM size: $SIZE_TOOL" >&2; exit 1; }

SECTIONS="$("$READELF" -SW "$ELF" | sed -E 's/^ *\[[[:space:]]*([0-9]+)\]/[\1]/')"
section_size() {
    local name="$1" hex
    hex="$(awk -v name="$name" '$2 == name { print $6; exit }' <<<"$SECTIONS")"
    test -n "$hex" || { echo "missing ELF section $name" >&2; return 1; }
    printf '%d\n' "$((16#$hex))"
}

data="$(section_size .data)"
wifi_data="$(section_size .data.wifi)"
bss="$(section_size .bss)"
rtc_data="$(section_size .rtc_fast.data)"
rtc_bss="$(section_size .rtc_fast.bss)"
rtc_persistent="$(section_size .rtc_fast.persistent)"
radio_heap="$(section_size .dram2_uninit)"
stack="$(section_size .stack)"
main_ram=$((data + wifi_data + bss))
rtc_ram=$((rtc_data + rtc_bss + rtc_persistent))
ram=$((main_ram + rtc_ram))
image=0
while read -r file_size; do
    file_size="${file_size#0x}"
    image=$((image + 16#$file_size))
done < <("$READELF" -lW "$ELF" | awk '$1 == "LOAD" { print $5 }')
(( ram <= RAM_BASELINE )) || { echo "application RAM $ram exceeds $RAM_BASELINE" >&2; exit 1; }
(( image > 0 && image <= IMAGE_LIMIT )) || { echo "image $image exceeds $IMAGE_LIMIT" >&2; exit 1; }
grep -Eq "heap_allocator!.*size: $RADIO_HEAP" "$SOURCE" || { echo "radio heap source limit changed" >&2; exit 1; }
(( radio_heap == RADIO_HEAP )) || { echo "linked radio heap is not $RADIO_HEAP" >&2; exit 1; }
(( stack >= STACK_FLOOR )) || { echo "stack headroom $stack is below $STACK_FLOOR" >&2; exit 1; }
(( rtc_ram <= RTC_LIMIT )) || { echo "RTC-fast use $rtc_ram exceeds $RTC_LIMIT of the 16384-byte bank" >&2; exit 1; }

immutable_assets=(ISRG_ROOT_X2_BYTES ISRG_ROOT_YR_BYTES ROOT_YR_MODULUS_LIMBS ROOT_YR_R2_LIMBS TABLES)
rodata_sections="$(awk '$2 ~ /^\.rodata/ { section = $1; gsub(/\[|\]/, "", section); print section }' <<<"$SECTIONS")"
symbols="$("$READELF" -sW "$ELF")"
for asset in "${immutable_assets[@]}"; do
    matches="$(awk -v asset="$asset" 'index($NF, asset) { print $2, $4, $7, $NF }' <<<"$symbols")"
    test -n "$matches" || { echo "immutable asset absent: $asset" >&2; exit 1; }
    while read -r address type section symbol; do
        if [[ "$type" != OBJECT ]] || [[ "$address" != 42* ]] || ! grep -qx "$section" <<<"$rodata_sections"; then
            echo "immutable asset is not in flash rodata: $symbol type=$type address=0x$address section=$section" >&2
            exit 1
        fi
    done <<<"$matches"
done
echo "PASS: RAM=$ram image=$image stack=$stack radio_heap=$radio_heap rtc=$rtc_ram/$RTC_LIMIT immutable_assets=${#immutable_assets[@]}"
