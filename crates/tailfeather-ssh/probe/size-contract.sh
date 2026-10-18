#!/usr/bin/env bash
set -euo pipefail

ELF="$1"
SIZE="$4"
bash "$5" "$ELF" "$2" "$3"
SECTIONS="$("$SIZE" "$ELF")"
read -r TEXT DATA BSS < <(awk 'NR == 2 { print $1, $2, $3 }' <<<"$SECTIONS")
if (( TEXT + DATA > 128 * 1024 )); then
    echo "SSH code budget exceeded: text=$TEXT data=$DATA (build with --config=optimized)" >&2
    exit 1
fi
echo "PASS: no_std SSH code/data=$((TEXT + DATA)) bytes, BSS=$BSS bytes (128 KiB budget)"
