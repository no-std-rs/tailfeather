#!/usr/bin/env bash
set -euo pipefail

ROOT="${BUILD_WORKSPACE_DIRECTORY:-$PWD}"
if grep -RInE '^[[:space:]]*(extern crate alloc|use alloc::)' \
    "$ROOT/harness/src" "$ROOT/firmware/src" \
    "$ROOT/crates/micro-h2/src" "$ROOT/crates/tailfeather/src" "$ROOT/crates/wirefeather/src"; then
    echo "allocation reached portable, harness, or firmware code" >&2
    exit 1
fi
echo "PASS: first-party portable/device sources do not import alloc"
