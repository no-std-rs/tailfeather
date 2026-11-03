#!/usr/bin/env bash
set -euo pipefail

ROOT="${BUILD_WORKSPACE_DIRECTORY:-$PWD}"
IMPORT='^[[:space:]]*(extern crate alloc|use alloc::)'

# Device code never imports alloc.
if grep -RInE "$IMPORT" "$ROOT/harness/src" "$ROOT/firmware/src"; then
    echo "allocation reached harness or firmware code" >&2
    exit 1
fi

# Portable crates may, but only behind their opt-in `alloc` feature, so a
# default (firmware) build of them stays allocation-free.
ungated=$(find "$ROOT/crates/tailfeather/src" "$ROOT/crates/tailfeather-ssh/src" \
    "$ROOT/crates/tailfeather-ssh/probe/src" "$ROOT/crates/wirefeather/src" \
    -name '*.rs' -print0 | xargs -0 awk -v import="$IMPORT" '
        FNR == 1 { previous = "" }
        $0 ~ import && previous !~ /^[[:space:]]*#\[cfg\(feature = "alloc"\)\][[:space:]]*$/ {
            print FILENAME ":" FNR ":" $0
        }
        { previous = $0 }
    ')
if [[ -n "$ungated" ]]; then
    echo "$ungated"
    echo "allocation reached portable code outside the alloc feature" >&2
    exit 1
fi
echo "PASS: device sources do not import alloc; portable sources only behind the alloc feature"
