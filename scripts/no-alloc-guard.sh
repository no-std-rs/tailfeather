#!/usr/bin/env bash
#
# Fails if the no-allocation rule has been broken.
#
# The rule is easy to state and easy to lose: no code in this repository may
# allocate, because the ESP32-C6 has no heap configured and the whole design
# depends on every buffer being accounted for. It is also easy to break by
# accident — one `Vec` in a dependency's default features is enough — and the
# resulting failure is a linker error on the device, long after the commit that
# caused it.
#
# Two mechanisms, because neither alone is sufficient.
#
#   1. A grep over our own sources. Catches the direct mistake.
#   2. Building the harness. This is the real guard: `x86_64-unknown-linux-none`
#      with `build-std = ["core", "compiler_builtins"]` has no `alloc` crate at
#      all, so a dependency that needs one cannot link. It fails at build time
#      rather than on hardware.
#
# `crates/ts-conformance` and the intentionally std-only
# `tailfeather-testkit` are exempt from the source scan.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

STATUS=0

echo "== checking our sources for allocation"
SOURCES=(harness/src firmware/src)
for crate in crates/*/; do
    [[ "$crate" == "crates/ts-conformance/" || "$crate" == "crates/tailfeather-testkit/" ]] && continue
    [[ -d "$crate/src" ]] && SOURCES+=("$crate/src")
done

if HITS="$(grep -rnE '^\s*(extern crate alloc|use alloc::)' "${SOURCES[@]}" 2>/dev/null)"; then
    echo "FAIL: allocation reached our code:"
    echo "$HITS"
    STATUS=1
else
    echo "ok: no 'extern crate alloc' or 'use alloc::' in ${#SOURCES[@]} source trees"
fi

echo
echo "== building the harness for a target with no alloc crate"
if (cd harness && cargo build --release >/dev/null 2>&1); then
    echo "ok: harness links for x86_64-unknown-linux-none"
else
    echo "FAIL: the harness no longer builds — run 'cd harness && cargo build --release'"
    echo "      A dependency that needs 'alloc' cannot link for this target, so this"
    echo "      is where allocation creep surfaces first."
    STATUS=1
fi

echo
if [[ "$STATUS" -eq 0 ]]; then
    echo "PASS: the tree is still allocation-free"
else
    echo "FAIL: see above"
fi
exit "$STATUS"
