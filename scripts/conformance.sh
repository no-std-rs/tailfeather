#!/usr/bin/env bash
#
# Run the whole compatibility measurement: bring up the reference
# implementations, capture ground truth from them, and print the matrix.
#
#   scripts/conformance.sh              # use existing vectors, skip re-capture
#   scripts/conformance.sh --capture    # refresh the lab and the vectors first
#
# Re-capturing needs root, for tcpdump and for tailscaled. The matrix itself
# does not, and runs against committed vectors when no lab is up.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPTURE=0
[[ "${1:-}" == "--capture" ]] && CAPTURE=1

cd "$REPO_ROOT"

if [[ "$CAPTURE" -eq 1 ]]; then
    echo "== bringing up the reference implementations"
    tests/lab/lab.sh up
    tests/lab/lab.sh reference
    echo
    echo "== capturing ground truth"
    sudo tests/lab/capture.sh
    echo
fi

# Crash recovery, not routine hygiene.
#
# The suite now tags every node it registers with a per-run id and deletes
# exactly those when it finishes, including when it finishes badly — see
# `crates/ts-conformance/src/runscope.rs`. So this is only here to clear debris
# left by a run that was killed outright, which no destructor can catch.
#
# It matters because the netmap refuses a map naming more peers than a device
# can hold rather than truncating it, so orphaned nodes eventually fail the
# netmap and disco checks for a reason unrelated to the code.
if tests/lab/lab.sh status >/dev/null 2>&1; then
    tests/lab/lab.sh prune || true
    echo
fi

# The suite drives the harness as a subprocess for the checks that must be
# proven in a binary with no libc and no allocator. Cargo discovers
# `.cargo/config.toml` from the working directory, which is what selects the
# bare target, so this cannot be a workspace member and has to be built here.
echo "== building the no_std harness"
(cd harness && cargo build --release)
echo

# Record what this machine can measure. The suite reads .lab/doctor.json and
# prints one banner naming what is missing and which checks it disables, rather
# than repeating the same news inside nineteen separate skip messages.
tests/lab/lab.sh doctor || true
echo

# `--expect` when a baseline for this environment exists.
#
# Gating on the printed score is not enough. A skip is excluded from the
# denominator, so a lab that stopped running reports "14/14 — 100% compatible"
# while twenty checks quietly measure nothing. The baseline names the expected
# status of every check, so that shows up as twenty regressions instead.
#
# Which baseline depends on whether a control server answered.
if [[ -n "${TS_CONTROL_URL:-}" ]]; then
    BASELINE=""      # hosted has no committed baseline yet
elif tests/lab/lab.sh status >/dev/null 2>&1; then
    BASELINE="tests/expectations/lab.json"
else
    BASELINE="tests/expectations/offline.json"
fi

echo "== compatibility matrix"
if [[ -n "$BASELINE" && -f "$BASELINE" ]]; then
    cargo run -q -p ts-conformance --bin conformance -- --expect "$BASELINE"
else
    cargo run -q -p ts-conformance --bin conformance
fi
