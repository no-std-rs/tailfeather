#!/usr/bin/env bash
# Feed deterministic malformed services to the allocation-free harness. A
# clean rejection is success; acceptance, hanging, or crashing the runner is
# not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="${HARNESS_BIN:-$ROOT/harness/target/x86_64-unknown-linux-none/release/harness}"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[[ -x "$HARNESS" ]] || { echo "build the no_std harness first" >&2; exit 2; }

expect_rejection() {
    local mode="$1" port="$2" event="$3"
    shift 3
    local server_log="$WORK/$mode.server.log"
    python3 "$ROOT/tests/adversarial/service.py" --mode "$mode" --host 127.0.0.1 --port "$port" >"$server_log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        grep -q 'listening on' "$server_log" && break
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "FAIL: adversarial service for $mode exited before becoming ready" >&2
            cat "$server_log" >&2
            exit 1
        fi
        sleep 0.1
    done
    if ! grep -q 'listening on' "$server_log"; then
        echo "FAIL: adversarial service for $mode did not become ready" >&2
        cat "$server_log" >&2
        exit 1
    fi
    set +e
    timeout --foreground 8 "$HARNESS" "$@" >"$WORK/$mode.log" 2>&1
    local status=$?
    set -e
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    if [[ $status -ne 1 ]]; then
        echo "FAIL: $mode did not produce the harness rejection exit code 1 (status $status)" >&2
        cat "$WORK/$mode.log" >&2
        exit 1
    fi
    if ! grep -Fq "\"event\":\"$event\",\"result\":\"fail\"" "$WORK/$mode.log"; then
        echo "FAIL: $mode did not emit a structured $event rejection" >&2
        cat "$WORK/$mode.log" >&2
        exit 1
    fi
    echo "PASS: bare harness rejected $mode"
}

expect_tls_rejection() {
    local label="$1" port="$2" server_name="$3" trust="$4" trusted_time="$5"
    local server_log="$WORK/$label.server.log"
    local certificate="$WORK/$label.der"
    python3 "$ROOT/tests/adversarial/service.py" --mode tls-wrong-name \
        --host 127.0.0.1 --port "$port" --certificate-out "$certificate" \
        >"$server_log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        grep -q 'listening on' "$server_log" && break
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "FAIL: TLS service for $label exited before becoming ready" >&2
            cat "$server_log" >&2
            exit 1
        fi
        sleep 0.1
    done
    if ! grep -q 'listening on' "$server_log"; then
        echo "FAIL: TLS service for $label did not become ready" >&2
        cat "$server_log" >&2
        exit 1
    fi
    [[ $trust == self ]] && trust="$certificate"

    local command=("$HARNESS" tls 127.0.0.1 "$port" "$server_name" "$trust")
    [[ -n $trusted_time ]] && command+=("$trusted_time")
    set +e
    timeout --foreground 8 "${command[@]}" >"$WORK/$label.log" 2>&1
    local status=$?
    set -e
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    if [[ $status -ne 1 ]] \
        || ! grep -Fq '"event":"tls","result":"fail"' "$WORK/$label.log" \
        || grep -Fq '"event":"handshake","verified":true' "$WORK/$label.log"; then
        echo "FAIL: TLS case $label was not rejected by the harness" >&2
        cat "$WORK/$label.log" >&2
        exit 1
    fi
    echo "PASS: bare harness rejected $label"
}

expect_rejection malformed-noise 18441 ts2021 ts2021 "$WORK/noise" 127.0.0.1 18441
expect_rejection malformed-h2 18442 ts2021 ts2021 "$WORK/h2" 127.0.0.1 18442
expect_rejection malformed-control 18443 map map "$WORK/control" 127.0.0.1 18443
expect_rejection map33 18446 map map-bound 127.0.0.1 18446
expect_rejection malformed-derp 18444 derp derp 127.0.0.1 18444 "$WORK/derp-a" "$WORK/derp-b"
expect_rejection disconnect 18445 ts2021 ts2021 "$WORK/disconnect" 127.0.0.1 18445
expect_tls_rejection tls-wrong-name 18447 right.invalid self ""
expect_tls_rejection tls-untrusted 18448 wrong.invalid "$WORK/tls-wrong-name.der" ""
expect_tls_rejection tls-invalid-time 18449 wrong.invalid self 0

echo "PASS: adversarial modes were routed through the no_std harness"
