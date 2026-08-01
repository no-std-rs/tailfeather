#!/usr/bin/env bash
#
# Capture ground truth from the reference implementations into tests/vectors/.
#
# The control protocol runs inside Noise, so a packet capture alone shows only
# opaque frames. The decrypted view comes from the reference client itself:
# TS_DEBUG_MAP makes tailscaled log the MapResponse it received in cleartext.
# Between the two we get both what went over the wire and what it meant, which
# is what a parser needs to be tested against.
#
# These vectors are committed. They are what lets the conformance suite check
# our decoders without needing a live lab on every run, and they pin the exact
# server and client versions the expectations came from.
#
#   sudo tests/lab/capture.sh

set -euo pipefail

RUNTIME="${CONTAINER_RUNTIME:-podman}"

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
STATE_DIR="${LAB_STATE_DIR:-$REPO_ROOT/.lab}"
VECTORS="$REPO_ROOT/tests/vectors"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0 (tcpdump and tailscaled's log both need it)" >&2
    exit 1
fi
if [[ ! -f "$STATE_DIR/lab.env" ]]; then
    echo "lab is not running; start it with tests/lab/lab.sh up" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$STATE_DIR/lab.env"

# "$RUNTIME" here is rootless, so anything touching the container must run as the
# invoking user; tcpdump and tailscaled need root. This script needs both, so
# it runs as root and drops back down for the container calls.
as_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" \
            XDG_RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")" \
            "$@"
    else
        "$@"
    fi
}

mkdir -p "$VECTORS"

echo "== recording versions"
TS_VERSION="$(tailscale version | head -1)"
cat >"$VECTORS/versions.json" <<EOF
{
  "headscale": "$HEADSCALE_VERSION",
  "tailscale_client": "$TS_VERSION",
  "captured_by": "tests/lab/capture.sh",
  "note": "Expectations in the conformance suite are pinned to these versions. Re-capture after upgrading either one."
}
EOF

echo "== probing the accepted capability version range"
as_user python3 "$LAB_DIR/probe_capver.py" "$HEADSCALE_URL" "$VECTORS/server_key.json"

echo "== capturing the ts2021 session on the wire"
PCAP="$VECTORS/ts2021-session.pcap"
timeout 45 tcpdump -i lo -n -s 0 -w "$PCAP" "tcp port 8080" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "== re-registering the reference client so the capture sees a full session"
pkill -f "tailscaled --tun=userspace-networking --socket=$STATE_DIR/tailscaled.sock" 2>/dev/null || true
rm -f "$STATE_DIR/tailscaled.sock"
rm -rf "$STATE_DIR/ts-state"
NEW_KEY="$(as_user "$LAB_DIR/lab.sh" preauth-key)"

TS_SOCKET="$STATE_DIR/tailscaled.sock"
TS_DEBUG_MAP=1 tailscaled \
    --tun=userspace-networking \
    --socket="$TS_SOCKET" \
    --statedir="$STATE_DIR/ts-state" \
    --port=0 \
    >"$STATE_DIR/tailscaled.log" 2>&1 &
sleep 3
tailscale --socket="$TS_SOCKET" up \
    --login-server="$HEADSCALE_URL" \
    --authkey="$NEW_KEY" \
    --hostname=reference-client \
    --accept-routes=false
sleep 5

kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "== extracting the decrypted MapResponse"
python3 "$LAB_DIR/extract_map.py" "$STATE_DIR/tailscaled.log" "$VECTORS/map_response.json"

echo "== recording what the server believes"
as_user "$RUNTIME" exec headscale-lab headscale nodes list --output json >"$VECTORS/headscale_nodes.json" 2>/dev/null || true
curl -s "$HEADSCALE_URL/health" >"$VECTORS/health.json" || true

# The captures are written as root; hand them back so ordinary builds can read
# and rewrite them.
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER" "$VECTORS"
fi

echo
echo "== vectors:"
ls -la "$VECTORS"
