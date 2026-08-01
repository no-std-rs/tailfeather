#!/usr/bin/env bash
#
# The conformance lab: a real Headscale and, optionally, a real Tailscale client
# to measure our implementation against.
#
# The whole point is that nothing here is a mock. Every protocol error this
# project has hit so far was caught by disagreeing with a real implementation
# and would have survived any test we wrote against our own understanding — the
# Noise construction string being the expensive example. So the lab runs the
# actual server and the actual client, and the conformance suite compares us to
# them rather than to our own assumptions.
#
#   tests/lab/lab.sh up            # start Headscale, create a user and preauth key
#   tests/lab/lab.sh down          # stop and remove everything
#   tests/lab/lab.sh status
#   tests/lab/lab.sh preauth-key   # mint another key
#   tests/lab/lab.sh reference     # join a real tailscaled to the lab as ground truth
#   tests/lab/lab.sh nodes         # what the server thinks is registered
#   tests/lab/lab.sh prune         # delete the nodes conformance runs left behind

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
STATE_DIR="${LAB_STATE_DIR:-$REPO_ROOT/.lab}"

CONTAINER=headscale-lab
IMAGE="${HEADSCALE_IMAGE:-docker.io/headscale/headscale:latest}"
PORT="${LAB_PORT:-8080}"
SERVER_URL="http://127.0.0.1:$PORT"
USER_NAME=conformance

# The reference client runs in userspace-networking mode so it needs no TUN
# device and makes no change to this machine's routing. A reference that
# rearranged the developer's network would not get run.
TS_SOCKET="$STATE_DIR/tailscaled.sock"
TS_STATE="$STATE_DIR/tailscaled.state"
TS_LOG="$STATE_DIR/tailscaled.log"

hs() { podman exec "$CONTAINER" headscale "$@"; }

require_container() {
    if ! podman container exists "$CONTAINER" 2>/dev/null; then
        echo "lab is not running; start it with: $0 up" >&2
        exit 1
    fi
}

cmd_up() {
    mkdir -p "$STATE_DIR/headscale"
    if podman container exists "$CONTAINER" 2>/dev/null; then
        echo "== lab already exists, restarting"
        podman rm -f "$CONTAINER" >/dev/null
    fi

    echo "== starting headscale on $SERVER_URL"
    # :Z relabels for SELinux, which Fedora enforces on volume mounts.
    podman run -d --name "$CONTAINER" \
        -p "127.0.0.1:$PORT:8080" \
        -p "127.0.0.1:3478:3478/udp" \
        -v "$LAB_DIR/headscale.yaml:/etc/headscale/config.yaml:ro,Z" \
        -v "$STATE_DIR/headscale:/var/lib/headscale:Z" \
        "$IMAGE" serve >/dev/null

    echo -n "== waiting for the API"
    for _ in $(seq 1 60); do
        if curl -sf "$SERVER_URL/health" >/dev/null 2>&1; then
            echo " ready"
            break
        fi
        echo -n "."
        sleep 1
    done
    if ! curl -sf "$SERVER_URL/health" >/dev/null 2>&1; then
        echo " failed"
        podman logs "$CONTAINER" 2>&1 | tail -30
        exit 1
    fi

    hs users create "$USER_NAME" >/dev/null 2>&1 || true
    cmd_preauth_key >"$STATE_DIR/preauth.key"
    {
        echo "HEADSCALE_URL=$SERVER_URL"
        echo "HEADSCALE_USER=$USER_NAME"
        echo "HEADSCALE_PREAUTH_KEY=$(cat "$STATE_DIR/preauth.key")"
        echo "HEADSCALE_VERSION=$(hs version 2>/dev/null | head -1 | awk '{print $NF}')"
    } >"$STATE_DIR/lab.env"

    echo "== lab ready"
    cat "$STATE_DIR/lab.env"
}

cmd_preauth_key() {
    require_container
    local user_id
    user_id="$(hs users list --output json | python3 -c \
        "import json,sys; print(next(u['id'] for u in json.load(sys.stdin) if u['name']=='$USER_NAME'))")"
    hs preauthkeys create --user "$user_id" --reusable --expiration 24h --output json |
        python3 -c "import json,sys; print(json.load(sys.stdin)['key'])"
}

# Crash recovery for nodes the suite could not delete itself.
#
# A conformance run tags its nodes `esp-gateway-<runid>` and removes them when
# it ends, on the failure path too. What it cannot clean up after is being
# killed outright — no destructor runs on SIGKILL — so this deletes anything
# still carrying the `esp-gateway` prefix.
#
# It matters because a netmap naming more peers than a device can hold is
# refused rather than silently truncated, so orphans eventually make the netmap
# and disco checks fail for a reason that has nothing to do with the code.
cmd_prune() {
    require_container
    local ids
    ids="$(hs nodes list --output json 2>/dev/null |
        python3 -c "
import json,sys
for node in json.load(sys.stdin):
    if node.get('name','').startswith('esp-gateway'):
        print(node['id'])
")"
    if [[ -z "$ids" ]]; then
        echo "== no test nodes to prune"
        return
    fi
    local count=0
    for id in $ids; do
        hs nodes delete --identifier "$id" --force >/dev/null 2>&1 && count=$((count + 1))
    done
    echo "== pruned $count test node(s)"
}

cmd_reference() {
    require_container
    # shellcheck disable=SC1090
    source "$STATE_DIR/lab.env"

    if [[ ! -x /usr/sbin/tailscaled && ! -x /usr/bin/tailscaled ]]; then
        echo "tailscaled not found; the reference client is what gives us ground truth" >&2
        exit 1
    fi

    cmd_reference_stop
    echo "== starting reference tailscaled (userspace networking)"
    # TS_DEBUG_MAP makes tailscaled log the decrypted MapResponse. That log is
    # the ground truth our netmap parser is checked against — the wire bytes
    # are inside Noise, so this is the only way to see what the server actually
    # said without reimplementing the very thing under test.
    sudo TS_DEBUG_MAP=1 tailscaled \
        --tun=userspace-networking \
        --socket="$TS_SOCKET" \
        --statedir="$STATE_DIR/ts-state" \
        --port=0 \
        >"$TS_LOG" 2>&1 &
    sleep 3

    echo "== registering it against the lab"
    sudo tailscale --socket="$TS_SOCKET" up \
        --login-server="$HEADSCALE_URL" \
        --authkey="$HEADSCALE_PREAUTH_KEY" \
        --hostname=reference-client \
        --accept-routes=false

    echo "== reference client is up"
    sudo tailscale --socket="$TS_SOCKET" status || true
}

cmd_reference_stop() {
    sudo pkill -f "tailscaled --tun=userspace-networking --socket=$TS_SOCKET" 2>/dev/null || true
    rm -f "$TS_SOCKET"
}

cmd_nodes() {
    require_container
    hs nodes list
}

cmd_status() {
    if podman container exists "$CONTAINER" 2>/dev/null; then
        podman ps --filter "name=$CONTAINER" --format "{{.Names}} {{.Status}} {{.Image}}"
        curl -sf "$SERVER_URL/health" && echo " health OK" || echo " health FAILED"
        [[ -f "$STATE_DIR/lab.env" ]] && cat "$STATE_DIR/lab.env"
    else
        echo "lab is not running"
    fi
}

cmd_down() {
    cmd_reference_stop
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo "== lab stopped (state kept in $STATE_DIR; delete it to start clean)"
}

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down ;;
    status) cmd_status ;;
    preauth-key) cmd_preauth_key ;;
    reference) cmd_reference ;;
    reference-stop) cmd_reference_stop ;;
    nodes) cmd_nodes ;;
    prune) cmd_prune ;;
    *)
        echo "usage: $0 {up|down|status|preauth-key|reference|reference-stop|nodes|prune}" >&2
        exit 2
        ;;
esac
