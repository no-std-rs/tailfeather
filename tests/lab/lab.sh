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
#   tests/lab/lab.sh doctor        # what is available, and which checks need it

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
STATE_DIR="${LAB_STATE_DIR:-$REPO_ROOT/.lab}"

CONTAINER=headscale-lab

# podman locally, docker in CI. The two are argument-compatible for everything
# this script does, and GitHub's runners ship docker rather than podman — so
# without this the lab workflow cannot start the very server it exists to
# measure against.
RUNTIME="${CONTAINER_RUNTIME:-podman}"
# Pinned, not `:latest`.
#
# The committed vectors and the conformance expectations describe one specific
# Headscale. `:latest` silently becomes a different server, and the resulting
# failures look like our bugs — the suite would be comparing today's code to
# yesterday's ground truth with nothing saying so. The digest is recorded in
# tests/vectors/versions.json and checked by `lab.sh doctor`.
IMAGE="${HEADSCALE_IMAGE:-docker.io/headscale/headscale:v0.29.3}"
PORT="${LAB_PORT:-8080}"
SERVER_URL="http://127.0.0.1:$PORT"
USER_NAME=conformance

# The reference client runs in userspace-networking mode so it needs no TUN
# device and makes no change to this machine's routing. A reference that
# rearranged the developer's network would not get run.
TS_SOCKET="$STATE_DIR/tailscaled.sock"
TS_STATE="$STATE_DIR/tailscaled.state"
TS_LOG="$STATE_DIR/tailscaled.log"

hs() { "$RUNTIME" exec "$CONTAINER" headscale "$@"; }

# `container exists` is podman-only; `container inspect` works on both.
container_exists() { "$RUNTIME" container inspect "$CONTAINER" >/dev/null 2>&1; }

require_container() {
    if ! container_exists; then
        echo "lab is not running; start it with: $0 up" >&2
        exit 1
    fi
}

cmd_up() {
    mkdir -p "$STATE_DIR/headscale"
    if container_exists; then
        echo "== lab already exists, restarting"
        "$RUNTIME" rm -f "$CONTAINER" >/dev/null
    fi

    echo "== starting headscale on $SERVER_URL"
    # :Z relabels for SELinux, which Fedora enforces on volume mounts.
    "$RUNTIME" run -d --name "$CONTAINER" \
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
        "$RUNTIME" logs "$CONTAINER" 2>&1 | tail -30
        exit 1
    fi

    hs users create "$USER_NAME" >/dev/null 2>&1 || true
    cmd_preauth_key >"$STATE_DIR/preauth.key"
    {
        echo "HEADSCALE_URL=$SERVER_URL"
        echo "HEADSCALE_USER=$USER_NAME"
        echo "HEADSCALE_PREAUTH_KEY=$(cat "$STATE_DIR/preauth.key")"
        echo "HEADSCALE_VERSION=$(hs version 2>/dev/null | awk 'NR==1 {print $NF}')"
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

# What the environment can and cannot measure.
#
# Writes $STATE_DIR/doctor.json, which the conformance suite reads so it can
# print one banner naming what is missing and which checks that disables —
# instead of nineteen separately-worded skips that each look like an isolated
# problem.
#
# Never fails. "Nothing is available" is a valid, reportable answer; exiting
# non-zero here would make it impossible to ask the question from a script that
# has `set -e`.
cmd_doctor() {
    mkdir -p "$STATE_DIR"

    local have_runtime=false have_container=false have_tailscaled=false
    local have_reference=false have_harness=false have_root=false
    local have_tls_front=false
    local headscale_version="" image_digest="" reason=""

    # Every probe below is `|| true`. This function runs under the `set -e` at
    # the top of the file, and `check && flag=true` returns non-zero when the
    # check fails — so a missing tool aborted the whole command. That made
    # `doctor` fail in exactly the degraded environment it exists to describe;
    # it did so on its first CI run, where tailscaled is absent.
    command -v "$RUNTIME" >/dev/null 2>&1 && have_runtime=true || true

    if [[ "$have_runtime" == true ]] && container_exists; then
        if curl -fsS --max-time 3 "$SERVER_URL/health" >/dev/null 2>&1; then
            have_container=true
            # `awk NR==1` rather than `head -1`: under `set -o pipefail`, head
            # exiting after the first of headscale's four output lines gives the
            # writer SIGPIPE and the whole pipeline a non-zero status, which
            # `set -e` then turns into an abort. That is buffering-dependent —
            # it never fired under podman locally and failed on the first docker
            # run in CI — so both assignments are also `|| true`.
            headscale_version="$(hs version 2>/dev/null | awk 'NR==1 {print $3}')" || true
            image_digest="$("$RUNTIME" inspect "$CONTAINER" \
                --format '{{.ImageName}}' 2>/dev/null)" || true
        else
            reason="the container exists but $SERVER_URL/health did not answer"
        fi
    elif [[ "$have_runtime" == true ]]; then
        reason="no $CONTAINER container; run '$0 up'"
    else
        reason="$RUNTIME is not installed"
    fi

    command -v tailscaled >/dev/null 2>&1 && have_tailscaled=true || true
    [[ -S "$TS_SOCKET" ]] && have_reference=true || true
    [[ -x "$REPO_ROOT/harness/target/x86_64-unknown-linux-none/release/harness" ]] &&
        have_harness=true || true
    sudo -n true 2>/dev/null && have_root=true || true

    # The TLS front is separate infrastructure (tests/lab/tls.sh), not part of
    # `lab.sh up`, so it has to be probed rather than assumed from the container.
    curl -fsS --max-time 3 -k "https://127.0.0.1:8443/health" >/dev/null 2>&1 &&
        have_tls_front=true || true

    cat > "$STATE_DIR/doctor.json" <<JSON
{
  "_comment": "Written by tests/lab/lab.sh doctor. The conformance suite reads this to explain, once, why checks are skipped.",
  "headscale": $have_container,
  "headscale_version": "${headscale_version}",
  "headscale_image": "${image_digest}",
  "headscale_reason": "${reason}",
  "tailscaled_installed": $have_tailscaled,
  "reference_client": $have_reference,
  "harness_built": $have_harness,
  "passwordless_sudo": $have_root,
  "tls_front": $have_tls_front
}
JSON

    echo "== lab doctor"
    printf '  %-22s %s\n' "headscale" "$($have_container && echo "yes ($headscale_version)" || echo "no — $reason")"
    printf '  %-22s %s\n' "tailscaled installed" "$($have_tailscaled && echo yes || echo "no — the disco and DERP checks need a reference client")"
    printf '  %-22s %s\n' "reference client" "$($have_reference && echo yes || echo "no — run '$0 reference'")"
    printf '  %-22s %s\n' "harness built" "$($have_harness && echo yes || echo "no — run 'cd harness && cargo build --release'")"
    printf '  %-22s %s\n' "passwordless sudo" "$($have_root && echo yes || echo "no — the exit-node and interop checks need it")"
    printf '  %-22s %s\n' "TLS front" "$($have_tls_front && echo yes || echo "no — run 'tests/lab/tls.sh up'")"
    echo
    echo "  wrote $STATE_DIR/doctor.json"
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
    if container_exists; then
        "$RUNTIME" ps --filter "name=$CONTAINER" --format "{{.Names}} {{.Status}} {{.Image}}"
        curl -sf "$SERVER_URL/health" && echo " health OK" || echo " health FAILED"
        [[ -f "$STATE_DIR/lab.env" ]] && cat "$STATE_DIR/lab.env"
    else
        echo "lab is not running"
    fi
}

cmd_down() {
    cmd_reference_stop
    "$RUNTIME" rm -f "$CONTAINER" >/dev/null 2>&1 || true
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
    doctor) cmd_doctor ;;
    *)
        echo "usage: $0 {up|down|status|preauth-key|reference|reference-stop|nodes|prune|doctor}" >&2
        exit 2
        ;;
esac
