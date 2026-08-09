#!/usr/bin/env bash
#
# Milestone M2, verified against the reference implementation.
#
# Stands up a real kernel WireGuard interface inside a network namespace and
# points it at the `responder` example, which runs our `wirefeather` on the host.
# The kernel initiates, our code responds, and an in-tunnel ping proves the
# whole path: handshake, transport keys, replay window, and encapsulation.
#
# A namespace is used so the test cannot disturb the machine's own routing, and
# so `AllowedIPs` can later widen to 0.0.0.0/0 for the M3 NAT work without
# cutting the developer's connectivity.
#
# Requires root (network namespaces and WireGuard interfaces both do).
#
# Three modes. The first two are responders, and must behave identically
# because both are the same `wirefeather`. The third reverses the roles: our code
# starts the handshake and the kernel answers, which is what a Tailscale node
# does to its peers.
#
#   sudo scripts/interop-wireguard.sh              # the std `responder` example
#   sudo scripts/interop-wireguard.sh harness      # the no_std, no-libc harness
#   sudo scripts/interop-wireguard.sh initiator    # the harness initiates

set -euo pipefail

MODE="${1:-example}"
NS=wgtest
UNDERLAY_HOST=10.98.0.1
UNDERLAY_NS=10.98.0.2
TUNNEL_KERNEL=10.99.0.1
TUNNEL_OURS=10.99.0.2
PORT=51820
KERNEL_PORT=51821

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
RESPONDER_PID=""

cleanup() {
    [[ -n "$RESPONDER_PID" ]] && kill "$RESPONDER_PID" 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi

echo "== building ($MODE)"
# Built as the invoking user so the target directory does not end up
# root-owned, which would break subsequent non-root builds.
BUILD_USER="${SUDO_USER:-root}"
BUILD_HOME="$(eval echo "~$BUILD_USER")"
CARGO="${CARGO:-$BUILD_HOME/.cargo/bin/cargo}"
if [[ ! -x "$CARGO" ]]; then
    echo "cargo not found at $CARGO; set CARGO=/path/to/cargo" >&2
    exit 1
fi
case "$MODE" in
    example)
        sudo -u "$BUILD_USER" env HOME="$BUILD_HOME" "$CARGO" \
            build --release --manifest-path "$REPO_ROOT/Cargo.toml" \
            --package wirefeather --example responder
        RESPONDER="$REPO_ROOT/target/release/examples/responder"
        ;;
    harness|initiator)
        # Built from inside `harness/`, not via --manifest-path: cargo
        # discovers `.cargo/config.toml` from the working directory, and that
        # file is what selects the bare `x86_64-unknown-linux-none` target.
        # Building from elsewhere silently produces a linux-gnu binary, which
        # then fails to link against libc's own `_start`.
        (cd "$REPO_ROOT/harness" && sudo -u "$BUILD_USER" env HOME="$BUILD_HOME" \
            "$CARGO" build --release)
        RESPONDER="$REPO_ROOT/harness/target/x86_64-unknown-linux-none/release/harness"
        ;;
    *)
        echo "unknown mode '$MODE'; expected 'example', 'harness' or 'initiator'" >&2
        exit 1
        ;;
esac

echo "== generating keys"
wg genkey >"$WORK/kernel.key"
wg pubkey <"$WORK/kernel.key" >"$WORK/kernel.pub"
wg genkey >"$WORK/ours.key"
wg pubkey <"$WORK/ours.key" >"$WORK/ours.pub"

b64_to_hex() { python3 -c "import base64,sys;print(base64.b64decode(sys.stdin.read().strip()).hex())"; }
OURS_PRIV_HEX="$(b64_to_hex <"$WORK/ours.key")"
KERNEL_PUB_HEX="$(b64_to_hex <"$WORK/kernel.pub")"

echo "== creating namespace and underlay"
ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip link add veth-h type veth peer name veth-n
ip link set veth-n netns "$NS"
ip addr add "$UNDERLAY_HOST/24" dev veth-h
ip link set veth-h up
ip -n "$NS" addr add "$UNDERLAY_NS/24" dev veth-n
ip -n "$NS" link set veth-n up
ip -n "$NS" link set lo up

echo "== configuring kernel WireGuard peer"
ip -n "$NS" link add wg0 type wireguard
ip -n "$NS" addr add "$TUNNEL_KERNEL/24" dev wg0
if [[ "$MODE" == "initiator" ]]; then
    # No endpoint: the kernel must not be able to start the handshake, so a
    # completed one proves *we* started it. It learns where to reply from the
    # initiation we send, which is the same way it would learn a roaming peer's
    # address.
    ip netns exec "$NS" wg set wg0 \
        private-key "$WORK/kernel.key" \
        listen-port "$KERNEL_PORT" \
        peer "$(cat "$WORK/ours.pub")" \
        allowed-ips "$TUNNEL_OURS/32"
else
    ip netns exec "$NS" wg set wg0 \
        private-key "$WORK/kernel.key" \
        peer "$(cat "$WORK/ours.pub")" \
        endpoint "$UNDERLAY_HOST:$PORT" \
        allowed-ips "$TUNNEL_OURS/32"
fi
ip -n "$NS" link set wg0 up

echo "== starting responder"
echo "keys: ours_priv=$OURS_PRIV_HEX kernel_pub=$KERNEL_PUB_HEX"
# The example takes a Rust-parsable socket address; the harness has no address
# parser beyond dotted quads, so it takes host and port separately.
case "$MODE" in
    example)
        ARGS=("$UNDERLAY_HOST:$PORT" "$OURS_PRIV_HEX" "$KERNEL_PUB_HEX" "$TUNNEL_OURS")
        ;;
    harness)
        ARGS=(respond "$UNDERLAY_HOST" "$PORT" "$OURS_PRIV_HEX" "$KERNEL_PUB_HEX" "$TUNNEL_OURS")
        ;;
    initiator)
        ARGS=(initiate "$UNDERLAY_HOST" "$PORT" "$OURS_PRIV_HEX" "$KERNEL_PUB_HEX" \
              "$TUNNEL_OURS" "$UNDERLAY_NS" "$KERNEL_PORT")
        ;;
esac
"$RESPONDER" "${ARGS[@]}" >"$WORK/responder.log" 2>&1 &
RESPONDER_PID=$!
sleep 1

if [[ "$MODE" == "initiator" ]]; then
    echo "== waiting for our initiation to be answered"
    for _ in $(seq 1 30); do
        grep -q "handshake complete" "$WORK/responder.log" && break
        sleep 0.5
    done
fi

echo "== in-tunnel ping"
PING_OK=0
if ip netns exec "$NS" ping -c 3 -W 3 "$TUNNEL_OURS"; then
    PING_OK=1
fi

echo
echo "== wg show"
ip netns exec "$NS" wg show

echo
echo "== responder log"
cat "$WORK/responder.log"

echo
HANDSHAKE="$(ip netns exec "$NS" wg show wg0 latest-handshakes | awk '{print $2}')"
if [[ "$HANDSHAKE" == "0" || -z "$HANDSHAKE" ]]; then
    echo "FAIL: kernel WireGuard never completed a handshake"
    exit 1
fi
echo "PASS: handshake completed"

if [[ "$MODE" == "initiator" ]]; then
    # The kernel had no endpoint configured, so it could not have sent the
    # first message. A completed handshake means ours was accepted.
    if ! grep -q "handshake complete" "$WORK/responder.log"; then
        echo "FAIL: our initiation was never answered"
        exit 1
    fi
    echo "PASS: kernel WireGuard accepted an initiation from wirefeather"
fi

if [[ "$PING_OK" -ne 1 ]]; then
    echo "FAIL: in-tunnel ping did not get replies"
    exit 1
fi
echo "PASS: in-tunnel ping answered ($MODE)"
