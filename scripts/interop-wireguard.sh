#!/bin/sh
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
#   sudo scripts/interop-wireguard.sh example-responder /path/to/responder
#   sudo scripts/interop-wireguard.sh harness-responder /path/to/harness
#   sudo scripts/interop-wireguard.sh harness-initiator /path/to/harness
#   sudo scripts/interop-wireguard.sh harness-rekey /path/to/harness

set -eu
umask 077

REQUESTED_MODE="${1:-}"
RESPONDER="${2:-}"
case "$REQUESTED_MODE" in
    example-responder) MODE=example ;;
    harness-responder) MODE=harness ;;
    harness-initiator) MODE=initiator ;;
    harness-rekey) MODE=rekey ;;
    *)
        echo "usage: $0 {example-responder|harness-responder|harness-initiator|harness-rekey} /path/to/bazel/runfile" >&2
        exit 2
        ;;
esac
test -x "$RESPONDER" || { echo "responder runfile is not executable: $RESPONDER" >&2; exit 1; }
NS=wgtest
UNDERLAY_HOST=10.98.0.1
UNDERLAY_NS=10.98.0.2
TUNNEL_KERNEL=10.99.0.1
TUNNEL_OURS=10.99.0.2
PORT=51820
KERNEL_PORT=51821

WORK="$(mktemp -d)"
RESPONDER_PID=""

cleanup() {
    if [ -n "$RESPONDER_PID" ]; then
        kill "$RESPONDER_PID" 2>/dev/null || true
    fi
    ip netns delete "$NS" 2>/dev/null || true
    ip link delete veth-h 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root: sudo $0" >&2
    exit 1
fi

echo "== generating keys"
wg genkey >"$WORK/kernel.key"
wg pubkey <"$WORK/kernel.key" >"$WORK/kernel.pub"
wg genkey >"$WORK/ours.key"
wg pubkey <"$WORK/ours.key" >"$WORK/ours.pub"

b64_to_hex() {
    base64 -d | od -An -v -tx1 | tr -d ' \n'
    printf '\n'
}
OURS_PRIV_HEX="$(b64_to_hex <"$WORK/ours.key")"
KERNEL_PUB_HEX="$(b64_to_hex <"$WORK/kernel.pub")"

echo "== creating namespace and underlay"
ip netns delete "$NS" 2>/dev/null || true
ip link delete veth-h 2>/dev/null || true
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
if [ "$MODE" = initiator ] || [ "$MODE" = rekey ]; then
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
# parser beyond dotted quads, so it takes host and port separately. Launch in
# each branch to keep this helper portable to the guest's POSIX shell.
case "$MODE" in
    example)
        "$RESPONDER" "$UNDERLAY_HOST:$PORT" "$OURS_PRIV_HEX" "$KERNEL_PUB_HEX" \
            "$TUNNEL_OURS" >"$WORK/responder.log" 2>&1 &
        ;;
    harness)
        "$RESPONDER" respond "$UNDERLAY_HOST" "$PORT" "$OURS_PRIV_HEX" "$KERNEL_PUB_HEX" \
            "$TUNNEL_OURS" >"$WORK/responder.log" 2>&1 &
        ;;
    initiator)
        "$RESPONDER" initiate "$UNDERLAY_HOST" "$PORT" "$OURS_PRIV_HEX" \
            "$KERNEL_PUB_HEX" "$TUNNEL_OURS" "$UNDERLAY_NS" "$KERNEL_PORT" \
            >"$WORK/responder.log" 2>&1 &
        ;;
    rekey)
        "$RESPONDER" initiate-rekey "$UNDERLAY_HOST" "$PORT" "$OURS_PRIV_HEX" \
            "$KERNEL_PUB_HEX" "$TUNNEL_OURS" "$UNDERLAY_NS" "$KERNEL_PORT" \
            >"$WORK/responder.log" 2>&1 &
        ;;
esac
RESPONDER_PID=$!
sleep 1

if [ "$MODE" = initiator ] || [ "$MODE" = rekey ]; then
    echo "== waiting for our initiation to be answered"
    for _ in $(seq 1 30); do
        grep -q "handshake complete" "$WORK/responder.log" && break
        sleep 0.5
    done
fi

echo "== in-tunnel ping"
PING_OK=0
PING_OUTPUT=""
if PING_OUTPUT="$(ip netns exec "$NS" ping -c 3 -W 3 "$TUNNEL_OURS" 2>&1)"; then
    PING_OK=1
fi
printf '%s\n' "$PING_OUTPUT"
PING_LOSSLESS=0
case "$PING_OUTPUT" in
    *", 0% packet loss"*) PING_LOSSLESS=1 ;;
esac

echo
echo "== wg show"
ip netns exec "$NS" wg show

echo
echo "== responder log"
cat "$WORK/responder.log"

echo
HANDSHAKE="$(ip netns exec "$NS" wg show wg0 latest-handshakes | awk '{print $2}')"
if [ "$HANDSHAKE" = 0 ] || [ -z "$HANDSHAKE" ]; then
    echo "FAIL: kernel WireGuard never completed a handshake"
    exit 1
fi
echo "PASS: handshake completed"

if [ "$MODE" = initiator ] || [ "$MODE" = rekey ]; then
    # The kernel had no endpoint configured, so it could not have sent the
    # first message. A completed handshake means ours was accepted.
    if ! grep -q "handshake complete" "$WORK/responder.log"; then
        echo "FAIL: our initiation was never answered"
        exit 1
    fi
    echo "PASS: kernel WireGuard accepted an initiation from wirefeather"
fi

if [ "$MODE" = rekey ]; then
    REKEYS="$(grep -c 'rekey .* complete' "$WORK/responder.log" || true)"
    if [ "$REKEYS" -lt 2 ]; then
        echo "FAIL: only $REKEYS accelerated rekeys completed"
        exit 1
    fi
    if [ "$PING_LOSSLESS" -ne 1 ]; then
        echo "FAIL: accelerated rekeys did not preserve every echo reply"
        exit 1
    fi
    echo "PASS: two kernel-accepted rekeys completed with uninterrupted traffic"
fi

if [ "$PING_OK" -ne 1 ]; then
    echo "FAIL: in-tunnel ping did not get replies"
    exit 1
fi
echo "PASS: in-tunnel ping answered ($MODE)"
