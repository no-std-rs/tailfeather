#!/usr/bin/env bash
#
# Configure this machine as the WireGuard peer of a flashed gateway, and prove
# the tunnel works.
#
# The gateway is responder-only: it never starts a handshake, so the initiator
# has to be something that can. Kernel WireGuard is that something. This is the
# hardware form of the test `scripts/interop-wireguard.sh` runs against the
# `responder` example and the harness — same protocol, same peer, real radio.
#
# The interface is created in the host namespace rather than a network
# namespace, which is safe only because `AllowedIPs` is a single /32 and adds
# one host route. When M3 widens it to 0.0.0.0/0 to test exit-node forwarding,
# this must move into a namespace or it will capture all of this machine's
# traffic.
#
#   sudo scripts/device-peer.sh up <device lan ip>
#   sudo scripts/device-peer.sh down
#   sudo scripts/device-peer.sh status

set -euo pipefail

IFACE=wg-dev
TUNNEL_US=10.99.0.1
TUNNEL_DEVICE=10.99.0.2
LISTEN_PORT=51821
DEVICE_PORT=51820

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0 $*" >&2
    exit 1
fi

case "${1:-}" in
    down)
        ip link del "$IFACE" 2>/dev/null && echo "removed $IFACE" || echo "$IFACE was not present"
        exit 0
        ;;
    status)
        wg show "$IFACE"
        exit 0
        ;;
    up) ;;
    *)
        echo "usage: $0 {up <device lan ip>|down|status}" >&2
        exit 2
        ;;
esac

DEVICE_IP="${2:-}"
if [[ -z "$DEVICE_IP" ]]; then
    echo "usage: $0 up <device lan ip>   (the DHCP address the firmware logs)" >&2
    exit 2
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "missing $ENV_FILE — it holds the keys this must match against" >&2
    exit 1
fi
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

for var in LAPTOP_PRIVATE_KEY_B64; do
    if [[ -z "${!var:-}" ]]; then
        echo "$var is not set in $ENV_FILE" >&2
        exit 1
    fi
done

if [[ -n "${DEVICE_PUBLIC_KEY_HEX:-}" ]]; then
    [[ "$DEVICE_PUBLIC_KEY_HEX" =~ ^[0-9A-Fa-f]{64}$ ]] || {
        echo "DEVICE_PUBLIC_KEY_HEX must be 32 bytes of hexadecimal" >&2
        exit 1
    }
    DEVICE_PUBLIC_KEY_B64="$(printf '%s' "$DEVICE_PUBLIC_KEY_HEX" | xxd -r -p | base64 -w0)"
elif [[ -z "${DEVICE_PUBLIC_KEY_B64:-}" ]]; then
    echo "DEVICE_PUBLIC_KEY_HEX or DEVICE_PUBLIC_KEY_B64 is not set in $ENV_FILE" >&2
    exit 1
fi

KEYFILE="$(mktemp)"
chmod 600 "$KEYFILE"
trap 'rm -f "$KEYFILE"' EXIT
printf '%s\n' "$LAPTOP_PRIVATE_KEY_B64" >"$KEYFILE"

ip link del "$IFACE" 2>/dev/null || true
ip link add "$IFACE" type wireguard
ip addr add "$TUNNEL_US/24" dev "$IFACE"
wg set "$IFACE" \
    private-key "$KEYFILE" \
    listen-port "$LISTEN_PORT" \
    peer "$DEVICE_PUBLIC_KEY_B64" \
    endpoint "$DEVICE_IP:$DEVICE_PORT" \
    allowed-ips "$TUNNEL_DEVICE/32"
ip link set "$IFACE" up

echo "== $IFACE up, peer at $DEVICE_IP:$DEVICE_PORT"
echo "== pinging $TUNNEL_DEVICE through the tunnel"

# The first echo request is what triggers the handshake, and is usually lost
# while it completes, so this must not treat a single loss as failure.
if ping -c 5 -W 3 "$TUNNEL_DEVICE"; then
    echo "PASS: in-tunnel ping answered"
else
    echo "FAIL: no replies through the tunnel"
    wg show "$IFACE"
    exit 1
fi

HANDSHAKE="$(wg show "$IFACE" latest-handshakes | awk '{print $2}')"
if [[ "$HANDSHAKE" == "0" || -z "$HANDSHAKE" ]]; then
    echo "FAIL: no handshake recorded"
    exit 1
fi
echo "PASS: handshake completed"
wg show "$IFACE"
