#!/usr/bin/env bash
# Physical exit-node acceptance through TailSocks. The test peer, credential,
# container, namespace, state, and firewall rules are all run-scoped.

set -euo pipefail

readonly IMAGE="ghcr.io/italypaleale/tailsocks@sha256:a96033e948bf75b28e520aff02f3dd90affc0f682395f4f1840c43e5711cebd4"
readonly NS="tsocks-accept"
readonly VETH_HOST="tsa-host"
readonly VETH_NS="tsa-ns"
readonly HOST_ADDR="10.97.0.1"
readonly NS_ADDR="10.97.0.2"
readonly SOCKS_ADDR="127.0.0.1:5040"
readonly CONTAINER="tailsocks-accept"
readonly ECHO_PORT="39080"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
DEVICE_ID=""
KEY_ID=""
DEVICE_NAME="tailsocks-accept-$$"
FORWARD_WAS=""
NAT_ADDED=0
FORWARD_OUT_ADDED=0
FORWARD_IN_ADDED=0
DERP_BLOCKED=0
FORCE_DERP=0
BENCHMARK=0
BENCHMARK_BYTES=10000000
ECHO_PID=""
ECHO_FIREWALL_ADDED=0
LOAD_PIDS=()
ESP_LAN_IP=""
LAN_URL="http://192.168.6.170:8080/ui/"
EXIT_NODE="esp-gateway"
ONET_URL="https://www.onet.pl/"

usage() {
    cat >&2 <<'EOF'
usage: sudo scripts/accept-tailsocks.sh --esp-lan-ip ADDRESS [--force-derp]
       [--benchmark] [--benchmark-bytes BYTES] [--exit-node NAME] [--lan-url URL]

Requires TSKEY_API in ../.env or ./.env. TAILSCALE_TAILNET defaults to `-`,
matching flash.sh. The ESP LAN address is used to isolate the WireGuard direct
path when --force-derp is selected and for deterministic LAN source checks.
EOF
}

while (( $# )); do
    case "$1" in
        --esp-lan-ip) ESP_LAN_IP="${2:?missing address}"; shift 2 ;;
        --exit-node) EXIT_NODE="${2:?missing name}"; shift 2 ;;
        --lan-url) LAN_URL="${2:?missing URL}"; shift 2 ;;
        --force-derp) FORCE_DERP=1; shift ;;
        --benchmark) BENCHMARK=1; shift ;;
        --benchmark-bytes) BENCHMARK_BYTES="${2:?missing byte count}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

[[ -n "$ESP_LAN_IP" ]] || { usage; exit 2; }
[[ "$BENCHMARK_BYTES" =~ ^[1-9][0-9]*$ ]] || {
    echo "--benchmark-bytes must be a positive integer" >&2
    exit 2
}

api() {
    local method="$1" url="$2"
    shift 2
    printf 'user = "%s:"\n' "$TSKEY_API" |
        curl --config - --silent --show-error --fail-with-body \
            --request "$method" "$@" "$url"
}

cleanup() {
    local exit_status=$?
    set +e
    if (( exit_status != 0 )); then
        podman logs "$CONTAINER" 2>&1 | tail -n 120 >&2
    fi
    if (( DERP_BLOCKED )); then
        iptables -w -D FORWARD -s "$NS_ADDR"/32 \
            -p udp -j DROP >/dev/null 2>&1
    fi
    if [[ -n "$ECHO_PID" ]]; then
        kill "$ECHO_PID" >/dev/null 2>&1
        wait "$ECHO_PID" >/dev/null 2>&1
    fi
    for load_pid in "${LOAD_PIDS[@]}"; do
        kill "$load_pid" >/dev/null 2>&1
        wait "$load_pid" >/dev/null 2>&1 || true
    done
    if (( ECHO_FIREWALL_ADDED )); then
        iptables -w -D INPUT -s "$ESP_LAN_IP"/32 -p tcp --dport "$ECHO_PORT" \
            -j ACCEPT >/dev/null 2>&1
    fi
    podman rm --force "$CONTAINER" >/dev/null 2>&1
    if [[ -z "$DEVICE_ID" && -n "${TSKEY_API:-}" && -n "${TAILSCALE_TAILNET:-}" ]]; then
        cleanup_devices="$(api GET \
            "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/devices" 2>/dev/null)"
        DEVICE_ID="$(jq -r --arg name "$DEVICE_NAME" \
            '.devices[] | select((.hostname == $name) or (.name | startswith($name + "."))) | .id' \
            <<<"$cleanup_devices" | head -n1)"
    fi
    if [[ -n "$DEVICE_ID" ]]; then
        api DELETE "https://api.tailscale.com/api/v2/device/$DEVICE_ID" >/dev/null 2>&1
    fi
    if [[ -n "$KEY_ID" ]]; then
        api DELETE "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/keys/$KEY_ID" \
            >/dev/null 2>&1
    fi
    if (( FORWARD_IN_ADDED )); then
        iptables -w -D FORWARD -d "$NS_ADDR"/32 -m conntrack \
            --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1
    fi
    if (( FORWARD_OUT_ADDED )); then
        iptables -w -D FORWARD -s "$NS_ADDR"/32 -j ACCEPT >/dev/null 2>&1
    fi
    if (( NAT_ADDED )); then
        iptables -w -t nat -D POSTROUTING -s "$NS_ADDR"/32 -j MASQUERADE \
            >/dev/null 2>&1
    fi
    ip netns delete "$NS" >/dev/null 2>&1
    ip link delete "$VETH_HOST" >/dev/null 2>&1
    if [[ -n "$FORWARD_WAS" ]]; then
        sysctl -qw net.ipv4.ip_forward="$FORWARD_WAS"
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for command in curl jq podman ip iptables python3 sysctl; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done

# Load only the two API settings used here; values are data, never evaluated.
for env_file in "$ROOT/../.env" "$ROOT/.env"; do
    [[ -f "$env_file" ]] || continue
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in ''|'#'*) continue ;; esac
        [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        case "${BASH_REMATCH[1]}" in
            TSKEY_API|TAILSCALE_TAILNET)
                printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
                ;;
        esac
    done <"$env_file"
done
: "${TSKEY_API:?TSKEY_API is required}"
: "${TAILSCALE_TAILNET:=-}"

echo "== minting one-use preauthorized ephemeral TailSocks key"
key_payload='{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":true,"preauthorized":true,"tags":[]}}},"expirySeconds":3600}'
key_response="$(api POST \
    "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/keys" \
    --header 'Content-Type: application/json' --data-binary "$key_payload")"
KEY_ID="$(jq -er '.id' <<<"$key_response")"
TS_AUTHKEY="$(jq -er '.key | select(startswith("tskey-auth-"))' <<<"$key_response")"
export TS_AUTHKEY
unset key_response

echo "== creating isolated namespace and run-scoped firewall rules"
ip netns delete "$NS" >/dev/null 2>&1 || true
ip link delete "$VETH_HOST" >/dev/null 2>&1 || true
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"
ip address add "$HOST_ADDR"/30 dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip -n "$NS" address add "$NS_ADDR"/30 dev "$VETH_NS"
ip -n "$NS" link set "$VETH_NS" up
ip -n "$NS" link set lo up
ip -n "$NS" route add default via "$HOST_ADDR"
FORWARD_WAS="$(sysctl -n net.ipv4.ip_forward)"
sysctl -qw net.ipv4.ip_forward=1
iptables -w -t nat -I POSTROUTING 1 -s "$NS_ADDR"/32 -j MASQUERADE
NAT_ADDED=1
iptables -w -I FORWARD 1 -s "$NS_ADDR"/32 -j ACCEPT
FORWARD_OUT_ADDED=1
iptables -w -I FORWARD 1 -d "$NS_ADDR"/32 -m conntrack \
    --ctstate ESTABLISHED,RELATED -j ACCEPT
FORWARD_IN_ADDED=1
echo "== starting pinned TailSocks v1.3.1 with loopback-only SOCKS"
mkdir "$WORK/state"
chown 65532:65532 "$WORK/state"
podman_args=(run --detach --name "$CONTAINER" --network "ns:/run/netns/$NS" --env TS_AUTHKEY)
podman_args+=(--volume "$WORK/state:/data:Z" "$IMAGE" \
    /bin/tailsocks --ephemeral --hostname "$DEVICE_NAME" --state-dir /data \
    --socks-addr "$SOCKS_ADDR" --exit-node "$EXIT_NODE")
podman "${podman_args[@]}" >/dev/null
unset TS_AUTHKEY

container_logs=""
for _ in $(seq 1 90); do
    container_logs="$(podman logs "$CONTAINER" 2>&1)"
    if grep -q 'SOCKS5 proxy listening' <<<"$container_logs"; then
        break
    fi
    sleep 1
done
grep -q 'SOCKS5 proxy listening' <<<"$container_logs" || {
    tail -n 120 <<<"$container_logs" >&2
    exit 1
}
unset container_logs

if (( FORCE_DERP )); then
    echo "== blocking all namespace UDP to force DERP"
    iptables -w -I FORWARD 1 -s "$NS_ADDR"/32 -p udp -j DROP
    DERP_BLOCKED=1
fi

# Let the tunnel handshake settle and any peer-API close-grace entries left by a
# just-removed ephemeral acceptance peer become reusable.
sleep 3

# Capture the ephemeral API device so cleanup does not depend on server-side
# ephemeral garbage collection.
devices="$(api GET "https://api.tailscale.com/api/v2/tailnet/$TAILSCALE_TAILNET/devices")"
DEVICE_ID="$(jq -er --arg name "$DEVICE_NAME" \
    '.devices[] | select((.hostname == $name) or (.name | startswith($name + "."))) | .id' \
    <<<"$devices" | head -n1)"
unset devices

proxy_curl=(ip netns exec "$NS" curl --silent --show-error --fail \
    --max-time 60 --proxy "socks5h://$SOCKS_ADDR")

if (( BENCHMARK )); then
    # Cloudflare returns exactly the requested number of bytes and is public,
    # so the measurements exercise DNS, TLS, TailSocks, and the ESP exit path
    # without depending on the LAN fixture below.
    benchmark_url="https://speed.cloudflare.com/__down?bytes=$BENCHMARK_BYTES"
    echo "== benchmarking a $BENCHMARK_BYTES byte public HTTPS download"
    printf 'direct '
    curl --silent --show-error --fail --max-time 60 --output /dev/null \
        --write-out 'connect_s=%{time_connect} ttfb_s=%{time_starttransfer} total_s=%{time_total} bytes_s=%{speed_download} downloaded_bytes=%{size_download}\n' \
        "$benchmark_url"
    for sample in 1 2 3; do
        metrics="$("${proxy_curl[@]}" --max-time 90 --output /dev/null \
            --write-out 'connect_s=%{time_connect} ttfb_s=%{time_starttransfer} total_s=%{time_total} bytes_s=%{speed_download} downloaded_bytes=%{size_download}' \
            "$benchmark_url")"
        printf 'tailsocks sample=%s %s\n' "$sample" "$metrics"
        downloaded="${metrics##*downloaded_bytes=}"
        [[ "$downloaded" =~ ^[0-9]+$ ]] && (( downloaded == BENCHMARK_BYTES )) || {
            echo "tailsocks sample $sample downloaded $downloaded bytes, expected $BENCHMARK_BYTES" >&2
            exit 1
        }
    done
    exit 0
fi

if (( FORCE_DERP )); then
    echo "== proving DNS and HTTPS over the forced DERP path"
    forced_ok=0
    for attempt in 1 2 3; do
        if "${proxy_curl[@]}" --output /dev/null "$ONET_URL"; then
            forced_ok=1
            break
        fi
        if (( attempt < 3 )); then
            echo "== cold DERP attempt $attempt did not complete; retrying established path"
            sleep 3
        fi
    done
    (( forced_ok )) || exit 1
else
    echo "== proving remote hostname resolution and HTTPS through the direct path"
    "${proxy_curl[@]}" --output /dev/null "$ONET_URL"
fi

if (( FORCE_DERP )); then
    echo "PASS: TailSocks DNS and HTTPS over forced DERP"
    exit 0
fi

echo "== checking public IP equality with the ESP home uplink"
direct_ip="$(curl --silent --show-error --fail --max-time 30 https://api.ipify.org)"
exit_ip="$("${proxy_curl[@]}" https://api.ipify.org)"
[[ "$exit_ip" == "$direct_ip" ]] || {
    echo "public IP mismatch: host=$direct_ip exit=$exit_ip" >&2
    exit 1
}

echo "== checking LAN UI through the exit node without LAN bypass"
status="$("${proxy_curl[@]}" --output /dev/null --write-out '%{http_code}' "$LAN_URL")"
[[ "$status" == 200 ]] || { echo "LAN UI returned HTTP $status" >&2; exit 1; }

echo "== exercising 24 concurrent and 40 sequential TCP connections"
if [[ -n "$ESP_LAN_IP" ]]; then
    host_lan_ip="$(ip -4 route get "$ESP_LAN_IP" | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)"
    : "${host_lan_ip:?could not determine LAN source address}"
    echo_log="$WORK/echo.log"
    iptables -w -I INPUT 1 -s "$ESP_LAN_IP"/32 -p tcp --dport "$ECHO_PORT" -j ACCEPT
    ECHO_FIREWALL_ADDED=1
    python3 -m http.server "$ECHO_PORT" --bind "$host_lan_ip" --directory "$WORK" \
        >/dev/null 2>"$echo_log" &
    ECHO_PID=$!
    sleep 1
    kill -0 "$ECHO_PID" 2>/dev/null || {
        echo "LAN echo server failed to start on $host_lan_ip:$ECHO_PORT" >&2
        exit 1
    }
    echo_url="http://$host_lan_ip:$ECHO_PORT/"
    for _ in $(seq 1 24); do
        ip netns exec "$NS" curl --silent --fail --max-time 90 --limit-rate 1 \
            --proxy "socks5h://$SOCKS_ADDR" --output /dev/null "$echo_url" \
            2>/dev/null &
        LOAD_PIDS+=("$!")
        sleep 0.2
    done
    alive=0
    for load_pid in "${LOAD_PIDS[@]}"; do
        kill -0 "$load_pid" 2>/dev/null && alive=$((alive + 1))
    done
    (( alive == 24 )) || {
        echo "only $alive/24 TCP load connections remained concurrent" >&2
        exit 1
    }
    concurrent_observed="$(grep -c "^$ESP_LAN_IP " "$echo_log" || true)"
    (( concurrent_observed >= 24 )) || {
        echo "echo server observed only $concurrent_observed/24 concurrent connections" >&2
        exit 1
    }
    for load_pid in "${LOAD_PIDS[@]}"; do
        kill "$load_pid" >/dev/null 2>&1
        wait "$load_pid" >/dev/null 2>&1 || true
    done
    LOAD_PIDS=()
    for _ in $(seq 1 40); do
        "${proxy_curl[@]}" --output /dev/null "$echo_url"
    done
    observed="$(grep -c "^$ESP_LAN_IP " "$echo_log" || true)"
    (( observed >= 64 )) || {
        echo "echo server observed $observed/64 connections from $ESP_LAN_IP" >&2
        exit 1
    }
else
    echo "--esp-lan-ip is required for deterministic TCP load and source-address checks" >&2
    exit 1
fi

echo "PASS: TailSocks DNS, HTTPS, public IP, LAN UI, and TCP load"
