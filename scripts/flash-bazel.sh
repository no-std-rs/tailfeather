#!/usr/bin/env bash
set -euo pipefail

ROOT="${BUILD_WORKSPACE_DIRECTORY:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENV_FILE="$ROOT/.env"
PARTITIONS="$ROOT/firmware/partitions.csv"
MONITOR=0
PORT="${ESPFLASH_PORT:-}"

usage() { echo "usage: scripts/flash.sh [--no-monitor] [--port /dev/ttyACM0]" >&2; }
while (( $# )); do
    case "$1" in
        --no-monitor) MONITOR=0; shift ;;
        --port)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            PORT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

[[ -f "$ENV_FILE" ]] || { echo "missing $ENV_FILE; copy .env.example and fill it in" >&2; exit 1; }
mode="$(stat -c '%a' "$ENV_FILE")"
[[ "$mode" == 600 ]] || {
    echo "$ENV_FILE permissions are $mode; run: chmod 600 '$ENV_FILE'" >&2
    exit 1
}

while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" != *$'\r' ]] || { echo "$ENV_FILE contains CRLF data" >&2; exit 1; }
    case "$line" in ''|'#'*) continue ;; esac
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || {
        echo "$ENV_FILE contains a malformed line" >&2
        exit 1
    }
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    if [[ "$value" == \"* || "$value" == \'* || "$value" =~ [[:space:]]# ]]; then
        echo "$ENV_FILE uses unsupported shell quoting or an inline comment for $key; store the literal value without quotes and put comments on their own line" >&2
        exit 1
    fi
    case "$key" in
        WIFI_SSID|WIFI_PASSWORD|TS_AUTH_KEY|TS_CONTROL_URL|TS_HOSTNAME|TS_CONTROL_CA_DER|TS_ALLOW_INSECURE_HTTP|SOURCE_DATE_EPOCH) ;;
        # Acceptance credentials share this gitignored file but must never be
        # exported into the firmware build action.
        TSKEY_API|TAILSCALE_TAILNET) continue ;;
        *) echo "$ENV_FILE contains unknown setting: $key" >&2; exit 1 ;;
    esac
    export "$key=$value"
done <"$ENV_FILE"

: "${TS_CONTROL_URL:=https://controlplane.tailscale.com}"
: "${TS_HOSTNAME:=esp-gateway}"
: "${TS_CONTROL_CA_DER:=}"
for var in WIFI_SSID WIFI_PASSWORD TS_AUTH_KEY TS_CONTROL_URL TS_HOSTNAME; do
    [[ -n "${!var:-}" ]] || { echo "$var is not set in $ENV_FILE" >&2; exit 1; }
done

byte_length() {
    local LC_ALL=C
    printf '%s\n' "${#1}"
}

valid_host() {
    local host="$1" label
    local -a labels
    [[ -n "$host" && "$host" != .* && "$host" != *. && "$host" != *..* ]] || return 1
    IFS=. read -r -a labels <<<"$host"
    for label in "${labels[@]}"; do
        (( $(byte_length "$label") <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

valid_ipv4() {
    local address="$1" octet
    local -a octets
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r -a octets <<<"$address"
    (( ${#octets[@]} == 4 )) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

wifi_ssid_bytes="$(byte_length "$WIFI_SSID")"
wifi_password_bytes="$(byte_length "$WIFI_PASSWORD")"
auth_key_bytes="$(byte_length "$TS_AUTH_KEY")"
hostname_bytes="$(byte_length "$TS_HOSTNAME")"
(( wifi_ssid_bytes <= 32 )) || { echo "WIFI_SSID must be at most 32 bytes" >&2; exit 1; }
(( wifi_password_bytes >= 8 && wifi_password_bytes <= 63 )) || {
    echo "WIFI_PASSWORD must be between 8 and 63 bytes" >&2
    exit 1
}
(( auth_key_bytes <= 512 )) && [[ ! "$TS_AUTH_KEY" =~ [[:space:]] ]] || {
    echo "TS_AUTH_KEY must be at most 512 non-whitespace bytes" >&2
    exit 1
}
(( hostname_bytes <= 63 )) && valid_host "$TS_HOSTNAME" || {
    echo "TS_HOSTNAME must be a DNS-style name of at most 63 characters" >&2
    exit 1
}
case "$TS_CONTROL_URL" in
    https://*) expected_scheme=https ;;
    http://*)
        [[ "${TS_ALLOW_INSECURE_HTTP:-0}" == 1 ]] || {
            echo "plaintext control requires TS_ALLOW_INSECURE_HTTP=1 and is test-only" >&2
            exit 1
        }
        expected_scheme=http
        ;;
    *) echo "TS_CONTROL_URL must start with https://" >&2; exit 1 ;;
esac
authority="${TS_CONTROL_URL#"$expected_scheme://"}"
authority="${authority%/}"
[[ -n "$authority" && "$authority" != */* && "$authority" != *'@'* && "$authority" != *'?'* && "$authority" != *'#'* && "$authority" != \[* ]] || {
    echo "TS_CONTROL_URL must contain one IPv4/DNS authority and no path" >&2
    exit 1
}
[[ "$authority" =~ ^[A-Za-z0-9.-]+(:[1-9][0-9]{0,4})?$ ]] || {
    echo "TS_CONTROL_URL contains an invalid host or port" >&2
    exit 1
}
control_host="${authority%%:*}"
control_host_bytes="$(byte_length "$control_host")"
(( control_host_bytes <= 128 )) || {
    echo "TS_CONTROL_URL host must be at most 128 bytes" >&2
    exit 1
}
if [[ "$control_host" =~ ^[0-9.]+$ ]]; then
    valid_ipv4 "$control_host"
else
    valid_host "$control_host"
fi || {
    echo "TS_CONTROL_URL contains an invalid DNS label" >&2
    exit 1
}
if [[ "$authority" == *:* ]]; then
    control_port="${authority##*:}"
    (( control_port <= 65535 )) || { echo "TS_CONTROL_URL port exceeds 65535" >&2; exit 1; }
fi

if [[ -n "$TS_CONTROL_CA_DER" ]]; then
    [[ "$TS_CONTROL_CA_DER" == /* ]] || TS_CONTROL_CA_DER="$ROOT/$TS_CONTROL_CA_DER"
    [[ -r "$TS_CONTROL_CA_DER" ]] || { echo "TS_CONTROL_CA_DER is not readable" >&2; exit 1; }
    ! LC_ALL=C grep -aq '^-----BEGIN ' "$TS_CONTROL_CA_DER" || {
        echo "TS_CONTROL_CA_DER must contain DER, not PEM" >&2
        exit 1
    }
    openssl x509 -inform DER -in "$TS_CONTROL_CA_DER" -noout >/dev/null 2>&1 || {
        echo "TS_CONTROL_CA_DER is not a valid DER-encoded X.509 certificate" >&2
        exit 1
    }
fi
if [[ -z "$TS_CONTROL_CA_DER" ]]; then
    TS_CONTROL_CA_DER="$ROOT/firmware/src/empty-ca.der"
fi
TS_CONTROL_CA_SHA256="$(openssl dgst -sha256 -r "$TS_CONTROL_CA_DER")"
TS_CONTROL_CA_SHA256="${TS_CONTROL_CA_SHA256%% *}"
TS_BUILD_TIME_FLOOR="${SOURCE_DATE_EPOCH:-$(date +%s)}"
[[ "$TS_BUILD_TIME_FLOOR" =~ ^[0-9]+$ ]] || {
    echo "SOURCE_DATE_EPOCH must be an unsigned decimal timestamp" >&2
    exit 1
}

if [[ -z "$PORT" ]]; then
    shopt -s nullglob
    candidates=(/dev/ttyACM* /dev/ttyUSB*)
    shopt -u nullglob
    (( ${#candidates[@]} == 1 )) || {
        echo "found ${#candidates[@]} candidate serial ports; pass --port explicitly" >&2
        (( ${#candidates[@]} == 0 )) || printf '  %s\n' "${candidates[@]}" >&2
        exit 1
    }
    PORT="${candidates[0]}"
fi
[[ -e "$PORT" ]] || { echo "serial port does not exist: $PORT" >&2; exit 1; }

if [[ ! -r "$PORT" || ! -w "$PORT" ]]; then
    command -v setfacl >/dev/null && command -v getfacl >/dev/null || {
        echo "serial port is not accessible and getfacl/setfacl are unavailable" >&2
        exit 1
    }
    serial_user="$(id -un)"
    previous_acl="$(getfacl -cp "$PORT" 2>/dev/null | awk -F: -v user="$serial_user" '$1 == "user" && $2 == user { print $3; exit }')"
    if [[ -n "$previous_acl" ]]; then
        trap 'sudo setfacl -m "u:'"$serial_user"':'"$previous_acl"'" "'"$PORT"'"' EXIT
    else
        trap 'sudo setfacl -x "u:'"$serial_user"'" "'"$PORT"'"' EXIT
    fi
    sudo setfacl -m "u:$serial_user:rw" "$PORT"
fi

ESPFLASH="$(command -v espflash || true)"
[[ -n "$ESPFLASH" ]] || { echo "espflash is not installed" >&2; exit 1; }
board_info="$($ESPFLASH board-info --chip esp32c6 --port "$PORT" --non-interactive 2>&1)" || {
    echo "could not inspect the ESP32-C6 on $PORT" >&2
    exit 1
}
grep -Eiq 'flash size:[[:space:]]*8[[:space:]]*(MB|MiB)' <<<"$board_info" || {
    echo "target on $PORT does not report 8 MB of flash" >&2
    exit 1
}

cd "$ROOT"
if [[ "$expected_scheme" == http ]]; then
    firmware_target=//firmware:lab_image
    firmware_config=lab-device
else
    firmware_target=//firmware:ci_image
    firmware_config=device
fi
bazel build "$firmware_target" --config="$firmware_config" \
    --action_env=WIFI_SSID="$WIFI_SSID" \
    --action_env=WIFI_PASSWORD="$WIFI_PASSWORD" \
    --action_env=TS_AUTH_KEY="$TS_AUTH_KEY" \
    --action_env=TS_CONTROL_URL="$TS_CONTROL_URL" \
    --action_env=TS_HOSTNAME="$TS_HOSTNAME" \
    --action_env=TS_CONTROL_CA_DER="$TS_CONTROL_CA_DER" \
    --action_env=TS_CONTROL_CA_SHA256="$TS_CONTROL_CA_SHA256" \
    --action_env=TS_BUILD_TIME_FLOOR="$TS_BUILD_TIME_FLOOR"

FLASH=(
    "$ESPFLASH" flash --chip esp32c6 --flash-size 8mb
    --partition-table "$PARTITIONS" --target-app-partition factory --port "$PORT"
)
(( MONITOR )) && FLASH+=(--monitor)
if [[ "$expected_scheme" == http ]]; then
    FLASH+=(bazel-bin/firmware/esp_gateway_firmware_lab)
else
    FLASH+=(bazel-bin/firmware/esp_gateway_firmware)
fi

"${FLASH[@]}"
