#!/usr/bin/env bash
# Fast local loop for the ESP exit-node lab: no VM and no root.
#
# Builds the lab firmware image (incremental, seconds when only firmware
# changed), then runs tests/lab/esp-exit.sh inside an unprivileged user, network
# and mount namespace. That gives the stage the CAP_NET_ADMIN it needs for its
# namespaces and tap device without touching the host network. The privileged
# smolVM target //tests/lab:esp_exit runs the same stage script for CI and RBE.
#
#   tests/lab/esp-exit-local.sh            # build + run
#   TF_ESP_EXIT_NO_BUILD=1 tests/lab/esp-exit-local.sh   # rerun the last build
#   TF_ESP_EXIT_BAZEL_FLAGS="--action_env=TS_FWD_UP_PACKETS=4" tests/lab/esp-exit-local.sh
#   TF_ESP_EXIT_TLS=1 tests/lab/esp-exit-local.sh   # the production TLS control path
#
# Needs on the host: unprivileged user namespaces with a subordinate ID range
# (/etc/subuid, for dnsmasq to drop privileges), /dev/net/tun, iproute2,
# socat and dnsmasq. Every TF_ESP_EXIT_* knob of esp-exit.sh applies.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
for tool in unshare ip socat dnsmasq; do
    command -v "$tool" >/dev/null || PATH=$PATH:/usr/sbin:/sbin
    command -v "$tool" >/dev/null || { echo "esp-exit-local: $tool is not installed" >&2; exit 1; }
done

VARIANT=emulab
TLS_DIR=""
if test -n "${TF_ESP_EXIT_TLS:-}"; then
    VARIANT=emulab_tls
    TLS_DIR=$ROOT/tests/lab/esp-tls
fi
TARGETS=("//firmware:${VARIANT}_flash" "//firmware:esp_gateway_firmware_$VARIANT"
    @esp_emu_0_50_0_linux_x86_64//:esp-emu @headscale_0_29_3_linux_amd64//file
    @tailscale_1_94_2_linux_amd64//:tailscale @tailscale_1_94_2_linux_amd64//:tailscaled)
# shellcheck disable=SC2206
FLAGS=(--noannounce_rc --config=optimized ${TF_ESP_EXIT_BAZEL_FLAGS:-})
if test -z "${TF_ESP_EXIT_NO_BUILD:-}"; then
    bazel build "${FLAGS[@]}" "${TARGETS[@]}"
fi
# Resolve each target's output through Bazel rather than guessing paths: the
# firmware is built in a platform-transitioned configuration.
query=$(printf '%s + ' "${TARGETS[@]}")
outputs=$(bazel cquery "${FLAGS[@]}" --output=files "${query% + }" 2>/dev/null)
pick() { grep -E "$1" <<<"$outputs" | head -1; }
EXEC_ROOT=$(bazel info "${FLAGS[@]}" execution_root 2>/dev/null)
abs() { case "$1" in /*) echo "$1" ;; *) echo "$EXEC_ROOT/$1" ;; esac; }
FLASH=$(abs "$(pick "/$VARIANT-flash\\.bin\$")")
ELF=$(abs "$(pick "/esp_gateway_firmware_$VARIANT\$")")
EMU=$(abs "$(pick '/esp-emu$')")
HEADSCALE_SRC=$(abs "$(pick 'headscale_0_29_3.*/headscale$')")
TAILSCALE=$(abs "$(pick '/tailscale$')")
TAILSCALED=$(abs "$(pick '/tailscaled$')")

# http_file outputs are not executable; run a private copy.
BIN=$(mktemp -d "${TMPDIR:-/tmp}/tf-esp-exit-local.XXXXXX")
trap 'rm -rf "$BIN"' EXIT
cp "$HEADSCALE_SRC" "$BIN/headscale"
chmod +x "$BIN/headscale"

unshare --user --map-auto --map-root-user --net --mount --propagation private bash -c '
    set -e
    mount -t tmpfs tmpfs /run
    mkdir -p /run/netns
    exec bash "$0" "$@"
' "$ROOT/tests/lab/esp-exit.sh" "$BIN/headscale" "$TAILSCALE" "$TAILSCALED" "$EMU" \
    "$FLASH" "$ELF" "$ROOT/tests/lab/headscale.yaml" $TLS_DIR
