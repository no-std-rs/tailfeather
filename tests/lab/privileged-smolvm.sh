#!/usr/bin/env bash
set -euo pipefail

fail() { echo "privileged-smolvm: FAIL: $*" >&2; exit 1; }
runfile() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$PWD" "$1" ;; esac; }

ROOTFS="" SMOLVM="" LIBKRUNFW="" GUEST="" HEADSCALE="" TAILSCALE="" TAILSCALED=""
CONFORMANCE="" HARNESS="" RESPONDER="" INTEROP="" NOSTD_INTEROP="" EXPECTATIONS="" VECTORS=""
HEADSCALE_CONFIG="" SSH_SERVER="" SSH_NETWORK="" REACTOR_NODE="" REACTOR_REBIND="" NAT_MATRIX=""
ESP_EMU="" ESP_FLASH="" ESP_ELF="" ESP_EXIT="" ESP_TLS=""
STAGES=all
APKS=()
for arg in "$@"; do
    case "$arg" in
        --rootfs=*) ROOTFS=$(runfile "${arg#*=}") ;;
        --smolvm=*) SMOLVM=$(runfile "${arg#*=}") ;;
        --libkrunfw=*) LIBKRUNFW=$(runfile "${arg#*=}") ;;
        --guest=*) GUEST=$(runfile "${arg#*=}") ;;
        --headscale=*) HEADSCALE=$(runfile "${arg#*=}") ;;
        --tailscale=*) TAILSCALE=$(runfile "${arg#*=}") ;;
        --tailscaled=*) TAILSCALED=$(runfile "${arg#*=}") ;;
        --conformance=*) CONFORMANCE=$(runfile "${arg#*=}") ;;
        --harness=*) HARNESS=$(runfile "${arg#*=}") ;;
        --responder=*) RESPONDER=$(runfile "${arg#*=}") ;;
        --interop=*) INTEROP=$(runfile "${arg#*=}") ;;
        --nostd-interop=*) NOSTD_INTEROP=$(runfile "${arg#*=}") ;;
        --expectations=*) EXPECTATIONS=$(runfile "${arg#*=}") ;;
        --vectors=*) VECTORS=$(runfile "${arg#*=}") ;;
        --ssh-server=*) SSH_SERVER=$(runfile "${arg#*=}") ;;
        --ssh-network=*) SSH_NETWORK=$(runfile "${arg#*=}") ;;
        --reactor-node=*) REACTOR_NODE=$(runfile "${arg#*=}") ;;
        --reactor-rebind=*) REACTOR_REBIND=$(runfile "${arg#*=}") ;;
        --headscale-config=*) HEADSCALE_CONFIG=$(runfile "${arg#*=}") ;;
        --nat-matrix=*) NAT_MATRIX=$(runfile "${arg#*=}") ;;
        --esp-emu=*) ESP_EMU=$(runfile "${arg#*=}") ;;
        --esp-flash=*) ESP_FLASH=$(runfile "${arg#*=}") ;;
        --esp-elf=*) ESP_ELF=$(runfile "${arg#*=}") ;;
        --esp-exit=*) ESP_EXIT=$(runfile "${arg#*=}") ;;
        --esp-tls=*) ESP_TLS=$(runfile "${arg#*=}") ;;
        --stages=*) STAGES=${arg#*=} ;;
        --apk=*) APKS+=("$(runfile "${arg#*=}")") ;;
        *) fail "unknown argument: $arg" ;;
    esac
done

for input in "$ROOTFS" "$SMOLVM" "$LIBKRUNFW" "$GUEST" "$HEADSCALE" "$TAILSCALE" "$TAILSCALED" \
    "$HEADSCALE_CONFIG"; do
    test -r "$input" || fail "missing runfile: $input"
done
# Stage inputs are optional so a focused target (one --stages subset) need not
# build the rest of the lab. The full lab passes them all, and a stage whose
# input was not staged fails inside the guest rather than being skipped.
if test "$STAGES" = all; then
    for input in "$CONFORMANCE" "$HARNESS" "$RESPONDER" "$INTEROP" "$NOSTD_INTEROP" "$EXPECTATIONS" \
        "$VECTORS" "$SSH_SERVER" "$SSH_NETWORK" "$REACTOR_NODE" "$REACTOR_REBIND" "$NAT_MATRIX"; do
        test -r "$input" || fail "missing runfile: $input"
    done
fi
test -r /dev/kvm && test -w /dev/kvm || fail "/dev/kvm is unavailable"
test -c /dev/net/tun || fail "/dev/net/tun is unavailable on the KVM worker"
command -v flock >/dev/null || fail "flock is unavailable"
# /tmp is shared by bare-isolation actions on one worker and writable by its
# unprivileged executor accounts, so this remains a host-global KVM lock. Open
# it read-only because a previous action may have created it under another UID.
LOCK=/tmp/tailfeather-privileged-lab.lock
if ! test -e "$LOCK"; then
    (umask 000; : >"$LOCK") || true
fi
exec 9<"$LOCK"
flock --exclusive 9

WORK=$(mktemp -d "${TEST_TMPDIR:-/tmp}/tailfeather-lab.XXXXXX")
STATE_ROOT=""
cleanup() {
    test -z "$STATE_ROOT" || rm -rf "$STATE_ROOT"
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

GUEST_ROOT="$WORK/rootfs"
mkdir -p "$GUEST_ROOT/opt/lab/vectors"
tar -xzf "$ROOTFS" -C "$GUEST_ROOT"
test -x "$GUEST_ROOT/bin/busybox" || fail "Alpine minirootfs has no BusyBox"
# APKs are checksum-pinned Bazel inputs. Materialize their payloads while the
# rootfs is still host-owned instead of mutating Alpine's package database from
# smolVM's workload overlay.
for apk in "${APKS[@]}"; do
    tar --warning=no-unknown-keyword --ignore-zeros -xzf "$apk" -C "$GUEST_ROOT" --exclude='.SIGN.*' --exclude='.PKGINFO'
done

stage_input() { test -z "$1" || cp "$1" "$GUEST_ROOT/opt/lab/$2"; }
stage_input "$GUEST" guest-controller.sh
stage_input "$HEADSCALE" headscale
stage_input "$TAILSCALE" tailscale
stage_input "$TAILSCALED" tailscaled
stage_input "$HEADSCALE_CONFIG" headscale.yaml
stage_input "$CONFORMANCE" conformance
stage_input "$HARNESS" harness
stage_input "$SSH_SERVER" ssh-server
stage_input "$SSH_NETWORK" ssh-network.sh
stage_input "$REACTOR_NODE" reactor-node
stage_input "$REACTOR_REBIND" reactor-rebind.sh
stage_input "$NAT_MATRIX" nat-matrix.sh
stage_input "$ESP_EMU" esp-emu
stage_input "$ESP_FLASH" esp-flash.bin
stage_input "$ESP_ELF" esp-firmware.elf
stage_input "$ESP_EXIT" esp-exit.sh
if test -n "$ESP_TLS"; then
    mkdir -p "$GUEST_ROOT/opt/lab/esp-tls"
    cp -L "$(dirname "$ESP_TLS")"/control.pem "$(dirname "$ESP_TLS")"/control.key \
        "$(dirname "$ESP_TLS")"/ca.pem "$GUEST_ROOT/opt/lab/esp-tls/"
fi
stage_input "$RESPONDER" responder
stage_input "$INTEROP" interop-wireguard.sh
stage_input "$NOSTD_INTEROP" nostd-interop.sh
stage_input "$EXPECTATIONS" lab.json
if test -n "$VECTORS"; then cp -RL "$(dirname "$VECTORS")"/. "$GUEST_ROOT/opt/lab/vectors/"; fi
find "$GUEST_ROOT/opt/lab" -maxdepth 1 -type f -exec chmod 755 {} +

SMOLVM_SOURCE=$(cd "$(dirname "$SMOLVM")" && pwd)
SMOLVM_DIR="$WORK/smolvm"
mkdir -p "$SMOLVM_DIR"
# Runfiles may be a tree of read-only symlinks. Materialize their targets so
# replacing firmware never mutates, or remains linked to, a Bazel input.
cp -RL "$SMOLVM_SOURCE"/. "$SMOLVM_DIR"
test -x "$SMOLVM_DIR/smolvm-bin" || fail "smolVM bundle is incomplete"
# The stock firmware omits kernel WireGuard. Replace only the test-owned copy
# with the checksum-pinned Linux 6.12.91/libkrunfw 5.5.0 networking build.
chmod u+w "$SMOLVM_DIR/lib" "$SMOLVM_DIR/lib/libkrunfw.so.5.5.0"
cp "$LIBKRUNFW" "$SMOLVM_DIR/lib/libkrunfw.so.5.5.0"
ln -sfn libkrunfw.so.5.5.0 "$SMOLVM_DIR/lib/libkrunfw.so.5"
ln -sfn libkrunfw.so.5 "$SMOLVM_DIR/lib/libkrunfw.so"
AGENT="$SMOLVM_DIR/agent-rootfs/usr/local/bin/smolvm-agent"
test -x "$AGENT" || fail "smolVM guest agent is missing"
cp "$AGENT" "$SMOLVM_DIR/agent-rootfs/sbin/init.materialized"
chmod 755 "$SMOLVM_DIR/agent-rootfs/sbin/init.materialized"
mv -f "$SMOLVM_DIR/agent-rootfs/sbin/init.materialized" "$SMOLVM_DIR/agent-rootfs/sbin/init"

# BuildBuddy execroot paths exceed sockaddr_un. Give every invocation a short,
# test-owned socket hierarchy and leave the copied bundle as the only mutable
# smolVM installation.
STATE_ROOT=$(mktemp -d /tmp/tf-smolvm.XXXXXX)
chmod 711 "$STATE_ROOT"
mkdir -p "$STATE_ROOT"/{cache,config,data,runtime,tmp}

status=0
TMPDIR="$STATE_ROOT/tmp" \
XDG_CACHE_HOME="$STATE_ROOT/cache" \
XDG_CONFIG_HOME="$STATE_ROOT/config" \
XDG_RUNTIME_DIR="$STATE_ROOT/runtime" \
SMOLVM_DATA_DIR="$STATE_ROOT/data" \
SMOLVM_BOOT_DEBUG=1 \
"$SMOLVM_DIR/smolvm" machine run \
    --image "$GUEST_ROOT" \
    --cpus 4 \
    --mem 6144 \
    --timeout 2400s \
    --no-init-cache \
    -- /usr/bin/env $(env | grep -E '^TF_ESP_EXIT_[A-Z_]+=[A-Za-z0-9.]*$' | tr '\n' ' ') \
    /opt/lab/guest-controller.sh "$STAGES" || status=$?

if test "$status" -ne 0; then
    echo "--- smolVM diagnostics ---" >&2
    find "$STATE_ROOT" -type f \( -name '*.log' -o -name '*.json' -o -name '*.error' \) -print | while read -r log; do
        echo "--- $log ---" >&2
        sed -n '1,260p' "$log" >&2 || true
    done
    fail "guest failed with status $status"
fi
echo "privileged-smolvm: ALL CHECKS PASSED"
