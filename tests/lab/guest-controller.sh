#!/bin/sh
set -eu

STATE=/tmp/tailfeather-lab
mkdir -p "$STATE/headscale" "$STATE/tailscale" "$STATE/tls-rsa"
fail() { echo "guest-controller: FAIL: $*" >&2; exit 1; }

# Comma-separated stage names, or "all". See the stage list at the bottom.
STAGES=${1:-all}
want() {
    test "$STAGES" = all && return 0
    case ",$STAGES," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}
want_any() {
    for wanted in "$@"; do want "$wanted" && return 0; done
    return 1
}
# Every requested stage runs even after another one failed, so one run
# reports every regression instead of only the first.
RESULTS="$STATE/stage-results"
: >"$RESULTS"
stage() {
    name=$1 budget=$2
    shift 2
    want "$name" || return 0
    echo "guest-controller: running $name"
    started=$(date +%s)
    if timeout "$budget" "$@" >"$STATE/$name.log" 2>&1; then
        result=PASS
    else
        result="FAIL(exit $?)"
    fi
    elapsed=$(($(date +%s) - started))
    echo "$name $result ${elapsed}s/${budget}s" >>"$RESULTS"
    echo "guest-controller: $name $result in ${elapsed}s"
}

diagnostics() {
    status=$?
    trap - EXIT
    echo "--- guest capability state ---" >&2
    uname -a >&2 || true
    ip link show >&2 || true
    ip netns list >&2 || true
    wg show all >&2 || true
    for log in "$STATE"/*.log; do
        test -f "$log" || continue
        echo "--- $log ---" >&2
        sed -n '1,260p' "$log" >&2 || true
    done
    pkill tailscaled 2>/dev/null || true
    pkill headscale 2>/dev/null || true
    pkill socat 2>/dev/null || true
    ip netns delete tf-preflight 2>/dev/null || true
    exit "$status"
}
trap diagnostics EXIT HUP INT TERM

echo "guest-controller: checking kernel networking capabilities"
# The host staging step unpacked all checksum-pinned APK payloads before boot;
# the guest remains offline and does not need a writable package database.
command -v ip >/dev/null || fail "iproute2 is unavailable"
command -v wg >/dev/null || fail "wireguard-tools is unavailable"
# smolVM supplies the TUN-capable kernel but its workload container owns a
# fresh /dev. Materialize the standard device node inside that disposable view.
if ! test -c /dev/net/tun; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 || fail "cannot materialize /dev/net/tun"
fi
test -c /dev/net/tun || fail "/dev/net/tun is unavailable"

# Tailscale deliberately pauses its control client when no non-loopback
# interface is up. smolVM's offline guest has a dummy underlay, so give it a
# documentation-only address without adding an external route.
ip address replace 192.0.2.1/32 dev dummy0
ip link set dummy0 up

ip netns add tf-preflight || fail "network namespaces are unavailable"
ip link add tf-veth-host type veth peer name tf-veth-guest || fail "veth devices are unavailable"
ip link set tf-veth-guest netns tf-preflight || fail "veth cannot enter a network namespace"
ip netns exec tf-preflight ip link add wg-preflight type wireguard || fail "kernel WireGuard is unavailable"
ip netns exec tf-preflight ip link delete wg-preflight
ip link delete tf-veth-host
ip netns delete tf-preflight

if want_any conformance wg-example wg-harness-responder wg-harness-initiator wg-harness-rekey nostd-interop; then
echo "guest-controller: starting headscale"
/opt/lab/headscale serve --config /opt/lab/headscale.yaml >"$STATE/headscale.log" 2>&1 &
for _ in $(seq 1 30); do
    wget -q -O /dev/null http://127.0.0.1:8080/health 2>/dev/null && break
    sleep 1
done
timeout 10 wget -q -O /dev/null http://127.0.0.1:8080/health
timeout 30 /opt/lab/headscale users create conformance --config /opt/lab/headscale.yaml >/dev/null 2>&1 || true
USER_ID=$(timeout 30 /opt/lab/headscale users list --config /opt/lab/headscale.yaml --output json | tr -d '[:space:]' | sed -n 's/.*"id":\([0-9][0-9]*\).*"name":"conformance".*/\1/p' | head -1)
test -n "$USER_ID"
AUTH_JSON=$(timeout 30 /opt/lab/headscale preauthkeys create --config /opt/lab/headscale.yaml --user "$USER_ID" --reusable --expiration 24h --output json | tr -d '[:space:]')
AUTH_KEY=$(printf '%s' "$AUTH_JSON" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
test -n "$AUTH_KEY"

echo "guest-controller: creating the TLS front"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$STATE/tls-rsa/ca.key" 2>/dev/null
openssl req -x509 -new -key "$STATE/tls-rsa/ca.key" -sha256 -days 1 \
    -subj /CN=tailfeather-lab \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "$STATE/tls-rsa/ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$STATE/tls-rsa/server.key" 2>/dev/null
openssl req -new -key "$STATE/tls-rsa/server.key" -subj /CN=localhost -out "$STATE/tls-rsa/server.csr"
cat >"$STATE/tls-rsa/server.ext" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF
openssl x509 -req -in "$STATE/tls-rsa/server.csr" \
    -CA "$STATE/tls-rsa/ca.crt" -CAkey "$STATE/tls-rsa/ca.key" -CAcreateserial \
    -days 1 -sha256 -extfile "$STATE/tls-rsa/server.ext" -out "$STATE/tls-rsa/server.crt"
cat "$STATE/tls-rsa/server.crt" "$STATE/tls-rsa/server.key" >"$STATE/tls-rsa/server.pem"
socat "OPENSSL-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork,cert=$STATE/tls-rsa/server.pem,cafile=$STATE/tls-rsa/ca.crt,verify=0,openssl-min-proto-version=TLS1.3" TCP:127.0.0.1:8080 >"$STATE/tls.log" 2>&1 &
for _ in $(seq 1 30); do
    timeout 2 openssl s_client -connect 127.0.0.1:8443 -servername localhost \
        -CAfile "$STATE/tls-rsa/ca.crt" -sigalgs rsa_pss_rsae_sha256 \
        </dev/null >/dev/null 2>&1 && break
    sleep 1
done
timeout 5 openssl s_client -connect 127.0.0.1:8443 -servername localhost \
    -CAfile "$STATE/tls-rsa/ca.crt" -sigalgs rsa_pss_rsae_sha256 \
    </dev/null >/dev/null 2>&1 || fail "TLS front is unavailable"

echo "guest-controller: registering the reference tailscale client"
HOME="$STATE" TS_NO_LOGS_NO_SUPPORT=1 TS_DEBUG_MAP=1 \
    /opt/lab/tailscaled --tun=tailscale0 --socket="$STATE/tailscaled.sock" --statedir="$STATE/tailscale" --port=0 >"$STATE/tailscaled.log" 2>&1 &
for _ in $(seq 1 60); do test -S "$STATE/tailscaled.sock" && break; sleep 1; done
test -S "$STATE/tailscaled.sock"
timeout 60 /opt/lab/tailscale --socket="$STATE/tailscaled.sock" up --login-server=http://127.0.0.1:8080 --auth-key="$AUTH_KEY" --hostname=reference-client --accept-routes=false
ip link show tailscale0

cat >"$STATE/doctor.json" <<'EOF'
{"headscale":true,"headscale_version":"0.29.3","headscale_image":"pinned-static-binary","headscale_reason":"","tailscaled_installed":true,"reference_client":true,"harness_built":true,"passwordless_sudo":true,"tls_front":true}
EOF

# Env::discover intentionally reads the live lab contract from .lab/lab.env.
# Recreate that repository-relative shape under writable guest state.
CONFORMANCE_ROOT="$STATE/conformance-root"
mkdir -p "$CONFORMANCE_ROOT/tests/vectors" "$CONFORMANCE_ROOT/.lab/tls-rsa" "$CONFORMANCE_ROOT/scripts"
cp -R /opt/lab/vectors/. "$CONFORMANCE_ROOT/tests/vectors/"
cp /opt/lab/interop-wireguard.sh "$CONFORMANCE_ROOT/scripts/interop-wireguard.sh"
cp /opt/lab/nostd-interop.sh "$CONFORMANCE_ROOT/scripts/nostd-interop.sh"
chmod 755 "$CONFORMANCE_ROOT/scripts"/*.sh
ln -s "$STATE/tailscaled.sock" "$CONFORMANCE_ROOT/.lab/tailscaled.sock"
cat >"$CONFORMANCE_ROOT/.lab/lab.env" <<EOF
HEADSCALE_URL=http://192.0.2.1:8080
HEADSCALE_USER=conformance
HEADSCALE_PREAUTH_KEY=$AUTH_KEY
HEADSCALE_VERSION=v0.29.3
EOF
openssl x509 -in "$STATE/tls-rsa/ca.crt" -outform DER -out "$CONFORMANCE_ROOT/.lab/tls-rsa/ca.der"

# The conformance runner normally asks Headscale for server-side state through
# `podman exec`. In this single-purpose guest Headscale is a direct process, so
# adapt the same command contract without a container daemon.
cat >"$STATE/headscale-runtime" <<'EOF'
#!/bin/sh
test "$1" = exec && test "$2" = headscale-lab && test "$3" = headscale || exit 2
shift 3
exec /opt/lab/headscale "$@" --config /opt/lab/headscale.yaml
EOF
chmod 755 "$STATE/headscale-runtime"

# Live disco checks use the same sudo-shaped command contract as the developer
# lab. The disposable guest already runs as root, so only the `-n` adapter and
# the pinned CLI's location are needed.
mkdir -p "$STATE/bin"
cat >"$STATE/bin/sudo" <<'EOF'
#!/bin/sh
test "$1" = -n || exit 2
shift
exec "$@"
EOF
chmod 755 "$STATE/bin/sudo"

export PATH="$STATE/bin:/opt/lab:$PATH"
export CONTAINER_RUNTIME="$STATE/headscale-runtime"
export TS_CONFORMANCE_HARNESS=/opt/lab/harness
export TS_CONFORMANCE_VECTORS="$CONFORMANCE_ROOT/tests/vectors/versions.json"
export TS_CONFORMANCE_EXPECTATIONS=/opt/lab/lab.json
export TS_CONFORMANCE_LAB_STATE="$STATE"
fi

# Stages sharing the host-level lab (Headscale on 127.0.0.1, tailscale0, the
# reference client) run one after another.
stage conformance 360 /opt/lab/conformance --expect /opt/lab/lab.json
stage wg-example 30 /opt/lab/interop-wireguard.sh example-responder /opt/lab/responder
stage wg-harness-responder 30 /opt/lab/interop-wireguard.sh harness-responder /opt/lab/harness
stage wg-harness-initiator 30 /opt/lab/interop-wireguard.sh harness-initiator /opt/lab/harness
stage wg-harness-rekey 30 /opt/lab/interop-wireguard.sh harness-rekey /opt/lab/harness
if want nostd-interop; then
    stage nostd-interop 180 "$CONFORMANCE_ROOT/scripts/nostd-interop.sh" /opt/lab/harness
fi

# Every stage below builds its own namespaces, Headscale and DERP, so they run
# concurrently: the phase takes as long as its slowest stage, not their sum.
NETWORK="/opt/lab/headscale /opt/lab/tailscale /opt/lab/tailscaled"
# Only these jobs are awaited: Headscale, the TLS front and the reference
# client are background jobs of this shell too, and never exit.
JOBS=""
for mode in nat udp-blocked hard-nat; do
    budget=220
    if test "$mode" = udp-blocked; then budget=540; fi
    # shellcheck disable=SC2086
    stage "ssh-$mode" "$budget" bash /opt/lab/ssh-network.sh $NETWORK \
        /opt/lab/ssh-server /opt/lab/headscale.yaml "$mode" &
    JOBS="$JOBS $!"
done
# shellcheck disable=SC2086
stage reactor-rebind 300 bash /opt/lab/reactor-rebind.sh $NETWORK \
    /opt/lab/reactor-node /opt/lab/headscale.yaml /usr/sbin/conntrack &
JOBS="$JOBS $!"
(
    export TF_NAT_JOBS="${TF_NAT_JOBS:-6}" TF_NAT_CONNTRACK=/usr/sbin/conntrack \
        TF_NAT_SSH_SERVER=/opt/lab/ssh-server
    # shellcheck disable=SC2086
    stage nat-matrix 1200 bash /opt/lab/nat-matrix.sh matrix $NETWORK \
        /opt/lab/reactor-node /opt/lab/headscale.yaml
) &
JOBS="$JOBS $!"
# shellcheck disable=SC2086
wait $JOBS

trap - EXIT HUP INT TERM
echo "--- stage summary ---"
sort "$RESULTS" | awk '{ printf "  %-22s %-14s %s\n", $1, $2, $3 }'
test -s "$RESULTS" || { echo "guest-controller: FAIL: no stage matched '$STAGES'" >&2; exit 1; }
diagnostics_status=0
if grep -q ' FAIL' "$RESULTS"; then diagnostics_status=1; fi
# The matrix report (its table, then the logs of any failing run) is the
# evidence a reviewer wants whether it passed or not.
if test -f "$STATE/nat-matrix.log"; then sed -n '/^== NAT matrix/,$p' "$STATE/nat-matrix.log" | head -n 600; fi
(exit "$diagnostics_status")
diagnostics
