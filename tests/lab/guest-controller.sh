#!/bin/sh
set -eu

STATE=/tmp/tailfeather-lab
mkdir -p "$STATE/headscale" "$STATE/tailscale" "$STATE/tls-rsa"
fail() { echo "guest-controller: FAIL: $*" >&2; exit 1; }

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
echo "guest-controller: running live conformance"
timeout 360 /opt/lab/conformance --expect /opt/lab/lab.json >"$STATE/conformance.log" 2>&1

echo "guest-controller: running WireGuard example-responder interop"
timeout 30 /opt/lab/interop-wireguard.sh example-responder /opt/lab/responder >"$STATE/wg-example.log" 2>&1
echo "guest-controller: running WireGuard harness-responder interop"
timeout 30 /opt/lab/interop-wireguard.sh harness-responder /opt/lab/harness >"$STATE/wg-harness-responder.log" 2>&1
echo "guest-controller: running WireGuard harness-initiator interop"
timeout 30 /opt/lab/interop-wireguard.sh harness-initiator /opt/lab/harness >"$STATE/wg-harness-initiator.log" 2>&1
echo "guest-controller: running WireGuard harness rekey interop"
timeout 30 /opt/lab/interop-wireguard.sh harness-rekey /opt/lab/harness >"$STATE/wg-harness-rekey.log" 2>&1
echo "guest-controller: running no-std WireGuard interop"
timeout 180 "$CONFORMANCE_ROOT/scripts/nostd-interop.sh" /opt/lab/harness >"$STATE/nostd-interop.log" 2>&1

for mode in nat udp-blocked hard-nat; do
    echo "guest-controller: running SSH network acceptance ($mode)"
    budget=220
    if test "$mode" = udp-blocked; then budget=540; fi
    timeout "$budget" bash /opt/lab/ssh-network.sh /opt/lab/headscale /opt/lab/tailscale /opt/lab/tailscaled \
        /opt/lab/ssh-server /opt/lab/headscale.yaml "$mode" >"$STATE/ssh-network-$mode.log" 2>&1
done

trap - EXIT HUP INT TERM
diagnostics
