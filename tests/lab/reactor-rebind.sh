#!/usr/bin/env bash
# Real tailscaled observes the shared reactor runtime across a NAT rebinding.
#
# Both nodes sit behind independent, filtering NAT routers. Once a stock
# client has a direct path, the reactor node's public UDP mapping changes
# mid-session (old mapping removed, new external port). The node must notice
# with its own periodic STUN sweep and publish the new endpoint through its
# existing map session, so the stock client reaches it directly at the new
# port within REBIND_BOUND seconds: well under Headscale's map keepalive
# interval (50-59 s), which must not be what triggers the publication.
set -euo pipefail
HEADSCALE=${1:?headscale binary}
TAILSCALE=${2:?tailscale binary}
TAILSCALED=${3:?tailscaled binary}
NODE=${4:?Tailfeather reactor lab_node binary}
BASE_CONFIG=${5:?Headscale base configuration}
CONNTRACK=${6:-conntrack}
REBIND_BOUND=${TF_TEST_REBIND_BOUND:-40}
NEW_PORT=46000
for tool in "$HEADSCALE" "$TAILSCALE" "$TAILSCALED" "$NODE"; do
    test -x "$tool" || { echo "missing executable: $tool" >&2; exit 1; }
done
WORK=$(mktemp -d "${TEST_TMPDIR:-/tmp}/tf-reactor-rebind.XXXXXX")
PREFIX=tfrb-$$-$RANDOM
NAMES=()
GROUPS_OWNED=()
ROOT=()
if test "$(id -u)" -ne 0; then ROOT=(sudo -n --preserve-env=TF_TEST_AUTH_KEY,TF_TEST_CA_DER,SSL_CERT_FILE,XDG_CONFIG_HOME); fi
ns() { "${ROOT[@]}" ip netns exec "$PREFIX-$1" "${@:2}"; }
fail() { echo "reactor-rebind: FAIL: $*" >&2; exit 1; }
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if test "$status" -ne 0; then
        for log in "$WORK"/*.log; do
            test -f "$log" || continue
            echo "--- $(basename "$log") ---" >&2
            tail -n 80 "$log" >&2
        done
        for router in cr sr; do ns "$router" iptables -t nat -vnL POSTROUTING >&2 || true; done
    fi
    for group in "${GROUPS_OWNED[@]}"; do "${ROOT[@]}" kill -TERM -- "-$group" 2>/dev/null || true; done
    for name in "${NAMES[@]}"; do
        for pid in $("${ROOT[@]}" ip netns pids "$name" 2>/dev/null); do "${ROOT[@]}" kill "$pid" 2>/dev/null || true; done
    done
    for name in "${NAMES[@]}"; do "${ROOT[@]}" ip netns delete "$name" 2>/dev/null || true; done
    "${ROOT[@]}" rm -rf -- "$WORK"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
start() {
    local space=$1 name=$2; shift 2
    setsid "${ROOT[@]}" ip netns exec "$PREFIX-$space" "$@" >"$WORK/$name.log" 2>&1 &
    LAST_PID=$!
    GROUPS_OWNED+=("$LAST_PID")
}
wait_log() {
    local pattern=$1 file=$2
    for _ in $(seq 1 300); do
        if test -f "$file" && sed -n "/$pattern/p" "$file" | head -1 | read -r _; then return; fi
        sleep 0.2
    done
    fail "timed out waiting for $pattern in $(basename "$file")"
}

# Topology: c (stock tailscaled) -- cr ==wan== sr -- s (reactor node), with
# Headscale, its DERP/STUN server and a TLS front on the wan bridge.
for name in wan cr sr c s; do
    "${ROOT[@]}" ip netns add "$PREFIX-$name"
    NAMES+=("$PREFIX-$name")
    ns "$name" ip link set lo up
done
ns wan ip link add wan0 type bridge
ns wan ip addr add 198.18.0.1/24 dev wan0
ns wan ip link set wan0 up
for side in c s; do
    if test "$side" = c; then router=cr; subnet=1; public=2; else router=sr; subnet=2; public=3; fi
    ns wan ip link add "port-$side" type veth peer name wan netns "$PREFIX-$router"
    ns wan ip link set "port-$side" master wan0
    ns wan ip link set "port-$side" up
    ns "$router" ip addr add "198.18.0.$public/24" dev wan
    ns "$router" ip link set wan up
    ns "$router" ip link add lan type veth peer name eth0 netns "$PREFIX-$side"
    ns "$router" ip addr add "10.44.$subnet.1/24" dev lan
    ns "$router" ip link set lan up
    ns "$side" ip addr add "10.44.$subnet.2/24" dev eth0
    ns "$side" ip link set eth0 up
    ns "$side" ip route add default via "10.44.$subnet.1"
    ns "$router" sysctl -qw net.ipv4.ip_forward=1
    # Endpoint-independent mapping, address-dependent filtering: unsolicited
    # UDP to a public port is dropped before conntrack confirmation.
    ns "$router" iptables -P INPUT DROP
    ns "$router" iptables -A INPUT -i lo -j ACCEPT
    ns "$router" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$router" iptables -P FORWARD DROP
    ns "$router" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$router" iptables -A FORWARD -i lan -o wan -j ACCEPT
    ns "$router" iptables -t nat -A POSTROUTING -s "10.44.$subnet.0/24" -o wan -j SNAT --to-source "198.18.0.$public"
done

mkdir -p "$WORK/hs" "$WORK/logs" "$WORK/config" "$WORK/node"
export XDG_CONFIG_HOME="$WORK/config"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj /CN=tf-reactor-rebind-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >"$WORK/cert.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj /CN=tf-reactor-rebind \
    -keyout "$WORK/server.key" -out "$WORK/server.csr" >>"$WORK/cert.log" 2>&1
cat >"$WORK/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:198.18.0.1
EOF
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 1 -sha256 -extfile "$WORK/server.ext" -out "$WORK/server.pem" >>"$WORK/cert.log" 2>&1
openssl x509 -in "$WORK/ca.pem" -outform DER -out "$WORK/ca.der"
export SSL_CERT_FILE="$WORK/ca.pem" TF_TEST_CA_DER="$WORK/ca.der"
cat >"$WORK/derp.json" <<'EOF'
regions:
  999:
    regionid: 999
    regioncode: lab
    regionname: NAT lab
    nodes:
      - name: lab
        regionid: 999
        hostname: 198.18.0.1
        ipv4: 198.18.0.1
        derpport: 8443
        stunport: 3478
EOF
sed -e "s#/tmp/tailfeather-lab/headscale#$WORK/hs#g" \
    -e 's#http://127.0.0.1:8080#http://198.18.0.1:8080#' \
    -e 's/automatically_add_embedded_derp_region: true/automatically_add_embedded_derp_region: false/' \
    -e "s#paths: \[\]#paths: ['$WORK/derp.json']#" \
    -e 's/level: debug/level: info/' "$BASE_CONFIG" >"$WORK/headscale.yaml"
printf '\nunix_socket: %s/headscale.sock\nunix_socket_permission: "0700"\n' "$WORK" >>"$WORK/headscale.yaml"
start wan headscale "$HEADSCALE" --config "$WORK/headscale.yaml" serve
for _ in $(seq 1 50); do
    if ns wan timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' 2>/dev/null; then break; fi
    sleep 0.2
done
# Verified TLS for both control (the reactor node) and DERP (both nodes).
start wan tls socat "OPENSSL-LISTEN:8443,bind=198.18.0.1,reuseaddr,fork,cert=$WORK/server.pem,key=$WORK/server.key,verify=0,openssl-min-proto-version=TLS1.3" TCP:127.0.0.1:8080
HS=("$HEADSCALE" --config "$WORK/headscale.yaml")
USER_JSON=$(ns wan "${HS[@]}" users create rebind --output json)
USER_ID=$(printf '%s' "$USER_JSON" | tr -d '[:space:]' | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
test -n "$USER_ID" || fail 'could not create user'
CLIENT_JSON=$(ns wan "${HS[@]}" preauthkeys create --user "$USER_ID" --ephemeral --expiration 10m --output json)
NODE_JSON=$(ns wan "${HS[@]}" preauthkeys create --user "$USER_ID" --ephemeral --expiration 10m --output json)
CLIENT_KEY=$(printf '%s' "$CLIENT_JSON" | tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
export TF_TEST_AUTH_KEY
TF_TEST_AUTH_KEY=$(printf '%s' "$NODE_JSON" | tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
test -n "$CLIENT_KEY" && test -n "$TF_TEST_AUTH_KEY" || fail 'could not mint disposable keys'
start c tailscaled env TS_NO_LOGS_NO_SUPPORT=1 TS_LOGS_DIR="$WORK/logs" "$TAILSCALED" \
    --tun=userspace-networking --socket="$WORK/tailscaled.sock" --statedir="$WORK/tailscale" --port=0
for _ in $(seq 1 100); do test -S "$WORK/tailscaled.sock" && break; sleep 0.1; done
test -S "$WORK/tailscaled.sock" || fail 'tailscaled socket missing'
CLIENT=("$TAILSCALE" "--socket=$WORK/tailscaled.sock")
printf '%s' "$CLIENT_KEY" | ns c timeout 45 "${CLIENT[@]}" up --login-server=http://198.18.0.1:8080 \
    --auth-key=file:/proc/self/fd/0 --hostname=stock-client --accept-dns=false --accept-routes=false
unset CLIENT_KEY CLIENT_JSON NODE_JSON
start s node "$NODE" https://198.18.0.1:8443 "$WORK/node" --timeout-seconds=280
NODE_PID=$LAST_PID
wait_log '^READY ' "$WORK/node.log"
ADDRESS=$(sed -n 's/^READY \([^ ]*\).*/\1/p' "$WORK/node.log" | head -1)
LOCAL_PORT=$(sed -n 's/^UDP_BOUND port=\([0-9]*\)$/\1/p' "$WORK/node.log" | head -1)
test -n "$ADDRESS" && test -n "$LOCAL_PORT" || fail 'node address or UDP port missing'
unset TF_TEST_AUTH_KEY

# Probe exactly as an operator would: one disco ping at a time, reporting the
# path the stock client currently uses.
direct_path() {
    local pattern=$1 seconds=$2 deadline output
    deadline=$((SECONDS + seconds))
    while test "$SECONDS" -lt "$deadline"; do
        output=$(ns c timeout 5 "${CLIENT[@]}" ping --c=1 --timeout=2s --until-direct=false "$ADDRESS" 2>&1 || true)
        printf '%s\n' "$output" >>"$WORK/ping.log"
        if printf '%s\n' "$output" | sed -n "/via $pattern/p" | read -r _; then
            printf '%s\n' "$output"
            return 0
        fi
        sleep 0.5
    done
    return 1
}
INITIAL=$(direct_path '198\.18\.0\.3:[0-9][0-9]*' 90) || fail 'no initial direct path to the reactor node'
OLD_PORT=$(printf '%s\n' "$INITIAL" | sed -n 's/.*via 198\.18\.0\.3:\([0-9]*\).*/\1/p' | head -1)
test -n "$OLD_PORT" && test "$OLD_PORT" != "$NEW_PORT" || fail "unexpected initial mapping: $INITIAL"
echo "PASS initial direct path via 198.18.0.3:$OLD_PORT"

# Rebind: new flows from the node's socket get a different external port and
# the old mapping disappears, exactly as a NAT that lost its state would.
ns sr iptables -t nat -I POSTROUTING 1 -p udp -s 10.44.2.2 --sport "$LOCAL_PORT" -o wan \
    -j SNAT --to-source "198.18.0.3:$NEW_PORT"
REBOUND_AT=$SECONDS
ns sr "$CONNTRACK" -D -p udp --orig-src 10.44.2.2 --sport "$LOCAL_PORT" >"$WORK/conntrack.log" 2>&1 || {
    sed -n '/flow entries have been deleted/p' "$WORK/conntrack.log" | read -r _ || fail 'could not remove the old UDP mapping'
}
REBOUND=$(direct_path "198\\.18\\.0\\.3:$NEW_PORT" "$REBIND_BOUND") ||
    fail "stock client saw no direct path via 198.18.0.3:$NEW_PORT within ${REBIND_BOUND}s of the NAT rebinding"
echo "PASS NAT rebinding observed after $((SECONDS - REBOUND_AT))s (bound ${REBIND_BOUND}s): $REBOUND"
kill -0 "$NODE_PID" 2>/dev/null && ! sed -n '/panicked/p' "$WORK/node.log" | read -r _ ||
    fail 'the reactor node did not survive the rebinding'
echo "PASS reactor-rebind: STUN re-sweep, in-session endpoint publication and renewed direct path"
