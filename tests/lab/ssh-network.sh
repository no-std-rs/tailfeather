#!/usr/bin/env bash
# Real tailscaled and Tailfeather behind two independent, filtering NAT routers.
# Every link, route, firewall rule and sysctl lives in a test-owned namespace.
set -euo pipefail
HEADSCALE=${1:?headscale binary}
TAILSCALE=${2:?tailscale binary}
TAILSCALED=${3:?tailscaled binary}
SERVER=${4:?Tailfeather live_server binary}
BASE_CONFIG=${5:?Headscale base configuration}
MODE=${6:-nat}
for tool in "$HEADSCALE" "$TAILSCALE" "$TAILSCALED" "$SERVER"; do
    test -x "$tool" || { echo "missing executable: $tool" >&2; exit 1; }
done
case "$MODE" in nat|udp-blocked|hard-nat) ;; *) echo "unknown network mode: $MODE" >&2; exit 2;; esac
WORK=$(mktemp -d "${TEST_TMPDIR:-/tmp}/tf-ssh-network.XXXXXX")
PREFIX=tfssh-$$-$RANDOM
NAMES=()
GROUPS_OWNED=()
ROOT=()
if test "$(id -u)" -ne 0; then ROOT=(sudo -n --preserve-env=TF_TEST_AUTH_KEY,TF_TEST_CA_DER,SSL_CERT_FILE,XDG_CONFIG_HOME); fi
ns() { "${ROOT[@]}" ip netns exec "$PREFIX-$1" "${@:2}"; }
fail() { echo "ssh-network: FAIL: $*" >&2; exit 1; }
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if test "$status" -ne 0; then
        for log in "$WORK"/*.log; do
            test -f "$log" || continue
            echo "--- $(basename "$log") ---" >&2
            tail -n 110 "$log" >&2
        done
        for router in cr sr; do ns "$router" iptables -vnL >&2 || true; done
    fi
    for group in "${GROUPS_OWNED[@]}"; do "${ROOT[@]}" kill -TERM -- "-$group" 2>/dev/null || true; done
    for name in "${NAMES[@]}"; do
        # Catch forked TLS proxy children as well as their original listeners.
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
    # Unsolicited UDP to an unmapped public port must be dropped before
    # conntrack confirmation. Accepting it as router-local traffic creates a
    # conflicting reverse tuple and spuriously forces a different SNAT port.
    ns "$router" iptables -P INPUT DROP
    ns "$router" iptables -A INPUT -i lo -j ACCEPT
    ns "$router" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$router" iptables -P FORWARD DROP
    ns "$router" iptables -N TF_PEER
    ns "$router" iptables -A FORWARD -p udp -j TF_PEER
    ns "$router" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$router" iptables -A FORWARD -i lan -o wan -j ACCEPT
    if test "$MODE" = hard-nat; then
        # Deterministic endpoint-dependent mapping: a STUN destination and a
        # peer destination always observe different public source ports.
        ns "$router" iptables -t nat -A POSTROUTING -p udp -d 198.18.0.1 -o wan -j SNAT --to-source "198.18.0.$public:4100$public"
        ns "$router" iptables -t nat -A POSTROUTING -p udp -o wan -j SNAT --to-source "198.18.0.$public:4200$public"
    fi
    ns "$router" iptables -t nat -A POSTROUTING -s "10.44.$subnet.0/24" -o wan -j SNAT --to-source "198.18.0.$public"
done
block_peers() {
    for router in cr sr; do
        ns "$router" iptables -F TF_PEER
        ns "$router" iptables -A TF_PEER -s 198.18.0.2 -j DROP
        ns "$router" iptables -A TF_PEER -d 198.18.0.2 -j DROP
        ns "$router" iptables -A TF_PEER -s 198.18.0.3 -j DROP
        ns "$router" iptables -A TF_PEER -d 198.18.0.3 -j DROP
    done
}
if test "$MODE" = udp-blocked; then
    for router in cr sr; do ns "$router" iptables -A TF_PEER -j DROP; done
elif test "$MODE" = nat; then block_peers; fi

mkdir -p "$WORK/hs" "$WORK/logs" "$WORK/config"
export XDG_CONFIG_HOME="$WORK/config"
# A private trust anchor exercises certificate verification on both peers.
# It is supplied to the normal Go verifier and Tailfeather's own TLS verifier.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj /CN=tf-ssh-network-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >"$WORK/cert.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj /CN=tf-ssh-network \
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
      - name: lab-primary
        regionid: 999
        hostname: 198.18.0.1
        ipv4: 198.18.0.1
        derpport: 8443
        stunport: 3479
      - name: lab-backup
        regionid: 999
        hostname: 198.18.0.1
        ipv4: 198.18.0.1
        derpport: 8443
        stunport: 3478
EOF
cat >"$WORK/policy.json" <<'EOF'
{"tagOwners":{"tag:client":[],"tag:server":[]},"acls":[{"action":"accept","src":["tag:client"],"dst":["tag:server:22"]}],"ssh":[{"action":"accept","src":["tag:client"],"dst":["tag:server"],"users":["console"]}]}
EOF
sed -e "s#/tmp/tailfeather-lab/headscale#$WORK/hs#g" \
    -e 's#http://127.0.0.1:8080#http://198.18.0.1:8080#' \
    -e 's/automatically_add_embedded_derp_region: true/automatically_add_embedded_derp_region: false/' \
    -e "s#paths: \[\]#paths: ['$WORK/derp.json']#" \
    -e "s#mode: database#mode: file\n  path: $WORK/policy.json#" \
    -e 's/level: debug/level: info/' "$BASE_CONFIG" >"$WORK/headscale.yaml"
printf '\nunix_socket: %s/headscale.sock\nunix_socket_permission: "0700"\n' "$WORK" >>"$WORK/headscale.yaml"
start wan headscale "$HEADSCALE" --config "$WORK/headscale.yaml" serve
# Health probes use the namespace's local route, without depending on host DNS.
for _ in $(seq 1 50); do
    if ns wan timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' 2>/dev/null; then break; fi
    sleep 0.2
done
HS=("$HEADSCALE" --config "$WORK/headscale.yaml")
USER_JSON=$(ns wan "${HS[@]}" users create network --output json)
USER_ID=$(printf '%s' "$USER_JSON" | tr -d '[:space:]' | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
test -n "$USER_ID" || fail 'could not create user'
CLIENT_JSON=$(ns wan "${HS[@]}" preauthkeys create --user "$USER_ID" --tags tag:client --expiration 10m --output json)
SERVER_JSON=$(ns wan "${HS[@]}" preauthkeys create --user "$USER_ID" --tags tag:server --expiration 10m --output json)
CLIENT_KEY=$(printf '%s' "$CLIENT_JSON" | tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
export TF_TEST_AUTH_KEY
TF_TEST_AUTH_KEY=$(printf '%s' "$SERVER_JSON" | tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
test -n "$CLIENT_KEY" && test -n "$TF_TEST_AUTH_KEY" || fail 'could not mint disposable keys'
start_relay() {
    start wan relay socat -b 37 "OPENSSL-LISTEN:8443,bind=198.18.0.1,reuseaddr,fork,cert=$WORK/server.pem,key=$WORK/server.key,verify=0,openssl-min-proto-version=TLS1.3" TCP:127.0.0.1:8080
    RELAY_PID=$LAST_PID
}
start_relay
start s control-proxy socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork TCP:198.18.0.1:8080
start c tailscaled env TS_NO_LOGS_NO_SUPPORT=1 TS_LOGS_DIR="$WORK/logs" "$TAILSCALED" \
    --tun=userspace-networking --socket="$WORK/tailscaled.sock" --statedir="$WORK/tailscale" --port=0
for _ in $(seq 1 100); do test -S "$WORK/tailscaled.sock" && break; sleep 0.1; done
test -S "$WORK/tailscaled.sock" || fail 'tailscaled socket missing'
CLIENT=("$TAILSCALE" "--socket=$WORK/tailscaled.sock")
# stdin, never argv or a key file, carries the single-use enrollment key.
printf '%s' "$CLIENT_KEY" | ns c timeout 45 "${CLIENT[@]}" up --login-server=http://198.18.0.1:8080 \
    --auth-key=file:/proc/self/fd/0 --hostname=nat-client --accept-dns=false --accept-routes=false
unset CLIENT_KEY CLIENT_JSON SERVER_JSON
SESSIONS=1
if test "$MODE" = nat; then SESSIONS=6; fi
if test -n "${TF_TEST_NETWORK_DEBUG:-}"; then
    start wan packets tcpdump -ln -i wan0 udp
fi
SERVER_ENV=()
if test -n "${TF_TEST_NETWORK_DEBUG:-}"; then SERVER_ENV=(env TF_TEST_NETWORK_DEBUG=1); fi
start s server "${SERVER_ENV[@]}" "$SERVER" 127.0.0.1:8080 10.44.2.2 "--sessions=$SESSIONS"
SERVER_PID=$LAST_PID
wait_log '^READY ' "$WORK/server.log"
ADDRESS=$(sed -n 's/^READY \([^ ]*\).*/\1/p' "$WORK/server.log" | head -1)
wait_log '^DERP_CONNECTED ' "$WORK/server.log"
if test "$MODE" = udp-blocked; then
    wait_log 'reflexive=None' "$WORK/server.log"
else
    wait_log '^STUN .*endpoint=198.18.0.3:' "$WORK/server.log"
    if test "$MODE" = hard-nat; then wait_log '^STUN .*endpoint=198.18.0.3:41003 ' "$WORK/server.log"; fi
    echo 'PASS STUN backup: primary port 3479 unavailable, backup 3478 answered'
fi
for _ in $(seq 1 100); do
    ns c "${CLIENT[@]}" status --json >"$WORK/status.json"
    if sed -n '/"sshHostKeys": \[/p' "$WORK/status.json" | read -r _; then break; fi
    sleep 0.1
done
# A stock client learns the host key from control and performs normal SSH.
ssh_roundtrip() {
    local number=$1 path=$2
    printf 'NAT console exchange %s\n' "$number" | ns c timeout 40 "${CLIENT[@]}" ssh "console@$ADDRESS" >"$WORK/ssh-$number.log" 2>&1
    tr -d '\r' <"$WORK/ssh-$number.log" >"$WORK/ssh-$number.txt"
    sed -n '/^Tailfeather live console$/p' "$WORK/ssh-$number.txt" | read -r _ || fail 'greeting missing'
    sed -n "/^NAT console exchange $number\$/p" "$WORK/ssh-$number.txt" | read -r _ || fail 'echo missing'
    wait_log "^DRAINED $number\$" "$WORK/server.log"
    local metrics direct relay
    metrics=$(sed -n '/^PATH_BYTES /p' "$WORK/server.log" | tail -1)
    direct=$(printf '%s' "$metrics" | sed -n 's/.*direct=\([0-9]*\).*/\1/p')
    relay=$(printf '%s' "$metrics" | sed -n 's/.*relay=\([0-9]*\).*/\1/p')
    if test "$path" = direct; then test "$direct" -gt 0 || fail 'SSH did not deliver authenticated IPv4 directly';
    else test "$direct" -eq 0 && test "$relay" -gt 0 || fail 'SSH bypassed the required relay path'; fi
    echo "PASS $MODE SSH #$number path=$path $metrics"
}
ssh_roundtrip 1 relay
if test "$MODE" = nat; then
    for router in cr sr; do ns "$router" iptables -F TF_PEER; done
    ns c timeout 35 "${CLIENT[@]}" ping --c=25 --timeout=1s "$ADDRESS" >"$WORK/punch.log" 2>&1
    sed -n '/via 198\.18\.0\.3:/p' "$WORK/punch.log" | read -r _ || fail 'no translated direct endpoint after punching'
    echo 'PASS STUN endpoint publication + bilateral hole punching to 198.18.0.3'
    ssh_roundtrip 2 direct
    block_peers
    ssh_roundtrip 3 relay
    connections=$(sed -n '/^DERP_CONNECTED /p' "$WORK/server.log" | wc -l)
    "${ROOT[@]}" kill -TERM -- "-$RELAY_PID"
    sleep 0.5
    start_relay
    for _ in $(seq 1 100); do
        current=$(sed -n '/^DERP_CONNECTED /p' "$WORK/server.log" | wc -l)
        test "$current" -gt "$connections" && break
        sleep 0.2
    done
    test "$current" -gt "$connections" || fail 'relay did not reconnect after transport loss'
    ssh_roundtrip 4 relay
    for router in cr sr; do ns "$router" iptables -F TF_PEER; done
    ns c timeout 35 "${CLIENT[@]}" ping --c=25 --timeout=1s "$ADDRESS" >"$WORK/recover.log" 2>&1
    sed -n '/via 198\.18\.0\.3:/p' "$WORK/recover.log" | read -r _ || fail 'direct path did not recover'
    ssh_roundtrip 5 direct
    # Expire the existing UDP conntrack mappings, then force a different public
    # source port. The server must discover and publish it without restarting.
    local_port=$(sed -n 's/^UDP_BOUND local=10\.44\.2\.2:\([0-9]*\).*/\1/p' "$WORK/server.log" | head -1)
    test -n "$local_port" || fail 'missing bound UDP socket address'
    ns sr iptables -t nat -I POSTROUTING 1 -p udp --sport "$local_port" -o wan -j SNAT --to-source 198.18.0.3:46000
    for router in cr sr; do
        ns "$router" sysctl -qw net.netfilter.nf_conntrack_udp_timeout=1
        ns "$router" sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=1
    done
    wait_log '^PUBLISHED .*198.18.0.3:46000' "$WORK/server.log"
    ns c timeout 35 "${CLIENT[@]}" ping --c=25 --timeout=1s "$ADDRESS" >"$WORK/rebind.log" 2>&1
    sed -n '/via 198\.18\.0\.3:46000/p' "$WORK/rebind.log" | read -r _ || fail 'NAT rebinding did not establish the new direct endpoint'
    ssh_roundtrip 6 direct
    echo 'PASS NAT rebinding: refreshed STUN endpoint, control publication and renewed hole punching'
fi
wait "$SERVER_PID"
if sed -n '/^SESSION /{/^SESSION Ok(())$/d;/^SESSION Err(Transport(UnexpectedEof))$/d;p;}' "$WORK/server.log" | read -r _; then
    fail 'SSH server reported an unexpected session error'
fi
# Print protocol/path evidence, without private identity or enrollment material.
sed -n -e '/^STUN /p' -e '/^DISCOVERY /p' -e '/^DERP_.*CONNECTED /p' -e '/^PATH_BYTES /p' -e '/^SESSION /p' "$WORK/server.log"
echo "PASS ssh-network mode=$MODE: default Tailscale SSH, verified TLS, host key and application output"
