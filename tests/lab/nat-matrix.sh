#!/usr/bin/env bash
# Differential NAT-traversal matrix: Tailfeather against the official client.
#
# Every scenario is run twice behind byte-identical network topologies. Side A
# is always a stock tailscaled, the observer. Side B is either a second stock
# tailscaled (the baseline: what the official client achieves) or the
# Tailfeather reactor node (the candidate). The observer reports the path it
# uses to B, so both runs are measured by the same, unmodified implementation
# and only through the standard disco/DERP/WireGuard protocols.
#
# The verdict is relative, not a hardcoded table: wherever the official
# client gets a direct path, Tailfeather must get one too, and no slower than
# the baseline plus a small tolerance. Where the official client has to relay,
# Tailfeather must still deliver through DERP.
#
#   nat-matrix.sh matrix   HEADSCALE TAILSCALE TAILSCALED NODE BASE_CONFIG
#   nat-matrix.sh one      HEADSCALE TAILSCALE TAILSCALED NODE BASE_CONFIG SCENARIO PEER
#   nat-matrix.sh list
#
# Every scenario owns its namespaces, its Headscale and its DERP/STUN server,
# so all runs execute in parallel (TF_NAT_JOBS, default: CPU count).
#
# NAT profiles (all with stateful, address+port-dependent filtering, which is
# what Linux conntrack and nearly every home router do):
#   public   host owns a public address, no NAT, no firewall
#   easy     endpoint-independent mapping, port preserved (typical home router)
#   cone     endpoint-independent mapping and filtering (full cone): any
#            outside host may send to a mapped port
#   hard     endpoint-dependent mapping: a fresh random port per destination
#            (symmetric NAT, typical of carrier-grade and enterprise NATs)
#   blocked  all UDP dropped (DERP over TCP is the only path)
#   cgnat    easy home NAT behind a second, carrier-grade easy NAT
set -euo pipefail

SCENARIOS=(
    lan            # both peers behind the same router: direct over the LAN
    public-public
    easy-public
    public-easy
    easy-easy
    cone-hard      # the hard side's per-flow port is learned from its ping
    hard-cone      # ... so a ping from an unknown source must be answered
    easy-hard
    hard-easy
    public-hard
    hard-public
    hard-hard      # the official client relays; we must deliver through DERP
    cgnat-easy
    easy-cgnat
    easy-blocked
    blocked-easy
    # Mid-session events, after the first direct path is established:
    #   +outage  all peer-to-peer UDP is cut, then restored: fail over to
    #            DERP without losing the session, then return to direct
    #   +rebind  B's outermost NAT moves B to a new public port (state loss,
    #            CGNAT port reassignment): the observer must reach the new port
    easy-easy+outage
    public-hard+outage
    cgnat-easy+outage
    easy-easy+rebind
    public-easy+rebind
    easy-cgnat+rebind
    #   +bulk     bulk TCP both ways over the established path; the observer
    #             uses a real TUN and the kernel's TCP, so it is never the
    #             bottleneck. +bulk-wan adds 20 ms of round trip first.
    lan+bulk
    easy-easy+bulk
    easy-easy+bulk-wan
    easy-blocked+bulk  # DERP relay throughput
    #   +ssh      Tailscale SSH from the stock client: session setup time and
    #             pasted-input echo throughput. Tailfeather serves its SSH
    #             console (TF_NAT_SSH_SERVER), the official client its own
    #             SSH server running `cat`; both echo as input arrives.
    easy-easy+ssh
    easy-blocked+ssh
)
# Where the official client cannot get a direct path either. Everywhere else
# the baseline itself must go direct and measure every event metric: a broken
# topology would otherwise fail both sides equally and pass unnoticed.
RELAY_EXPECTED=" easy-hard hard-easy hard-hard easy-blocked blocked-easy "
# Timing metrics compared between the official client and Tailfeather.
METRICS=(direct_s failover_s recovery_s rebind_s ssh_s)
# Throughput metrics (Mbit/s, higher is better) from the +bulk events.
# Each rate passes if it is within SLACK_RATE_PERCENT of the official client
# either in raw throughput or per CPU core (the field named like the rate
# with _cpu, 100 = one core): Tailfeather runs one packet thread, while the
# official client spreads WireGuard over every core it can take.
# SSH paste_kbps is reported, not gated: the Tailfeather SSH console grants
# input one small chunk per round trip to keep fixed, microcontroller-sized
# memory.
RATES=(up_mbps down_mbps)
PEERS=(stock tailfeather)
DIRECT_BUDGET=${TF_NAT_DIRECT_BUDGET:-45}
HOLD=${TF_NAT_HOLD:-8}
# Candidate may be this much slower than the baseline (seconds and percent),
# absorbing scheduler noise without hiding a real regression.
SLACK_SECONDS=${TF_NAT_SLACK_SECONDS:-3}
SLACK_PERCENT=${TF_NAT_SLACK_PERCENT:-50}
# Direct-path round trip may exceed the baseline by this many milliseconds.
# Build the node optimized: a debug build adds ~10 ms of curve arithmetic.
SLACK_RTT_MS=${TF_NAT_SLACK_RTT_MS:-3}
# Throughput may fall below the baseline by this many percent.
SLACK_RATE_PERCENT=${TF_NAT_SLACK_RATE_PERCENT:-15}
# Bytes per bulk transfer and transfers per direction (the median is kept).
BULK_MB=${TF_NAT_BULK_MB:-128}
BULK_ROUNDS=${TF_NAT_BULK_ROUNDS:-3}
# Pasted bytes per SSH echo session.
SSH_BYTES=${TF_NAT_SSH_BYTES:-16384}

die() { echo "nat-matrix: FAIL: $*" >&2; exit 1; }

cmd=${1:-}
case "$cmd" in
    list) printf '%s\n' "${SCENARIOS[@]}"; exit 0 ;;
    one|matrix) shift ;;
    *) echo "usage: $0 {matrix|one|list} HEADSCALE TAILSCALE TAILSCALED NODE BASE_CONFIG [SCENARIO PEER]" >&2; exit 2 ;;
esac
HEADSCALE=$(realpath "${1:?headscale binary}")
TAILSCALE=$(realpath "${2:?tailscale binary}")
TAILSCALED=$(realpath "${3:?tailscaled binary}")
NODE=$(realpath "${4:?Tailfeather reactor lab_node binary}")
BASE_CONFIG=$(realpath "${5:?Headscale base configuration}")
# The Tailfeather SSH console server, for +ssh scenarios only.
SSH_SERVER=${TF_NAT_SSH_SERVER:+$(realpath "$TF_NAT_SSH_SERVER")}
for tool in "$HEADSCALE" "$TAILSCALE" "$TAILSCALED" "$NODE"; do
    test -x "$tool" || die "missing executable: $tool"
done

ROOT=()
if test "$(id -u)" -ne 0; then
    ROOT=(sudo -n --preserve-env=TF_TEST_AUTH_KEY,TF_BULK_BYTES,TF_TCP_BUFFER,TF_TEST_CA_DER,SSL_CERT_FILE,XDG_CONFIG_HOME)
fi

now() { printf '%s' "$EPOCHREALTIME"; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }

# ---------------------------------------------------------------- matrix ----
if test "$cmd" = matrix; then
    jobs=${TF_NAT_JOBS:-$(nproc)}
    only=${TF_NAT_SCENARIOS:-${SCENARIOS[*]}}
    out=$(mktemp -d "${TEST_TMPDIR:-/tmp}/tf-nat-matrix.XXXXXX")
    trap 'rm -rf "$out"' EXIT
    started=$(now)
    self=$(realpath "$0")
    running=0
    run_one() {
        "$self" one "$HEADSCALE" "$TAILSCALE" "$TAILSCALED" "$NODE" "$BASE_CONFIG" "$1" "$2" \
            >"$out/$1.$2.log" 2>&1
    }
    # Throughput and SSH timings measure CPU, so they run alone, after the
    # parallel phase. Of the rest, the longest runs (mid-session events)
    # start first to shorten the makespan.
    measured=$(printf '%s\n' $only | grep -E '\+(bulk|ssh)' || true)
    for scenario in $(printf '%s\n' $only | grep -vE '\+(bulk|ssh)' | grep '+') \
        $(printf '%s\n' $only | grep -v '+'); do
        for peer in "${PEERS[@]}"; do
            run_one "$scenario" "$peer" &
            running=$((running + 1))
            if test "$running" -ge "$jobs"; then
                wait -n || true
                running=$((running - 1))
            fi
        done
    done
    wait || true
    for scenario in $measured; do
        for peer in "${PEERS[@]}"; do run_one "$scenario" "$peer" || true; done
    done
    echo "== NAT matrix finished in $(elapsed "$started" "$(now)")s with $jobs parallel jobs"
    echo "   columns: path, seconds to first pong / direct [/ failover / recovery / rebind], median direct RTT [, Mbit/s up/down]"
    printf '%-18s | %-40s | %-40s | %s\n' scenario "official client" tailfeather verdict
    printf '%s\n' "-------------------+------------------------------------------+------------------------------------------+--------"
    failed=0
    field() { sed -n "s/^RESULT .* $2=\([^ ]*\).*/\1/p" "$1" | tail -1; }
    numeric() { case "$1" in ''|-|fail) return 1 ;; *) return 0 ;; esac; }
    summary() {
        local log=$1 text metric value
        text="$(field "$log" path) $(field "$log" first_s)"
        for metric in "${METRICS[@]}"; do
            value=$(field "$log" "$metric")
            test -n "$value" || continue
            text="$text/$value"
        done
        printf '%ss %sms' "$text" "$(field "$log" rtt_ms)"
        if test -n "$(field "$log" up_mbps)"; then
            printf ' %s/%sMb@%s/%s%%' "$(field "$log" up_mbps)" "$(field "$log" down_mbps)" \
                "$(field "$log" up_cpu)" "$(field "$log" down_cpu)"
        fi
        if test -n "$(field "$log" paste_kbps)"; then
            printf ' paste %skb' "$(field "$log" paste_kbps)"
        fi
    }
    for scenario in $only; do
        base="$out/$scenario.stock.log" cand="$out/$scenario.tailfeather.log"
        bp=$(field "$base" path) cp=$(field "$cand" path)
        verdict=ok notes="" fails="" percore=""
        if test -z "$bp" || test "$bp" = none; then
            verdict="BASELINE-ERROR"; failed=1
        elif case "$RELAY_EXPECTED" in *" ${scenario%%+*} "*) false ;; *) test "$bp" != direct ;; esac ||
            sed -n '/^RESULT .*=fail/p' "$base" | read -r _; then
            verdict="BASELINE-ERROR: the official client did not behave as this topology requires"; failed=1
        elif test -z "$cp" || test "$cp" = none || test "$cp" = crashed; then
            verdict="FAIL: ${cp:-no result}"; failed=1
        elif test "$cp" = flapped; then
            verdict="FAIL: direct path not stable"; failed=1
        elif test "$bp" = direct && test "$cp" != direct; then
            verdict="FAIL: official went direct, we relayed"; failed=1
        else
            for metric in "${METRICS[@]}"; do
                b=$(field "$base" "$metric") c=$(field "$cand" "$metric")
                if numeric "$b"; then
                    if ! numeric "$c"; then
                        fails="$fails ${metric%_s}:never"; continue
                    fi
                    limit=$(awk -v b="$b" -v s="$SLACK_SECONDS" -v p="$SLACK_PERCENT" 'BEGIN { l = b * (1 + p / 100); if (l < b + s) l = b + s; printf "%.1f", l }')
                    if awk -v c="$c" -v l="$limit" 'BEGIN { exit !(c > l) }'; then
                        fails="$fails ${metric%_s}:${c}s>${limit}s"
                    elif awk -v c="$c" -v b="$b" 'BEGIN { exit !(c + 1 < b) }'; then
                        notes="$notes ${metric%_s}"
                    fi
                elif numeric "$c"; then
                    notes="$notes ${metric%_s}(official: none)"
                fi
            done
            br=$(field "$base" rtt_ms) cr=$(field "$cand" rtt_ms)
            if numeric "$br" && numeric "$cr" &&
                awk -v c="$cr" -v b="$br" -v s="$SLACK_RTT_MS" 'BEGIN { exit !(c > b + s) }'; then
                fails="$fails rtt:${cr}ms>${br}+${SLACK_RTT_MS}ms"
            fi
            for metric in "${RATES[@]}"; do
                b=$(field "$base" "$metric") c=$(field "$cand" "$metric")
                bc=$(field "$base" "${metric%_*}_cpu") cc=$(field "$cand" "${metric%_*}_cpu")
                numeric "$b" || continue
                if ! numeric "$c"; then fails="$fails ${metric%_*}:none"; continue; fi
                floor=$(awk -v b="$b" -v p="$SLACK_RATE_PERCENT" 'BEGIN { printf "%d", b * (1 - p / 100) }')
                if awk -v c="$c" -v f="$floor" 'BEGIN { exit !(c >= f) }'; then
                    if awk -v c="$c" -v b="$b" 'BEGIN { exit !(c > b * 1.1) }'; then notes="$notes ${metric%_*}"; fi
                elif numeric "$bc" && numeric "$cc" && awk -v c="$c" -v b="$b" -v cc="$cc" -v bc="$bc" -v p="$SLACK_RATE_PERCENT" \
                    'BEGIN { exit !(cc > 0 && bc > 0 && c / cc >= (b / bc) * (1 - p / 100)) }'; then
                    percore="$percore ${metric%_*}:${c}<${floor}Mb,per-core:$((c * 100 / cc))>=$((b * 100 / bc))"
                else
                    fails="$fails ${metric%_*}:${c}<${floor}"
                fi
            done
            if test -n "$fails"; then verdict="FAIL:$fails"; failed=1; fi
            if test "$verdict" = ok && test -n "$notes"; then verdict="better:$notes"; fi
            if test -z "$fails" && test -n "$percore"; then verdict="$verdict; per-core only:$percore"; fi
        fi
        printf '%-18s | %-40s | %-40s | %s\n' "$scenario" "$(summary "$base")" "$(summary "$cand")" "$verdict"
    done
    if test "$failed" -ne 0 || test -n "${TF_NAT_VERBOSE:-}"; then
        for log in "$out"/*.log; do
            if test -n "${TF_NAT_VERBOSE:-}" || ! sed -n '/^RESULT /p' "$log" | read -r _ ||
                sed -n '/^RESULT .*\(path=\(none\|flapped\|crashed\)\|=fail\)/p' "$log" | read -r _; then
                echo "--- $(basename "$log") ---"
                tail -n 60 "$log"
            fi
        done
    fi
    test "$failed" -eq 0 || die "Tailfeather is behind the official client in at least one scenario"
    echo "PASS nat-matrix: Tailfeather matches or beats the official client in every scenario"
    exit 0
fi

# ------------------------------------------------------------------- one ----
SCENARIO=${6:?scenario}
PEER=${7:?peer: stock or tailfeather}
case " ${SCENARIOS[*]} " in *" $SCENARIO "*) ;; *) die "unknown scenario: $SCENARIO" ;; esac
case "$PEER" in stock|tailfeather) ;; *) die "unknown peer: $PEER" ;; esac
EVENT="" TOPOLOGY=$SCENARIO
case "$SCENARIO" in *+*) EVENT=${SCENARIO#*+} TOPOLOGY=${SCENARIO%%+*} ;; esac
if test "$TOPOLOGY" = lan; then PROFILE_A=easy PROFILE_B=lan; else PROFILE_A=${TOPOLOGY%-*} PROFILE_B=${TOPOLOGY#*-}; fi
CONNTRACK=${TF_NAT_CONNTRACK:-conntrack}
if test "$EVENT" = ssh && test "$PEER" = tailfeather; then
    test -x "$SSH_SERVER" || die "ssh scenarios need TF_NAT_SSH_SERVER (the Tailfeather SSH console server)"
fi
if test "$EVENT" = rebind; then
    case "$PROFILE_B" in easy|cone|cgnat) ;; *) die "rebind needs B behind an easy, cone or cgnat router" ;; esac
    "${ROOT[@]}" "$CONNTRACK" --version >/dev/null 2>&1 || die "rebind needs conntrack (TF_NAT_CONNTRACK)"
fi

WORK=$(mktemp -d "${TEST_TMPDIR:-/tmp}/tf-nat-$SCENARIO-$PEER.XXXXXX")
PREFIX=tfnm-$$-$RANDOM
NAMES=()
GROUPS_OWNED=()
ns() { "${ROOT[@]}" ip netns exec "$PREFIX-$1" "${@:2}"; }
fail() {
    echo "RESULT scenario=$SCENARIO peer=$PEER path=none first_s=- direct_s=- reason=$(printf '%s' "$*" | tr ' ' _)"
    die "$SCENARIO/$PEER: $*"
}
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if test "$status" -ne 0 || test -n "${TF_NAT_VERBOSE:-}"; then
        for log in "$WORK"/*.log; do
            test -f "$log" || continue
            echo "--- $(basename "$log") ---" >&2
            tail -n 40 "$log" >&2
        done
    fi
    for group in "${GROUPS_OWNED[@]}"; do "${ROOT[@]}" kill -TERM -- "-$group" 2>/dev/null || true; done
    for name in "${NAMES[@]}"; do
        for pid in $("${ROOT[@]}" ip netns pids "$name" 2>/dev/null); do "${ROOT[@]}" kill "$pid" 2>/dev/null || true; done
    done
    for name in "${NAMES[@]}"; do "${ROOT[@]}" ip netns delete "$name" 2>/dev/null || true; done
    # TF_NAT_KEEP=1 keeps every log and packet capture for debugging.
    if test -n "${TF_NAT_KEEP:-}"; then echo "kept $WORK" >&2; else "${ROOT[@]}" rm -rf -- "$WORK"; fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
start() {
    local space=$1 name=$2; shift 2
    setsid "${ROOT[@]}" ip netns exec "$PREFIX-$space" "$@" >"$WORK/$name.log" 2>&1 &
    LAST_PID=$!
    GROUPS_OWNED+=("$LAST_PID")
}
add_ns() {
    "${ROOT[@]}" ip netns add "$PREFIX-$1"
    NAMES+=("$PREFIX-$1")
    ns "$1" ip link set lo up
}

# wan: 198.18.0.0/24 bridge hosting Headscale, DERP (TLS on 8443) and STUN.
add_ns wan
ns wan ip link add wan0 type bridge
ns wan ip addr add 198.18.0.1/24 dev wan0
ns wan ip link set wan0 up

# A stateful router namespace `r$1` whose upstream is the wan bridge (or, for
# the inner router of a CGNAT chain, another router's LAN).
#   router NAME PUBLIC_IP/LEN UPSTREAM_NS UPSTREAM_GW LAN_PREFIX PROFILE
router() {
    local name=$1 public=$2 upstream=$3 gateway=$4 lan=$5 profile=$6
    add_ns "$name"
    if test "$upstream" = wan; then
        ns wan ip link add "port-$name" type veth peer name wan netns "$PREFIX-$name"
        ns wan ip link set "port-$name" master wan0
        ns wan ip link set "port-$name" up
    else
        ns "$upstream" ip link add "port-$name" type veth peer name wan netns "$PREFIX-$name"
        ns "$upstream" ip link set "port-$name" master lan0
        ns "$upstream" ip link set "port-$name" up
    fi
    ns "$name" ip addr add "$public" dev wan
    ns "$name" ip link set wan up
    if test "$gateway" != none; then ns "$name" ip route add default via "$gateway"; fi
    ns "$name" ip link add lan0 type bridge
    ns "$name" ip addr add "$lan.1/24" dev lan0
    ns "$name" ip link set lan0 up
    ns "$name" sysctl -qw net.ipv4.ip_forward=1
    ns "$name" iptables -P INPUT DROP
    ns "$name" iptables -A INPUT -i lo -j ACCEPT
    ns "$name" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$name" iptables -P FORWARD DROP
    if test "$profile" = blocked; then
        ns "$name" iptables -A FORWARD -p udp -j DROP
    fi
    ns "$name" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ns "$name" iptables -A FORWARD -i lan0 -o wan -j ACCEPT
    # With br_netfilter loaded, frames between two hosts on this LAN also
    # traverse FORWARD; a router never filters its own LAN segment.
    ns "$name" iptables -A FORWARD -i lan0 -o lan0 -j ACCEPT
    local addr=${public%/*}
    case "$profile" in
        easy|blocked|cgnat)
            ns "$name" iptables -t nat -A POSTROUTING -s "$lan.0/24" -o wan -j SNAT --to-source "$addr" ;;
        cone)
            # Port-preserving SNAT plus a catch-all DNAT back to the single
            # LAN host: every mapped port accepts any outside sender.
            ns "$name" iptables -t nat -A POSTROUTING -s "$lan.0/24" -o wan -j SNAT --to-source "$addr"
            ns "$name" iptables -t nat -A PREROUTING -i wan -p udp -d "$addr" -j DNAT --to-destination "$lan.2"
            ns "$name" iptables -I FORWARD 1 -i wan -o lan0 -p udp -m conntrack --ctstate DNAT -j ACCEPT ;;
        hard)
            # A fresh random port for every new (source, destination) flow.
            ns "$name" iptables -t nat -A POSTROUTING -s "$lan.0/24" -o wan -p udp -j SNAT --to-source "$addr:20000-60000" --random-fully
            ns "$name" iptables -t nat -A POSTROUTING -s "$lan.0/24" -o wan -j SNAT --to-source "$addr" ;;
        *) die "unknown router profile: $profile" ;;
    esac
}
# host NAME UPSTREAM_NS ADDR/LEN GATEWAY
host() {
    local name=$1 upstream=$2 addr=$3 gateway=$4 bridge=lan0
    add_ns "$name"
    if test "$upstream" = wan; then bridge=wan0; fi
    ns "$upstream" ip link add "port-$name" type veth peer name eth0 netns "$PREFIX-$name"
    ns "$upstream" ip link set "port-$name" master "$bridge"
    ns "$upstream" ip link set "port-$name" up
    ns "$name" ip addr add "$addr" dev eth0
    ns "$name" ip link set eth0 up
    if test "$gateway" != none; then ns "$name" ip route add default via "$gateway"; fi
}
# side NAME INDEX PROFILE: place host NAME behind the given NAT profile.
side() {
    local name=$1 index=$2 profile=$3
    case "$profile" in
        public) host "$name" wan "198.18.0.$((10 + index))/24" none ;;
        lan) host "$name" ra "10.44.1.3/24" 10.44.1.1 ;;
        cgnat)
            # Carrier NAT owns the public address; the home router behind it
            # gets a shared-address-space (RFC 6598) uplink.
            router "c$name" "198.18.0.$((2 + index))/24" wan none "100.80.$index" easy
            router "r$name" "100.80.$index.2/24" "c$name" "100.80.$index.1" "10.44.$index" easy
            host "$name" "r$name" "10.44.$index.2/24" "10.44.$index.1" ;;
        *)
            router "r$name" "198.18.0.$((2 + index))/24" wan none "10.44.$index" "$profile"
            host "$name" "r$name" "10.44.$index.2/24" "10.44.$index.1" ;;
    esac
}
side a 1 "$PROFILE_A"
side b 2 "$PROFILE_B"

mkdir -p "$WORK/hs" "$WORK/logs" "$WORK/config" "$WORK/node"
export XDG_CONFIG_HOME="$WORK/config"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj /CN=tf-nat-matrix-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >"$WORK/cert.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj /CN=tf-nat-matrix \
    -keyout "$WORK/server.key" -out "$WORK/server.csr" >>"$WORK/cert.log" 2>&1
printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature,keyEncipherment \
    extendedKeyUsage=serverAuth subjectAltName=IP:198.18.0.1 >"$WORK/server.ext"
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
if test "$EVENT" = ssh; then
    # Tailscale SSH needs tagged nodes and an SSH rule from control.
    cat >"$WORK/policy.json" <<'EOF'
{"tagOwners":{"tag:client":[],"tag:server":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"ssh":[{"action":"accept","src":["tag:client"],"dst":["tag:server"],"users":["console","root"]}]}
EOF
    sed -i "s#mode: database#mode: file\n  path: $WORK/policy.json#" "$WORK/headscale.yaml"
fi
# TF_NAT_PCAP=1 records every UDP datagram on the public segment
# (TF_NAT_PCAP_FILTER overrides the capture filter).
if test -n "${TF_NAT_PCAP:-}"; then
    start wan pcap tcpdump -lnn -tt -i wan0 ${TF_NAT_PCAP_FILTER:-udp and not port 3478}
fi
start wan headscale "$HEADSCALE" --config "$WORK/headscale.yaml" serve
for _ in $(seq 1 100); do
    if ns wan timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' 2>/dev/null; then break; fi
    sleep 0.1
done
# Like a real DERP server (Go's default), the TLS front disables Nagle: a
# delayed ACK would otherwise hold every small relayed frame for 40 ms.
start wan tls socat "OPENSSL-LISTEN:8443,bind=198.18.0.1,reuseaddr,fork,nodelay,cert=$WORK/server.pem,key=$WORK/server.key,verify=0,openssl-min-proto-version=TLS1.3" TCP:127.0.0.1:8080,nodelay
HS=("$HEADSCALE" --config "$WORK/headscale.yaml")
USER_JSON=$(ns wan "${HS[@]}" users create matrix --output json)
USER_ID=$(printf '%s' "$USER_JSON" | tr -d '[:space:]' | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
test -n "$USER_ID" || fail 'could not create user'
# mint [TAG]: a single-use enrollment key, tagged only for SSH scenarios.
mint() {
    local tags=()
    if test "$EVENT" = ssh && test -n "${1:-}"; then tags=(--tags "$1"); fi
    ns wan "${HS[@]}" preauthkeys create --user "$USER_ID" --ephemeral --expiration 10m "${tags[@]}" --output json |
        tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p'
}

stock_up() {
    local name=$1 key=$2 tun=userspace-networking ssh=()
    if test "$name/$EVENT" = b/ssh; then ssh=(--ssh --accept-risk=lose-ssh); fi
    # The bulk observer routes through a real TUN so the kernel's TCP drives
    # the transfer; B (stock or Tailfeather) always runs a userspace stack.
    case "$name/$EVENT" in a/bulk*) tun=tailscale0 ;; esac
    start "$name" "tailscaled-$name" env TS_NO_LOGS_NO_SUPPORT=1 TS_LOGS_DIR="$WORK/logs" "$TAILSCALED" \
        "--tun=$tun" --socket="$WORK/$name.sock" --statedir="$WORK/ts-$name" --port=0 \
        "--verbose=${TF_NAT_TS_VERBOSE:-0}"
    for _ in $(seq 1 100); do test -S "$WORK/$name.sock" && break; sleep 0.1; done
    test -S "$WORK/$name.sock" || fail "tailscaled socket missing on $name"
    printf '%s' "$key" | ns "$name" timeout 45 "$TAILSCALE" "--socket=$WORK/$name.sock" up \
        --login-server=http://198.18.0.1:8080 --auth-key=file:/proc/self/fd/0 \
        --hostname="peer-$name" --accept-dns=false --accept-routes=false --netfilter-mode=off "${ssh[@]}" >"$WORK/up-$name.log" 2>&1 ||
        fail "tailscale up failed on $name"
}
A=("$TAILSCALE" "--socket=$WORK/a.sock")
stock_up a "$(mint tag:client)"
BULK_BYTES=$((BULK_MB << 20))
if test "$PEER" = stock; then
    stock_up b "$(mint tag:server)"
    if case "$EVENT" in bulk*) true ;; *) false ;; esac; then
        # A userspace tailscaled delivers inbound tailnet TCP to loopback.
        start b sink socat -t 60 TCP-LISTEN:5001,bind=127.0.0.1,reuseaddr,fork SYSTEM:'cat >/dev/null; echo done'
        start b source socat -t 60 TCP-LISTEN:5002,bind=127.0.0.1,reuseaddr,fork SYSTEM:"head -c $BULK_BYTES /dev/zero"
    fi
    ADDRESS=$(ns b "$TAILSCALE" "--socket=$WORK/b.sock" ip -4)
else
    export TF_TEST_AUTH_KEY TF_BULK_BYTES=$BULK_BYTES
    TF_TEST_AUTH_KEY=$(mint tag:server)
    if test "$EVENT" = ssh; then
        # The SSH console server speaks plaintext control to loopback only.
        start b control-proxy socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork TCP:198.18.0.1:8080
        lan_ip=$(ns b ip -4 -o addr show dev eth0 | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p')
        start b node "$SSH_SERVER" 127.0.0.1:8080 "$lan_ip" --sessions=1000 \
            --timeout-seconds=$((DIRECT_BUDGET + HOLD + 600))
    else
        start b node "$NODE" https://198.18.0.1:8443 "$WORK/node" --timeout-seconds=$((DIRECT_BUDGET + HOLD + 300))
    fi
    NODE_PID=$LAST_PID
    unset TF_TEST_AUTH_KEY
    for _ in $(seq 1 600); do sed -n '/^READY /p' "$WORK/node.log" | read -r _ && break; sleep 0.1; done
    ADDRESS=$(sed -n 's/^READY \([^ ]*\).*/\1/p' "$WORK/node.log" | head -1)
fi
test -n "$ADDRESS" || fail 'peer B never became ready'
# The observer must know B before the clock starts, so control-plane
# propagation does not count against either implementation.
for _ in $(seq 1 300); do
    ns a "${A[@]}" status --json >"$WORK/status.json" 2>/dev/null || true
    sed -n "/\"$ADDRESS\"/p" "$WORK/status.json" | read -r _ && break
    sleep 0.1
done
sed -n "/\"$ADDRESS\"/p" "$WORK/status.json" | read -r _ || fail "observer never learned $ADDRESS"

# Clock starts now. The observer's own disco ping is the probe: it reports
# the path every pong took ("via DERP(...)" or "via ip:port"), and it drives
# path discovery in the official client exactly as application traffic does.
T0=$(now)
probe() {
    ns a timeout 4 "${A[@]}" ping --c=1 --timeout=2s --until-direct=false "$ADDRESS" 2>&1 || true
}
first="" direct="" endpoint=""
deadline=$((SECONDS + DIRECT_BUDGET))
while test "$SECONDS" -lt "$deadline"; do
    out=$(probe)
    printf '%s %s\n' "$(elapsed "$T0" "$(now)")" "$out" >>"$WORK/ping.log"
    case "$out" in
        *"pong from "*" via DERP("*) test -n "$first" || first=$(elapsed "$T0" "$(now)") ;;
        *"pong from "*" via "*)
            test -n "$first" || first=$(elapsed "$T0" "$(now)")
            direct=$(elapsed "$T0" "$(now)")
            endpoint=$(printf '%s' "$out" | sed -n 's/.* via \([0-9.]*:[0-9]*\) .*/\1/p' | head -1)
            break ;;
    esac
    sleep 0.2
done
path=relay
if test -n "$direct"; then
    path=direct
    # A path is only useful if it stays: every probe in the hold window must
    # still be answered directly.
    hold_end=$((SECONDS + HOLD))
    while test "$SECONDS" -lt "$hold_end"; do
        out=$(probe)
        printf 'hold %s %s\n' "$(elapsed "$T0" "$(now)")" "$out" >>"$WORK/ping.log"
        case "$out" in
            *"pong from "*" via DERP("*|*"timed out"*|*"no reply"*) path=flapped; break ;;
        esac
        sleep 0.5
    done
elif test -z "$first"; then
    path=none
fi

# wait_for PATTERN BUDGET: seconds until a probe's output matches PATTERN.
wait_for() {
    local pattern=$1 budget=$2 begin end out
    begin=$(now) end=$((SECONDS + budget))
    while test "$SECONDS" -lt "$end"; do
        out=$(probe)
        printf '%s %s %s\n' "$EVENT" "$(elapsed "$T0" "$(now)")" "$out" >>"$WORK/ping.log"
        if printf '%s\n' "$out" | sed -n "/pong from .* via $pattern/p" | read -r _; then
            elapsed "$begin" "$(now)"
            return 0
        fi
        sleep 0.2
    done
    printf fail
}
median() { printf '%s\n' "$@" | sort -n | awk '{ a[NR] = $1 } END { printf "%s", a[int((NR + 1) / 2)] }'; }
# CPU ticks used so far by B's tailnet implementation (not its test apps).
b_ticks() {
    local pid total=0 node
    node=$(basename "$NODE" | cut -c1-15)
    for pid in $("${ROOT[@]}" ip netns pids "$PREFIX-b"); do
        case "$("${ROOT[@]}" cat "/proc/$pid/comm" 2>/dev/null)" in
            tailscaled|"$node") total=$((total + $("${ROOT[@]}" awk '{ print $14 + $15 }' "/proc/$pid/stat"))) ;;
        esac
    done
    printf '%s' "$total"
}
# bulk DIRECTION: "Mbit/s CPU%" of one transfer as the observer's application
# sees it, with the CPU B's tailnet implementation spent (100 = one core).
# Upload ends when B answers after reading the FIN, so data still queued in
# the observer's socket buffer is counted; download ends at B's FIN.
bulk() {
    local begin end bytes ticks
    begin=$(now) ticks=$(b_ticks)
    if test "$1" = up; then
        bytes=$(head -c "$BULK_BYTES" /dev/zero |
            ns a timeout 120 socat -t 60 - "TCP:$ADDRESS:5001,connect-timeout=5" 2>>"$WORK/bulk.err" | tr -d '\n' || true)
        test "$bytes" = done || { printf fail; return; }
    else
        bytes=$(ns a timeout 120 socat -u "TCP:$ADDRESS:5002,connect-timeout=5" - 2>>"$WORK/bulk.err" | wc -c || true)
        test "$bytes" = "$BULK_BYTES" || { printf fail; return; }
    fi
    end=$(now) ticks=$(($(b_ticks) - ticks))
    awk -v a="$begin" -v b="$end" -v n="$BULK_BYTES" -v t="$ticks" \
        'BEGIN { printf "%d %d", n * 8 / (b - a) / 1e6, t / (b - a) }'
}
# bulk_median DIRECTION: "median-Mbit/s median-CPU%" over BULK_ROUNDS.
bulk_median() {
    local direction=$1 rates=() cpus=() round sample
    for round in $(seq 1 "$BULK_ROUNDS"); do
        sample=$(bulk "$direction")
        printf '%s %s round %s: %s\n' "$EVENT" "$direction" "$round" "$sample" >>"$WORK/bulk.log"
        test "$sample" != fail || { printf 'fail fail'; return; }
        rates+=("${sample% *}") cpus+=("${sample#* }")
    done
    printf '%s %s' "$(median "${rates[@]}")" "$(median "${cpus[@]}")"
}
# ssh_session BYTES: seconds for one Tailscale SSH session that pastes BYTES
# and a newline and receives them echoed back.
ssh_session() {
    # Both servers stream the echo: the official one runs cat until the
    # client's EOF, the Tailfeather console echoes until the newline.
    local bytes=$1 user=root command=(cat) begin end
    if test "$PEER" = tailfeather; then user=console command=(); fi
    begin=$(now)
    if ! { head -c "$bytes" /dev/zero | tr '\0' x; printf '\n'; } |
        ns a timeout 300 "${A[@]}" ssh "$user@$ADDRESS" "${command[@]}" >"$WORK/ssh.out" 2>>"$WORK/ssh.err"; then
        printf fail; return
    fi
    end=$(now)
    if test "$(tr -cd x <"$WORK/ssh.out" | wc -c)" -ne "$bytes"; then printf fail; return; fi
    awk -v a="$begin" -v b="$end" 'BEGIN { printf "%.3f", b - a }'
}
events=""
if test "$EVENT" = ssh && test "$path" != none; then
    # The client learns B's SSH host key from control before connecting.
    for _ in $(seq 1 100); do
        ns a "${A[@]}" status --json >"$WORK/status.json"
        if sed -n '/"sshHostKeys": \[/p' "$WORK/status.json" | read -r _; then break; fi
        sleep 0.2
    done
    setups=() pastes=()
    for round in $(seq 1 "$BULK_ROUNDS"); do
        setups+=("$(ssh_session 0)")
        pastes+=("$(ssh_session "$SSH_BYTES")")
        printf 'ssh round %s: setup %ss paste %s bytes %ss\n' "$round" "${setups[-1]}" "$SSH_BYTES" "${pastes[-1]}" >>"$WORK/bulk.log"
    done
    case " ${setups[*]} ${pastes[*]} " in
        *" fail "*) events="ssh_s=fail paste_kbps=fail" ;;
        *)
            setup=$(median "${setups[@]}") paste=$(median "${pastes[@]}")
            # Input throughput beyond the cost of setting the session up.
            kbps=$(awk -v s="$setup" -v p="$paste" -v n="$SSH_BYTES" 'BEGIN { d = p - s; if (d < 0.001) d = 0.001; printf "%d", n * 8 / d / 1000 }')
            events="ssh_s=$(awk -v s="$setup" 'BEGIN { printf "%.1f", s }') paste_kbps=$kbps" ;;
    esac
elif test "${EVENT%-wan}" = bulk && test "$path" != none; then
    if test "$EVENT" = bulk-wan; then
        # 10 ms on every public port, each way: 20 ms between the peers.
        for port in $(ns wan ip -o link show master wan0 | sed -n 's/^[0-9]*: \(port-[^@:]*\).*/\1/p'); do
            ns wan tc qdisc add dev "$port" root netem delay 10ms limit 10000
        done
    fi
    # TF_NAT_PCAP=1 also records the observer's plaintext tailnet TCP.
    if test -n "${TF_NAT_PCAP:-}"; then
        start a pcap-tun tcpdump -nn -s 96 -i tailscale0 -w "$WORK/tun.pcap" tcp
        sleep 1
    fi
    read -r up up_cpu <<<"$(bulk_median up)"
    read -r down down_cpu <<<"$(bulk_median down)"
    # Datagrams the kernel dropped because B did not read them in time.
    ns b sed -n 's/^Udp: [0-9]/&/p' /proc/net/snmp |
        awk '{ printf "B udp: in %s rcvbuf-drops %s sndbuf-drops %s\n", $2, $6, $7 }' >>"$WORK/bulk.log"
    events="up_mbps=$up up_cpu=$up_cpu down_mbps=$down down_cpu=$down_cpu"
elif test -n "$EVENT" && test "$path" = direct; then
    case "$EVENT" in
        outage)
            # Cut every UDP flow of B except to the DERP/STUN server. TCP to
            # DERP is untouched, so a correct node keeps the session alive.
            ns b iptables -I OUTPUT 1 -p udp ! -d 198.18.0.1 -j DROP
            ns b iptables -I INPUT 1 -p udp ! -s 198.18.0.1 -j DROP
            failover=$(wait_for 'DERP(' 40)
            ns b iptables -D OUTPUT -p udp ! -d 198.18.0.1 -j DROP
            ns b iptables -D INPUT -p udp ! -s 198.18.0.1 -j DROP
            recovery=$(wait_for '[0-9.]*:[0-9]* ' 60)
            events="failover_s=$failover recovery_s=$recovery" ;;
        rebind)
            outer=rb
            test "$PROFILE_B" != cgnat || outer=cb
            public=${endpoint%:*} port=${endpoint##*:}
            ns "$outer" iptables -t nat -I POSTROUTING 1 -p udp --sport "$port" -o wan -j SNAT --to-source "$public:46000"
            ns "$outer" "$CONNTRACK" -D -p udp --sport "$port" >"$WORK/conntrack.log" 2>&1 || true
            rebind=$(wait_for "$public:46000 " 90)
            events="rebind_s=$rebind" ;;
        *) die "unknown event: $EVENT" ;;
    esac
elif test -n "$EVENT"; then
    case "$EVENT" in
        outage) events="failover_s=fail recovery_s=fail" ;;
        rebind) events="rebind_s=fail" ;;
        bulk*) events="up_mbps=fail up_cpu=fail down_mbps=fail down_cpu=fail" ;;
        ssh) events="ssh_s=fail paste_kbps=fail" ;;
    esac
fi
if test "$PEER" = tailfeather; then
    kill -0 "$NODE_PID" 2>/dev/null || path=crashed
    if sed -n '/panicked/p' "$WORK/node.log" | read -r _; then path=crashed; fi
fi
# Median round trip of the direct pongs (Go durations: "0s", "11ms", "1.2s").
rtt=$(sed -n 's/.* via [0-9.]*:[0-9]* in \([0-9.]*\)\(ms\|s\|µs\)$/\1 \2/p' "$WORK/ping.log" |
    awk '{ v = $1; if ($2 == "s") v *= 1000; if ($2 == "µs") v /= 1000; print v }' | sort -n |
    awk '{ a[NR] = $1 } END { if (NR) printf "%g", a[int((NR + 1) / 2)]; else printf "-" }')
echo "RESULT scenario=$SCENARIO peer=$PEER path=$path first_s=${first:--} direct_s=${direct:--} rtt_ms=$rtt endpoint=${endpoint:--} $events"
test "$path" != none && test "$path" != crashed
