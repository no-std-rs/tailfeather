#!/usr/bin/env bash
# The production ESP32-C6 firmware, booted in ESP-EMU, joins a Headscale
# tailnet and serves as the exit node of a stock Tailscale client. The stage
# proves the exit path (the internet server sees the ESP's Wi-Fi address, not
# the client's) and measures IPv4 TCP throughput through it.
#
#   client ns ── 10.78.0.0/24 ──┐
#                               lan ns: Headscale+DERP 10.77.0.1:8080, STUN,
#                               IPv6 RA (dnsmasq)
#   ESP (esp-emu, tap0) ── 192.168.4.0/24 + 2001:db8:77::/64 (Wi-Fi segment)
#                               │
#   inet ns (bulk servers) ── 10.79.0.0/24
#
# ESP-EMU's SoftAP answers the station's DHCP and gateway ARP itself and always
# leases 192.168.4.x behind gateway 192.168.4.1, so the router takes that
# address on tap0. Control lives off-segment on the router's loopback, as an
# internet control server would.
#
# The lan namespace routes between the three segments without NAT, so the only
# address translation on the measured path is the ESP's own. The client is
# routed to the ESP's Wi-Fi address directly, so the tunnel runs over a direct
# UDP path rather than DERP.
#
# The ESP gets IPv6 by router advertisement only so it also advertises ::/0:
# stock clients offer a peer as an exit node only when both default routes are
# present. The measured traffic is IPv4.
#
#   esp-exit.sh HEADSCALE TAILSCALE TAILSCALED ESP_EMU FLASH_IMAGE ELF BASE_CONFIG [TLS_DIR]
#
# With TLS_DIR (tests/lab/esp-tls) the stage serves the production control
# path for the emulab_tls image: control at https://control.lab:8443 behind a
# TLS 1.3 front with that directory's certificate, DNS for control.lab and
# pool.ntp.org, and SNTP from two addresses (the firmware wants two agreeing
# servers before it trusts the time).
#
# Knobs (environment):
#   TF_ESP_EXIT_KIB       KiB per bulk transfer (default 2048)
#   TF_ESP_EXIT_STREAMS   concurrent transfers of the multi-stream runs (default 4)
#   TF_ESP_EXIT_PAGES     browser-like page loads (default 3)
#   TF_ESP_EXIT_CONNS     concurrent connections per page load (default 6)
#   TF_ESP_EXIT_DNS       concurrent DNS lookups (default 10), one retry each
#   TF_ESP_EXIT_DNS_PROBE extra lookup bursts with loss accounting (default 0)
#   TF_ESP_EXIT_MIN_MBPS  fail when a single-stream direction is slower (default 0)
#   TF_ESP_EXIT_BATCH     esp-emu --batch-size, if set
#   TF_ESP_EXIT_KEEP      directory to copy every log into when the stage ends
#   TF_ESP_EXIT_PCAP_TAP  tcpdump filter for the ESP's Wi-Fi segment (tap.pcap)
#   TF_ESP_EXIT_PCAP      tcpdump filter; captures both sides of the ESP into
#                         inet.pcap and client.pcap (kept with TF_ESP_EXIT_KEEP)
set -euo pipefail

HEADSCALE=$1 TAILSCALE=$2 TAILSCALED=$3 ESP_EMU=$4 FLASH=$5 ELF=$6 BASE_CONFIG=$7 TLS_DIR=${8:-}
BULK_BYTES=$((${TF_ESP_EXIT_KIB:-2048} << 10))
STREAMS=${TF_ESP_EXIT_STREAMS:-4}
PAGES=${TF_ESP_EXIT_PAGES:-3}
CONNS=${TF_ESP_EXIT_CONNS:-6}
DNS_BURST=${TF_ESP_EXIT_DNS:-10}
MIN_MBPS=${TF_ESP_EXIT_MIN_MBPS:-0}
PREFIX=ee
WORK=$(mktemp -d /tmp/tf-esp-exit.XXXXXX)
PIDS=()
NAMES=()

log() { echo "esp-exit: $*"; }
fail() { echo "esp-exit: FAIL: $*" >&2; exit 1; }
ns() { ip netns exec "$PREFIX-$1" "${@:2}"; }
start() {
    local space=$1 name=$2
    shift 2
    setsid ip netns exec "$PREFIX-$space" "$@" >"$WORK/$name.log" 2>&1 &
    PIDS+=("$!")
}
add_ns() {
    ip netns add "$PREFIX-$1"
    NAMES+=("$PREFIX-$1")
    ns "$1" ip link set lo up
}
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if test "$status" -ne 0; then
        for f in "$WORK"/*.log; do
            test -f "$f" || continue
            echo "--- $(basename "$f") (last 120 lines) ---"
            tail -n 120 "$f"
        done
    fi
    if test -n "${TF_ESP_EXIT_KEEP:-}"; then
        mkdir -p "$TF_ESP_EXIT_KEEP" &&
            find "$WORK" -maxdepth 1 -type f ! -name flash.bin -exec cp {} "$TF_ESP_EXIT_KEEP"/ \; 2>/dev/null || true
    fi
    for pid in "${PIDS[@]}"; do kill -TERM -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; done
    sleep 0.5
    for pid in "${PIDS[@]}"; do kill -KILL -- "-$pid" 2>/dev/null || true; done
    for name in "${NAMES[@]}"; do ip netns delete "$name" 2>/dev/null || true; done
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

# A firmware panic or exception ends the run at once instead of at the next
# timeout. Every polling loop calls this.
esp_alive() {
    if test -f "$WORK/esp.log" && grep -Eq '^panicked at|Exception .* mepc=' "$WORK/esp.log"; then
        grep -E -A4 '^panicked at' "$WORK/esp.log" >&2 || true
        fail "the firmware crashed"
    fi
}
# wait_for SECONDS FILE PATTERN: poll a log for an extended regex.
wait_for() {
    local deadline=$(($(date +%s) + $1))
    while ! grep -Eq "$3" "$2" 2>/dev/null; do
        esp_alive
        test "$(date +%s)" -lt "$deadline" || return 1
        sleep 0.2
    done
}

t0=$(date +%s)
elapsed() { echo $(($(date +%s) - t0)); }

log "building namespaces"
add_ns lan
add_ns client
add_ns inet
ns lan sysctl -qw net.ipv4.ip_forward=1
ns lan sysctl -qw net.ipv6.conf.all.forwarding=1
for side in client:78 inet:79; do
    name=${side%:*} octet=${side#*:}
    ip link add "$PREFIX-$name-up" netns "$PREFIX-lan" type veth peer name eth0 netns "$PREFIX-$name"
    ns lan ip addr add "10.$octet.0.1/24" dev "$PREFIX-$name-up"
    ns lan ip link set "$PREFIX-$name-up" up
    ns "$name" ip addr add "10.$octet.0.2/24" dev eth0
    ns "$name" ip link set eth0 up
    ns "$name" ip route add default via "10.$octet.0.1"
done

# esp-emu opens tap0 when it starts; pre-create it persistent so addressing and
# router advertisements are ready before the firmware associates.
ns lan ip addr add 10.77.0.1/32 dev lo
ns lan ip tuntap add dev tap0 mode tap
ns lan ip addr add 192.168.4.1/24 dev tap0
ns lan ip -6 addr add 2001:db8:77::1/64 dev tap0 nodad
ns lan ip link set tap0 up

mkdir -p "$WORK/hs" "$WORK/ts"
# Plaintext DERP for the plaintext image; in TLS mode the relay is verified
# TLS on 443 behind the same front as control, as production expects.
if test -n "$TLS_DIR"; then
    DERP_NODE="hostname: control.lab
        ipv4: 10.77.0.1
        derpport: 443"
else
    DERP_NODE="hostname: 10.77.0.1
        ipv4: 10.77.0.1
        derpport: 8080
        insecurefortests: true"
fi
cat >"$WORK/derp.yaml" <<EOF
regions:
  999:
    regionid: 999
    regioncode: lab
    regionname: ESP exit lab
    nodes:
      - name: lab
        regionid: 999
        $DERP_NODE
        stunport: 3478
EOF
sed -e "s#/tmp/tailfeather-lab/headscale#$WORK/hs#g" \
    -e 's#http://127.0.0.1:8080#http://10.77.0.1:8080#' \
    -e 's/automatically_add_embedded_derp_region: true/automatically_add_embedded_derp_region: false/' \
    -e "s#paths: \[\]#paths: ['$WORK/derp.yaml']#" \
    -e 's/level: debug/level: info/' "$BASE_CONFIG" >"$WORK/headscale.yaml"
printf '\nunix_socket: %s/headscale.sock\nunix_socket_permission: "0700"\n' "$WORK" >>"$WORK/headscale.yaml"
cat >"$WORK/policy.json" <<'EOF'
{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"autoApprovers":{"exitNode":["exitlab@"]}}
EOF
sed -i "s#mode: database#mode: file\n  path: $WORK/policy.json#" "$WORK/headscale.yaml"
HS=("$HEADSCALE" --config "$WORK/headscale.yaml")
start lan headscale "${HS[@]}" serve
for _ in $(seq 1 100); do
    ns lan timeout 1 bash -c 'exec 3<>/dev/tcp/10.77.0.1/8080' 2>/dev/null && break
    sleep 0.1
done
ns lan timeout 1 bash -c 'exec 3<>/dev/tcp/10.77.0.1/8080' || fail "headscale did not start"
USER_ID=$(ns lan "${HS[@]}" users create exitlab --output json | tr -d '[:space:]' |
    sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
test -n "$USER_ID" || fail "could not create the Headscale user"
mint() {
    ns lan "${HS[@]}" preauthkeys create --user "$USER_ID" --expiration 1h --output json |
        tr -d '[:space:]' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p'
}
ESP_KEY=$(mint)
CLIENT_KEY=$(mint)
test -n "$ESP_KEY" && test -n "$CLIENT_KEY" || fail "could not mint auth keys"

# TLS mode needs names: ESP-EMU's SoftAP DHCP always names 8.8.8.8 as the
# resolver, so the router answers as 8.8.8.8 for the lab's two names.
if test -n "$TLS_DIR"; then
    ns lan ip addr add 8.8.8.8/32 dev lo
    start lan dns dnsmasq --user=nobody --group=nobody --keep-in-foreground --log-facility=- --conf-file=/dev/null --no-resolv \
        --no-hosts --no-dhcp-interface=lo --listen-address=8.8.8.8 --bind-interfaces \
        --pid-file="$WORK/dns.pid" --host-record=control.lab,10.77.0.1 \
        --host-record=pool.ntp.org,10.77.0.123 --host-record=pool.ntp.org,10.77.0.124 --log-queries
    ns lan ip addr add 10.77.0.123/32 dev lo
    ns lan ip addr add 10.77.0.124/32 dev lo
    # SNTP server mode 4 reply: the request's transmit timestamp (the
    # firmware's nonce) comes back as the originate timestamp.
    cat >"$WORK/ntp.sh" <<'EOF'
#!/usr/bin/env bash
req=$(od -An -tx1 -N48 -v | tr -d ' \n')
nonce=${req:80:16}
ts=$(printf '%08x00000000' $(($(date +%s) + 2208988800)))
hex="2401000000000000000000004c414230${ts}${nonce}${ts}${ts}"
printf "$(sed 's/../\\x&/g' <<<"$hex")"
EOF
    chmod +x "$WORK/ntp.sh"
    for ntp in 10.77.0.123 10.77.0.124; do
        start lan "ntp-$ntp" socat "UDP-RECVFROM:123,bind=$ntp,fork" "SYSTEM:$WORK/ntp.sh"
    done
    # Like a real DERP server (Go's default), the front disables Nagle.
    for port in 8443 443; do
        start lan "tls-$port" socat "OPENSSL-LISTEN:$port,bind=10.77.0.1,reuseaddr,fork,nodelay,cert=$TLS_DIR/control.pem,key=$TLS_DIR/control.key,verify=0,openssl-min-proto-version=TLS1.3" \
            TCP:10.77.0.1:8080,nodelay
    done
fi
# SLAAC for the Wi-Fi segment (DHCPv4 is the SoftAP's). Port 0 disables DNS.
start lan dnsmasq dnsmasq --user=nobody --group=nobody --keep-in-foreground --log-facility=- --conf-file=/dev/null --no-resolv --no-hosts \
    --port=0 --interface=tap0 --bind-interfaces --pid-file="$WORK/dnsmasq.pid" \
    --dhcp-leasefile="$WORK/dnsmasq.leases" --enable-ra --ra-param=tap0,10 \
    --dhcp-range=2001:db8:77::,ra-only,64,1h

# The flash image is a read-only Bazel output: work on a copy and write the
# freshly minted key into the lab auth-key sector (flash::LAB_AUTH_KEY_ADDRESS).
cp "$FLASH" "$WORK/flash.bin"
chmod u+w "$WORK/flash.bin"
test "$(stat -c %s "$WORK/flash.bin")" -ge $((0x400000)) || fail "flash image is smaller than 4 MiB"
printf '%s\0' "$ESP_KEY" | dd of="$WORK/flash.bin" bs=1 seek=$((0x3FF000)) conv=notrunc status=none
unset ESP_KEY

EMU=("$ESP_EMU" --chip esp32c6 --firmware "$WORK/flash.bin" --elf "$ELF"
    --wifi-ssid tailfeather-lab --wifi-password tailfeather-lab --net tap,ifname=tap0
    --console usb-jtag --log-color never --timeout 1800s)
if test -n "${TF_ESP_EXIT_BATCH:-}"; then EMU+=(--batch-size "$TF_ESP_EXIT_BATCH"); fi
log "booting the firmware in esp-emu"
start lan esp "${EMU[@]}"
wait_for 90 "$WORK/esp.log" 'DHCP lease: 192\.168\.4\.' || fail "the ESP got no DHCP lease"
ESP_LAN=$(sed -n 's/.*DHCP lease: \(192\.168\.4\.[0-9]*\).*/\1/p' "$WORK/esp.log" | head -1)
log "ESP lease $ESP_LAN after $(elapsed)s"
wait_for 60 "$WORK/esp.log" 'lab-auth-key=flash' || fail "the firmware did not read the lab auth key"

log "joining the stock client"
CLIENT_ENV=(TS_NO_LOGS_NO_SUPPORT=1)
if test -n "$TLS_DIR"; then CLIENT_ENV+=("SSL_CERT_FILE=$TLS_DIR/ca.pem"); fi
start client tailscaled env "${CLIENT_ENV[@]}" "$TAILSCALED" --tun=tailscale0 \
    --socket="$WORK/client.sock" --statedir="$WORK/ts" --port=41641
for _ in $(seq 1 100); do test -S "$WORK/client.sock" && break; sleep 0.1; done
TS=("$TAILSCALE" --socket="$WORK/client.sock")
printf '%s' "$CLIENT_KEY" | ns client timeout 60 "${TS[@]}" up --login-server=http://10.77.0.1:8080 \
    --auth-key=file:/proc/self/fd/0 --hostname=exit-client --accept-dns=false \
    --accept-routes=false --netfilter-mode=off >"$WORK/up.log" 2>&1 || fail "tailscale up failed"

log "waiting for the ESP to join the client's netmap"
ESP_TS=""
for _ in $(seq 1 600); do
    ESP_TS=$(ns client "${TS[@]}" ip -4 esp-exit-lab 2>/dev/null || true)
    test -n "$ESP_TS" && break
    esp_alive
    sleep 0.2
done
test -n "$ESP_TS" || fail "the client never saw the ESP in its netmap"
log "ESP joined as $ESP_TS after $(elapsed)s"

# The policy auto-approves the ESP's exit routes once it advertises them, which
# it does after SLAAC (both default routes are needed for a stock client to
# offer it as an exit node).
for _ in $(seq 1 300); do
    ns client "${TS[@]}" set --exit-node="$ESP_TS" >"$WORK/exit.log" 2>&1 && break
    esp_alive
    sleep 0.5
done
ns client "${TS[@]}" status --json | tr -d '[:space:]' | grep -q '"ExitNode":true' ||
    fail "the ESP was not accepted as an exit node: $(cat "$WORK/exit.log")"
log "exit node $ESP_TS selected after $(elapsed)s"

if test -n "${TF_ESP_EXIT_PCAP_TAP:-}"; then
    start lan pcap-tap tcpdump -Z root -U -s 96 -nni tap0 -w "$WORK/tap.pcap" $TF_ESP_EXIT_PCAP_TAP
fi
if test -n "${TF_ESP_EXIT_PCAP:-}"; then
    start lan pcap-inet tcpdump -Z root -s 128 -nni "$PREFIX-inet-up" -w "$WORK/inet.pcap" $TF_ESP_EXIT_PCAP
    start client pcap-client tcpdump -Z root -s 128 -nni tailscale0 -w "$WORK/client.pcap" $TF_ESP_EXIT_PCAP
    sleep 1
fi
start inet echo socat TCP-LISTEN:7000,bind=10.79.0.2,reuseaddr,fork SYSTEM:'echo "$SOCAT_PEERADDR"'
# Bulk endpoints, as in the NAT matrix: the sink acknowledges only after it has
# read everything, so the uploader's clock stops on delivery, not on buffering.
start inet sink socat TCP-LISTEN:5001,bind=10.79.0.2,reuseaddr,fork SYSTEM:'cat >/dev/null; echo done'
start inet source socat TCP-LISTEN:5002,bind=10.79.0.2,reuseaddr,fork SYSTEM:"head -c $BULK_BYTES /dev/zero"
# Web-like origin: each connection asks for N bytes and gets exactly N back.
start inet web socat TCP-LISTEN:5003,bind=10.79.0.2,reuseaddr,fork,backlog=64 SYSTEM:'read n; head -c "$n" /dev/zero'
# A real resolver on the internet side, as a page load's lookups would reach.
start inet resolver dnsmasq --user=nobody --group=nobody --keep-in-foreground --log-facility=- \
    --conf-file=/dev/null --no-resolv --no-hosts --listen-address=10.79.0.2 --bind-interfaces \
    --port=5353 --pid-file="$WORK/resolver.pid" --host-record=www.lab,10.79.0.2 --cache-size=0 \
    --log-queries
sleep 0.5
# The internet server must observe the ESP's own Wi-Fi address as the source.
seen=""
for _ in $(seq 1 60); do
    seen=$(ns client timeout 5 socat -T 4 - TCP:10.79.0.2:7000,connect-timeout=4 2>/dev/null </dev/null || true)
    test -n "$seen" && break
    sleep 0.5
done
test "$seen" = "$ESP_LAN" || fail "the internet server saw '$seen', expected the ESP's address $ESP_LAN"
log "exit path verified: internet server sees $seen after $(elapsed)s"
path=$(ns client "${TS[@]}" ping --c 1 --timeout 5s "$ESP_TS" 2>&1 | tail -1 || true)
log "tunnel path: $path"

# bulk DIRECTION: Mbit/s of one BULK_BYTES transfer through the exit node.
bulk() {
    local start end bytes
    start=$EPOCHREALTIME
    if test "$1" = up; then
        reply=$(head -c "$BULK_BYTES" /dev/zero |
            ns client timeout 300 socat -t 60 - TCP:10.79.0.2:5001,connect-timeout=5 2>>"$WORK/bulk.err" || true)
        bytes=$BULK_BYTES
        test "$reply" = done || bytes=0
    else
        bytes=$(ns client timeout 300 socat -u TCP:10.79.0.2:5002,connect-timeout=5 - 2>>"$WORK/bulk.err" | wc -c || true)
        echo "down $EPOCHREALTIME bytes=$bytes" >>"$WORK/bulk.trace"
    fi
    end=$EPOCHREALTIME
    awk -v b="$bytes" -v s="$start" -v e="$end" -v want="$BULK_BYTES" \
        'BEGIN { if (b + 0 < want + 0) print 0; else printf "%.3f\n", b * 8 / (e - s) / 1e6 }'
}
# parallel DIRECTION N: aggregate Mbit/s of N concurrent transfers.
parallel() {
    local direction=$1 count=$2 i start end ok=0
    start=$EPOCHREALTIME
    local pids=()
    for i in $(seq 1 "$count"); do
        bulk "$direction" >"$WORK/par-$direction-$i" &
        pids+=("$!")
    done
    wait "${pids[@]}" || true
    end=$EPOCHREALTIME
    for i in $(seq 1 "$count"); do
        awk '{ exit !($1 > 0) }' "$WORK/par-$direction-$i" && ok=$((ok + 1))
    done
    awk -v n="$ok" -v c="$count" -v b="$BULK_BYTES" -v s="$start" -v e="$end" \
        'BEGIN { if (n < c) print 0; else printf "%.3f\n", n * b * 8 / (e - s) / 1e6 }'
}
log "measuring IPv4 TCP throughput ($((BULK_BYTES >> 10)) KiB per transfer)"
up=$(bulk up)
down=$(bulk down)
up_multi=$(parallel up "$STREAMS")
down_multi=$(parallel down "$STREAMS")

# A page load as a browser does it: the document first, then its subresources
# over at most CONNS concurrent connections, each a fresh TCP connection
# (HTTP/1.0 style, the hardest case for the NAT table). Object sizes follow a
# typical page: many small assets, a few large ones. 24 objects, ~1.1 MiB.
PAGE_OBJECTS="2048 4096 8192 1024 16384 32768 65536 3072 12288 24576 131072 2048
    6144 49152 1536 262144 8192 4096 16384 98304 2048 196608 12288 4096"
# fetch BYTES: print BYTES if the object arrived whole, else 0, and record how
# a failed fetch ended in $WORK/web-errors.
fetch() {
    local got err start
    err=$(mktemp "$WORK/fetch.XXXXXX")
    start=$EPOCHREALTIME
    got=$(printf '%s\n' "$1" | ns client timeout 60 socat -t 30 - TCP:10.79.0.2:5003,connect-timeout=10 2>"$err" | wc -c)
    if test "$got" -eq "$1"; then
        echo "$1"
    else
        echo 0
        printf 'want=%s got=%s after=%ss %s\n' "$1" "$got" \
            "$(awk -v s="$start" -v e="$EPOCHREALTIME" 'BEGIN { printf "%.2f", e - s }')" \
            "$(tr '\n' ' ' <"$err")" >>"$WORK/web-errors"
    fi
    rm -f "$err"
}
export -f fetch ns
export PREFIX WORK
# page_load N: seconds for one page load; failed objects go to $WORK/web-failed.
page_load() {
    local start end html
    start=$EPOCHREALTIME
    html=$(fetch 30720)
    test "$html" -gt 0 || echo "page$1 document" >>"$WORK/web-failed"
    # shellcheck disable=SC2086
    printf '%s\n' $PAGE_OBJECTS | xargs -P "$CONNS" -I{} bash -c 'fetch {}' >"$WORK/web-$1"
    end=$EPOCHREALTIME
    awk -v p="$1" '$1 == 0 { print "page" p " object" NR }' "$WORK/web-$1" >>"$WORK/web-failed"
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.2f\n", e - s }'
}
# dns_burst N: N concurrent A lookups for www.lab, each from its own socket and
# transaction ID, retried once after a second without an answer as a stub
# resolver would. Prints "first-try-answers lookups-answered".
dns_burst() {
    seq 1 "$1" | xargs -P "$1" -I{} bash -c '
        id=$(printf "%04x" $(({} * 257)))
        q="${id}0100000100000000000003777777036c61620000010001"
        for attempt in 1 2; do
            got=$(printf "$(sed "s/../\\\\x&/g" <<<"$q")" |
                ns client timeout 5 socat -T 1 - UDP:10.79.0.2:5353 2>/dev/null | wc -c)
            if test "$got" -gt 0; then echo "$attempt"; exit 0; fi
        done
        echo 0' |
        awk '$1 == 1 { first++ } $1 > 0 { ok++ } END { print first + 0, ok + 0 }'
}
log "browser-like load: $PAGES pages x 25 objects over $CONNS connections"
: >"$WORK/web-failed"
page_times=""
for page in $(seq 1 "$PAGES"); do
    t=$(page_load "$page")
    page_times="$page_times $t"
    log "page $page loaded in ${t}s"
done
web_failed=$(wc -l <"$WORK/web-failed")
page_median=$(printf '%s\n' $page_times | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }')
# TF_ESP_EXIT_DNS_PROBE=N: N extra bursts after a quiet gap each, reporting the
# WireGuard datagrams the router put on the Wi-Fi segment (needs
# TF_ESP_EXIT_PCAP_TAP) against those the firmware received.
wg_rx_now() { grep -a -o 'wg_rx=[0-9]*' "$WORK/esp.log" | tail -1 | cut -d= -f2; }
tap_now() { tcpdump -r "$WORK/tap.pcap" 2>/dev/null | wc -l; }
for round in $(seq 1 "${TF_ESP_EXIT_DNS_PROBE:-0}"); do
    sleep 3
    fw0=$(wg_rx_now) tap0=$(tap_now)
    read -r first ok <<<"$(dns_burst "$DNS_BURST")"
    sleep 3
    fw1=$(wg_rx_now) tap1=$(tap_now)
    log "dns probe $round: answered $ok/$DNS_BURST ($first first try), segment carried $((tap1 - tap0)), firmware received $((fw1 - fw0))"
done
read -r dns_first dns_ok <<<"$(dns_burst "$DNS_BURST")"
sleep 0.5
dns_seen=$(grep -c 'query\[A\] www.lab' "$WORK/resolver.log" || true)

echo "== ESP exit-node throughput (IPv4 TCP, Mbit/s)"
printf 'METRIC esp_exit_up_mbps=%s\n' "$up"
printf 'METRIC esp_exit_down_mbps=%s\n' "$down"
printf 'METRIC esp_exit_up_x%s_mbps=%s\n' "$STREAMS" "$up_multi"
printf 'METRIC esp_exit_down_x%s_mbps=%s\n' "$STREAMS" "$down_multi"
printf 'METRIC esp_exit_page_load_s=%s\n' "$page_median"
printf 'METRIC esp_exit_page_failed_objects=%s\n' "$web_failed"
printf 'METRIC esp_exit_dns_answered=%s/%s\n' "$dns_ok" "$DNS_BURST"
printf 'METRIC esp_exit_dns_first_try=%s/%s\n' "$dns_first" "$DNS_BURST"
# Queries the resolver received, retries included: against the first-try and
# total answers this shows whether loss is on the way out or on the way back.
printf 'METRIC esp_exit_dns_queries_at_resolver=%s\n' "$dns_seen"
grep -E 'forward-budget|metric=|WARN|ERROR|panic' "$WORK/esp.log" | grep -v 'metric=heap' | tail -n 40 || true
grep 'metric=heap' "$WORK/esp.log" | tail -n 1 || true

test "$web_failed" -eq 0 || fail "$web_failed web objects failed: $(tr '\n' ' ' <"$WORK/web-failed")
$(cat "$WORK/web-errors" 2>/dev/null)"
test "$dns_ok" -eq "$DNS_BURST" || fail "only $dns_ok of $DNS_BURST concurrent DNS lookups were answered"
for metric in "$up" "$down"; do
    awk -v m="$metric" -v f="$MIN_MBPS" 'BEGIN { exit !(m > 0 && m >= f) }' ||
        fail "a single-stream direction ran at $metric Mbit/s (floor $MIN_MBPS)"
done
# `parallel` reports 0 when any of its transfers fell short.
for metric in "$up_multi" "$down_multi"; do
    awk -v m="$metric" 'BEGIN { exit !(m > 0) }' ||
        fail "a $STREAMS-stream transfer failed (aggregate $metric Mbit/s)"
done
log "PASS in $(elapsed)s"
