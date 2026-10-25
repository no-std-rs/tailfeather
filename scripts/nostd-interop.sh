#!/usr/bin/env bash
# End-to-end no_std exit-node interoperability:
# kernel client -> WireGuard -> userspace NAT -> raw IPv4 -> kernel server.

set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="${1:-$REPO_ROOT/bazel-bin/harness/harness}"
SUFFIX="$$"
CLIENT_NS="tf-client-$SUFFIX"
GATEWAY_NS="tf-gateway-$SUFFIX"
SERVER_NS="tf-server-$SUFFIX"
LINK_TAG="${SUFFIX: -5}"
CLIENT_LINK="tfc-$LINK_TAG"
GATEWAY_DOWNLINK="tfgc-$LINK_TAG"
GATEWAY_UPLINK="tfgs-$LINK_TAG"
SERVER_LINK="tfs-$LINK_TAG"
WORK="$(mktemp -d)"
PIDS=()

UNDERLAY_CLIENT=10.210.0.2
UNDERLAY_GATEWAY=10.210.0.1
UPLINK_GATEWAY=10.211.0.1
SERVER=10.211.0.2
TUNNEL_CLIENT=100.64.0.2
TUNNEL_GATEWAY=100.64.0.1
WG_PORT=51820
PEER_API_PORT=5254
DOH_NAME=doh.probe.internal
DOH_ANSWER=203.0.113.7
RAW_MARK=0x7466

cleanup() {
    local result=$?
    if [[ $result -ne 0 ]]; then
        for log in "$WORK"/*6*.log "$WORK"/udp6-response; do
            [[ -f $log ]] && cat "$log" >&2
        done
    fi
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    ip netns delete "$CLIENT_NS" 2>/dev/null || true
    ip netns delete "$GATEWAY_NS" 2>/dev/null || true
    ip netns delete "$SERVER_NS" 2>/dev/null || true
    ip link delete "$CLIENT_LINK" 2>/dev/null || true
    ip link delete "$GATEWAY_DOWNLINK" 2>/dev/null || true
    ip link delete "$GATEWAY_UPLINK" 2>/dev/null || true
    ip link delete "$SERVER_LINK" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -x "$HARNESS" ]] || { echo "bare harness not executable: $HARNESS" >&2; exit 2; }
for command in ethtool ip wg ping iptables ip6tables openssl ss socat; do
    command -v "$command" >/dev/null || { echo "missing dependency: $command" >&2; exit 2; }
done

wait_ready() {
    local pid="$1" log="$2"
    for _ in $(seq 1 100); do
        grep -q '"event":"ready"' "$log" && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "process exited before ready: $log" >&2
            cat "$log" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "process did not become ready: $log" >&2
    cat "$log" >&2
    return 1
}

wait_listening() {
    local pid="$1" namespace="$2" address="$3" port="$4" log="$5"
    for _ in $(seq 1 100); do
        ip netns exec "$namespace" ss -H -ltn | grep -q "$address:$port" && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "process exited before listening: $log" >&2
            cat "$log" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "process did not begin listening: $log" >&2
    cat "$log" >&2
    return 1
}

b64_to_hex() {
    openssl base64 -d -A | od -An -tx1 | tr -d ' \n'
}

echo "== allocation-free replay selftest"
"$HARNESS" wg-selftest
echo "PASS: wg.replay"
echo "== shared production gateway core selftest"
"$HARNESS" gateway-selftest

echo "== isolated client/gateway/server topology"
ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip netns add "$SERVER_NS"
ip link add "$CLIENT_LINK" type veth peer name "$GATEWAY_DOWNLINK"
ip link set "$CLIENT_LINK" netns "$CLIENT_NS"
ip link set "$GATEWAY_DOWNLINK" netns "$GATEWAY_NS"
ip link add "$GATEWAY_UPLINK" type veth peer name "$SERVER_LINK"
ip link set "$GATEWAY_UPLINK" netns "$GATEWAY_NS"
ip link set "$SERVER_LINK" netns "$SERVER_NS"

# A veth can expose CHECKSUM_PARTIAL packets to raw sockets before Linux has
# materialized their transport checksum. Disable transmit checksum offload on
# both ends of the uplink so the harness observes real wire-format checksums
# and can reject invalid packets without guessing from attacker-controlled data.
ip netns exec "$GATEWAY_NS" ethtool -K "$GATEWAY_UPLINK" tx off >/dev/null
ip netns exec "$SERVER_NS" ethtool -K "$SERVER_LINK" tx off >/dev/null

ip -n "$CLIENT_NS" addr add "$UNDERLAY_CLIENT/24" dev "$CLIENT_LINK"
ip -n "$GATEWAY_NS" addr add "$UNDERLAY_GATEWAY/24" dev "$GATEWAY_DOWNLINK"
ip -n "$GATEWAY_NS" addr add "$UPLINK_GATEWAY/24" dev "$GATEWAY_UPLINK"
ip -n "$SERVER_NS" addr add "$SERVER/24" dev "$SERVER_LINK"
for pair in \
    "$CLIENT_NS $CLIENT_LINK" \
    "$GATEWAY_NS $GATEWAY_DOWNLINK" \
    "$GATEWAY_NS $GATEWAY_UPLINK" \
    "$SERVER_NS $SERVER_LINK"; do
    read -r ns dev <<<"$pair"
    ip -n "$ns" link set lo up
    ip -n "$ns" link set "$dev" up
done

echo "== ephemeral WireGuard identity and routed server address"
wg genkey >"$WORK/client.key"
wg pubkey <"$WORK/client.key" >"$WORK/client.pub"
wg genkey >"$WORK/gateway.key"
wg pubkey <"$WORK/gateway.key" >"$WORK/gateway.pub"
CLIENT_PUB_HEX="$(b64_to_hex <"$WORK/client.pub")"
GATEWAY_PRIV_HEX="$(b64_to_hex <"$WORK/gateway.key")"

ip -n "$CLIENT_NS" link add wg0 type wireguard
ip -n "$CLIENT_NS" addr add "$TUNNEL_CLIENT/32" dev wg0
ip netns exec "$CLIENT_NS" wg set wg0 \
    private-key "$WORK/client.key" \
    peer "$(cat "$WORK/gateway.pub")" \
    endpoint "$UNDERLAY_GATEWAY:$WG_PORT" \
    allowed-ips "$SERVER/32,$TUNNEL_GATEWAY/32"
ip -n "$CLIENT_NS" link set wg0 mtu 1280 up
ip -n "$CLIENT_NS" route add "$SERVER/32" dev wg0
# The peer API lives on the gateway's own tunnel address, not past it.
ip -n "$CLIENT_NS" route add "$TUNNEL_GATEWAY/32" dev wg0

echo "== suppressing only the gateway kernel's competing errors"
# Raw-socket packets carry this fixed mark. Kernel-generated TCP resets do not.
ip netns exec "$GATEWAY_NS" iptables -A OUTPUT -m mark --mark "$RAW_MARK" -j ACCEPT
# Reusing a closed slot rotates its external port up through the whole
# generation sequence (base + slot + n * TCP_SLOTS), so the range has to cover
# every port `external_port_for_packet` can hand out, not just the first
# generation. The kernel has no socket for these flows, so an unsuppressed RST
# would kill a connection the gateway translated correctly.
ip netns exec "$GATEWAY_NS" iptables -A OUTPUT \
    -p tcp --tcp-flags RST RST --sport 41000:65535 \
    -m mark ! --mark "$RAW_MARK" -j DROP
# For UDP, match port-unreachable errors whose quoted inner datagram targeted
# one of the translated ports. The u32 expression follows both variable-length
# IPv4 headers before reading the quoted UDP destination port.
ip netns exec "$GATEWAY_NS" iptables -A OUTPUT \
    -p icmp --icmp-type port-unreachable -m mark ! --mark "$RAW_MARK" \
    -m u32 --u32 '0>>22&0x3C@8>>22&0x3C@0&0xFFFF=40000:40031' -j DROP

GATEWAY_LOG="$WORK/gateway.log"
ip netns exec "$GATEWAY_NS" "$HARNESS" gateway \
    "$UNDERLAY_GATEWAY" "$WG_PORT" "$GATEWAY_PRIV_HEX" "$CLIENT_PUB_HEX" \
    "$TUNNEL_GATEWAY" "$UPLINK_GATEWAY" >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")
wait_ready "$GATEWAY_PID" "$GATEWAY_LOG"

run_exit_probe() {
    local protocol="$1" server_port="$2"
    local server_log="$WORK/$protocol-server.log"
    timeout 20 ip netns exec "$SERVER_NS" "$HARNESS" \
        probe-server "$protocol" "$SERVER" "$server_port" >"$server_log" 2>&1 &
    local server_pid=$!
    PIDS+=("$server_pid")
    wait_ready "$server_pid" "$server_log"

    # The client connects directly to the server tuple. There is no gateway
    # listener: the route sends the kernel-generated packet into WireGuard.
    timeout 20 ip netns exec "$CLIENT_NS" "$HARNESS" \
        probe-client "$protocol" "$SERVER" "$server_port" "$UPLINK_GATEWAY"
    wait "$server_pid"
    cat "$server_log"
}

run_tls_probe() {
    local server_port="$1"
    local server_log="$WORK/tls-server.log"
    local client_log="$WORK/tls-client.log"
    local response="$WORK/tls-response.txt"

    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
        -subj '/CN=nostd-interop' -addext "subjectAltName=IP:$SERVER" \
        -keyout "$WORK/tls.key" -out "$WORK/tls.crt" >/dev/null 2>&1

    timeout 20 ip netns exec "$SERVER_NS" openssl s_server \
        -accept "$SERVER:$server_port" -cert "$WORK/tls.crt" \
        -key "$WORK/tls.key" -tls1_3 -quiet -www -naccept 1 \
        >"$server_log" 2>&1 &
    local server_pid=$!
    PIDS+=("$server_pid")
    wait_listening "$server_pid" "$SERVER_NS" "$SERVER" "$server_port" "$server_log"

    printf 'GET / HTTP/1.0\r\nHost: nostd-interop\r\n\r\n' | \
        timeout 20 ip netns exec "$CLIENT_NS" openssl s_client \
            -connect "$SERVER:$server_port" -CAfile "$WORK/tls.crt" \
            -verify_return_error -verify_ip "$SERVER" -tls1_3 -quiet \
            >"$response" 2>"$client_log"
    wait "$server_pid"
    grep -q '^HTTP/1.0 200 ok' "$response"
    [[ $(wc -c <"$response") -gt 2048 ]] || {
        echo "TLS response was too small to exercise multi-packet forwarding" >&2
        return 1
    }
}

run_exit_probe udp 42001
echo "PASS: exit.forward.udp"
run_exit_probe tcp 42002
run_tls_probe 42003
echo "PASS: exit.forward.tcp"
cat "$GATEWAY_LOG"

kill "$GATEWAY_PID"
wait "$GATEWAY_PID" 2>/dev/null || true

echo "== IPv6 UDP, TCP, ICMP and hop-limit forwarding"
V6_CLIENT=fd7a:115c:a1e0::2
V6_GATEWAY=fd7a:115c:a1e0::1
V6_UPLINK=2001:db8:211::1
V6_SERVER=2001:db8:211::2
V6_UNROUTABLE=2001:db8:212::2
ip -n "$CLIENT_NS" -6 addr add "$V6_CLIENT/128" dev wg0 nodad
ip -n "$GATEWAY_NS" -6 addr add "$V6_UPLINK/64" dev "$GATEWAY_UPLINK" nodad
ip -n "$SERVER_NS" -6 addr add "$V6_SERVER/64" dev "$SERVER_LINK" nodad
ip netns exec "$CLIENT_NS" wg set wg0 peer "$(cat "$WORK/gateway.pub")" remove
ip netns exec "$CLIENT_NS" wg set wg0 peer "$(cat "$WORK/gateway.pub")" \
    endpoint "$UNDERLAY_GATEWAY:$WG_PORT" \
    allowed-ips "$SERVER/32,$TUNNEL_GATEWAY/32,$V6_SERVER/128,$V6_GATEWAY/128,$V6_UNROUTABLE/128"
ip -n "$CLIENT_NS" -6 route add "$V6_SERVER/128" dev wg0
ip -n "$CLIENT_NS" -6 route add "$V6_UNROUTABLE/128" dev wg0
ip -n "$CLIENT_NS" -6 route add "$V6_GATEWAY/128" dev wg0
ip netns exec "$GATEWAY_NS" ip6tables -A OUTPUT -m mark --mark "$RAW_MARK" -j ACCEPT
ip netns exec "$GATEWAY_NS" ip6tables -A OUTPUT -p tcp --tcp-flags RST RST \
    --sport 45000:65000 -m mark ! --mark "$RAW_MARK" -j DROP
ip netns exec "$GATEWAY_NS" ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type destination-unreachable \
    -m mark ! --mark "$RAW_MARK" -j DROP
V6_LOG="$WORK/gateway-v6.log"
ip netns exec "$GATEWAY_NS" "$HARNESS" gateway6 \
    "$UNDERLAY_GATEWAY" "$WG_PORT" "$GATEWAY_PRIV_HEX" "$CLIENT_PUB_HEX" \
    "$TUNNEL_GATEWAY" "$V6_UPLINK" "$V6_CLIENT" "$V6_GATEWAY" >"$V6_LOG" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")
wait_ready "$GATEWAY_PID" "$V6_LOG"
ip netns exec "$CLIENT_NS" ping -6 -c 1 -W 3 "$V6_GATEWAY"
echo "PASS: exit.forward.ipv6.local-echo"
ip netns exec "$CLIENT_NS" ping -6 -c 2 -W 3 "$V6_SERVER"
echo "PASS: exit.forward.ipv6.icmp"
# Real raw send failures must not reserve NAT entries. This off-link test
# address has no route in the isolated gateway, so its sendto fails before a
# packet reaches the wire. Thirty-two distinct failed flows must leave room
# for the successful UDP and TCP exchanges below.
if ip -n "$GATEWAY_NS" -6 route get "$V6_UNROUTABLE" >"$WORK/udp6-no-route.log" 2>&1; then
    echo "IPv6 failed-send fixture unexpectedly has an uplink route" >&2
    exit 1
fi
for index in $(seq 1 32); do
    printf 'rejected-send' | timeout 3 ip netns exec "$CLIENT_NS" socat -u - \
        "UDP6:[$V6_UNROUTABLE]:42011,sourceport=$((43000 + index))" >>"$WORK/udp6-rejected.log" 2>&1
done
# No kernel IPv6 forwarding is enabled: replies must pass the shared no_std
# translator. The observed server-side source is the uplink, not the tailnet.
timeout 20 ip netns exec "$SERVER_NS" socat -d -d \
    "UDP6-RECVFROM:42011,bind=[$V6_SERVER],fork" EXEC:/bin/cat >"$WORK/udp6-server.log" 2>&1 &
PIDS+=("$!")
sleep 0.2
printf 'ipv6-udp-roundtrip' | timeout 8 ip netns exec "$CLIENT_NS" socat -T 2 - \
    "UDP6:[$V6_SERVER]:42011" >"$WORK/udp6-response"
[[ $(cat "$WORK/udp6-response") == ipv6-udp-roundtrip ]]
grep -Eq 'receiving packet from.*(2001:db8:211::1|2001:0db8:0211:0000:0000:0000:0000:0001)' "$WORK/udp6-server.log"
echo "PASS: exit.forward.ipv6.udp"
# A large reply fits the 1500-byte uplink but exceeds the tunnel's 1280-byte
# MTU. The upstream kernel must receive our ICMPv6 Packet Too Big and install
# the smaller PMTU; losing the packet in a 1312-byte WireGuard RX arena would
# leave this route at 1500 and fail the check.
timeout 20 ip netns exec "$SERVER_NS" socat \
    "UDP6-RECVFROM:42013,bind=[$V6_SERVER],fork" \
    'SYSTEM:head -c 1400 /dev/zero' >"$WORK/udp6-pmtu.log" 2>&1 &
PIDS+=("$!")
sleep 0.2
printf 'ipv6-pmtu' | timeout 8 ip netns exec "$CLIENT_NS" socat -T 1 - \
    "UDP6:[$V6_SERVER]:42013" >"$WORK/udp6-pmtu-response"
ip -n "$SERVER_NS" -6 route get "$V6_UPLINK" | grep -q 'mtu 1280'
echo "PASS: exit.forward.ipv6.packet-too-big"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj '/CN=nostd-ipv6-interop' -addext "subjectAltName=IP:$V6_SERVER" \
    -keyout "$WORK/tls6.key" -out "$WORK/tls6.crt" >/dev/null 2>&1
timeout 20 ip netns exec "$SERVER_NS" openssl s_server -6 \
    -accept "[$V6_SERVER]:42012" -cert "$WORK/tls6.crt" -key "$WORK/tls6.key" \
    -tls1_3 -quiet -www -naccept 1 >"$WORK/tcp6-server.log" 2>&1 &
V6_TLS_PID=$!
PIDS+=("$V6_TLS_PID")
sleep 0.2
printf 'GET / HTTP/1.0\r\nHost: nostd-ipv6-interop\r\n\r\n' | \
    timeout 15 ip netns exec "$CLIENT_NS" openssl s_client -6 \
    -connect "[$V6_SERVER]:42012" -CAfile "$WORK/tls6.crt" -verify_return_error \
    -verify_ip "$V6_SERVER" -tls1_3 -quiet >"$WORK/tcp6-response" 2>"$WORK/tcp6-client.log"
wait "$V6_TLS_PID"
grep -q '^HTTP/1.0 200 ok' "$WORK/tcp6-response"
[[ $(wc -c <"$WORK/tcp6-response") -gt 2048 ]]
echo "PASS: exit.forward.ipv6.tcp"
echo "PASS: exit.forward.ipv6.failed-send-state"
# BusyBox ping's -t does not set the IPv6 unicast hop limit, and its IPv6
# mode omits received ICMP error text. Set the actual IPv6 route metric and observe the kernel's
# validated Time Exceeded counter rather than depending on ping's CLI/output.
V6_EXPIRED_BEFORE=$(ip netns exec "$CLIENT_NS" awk '$1 == "Icmp6InTimeExcds" { print $2 }' /proc/net/snmp6)
[[ -n $V6_EXPIRED_BEFORE ]]
ip -n "$CLIENT_NS" -6 route replace "$V6_SERVER/128" dev wg0 hoplimit 1
if ip netns exec "$CLIENT_NS" ping -6 -c 1 -W 3 "$V6_SERVER" >"$WORK/v6-hop.log" 2>&1; then
    echo "expired IPv6 hop limit unexpectedly reached the server" >&2
    exit 1
fi
V6_EXPIRED_AFTER=$(ip netns exec "$CLIENT_NS" awk '$1 == "Icmp6InTimeExcds" { print $2 }' /proc/net/snmp6)
[[ $V6_EXPIRED_AFTER -gt $V6_EXPIRED_BEFORE ]]
echo "PASS: exit.forward.ipv6.hop-limit"
kill "$GATEWAY_PID"
wait "$GATEWAY_PID" 2>/dev/null || true

echo "== peer-API DNS over the same tunnel"
# One resolver for both phases. It answers everything with the same address and
# reports the EDNS0 payload size it was asked for, which is the only way to see
# from outside whether the proxy lowered it.
DNS_LOG="$WORK/dns-server.log"
# 250 ms per answer. A resolver that replies instantly lets the proxy retire
# each request before the next arrives, so its four connection slots are never
# under simultaneous pressure and dns.peerapi.concurrency would prove nothing.
ip netns exec "$SERVER_NS" "$HARNESS" dns-server "$SERVER" 53 250 >"$DNS_LOG" 2>&1 &
DNS_PID=$!
PIDS+=("$DNS_PID")
wait_ready "$DNS_PID" "$DNS_LOG"

# A restarted gateway has no WireGuard session state, and the kernel client
# would keep encrypting to the old one until its own rekey timer expired.
# Removing and re-adding the peer forces a fresh handshake immediately.
reset_client_peer() {
    ip netns exec "$CLIENT_NS" wg set wg0 \
        peer "$(cat "$WORK/gateway.pub")" remove
    ip netns exec "$CLIENT_NS" wg set wg0 \
        peer "$(cat "$WORK/gateway.pub")" \
        endpoint "$UNDERLAY_GATEWAY:$WG_PORT" \
        allowed-ips "$SERVER/32,$TUNNEL_GATEWAY/32"
}

run_doh_probe() {
    local filter="$1"
    local gateway_log="$WORK/gateway-$filter.log"

    ip netns exec "$GATEWAY_NS" "$HARNESS" gateway \
        "$UNDERLAY_GATEWAY" "$WG_PORT" "$GATEWAY_PRIV_HEX" "$CLIENT_PUB_HEX" \
        "$TUNNEL_GATEWAY" "$UPLINK_GATEWAY" "$SERVER" "$filter" >"$gateway_log" 2>&1 &
    local gateway_pid=$!
    PIDS+=("$gateway_pid")
    wait_ready "$gateway_pid" "$gateway_log"
    reset_client_peer

    # Both RFC 8484 forms, because they reach the same resolver by different
    # request parsers: base64url in a query string, and a request body.
    local method
    for method in get post; do
        timeout 30 ip netns exec "$CLIENT_NS" "$HARNESS" doh-client \
            "$TUNNEL_GATEWAY" "$PEER_API_PORT" "$method" "$DOH_NAME" "$DOH_ANSWER"
    done

    kill "$gateway_pid"
    wait "$gateway_pid" 2>/dev/null || true
    cat "$gateway_log"
}

assert_edns_clamped() {
    # The client advertised 4096, which is past what the proxy can buffer: a
    # reply that size would have been dropped on arrival and the client would
    # have waited out the whole deadline for a 500. The clamp is only
    # observable from the resolver's side.
    grep -q '"advertised":1232' "$DNS_LOG" || {
        echo "the resolver never saw a clamped EDNS payload size" >&2
        cat "$DNS_LOG" >&2
        return 1
    }
    if grep -q '"advertised":4096' "$DNS_LOG"; then
        echo "the proxy forwarded the client's 4096-byte EDNS advertisement" >&2
        cat "$DNS_LOG" >&2
        return 1
    fi
}

# An unrestricted filter, so this phase measures the DoH round trip itself.
run_doh_probe open
assert_edns_clamped
echo "PASS: dns.peerapi.doh"

# The configuration that used to fail: the resolver is RFC1918 and the tailnet
# grant is autogroup:internet, which excludes private ranges. Authorizing the
# client's right to reach the internet on port 53 — rather than its right to
# reach the resolver, which it never addresses — is what makes this resolve
# instead of returning 500.
run_doh_probe internet
assert_edns_clamped
cat "$DNS_LOG"
echo "PASS: dns.peerapi.acl"

# The peer API terminates peerapi::CONNECTIONS (4) connections at once. On
# hardware, sustained DoH traffic exhausted them -- 256 capacity drops -- while
# the single-request checks above stayed green, because one request at a time
# never occupies more than one slot. Drive exactly the documented capacity
# concurrently, against the deliberately slow resolver, and require that every
# client is answered and that the gateway reports no drop.
run_concurrent_doh_probe() {
    local filter="$1" clients="$2"
    local gateway_log="$WORK/gateway-concurrent.log"

    ip netns exec "$GATEWAY_NS" "$HARNESS" gateway \
        "$UNDERLAY_GATEWAY" "$WG_PORT" "$GATEWAY_PRIV_HEX" "$CLIENT_PUB_HEX" \
        "$TUNNEL_GATEWAY" "$UPLINK_GATEWAY" "$SERVER" "$filter" >"$gateway_log" 2>&1 &
    local gateway_pid=$!
    PIDS+=("$gateway_pid")
    wait_ready "$gateway_pid" "$gateway_log"
    reset_client_peer

    # One warm-up request, so the WireGuard handshake is not part of what the
    # concurrent clients are racing against.
    timeout 30 ip netns exec "$CLIENT_NS" "$HARNESS" doh-client \
        "$TUNNEL_GATEWAY" "$PEER_API_PORT" get "$DOH_NAME" "$DOH_ANSWER" >/dev/null

    local pids=() index rc=0
    for index in $(seq 1 "$clients"); do
        timeout 30 ip netns exec "$CLIENT_NS" "$HARNESS" doh-client \
            "$TUNNEL_GATEWAY" "$PEER_API_PORT" post "$DOH_NAME" "$DOH_ANSWER" \
            >"$WORK/doh-$index.log" 2>&1 &
        pids+=("$!")
        PIDS+=("$!")
    done
    for index in "${!pids[@]}"; do
        if ! wait "${pids[$index]}"; then
            echo "concurrent DoH client $((index + 1)) failed:" >&2
            cat "$WORK/doh-$((index + 1)).log" >&2
            rc=1
        fi
    done

    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    cat "$gateway_log"

    (( rc == 0 )) || return 1
    if grep -q "peer-API capacity drop" "$gateway_log"; then
        echo "the peer API dropped a request at its documented capacity of $clients" >&2
        return 1
    fi
}

run_concurrent_doh_probe open 4
echo "PASS: dns.peerapi.concurrency"

kill "$DNS_PID" 2>/dev/null || true
wait "$DNS_PID" 2>/dev/null || true
PIDS=()

echo "== standalone kernel WireGuard regression checks"
"$REPO_ROOT/scripts/interop-wireguard.sh" harness-responder "$HARNESS"
echo "PASS: wg.handshake.responder"
echo "PASS: wg.transport.roundtrip"
"$REPO_ROOT/scripts/interop-wireguard.sh" harness-initiator "$HARNESS"
echo "PASS: wg.handshake.initiator"
"$REPO_ROOT/scripts/interop-wireguard.sh" harness-rekey "$HARNESS"
echo "PASS: wg.rekey"

echo "PASS: all no_std interoperability checks completed"
