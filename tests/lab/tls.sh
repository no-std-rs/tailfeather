#!/usr/bin/env bash
#
# A TLS front for the lab, so the TLS client can be measured against a real
# handshake with real certificate verification.
#
# # Why a proxy rather than turning Headscale's own TLS on
#
# Headscale serves one scheme at a time, so switching it to HTTPS would take
# every other check offline — and those checks are the reason the suite is worth
# anything. A terminating proxy on a second port leaves plain HTTP where it was
# and adds TLS beside it, which is also closer to how the hosted service is
# actually reached: TLS is a layer over the same protocol, not a different one.
#
# # Why ECDSA
#
# `embedded-tls`'s certificate verifier is allocation-free for ECDSA chains. Its
# RSA support pulls in `alloc`, which this project does not have. The hosted
# endpoint is dual-chain and serves ECDSA when the client offers it, so RSA is
# not the hosted blocker. This local P-256 chain exercises the verifier's trust,
# name, and validity checks; it does not stand in for a hosted result. The
# hosted path is still blocked on the presented-chain anchor model and measured
# certificate-buffer headroom described in `harness/src/tls.rs`.
#
#   tests/lab/tls.sh up      # generate a CA and certificate, start the proxy
#   tests/lab/tls.sh down
#   tests/lab/tls.sh status

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LAB_DIR/../.." && pwd)"
STATE_DIR="${LAB_STATE_DIR:-$REPO_ROOT/.lab}"
CERT_DIR="$STATE_DIR/tls"

BACKEND_PORT="${LAB_PORT:-8080}"
TLS_PORT="${LAB_TLS_PORT:-8443}"
PID_FILE="$STATE_DIR/tls-proxy.pid"

cmd_certs() {
    mkdir -p "$CERT_DIR"
    if [[ -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/ca.crt" ]]; then
        echo "== certificates already present in $CERT_DIR"
        return
    fi

    echo "== generating an ECDSA P-256 certificate chain"
    # A CA, so the client verifies a chain rather than a self-signed leaf.
    # Verifying a self-signed certificate proves the parser works and nothing
    # about the part that matters.
    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$CERT_DIR/ca.key" -sha256 -days 365 \
        -subj "/CN=esp-gateway conformance CA" -out "$CERT_DIR/ca.crt" 2>/dev/null

    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/server.key" 2>/dev/null
    openssl req -new -key "$CERT_DIR/server.key" \
        -subj "/CN=localhost" -out "$CERT_DIR/server.csr" 2>/dev/null

    # The name the client checks must be in a SAN; CN alone has not been
    # accepted by anything for years.
    cat >"$CERT_DIR/server.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF
    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -out "$CERT_DIR/server.crt" -days 365 -sha256 \
        -extfile "$CERT_DIR/server.ext" 2>/dev/null

    cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" >"$CERT_DIR/server.pem"
    # DER is what a TLS client compares against: the trust anchor has to be raw
    # bytes, not base64 in an envelope.
    openssl x509 -in "$CERT_DIR/ca.crt" -outform DER -out "$CERT_DIR/ca.der"
    chmod 600 "$CERT_DIR"/*.key "$CERT_DIR/server.pem"

    echo "== chain:"
    openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
}

cmd_up() {
    cmd_certs
    cmd_down

    echo "== starting the TLS front on 127.0.0.1:$TLS_PORT -> $BACKEND_PORT"
    # TLS 1.3 only: that is what embedded-tls speaks, and pinning it here means
    # a successful handshake cannot have silently fallen back.
    setsid socat \
        "OPENSSL-LISTEN:$TLS_PORT,bind=127.0.0.1,reuseaddr,fork,cert=$CERT_DIR/server.pem,cafile=$CERT_DIR/ca.crt,verify=0,openssl-min-proto-version=TLS1.3" \
        "TCP:127.0.0.1:$BACKEND_PORT" \
        >"$STATE_DIR/tls-proxy.log" 2>&1 &
    echo $! >"$PID_FILE"
    sleep 1

    if ! cmd_status >/dev/null 2>&1; then
        echo "the TLS front did not come up; see $STATE_DIR/tls-proxy.log" >&2
        cat "$STATE_DIR/tls-proxy.log" >&2
        exit 1
    fi
    echo "== TLS front is up"

    # Prove it with an independent client before anything of ours touches it.
    echo "== openssl s_client sees:"
    echo | openssl s_client -connect "127.0.0.1:$TLS_PORT" \
        -CAfile "$CERT_DIR/ca.crt" -servername localhost 2>/dev/null |
        grep -E "Protocol|Cipher|Verify return code" | head -4
}

cmd_down() {
    if [[ -f "$PID_FILE" ]]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
    pkill -f "OPENSSL-LISTEN:$TLS_PORT" 2>/dev/null || true
}

cmd_status() {
    ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " || {
        echo "the TLS front is not listening on $TLS_PORT" >&2
        return 1
    }
    echo "listening on 127.0.0.1:$TLS_PORT"
}

case "${1:-up}" in
    up) cmd_up ;;
    down) cmd_down ;;
    certs) cmd_certs ;;
    status) cmd_status ;;
    *)
        echo "usage: $0 {up|down|certs|status}" >&2
        exit 1
        ;;
esac
