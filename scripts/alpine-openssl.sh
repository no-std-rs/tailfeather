#!/usr/bin/env bash
set -euo pipefail

ROOTFS="${TS_TEST_ALPINE_ROOTFS:?}"
OPENSSL_APK="${TS_TEST_OPENSSL_APK:?}"
LIBCRYPTO_APK="${TS_TEST_LIBCRYPTO_APK:?}"
LIBSSL_APK="${TS_TEST_LIBSSL_APK:?}"

RUNTIME="$(mktemp -d "${TEST_TMPDIR:-/tmp}/tailfeather-openssl.XXXXXX")"
tar --warning=no-unknown-keyword --ignore-zeros -xzf "$ROOTFS" -C "$RUNTIME" \
    ./lib/ld-musl-x86_64.so.1 ./lib/libc.musl-x86_64.so.1
tar --warning=no-unknown-keyword --ignore-zeros -xzf "$OPENSSL_APK" -C "$RUNTIME" \
    --exclude='.SIGN.*' --exclude='.PKGINFO' usr/bin/openssl
tar --warning=no-unknown-keyword --ignore-zeros -xzf "$LIBCRYPTO_APK" -C "$RUNTIME" \
    --exclude='.SIGN.*' --exclude='.PKGINFO' usr/lib/libcrypto.so.3
tar --warning=no-unknown-keyword --ignore-zeros -xzf "$LIBSSL_APK" -C "$RUNTIME" \
    --exclude='.SIGN.*' --exclude='.PKGINFO' usr/lib/libssl.so.3

exec "$RUNTIME/lib/ld-musl-x86_64.so.1" \
    --library-path "$RUNTIME/usr/lib:$RUNTIME/lib" \
    "$RUNTIME/usr/bin/openssl" "$@"
