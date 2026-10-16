#!/usr/bin/env bash
set -euo pipefail

ELF="$1"
READELF="$2"
NM="$3"
fail() { echo "harness artifact contract: FAIL: $*" >&2; exit 1; }

test -x "$ELF" || fail "missing executable: $ELF"
test -x "$READELF" || fail "missing LLVM readelf: $READELF"
test -x "$NM" || fail "missing LLVM nm: $NM"

# Capture tool output before matching it. With pipefail, piping llvm-readelf into
# grep -q races the reader's early exit against the writer and can turn a valid
# ELF into an intermittent SIGPIPE failure. The same race could also hide a
# forbidden match in the negative checks below.
HEADER="$("$READELF" -h "$ELF")" || fail "cannot read ELF header"
PROGRAM_HEADERS="$("$READELF" -lW "$ELF")" || fail "cannot read ELF program headers"
DYNAMIC="$("$READELF" -dW "$ELF" 2>&1)" || fail "cannot read ELF dynamic section"

grep -Eq '[[:space:]]Type:[[:space:]]+EXEC[[:space:]]' <<<"$HEADER" || fail "not an ELF executable"
grep -q 'Entry point address:' <<<"$HEADER" || fail "ELF has no entry point"
grep -q ' INTERP ' <<<"$PROGRAM_HEADERS" && fail "ELF has a program interpreter"
grep -q '(NEEDED)' <<<"$DYNAMIC" && fail "ELF has dynamic dependencies"

SYMBOLS="$("$NM" -a "$ELF")"
grep -Eq '[[:space:]]_start$' <<<"$SYMBOLS" || fail "_start is absent"
if grep -Eiq '(^|[^[:alnum:]_])(malloc|calloc|realloc|free|__rust_alloc|__rdl_alloc|__rg_alloc)([^[:alnum:]_]|$)' <<<"$SYMBOLS"; then
    fail "allocator or allocation symbols reached the harness"
fi
if grep -Eiq '(^|[^[:alnum:]_])(__libc_start_main|libc)([^[:alnum:]_]|$)' <<<"$SYMBOLS"; then
    fail "libc symbols reached the harness"
fi

echo "PASS: static no-libc/no-allocator harness ELF"
