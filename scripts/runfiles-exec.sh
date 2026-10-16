#!/usr/bin/env bash
set -euo pipefail
PROGRAM="$1"
shift
exec "$PROGRAM" "$@"
