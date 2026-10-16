#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
case "${1:-offline}" in
    offline) exec bazel test //:offline_conformance --test_output=all ;;
    lab) exec bazel test //:privileged_lab --test_output=all ;;
    *) echo "usage: $0 {offline|lab}" >&2; exit 2 ;;
esac
