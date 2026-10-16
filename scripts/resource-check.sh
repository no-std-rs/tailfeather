#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec bazel test //:firmware_resource_contract //crates/tailfeather:unit_test \
    --config=optimized --test_output=all
