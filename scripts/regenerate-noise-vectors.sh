#!/usr/bin/env bash
set -euo pipefail

ROOT="${BUILD_WORKSPACE_DIRECTORY:?bazel run must be invoked from a workspace}"
TEST_BINARY="$1"

TS_CONFORMANCE_VECTORS="$ROOT/tests/vectors/versions.json" \
    "$TEST_BINARY" --exact regenerate_the_frozen_vectors --ignored --nocapture
