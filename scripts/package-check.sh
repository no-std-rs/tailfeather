#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo publish --dry-run --allow-dirty -p wirefeather
cargo publish --dry-run --allow-dirty -p micro-h2
cargo package --no-verify --allow-dirty \
    -p wirefeather -p micro-h2 -p tailfeather -p tailfeather-testkit

unpack="$(mktemp -d)"
trap 'rm -rf -- "$unpack"' EXIT
for archive in target/package/{wirefeather,micro-h2,tailfeather,tailfeather-testkit}-0.0.1.crate; do
    tar -xzf "$archive" -C "$unpack"
done

patches=(
    --config "patch.crates-io.wirefeather.path='$unpack/wirefeather-0.0.1'"
    --config "patch.crates-io.micro-h2.path='$unpack/micro-h2-0.0.1'"
    --config "patch.crates-io.tailfeather.path='$unpack/tailfeather-0.0.1'"
    --config "patch.crates-io.tailfeather-testkit.path='$unpack/tailfeather-testkit-0.0.1'"
)
cp -R release/consumers "$unpack/consumers"
cargo check --manifest-path "$unpack/consumers/wirefeather/Cargo.toml" --target-dir "$unpack/target" "${patches[@]}"
cargo check --manifest-path "$unpack/consumers/micro-h2/Cargo.toml" --target-dir "$unpack/target" "${patches[@]}"
cargo check --manifest-path "$unpack/consumers/tailfeather/Cargo.toml" --target-dir "$unpack/target" "${patches[@]}"
cargo run --quiet --manifest-path "$unpack/consumers/testkit/Cargo.toml" --target-dir "$unpack/target" "${patches[@]}" | \
    python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["schema_version"] == 1; assert all(c["status"] == "pass" for c in r["checks"])'

for archive in target/package/{wirefeather,micro-h2,tailfeather,tailfeather-testkit}-0.0.1.crate; do
    [[ -f "$archive" ]] || { echo "FAIL: missing $archive"; exit 1; }
    archive_list="$(tar -tzf "$archive")"
    [[ "$archive_list" == *"/LICENSE-MIT"* ]] || { echo "FAIL: MIT license missing from $archive"; exit 1; }
    [[ "$archive_list" == *"/LICENSE-APACHE"* ]] || { echo "FAIL: Apache license missing from $archive"; exit 1; }
    if tar -xOzf "$archive" | rg -i '(tskey-auth-|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|oauth.*secret)'; then
        echo "FAIL: possible secret in $archive"
        exit 1
    fi
done
echo "PASS: four packages contain licenses and no obvious secrets"
