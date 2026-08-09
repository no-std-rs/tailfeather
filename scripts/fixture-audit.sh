#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/crates/tailfeather-testkit/fixtures"

python3 - "$FIXTURES" <<'PY'
import hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "provenance.json").read_text())
assert manifest["schema_version"] == 1
listed = set()
required = {"path", "origin", "versions", "date", "redistribution_basis", "sanitization", "sha256"}
for item in manifest["fixtures"]:
    missing = required - item.keys()
    assert not missing, f"{item.get('path', '<unknown>')}: missing {sorted(missing)}"
    path = root / item["path"]
    assert path.is_file(), f"missing fixture: {path}"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == item["sha256"], f"{path}: sha256 {actual}, expected {item['sha256']}"
    listed.add(item["path"])
embedded = {p.name for p in root.iterdir() if p.is_file() and p.name != "provenance.json"}
assert embedded == listed, f"manifest mismatch: embedded={sorted(embedded)}, listed={sorted(listed)}"
print(f"PASS: {len(listed)} published fixture(s) have complete provenance and matching SHA-256")
PY
