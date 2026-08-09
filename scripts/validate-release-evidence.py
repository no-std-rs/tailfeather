#!/usr/bin/env python3
"""Validate release evidence semantics without adding a package dependency."""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_KINDS = {"headscale", "hosted", "hardware", "adversarial"}
RESOURCE_FIELDS = {
    "ram_bytes",
    "image_bytes",
    "radio_heap_bytes",
    "minimum_stack_headroom_percent",
    "artifact",
}
ARTIFACT_FIELDS = {"uri", "sha256"}
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
TOP_LEVEL = {
    "schema_version",
    "commit",
    "created_at",
    "references",
    "baseline_hashes",
    "runs",
    "resources",
    "cleanup",
    "permission_reviews",
}


def fail(message: str) -> None:
    raise ValueError(message)


def nonempty_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{name} must be a non-empty string")
    return value


def require_fields(value: object, fields: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    missing = fields - value.keys()
    if missing:
        fail(f"{name} is missing {sorted(missing)}")
    return value


def require_exact_fields(
    value: object, fields: set[str], name: str
) -> dict[str, object]:
    result = require_fields(value, fields, name)
    extra = result.keys() - fields
    if extra:
        fail(f"{name} has unsupported fields {sorted(extra)}")
    return result


def remote_sha256(uri: str, name: str) -> str:
    request = urllib.request.Request(
        uri, headers={"User-Agent": "tailfeather-release-evidence/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if urllib.parse.urlparse(response.geturl()).scheme != "https":
                fail(f"{name}.uri redirected away from HTTPS")
            digest = hashlib.sha256()
            total = 0
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    fail(f"{name}.uri exceeds the {MAX_ARTIFACT_BYTES}-byte limit")
                digest.update(chunk)
            return digest.hexdigest()
    except (OSError, urllib.error.URLError) as error:
        fail(f"cannot retrieve {name}.uri: {error}")


def artifact_reference(
    value: object, name: str, root: pathlib.Path
) -> None:
    artifact = require_exact_fields(value, ARTIFACT_FIELDS, name)
    uri = nonempty_string(artifact["uri"], f"{name}.uri")
    if not (uri.startswith("https://") or uri.startswith("artifacts/")):
        fail(f"{name}.uri must be an HTTPS URL or an artifacts/ path")
    expected = nonempty_string(artifact["sha256"], f"{name}.sha256")
    if not HEX64.fullmatch(expected):
        fail(f"{name}.sha256 is not a lowercase SHA-256")

    if uri.startswith("artifacts/"):
        artifact_root = (root / "artifacts").resolve()
        path = (root / uri).resolve()
        if path != artifact_root and artifact_root not in path.parents:
            fail(f"{name}.uri escapes the artifacts directory")
        if not path.is_file():
            fail(f"{name}.uri does not name a regular file")
        actual = sha256(path)
    else:
        actual = remote_sha256(uri, name)
    if actual != expected:
        fail(f"{name}.sha256 does not match the referenced artifact")


def bounded_integer(
    value: object, name: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        fail(f"{name} must be between {minimum} and {maximum}")
    return value


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(path: pathlib.Path, expected_commit: str) -> None:
    if not HEX40.fullmatch(expected_commit):
        fail("expected commit is not a full lowercase Git object id")
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read valid JSON from {path}: {error}")

    document = require_fields(document, TOP_LEVEL, "evidence")
    extra = document.keys() - TOP_LEVEL
    if extra:
        fail(f"evidence has unsupported fields {sorted(extra)}")
    if document["schema_version"] != 1:
        fail("schema_version must be 1")
    if document["commit"] != expected_commit:
        fail("evidence commit does not match the candidate commit")

    created_at = nonempty_string(document["created_at"], "created_at")
    try:
        timestamp = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        fail("created_at must be an ISO-8601 date-time")
    if timestamp.tzinfo is None:
        fail("created_at must include a timezone")

    references = require_fields(
        document["references"], {"headscale", "tailscaled"}, "references"
    )
    if references["headscale"] != "v0.29.3" or references["tailscaled"] != "1.94.2":
        fail("reference versions do not match the pinned release matrix")

    root = path.resolve().parents[2]
    hashes = require_fields(
        document["baseline_hashes"], {"offline", "headscale", "hosted"}, "baseline_hashes"
    )
    for name, value in hashes.items():
        recorded = nonempty_string(value, f"baseline_hashes.{name}")
        if not HEX64.fullmatch(recorded):
            fail(f"baseline_hashes.{name} is not a lowercase SHA-256")
    for name in ("offline", "headscale", "hosted"):
        recorded = hashes[name]
        baseline = root / "tests" / "expectations" / f"{name}.json"
        if not baseline.is_file():
            fail(f"missing baseline {baseline}")
        if sha256(baseline) != recorded:
            fail(f"baseline_hashes.{name} does not match {baseline}")

    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) < len(RUN_KINDS):
        fail("runs must contain at least four entries")
    seen: set[str] = set()
    for index, item in enumerate(runs):
        run = require_fields(
            item, {"kind", "run_id", "artifact", "commit", "result"}, f"runs[{index}]"
        )
        kind = run["kind"]
        if kind not in RUN_KINDS:
            fail(f"runs[{index}].kind is unsupported")
        seen.add(kind)
        nonempty_string(run["run_id"], f"runs[{index}].run_id")
        artifact_reference(run["artifact"], f"runs[{index}].artifact", root)
        if run["commit"] != expected_commit:
            fail(f"runs[{index}].commit does not match the candidate commit")
        if run["result"] != "pass":
            fail(f"runs[{index}].result must be pass")
        if "device_id" in run:
            nonempty_string(run["device_id"], f"runs[{index}].device_id")
    if seen != RUN_KINDS:
        fail(f"runs are missing required kinds {sorted(RUN_KINDS - seen)}")

    resources = require_exact_fields(document["resources"], RESOURCE_FIELDS, "resources")
    bounded_integer(resources["ram_bytes"], "resources.ram_bytes", 1, 204_800)
    bounded_integer(resources["image_bytes"], "resources.image_bytes", 1, 1_572_864)
    bounded_integer(
        resources["radio_heap_bytes"], "resources.radio_heap_bytes", 65_536, 65_536
    )
    bounded_integer(
        resources["minimum_stack_headroom_percent"],
        "resources.minimum_stack_headroom_percent",
        25,
        100,
    )
    artifact_reference(resources["artifact"], "resources.artifact", root)

    cleanup = require_fields(document["cleanup"], {"result", "artifact"}, "cleanup")
    if cleanup["result"] != "pass":
        fail("cleanup.result must be pass")
    artifact_reference(cleanup["artifact"], "cleanup.artifact", root)

    reviews = require_fields(
        document["permission_reviews"], {"wireguard", "tailscale"}, "permission_reviews"
    )
    wireguard_review = nonempty_string(
        reviews["wireguard"], "permission_reviews.wireguard"
    )
    tailscale_review = nonempty_string(
        reviews["tailscale"], "permission_reviews.tailscale"
    )
    trademark_path = root / "release" / "trademark-review.toml"
    try:
        trademark = tomllib.loads(trademark_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read valid trademark review from {trademark_path}: {error}")
    if trademark.get("wireguard", {}).get("authorization_id") != wireguard_review:
        fail("permission_reviews.wireguard does not match the trademark review")
    if trademark.get("tailscale", {}).get("review_id") != tailscale_review:
        fail("permission_reviews.tailscale does not match the trademark review")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate-release-evidence.py EVIDENCE COMMIT", file=sys.stderr)
        return 2
    try:
        validate(pathlib.Path(sys.argv[1]), sys.argv[2])
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: release evidence is complete and bound to {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
