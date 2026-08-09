#!/usr/bin/env python3
"""Validate that both trademark reviews contain explicit approval records."""

from __future__ import annotations

import pathlib
import sys
import tomllib


REQUIRED = {
    "wireguard": {
        "status",
        "policy",
        "authorization_id",
        "approved_wording",
        "acknowledgment",
        "non_affiliation_disclaimer",
    },
    "tailscale": {
        "status",
        "review_id",
        "approved_wording",
        "non_affiliation_disclaimer",
    },
}


def fail(message: str) -> None:
    raise ValueError(message)


def validate(path: pathlib.Path) -> None:
    try:
        document = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read valid TOML from {path}: {error}")
    if document.get("schema_version") != 1:
        fail("schema_version must be 1")

    for owner, required in REQUIRED.items():
        review = document.get(owner)
        if not isinstance(review, dict):
            fail(f"missing [{owner}] review")
        missing = required - review.keys()
        if missing:
            fail(f"[{owner}] is missing {sorted(missing)}")
        extra = review.keys() - required
        if extra:
            fail(f"[{owner}] has unsupported fields {sorted(extra)}")
        if review["status"] != "approved":
            fail(f"[{owner}].status must be approved")
        for field in required - {"status"}:
            value = review[field]
            if not isinstance(value, str) or not value.strip():
                fail(f"[{owner}].{field} must be a non-empty string")

    policy = document["wireguard"]["policy"]
    if not policy.startswith("https://www.wireguard.com/"):
        fail("[wireguard].policy must reference wireguard.com over HTTPS")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-trademark-review.py REVIEW.toml", file=sys.stderr)
        return 2
    try:
        validate(pathlib.Path(sys.argv[1]))
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: WireGuard and Tailscale trademark approval records are complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
