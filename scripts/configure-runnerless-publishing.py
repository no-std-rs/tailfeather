#!/usr/bin/env python3
"""Configure the three independent public-crate destinations in Runnerless."""

import argparse
import json
import subprocess
from urllib.parse import quote

from release_packages import PACKAGES

REPOSITORY = "no-std-rs/tailfeather"


def api(method, path, body=None):
    # The portable Runl executable uses a shell loader on Linux.
    result = subprocess.run(["bash", "-c", 'runl "$@"', "--", "api", method, path],
                            input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def configure(organization, *, dry_run=False, organization_credential=False):
    base = f"/api/v1/orgs/{quote(organization, safe='')}/repositories"
    repositories = api("GET", base)["repositories"]
    matches = [item for item in repositories if item["full_name"] == REPOSITORY]
    if len(matches) != 1 or matches[0]["state"] not in ("active", "adopted"):
        raise ValueError(f"connect {REPOSITORY} in Runnerless first")
    base += "/" + quote(matches[0]["id"], safe="")
    current = api("GET", base + "/publishing")
    previous = next((item for item in current["registries"] if item["registry"] == "crates"), {})
    desired = {
        "packages": list(PACKAGES), "tag_prefix": "",
        "package_tag_prefixes": {name: name + "-v" for name in PACKAGES},
        "organization_credential": organization_credential or previous.get("organization_credential", False),
        "options": {},
    }
    if dry_run:
        print(json.dumps({"repository": REPOSITORY, "target": desired,
                          "enable_production": True}, indent=2))
        return
    if any(previous.get(key) != value for key, value in desired.items()):
        api("PUT", base + "/publishing/crates/target", desired)
    production = current["production"]
    if production is None:
        production = api("POST", base + "/environments", {"name": "production"})
    if not production["enabled"]:
        api("PATCH", base + "/environments/" + quote(production["id"], safe=""), {"enabled": True})
    actual = api("GET", base + "/publishing")
    target = next(item for item in actual["registries"] if item["registry"] == "crates")
    if any(target.get(key) != value for key, value in desired.items()):
        raise ValueError("Runnerless publishing target differs from the requested configuration")
    if not actual["production"]["enabled"]:
        raise ValueError("Runnerless Production is disabled")
    print(json.dumps({"repository": REPOSITORY, "production": actual["production"],
                      "packages": target["package_credentials"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--organization-credential", action="store_true")
    args = parser.parse_args()
    try:
        configure(args.organization, dry_run=args.dry_run,
                  organization_credential=args.organization_credential)
    except (ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
