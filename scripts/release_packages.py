"""Independent public crates, in dependency order."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("wirefeather", "tailfeather", "tailfeather-gateway")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def versions(root=ROOT):
    result = {}
    for name in PACKAGES:
        value = root.joinpath("crates", name, "version.txt").read_text().strip()
        if not VERSION.fullmatch(value):
            raise ValueError(f"invalid release version for {name}")
        result[name] = value
    return result


def release(tag, root=ROOT):
    current = versions(root)
    for name in PACKAGES:
        if tag == f"{name}-v{current[name]}":
            return name, current[name]
    raise ValueError("tag must match a public crate's recorded stable version")
