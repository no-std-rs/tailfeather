#!/usr/bin/env python3
"""Align build/package metadata with Runnerless's per-crate version files."""

import argparse
import os
from pathlib import Path
import re
import tomllib

from release_packages import ROOT, PACKAGES, release, versions


def package_version(source, version):
    sections = re.split(r"(?m)(?=^\[[^\n]+\]\s*$)", source)
    for index, section in enumerate(sections):
        if not section.startswith("[package]"):
            continue
        sections[index], count = re.subn(
            r'(?m)^(version\s*=\s*)"[^"\n]+"',
            lambda match: match[1] + f'"{version}"', section,
        )
        if count != 1:
            raise ValueError("expected exactly one package version")
        return "".join(sections)
    raise ValueError("missing package section")


def prepare(root=ROOT, *, tag=None, web_channel=None, commit=None):
    current = versions(root)
    selected = release(tag, root) if tag else None
    if web_channel == "stable" and (not selected or selected[0] != "tailfeather"):
        raise ValueError("stable web builds require a Tailfeather release tag")
    if web_channel and not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        raise ValueError("web builds require a full commit SHA")
    web_version = current["tailfeather"]
    if web_channel == "main":
        web_version += f"-main.{commit[:12]}"
    manifests = [root / "Cargo.toml", *root.glob("crates/*/Cargo.toml")]
    manifests += [root / path / "Cargo.toml" for path in ("harness", "firmware", "web/client")]
    changed = {}
    for path in manifests:
        if not path.exists():
            continue
        source = path.read_text()
        package = tomllib.loads(source).get("package", {}).get("name")
        if package in current:
            source = package_version(source, current[package])
        if package == "tailfeather-web" and web_channel:
            source = package_version(source, web_version)
        for name, version in current.items():
            def dependency(match):
                fields = match[2]
                if not re.search(r"\bpath\s*=", fields):
                    return match[0]
                if re.search(r"\bversion\s*=", fields):
                    fields = re.sub(r'\bversion\s*=\s*"[^"\n]+"', f'version = "{version}"', fields)
                else:
                    fields = fields.rstrip().rstrip(",") + f', version = "{version}" '
                return match[1] + fields + "}"
            source = re.sub(rf"(?m)^(\s*{re.escape(name)}\s*=\s*\{{)([^\n}}]*)\}}", dependency, source)
        tomllib.loads(source)
        changed[path] = source
    locked_versions = dict(current)
    if web_channel:
        locked_versions["tailfeather-web"] = web_version
    for relative in ("Cargo.lock", "harness/Cargo.lock", "firmware/Cargo.lock", "web/client/Cargo.lock"):
        path = root / relative
        if not path.exists():
            continue
        sections = path.read_text().split("[[package]]")
        for index, section in enumerate(sections[1:], 1):
            package = tomllib.loads(section)
            name = package["name"]
            if name not in locked_versions:
                continue
            if "source" in package:
                raise ValueError(f"expected a local {name} in {relative}")
            sections[index], count = re.subn(
                r'(?m)^version = "[^"\n]+"', f'version = "{locked_versions[name]}"', section,
            )
            if count != 1:
                raise ValueError(f"ambiguous {name} in {relative}")
        changed[path] = "[[package]]".join(sections)
    for path, source in changed.items():
        path.write_text(source)
    result = {"package": selected[0], "version": selected[1], "tag": tag} if selected else {}
    if web_channel:
        result.update(web_version=web_version, channel=web_channel, commit=commit)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag")
    parser.add_argument("--track", choices=PACKAGES)
    parser.add_argument("--web-channel", choices=("stable", "main"))
    parser.add_argument("--commit")
    args = parser.parse_args()
    tag = args.tag
    if args.track:
        if tag:
            parser.error("choose --tag or --track")
        tag = f"{args.track}-v{versions()[args.track]}"
    result = prepare(tag=tag, web_channel=args.web_channel, commit=args.commit)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")
    if args.web_channel and (environment := os.environ.get("GITHUB_ENV")):
        with open(environment, "a") as stream:
            for key in ("version", "channel", "commit"):
                value = result["web_version" if key == "version" else key]
                stream.write(f"WEB_BUILD_{key.upper()}={value}\n")
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from None
