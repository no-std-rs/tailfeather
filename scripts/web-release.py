#!/usr/bin/env python3
"""Package tested web builds and compose stable + rolling-main GitHub Pages."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ARCHIVE = "tailfeather-web.tar.gz"
CHECKSUM = "tailfeather-web-SHA256SUMS"
BOOTSTRAP = "tailfeather-web-stable.tar.gz"
BOOTSTRAP_SUM = "tailfeather-web-stable-SHA256SUMS"
ROLLING = "tailfeather-main"
MAX_BYTES = 32 * 1024 * 1024
BOT_ID = 317265358


def stamp(directory):
    root = Path(__file__).resolve().parents[1]
    version = os.environ.get("WEB_BUILD_VERSION") or tomllib.loads(
        (root / "web/client/Cargo.toml").read_text())["package"]["version"]
    commit = os.environ.get("WEB_BUILD_COMMIT") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    value = {"version": version, "commit": commit,
             "channel": os.environ.get("WEB_BUILD_CHANNEL", "main")}
    (directory / "build.json").write_text(json.dumps(value, sort_keys=True) + "\n")
    metadata(directory)


def metadata(directory):
    value = json.loads((directory / "build.json").read_text())
    if (value.get("channel") not in ("main", "stable")
            or not re.fullmatch(r"[0-9a-f]{40}", value.get("commit", ""))
            or not re.fullmatch(r"\d+\.\d+\.\d+(?:-main\.[0-9a-f]{12})?", value.get("version", ""))):
        raise ValueError("invalid web build identity")
    return value


def safe_name(name):
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute()
            and ".." not in path.parts and re.fullmatch(r"[A-Za-z0-9_./-]+", name))


def pack(directory, archive):
    metadata(directory)
    entries = sorted(directory.rglob("*"))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in entries):
        raise ValueError("web build contains an unsafe path")
    paths = [path for path in entries if path.is_file()]
    if len(paths) > 128 or sum(path.stat().st_size for path in paths) > MAX_BYTES:
        raise ValueError("web build exceeds archive bounds")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as bundle:
            for path in paths:
                name = path.relative_to(directory).as_posix()
                if path.is_symlink() or not safe_name(name):
                    raise ValueError("web build contains an unsafe path")
                info = bundle.gettarinfo(path, arcname=name)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = 0o644
                with path.open("rb") as source:
                    bundle.addfile(info, source)
    return archive


def unpack(archive, destination):
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 128 or sum(item.size for item in members) > MAX_BYTES:
            raise ValueError("web archive exceeds bounds")
        names = set()
        for item in members:
            if (not item.isfile() or not safe_name(item.name)
                    or item.name in names):
                raise ValueError("web archive contains an unsafe or duplicate entry")
            names.add(item.name)
        if not {"index.html", "build.json", "pkg/tailfeather_web_bg.wasm"} <= names:
            raise ValueError("incomplete web archive")
        bundle.extractall(destination, members=members, filter="data")
    return metadata(destination)


def checksum(archive, path):
    path.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")


def verify(archive, manifest):
    expected = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    if manifest.read_text() != expected:
        raise ValueError("web archive checksum differs from its release manifest")


def gh(*args, body=None, missing=False):
    result = subprocess.run(["gh", *args], input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, timeout=120)
    if result.returncode:
        if missing and "HTTP 404" in result.stderr:
            return None
        raise RuntimeError(f"GitHub command failed: {' '.join(args[:3])}: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def release(repo, tag, missing=False):
    return gh("api", f"repos/{repo}/releases/tags/{tag}", missing=missing)


def download(repo, item, name, manifest, destination):
    assets = {asset["name"]: asset for asset in item["assets"]}
    if not {name, manifest} <= assets.keys():
        return None
    if assets[name]["size"] > MAX_BYTES or assets[manifest]["size"] > 1024:
        raise ValueError("release web asset exceeds bounds")
    subprocess.run(["gh", "release", "download", item["tag_name"], "--repo", repo,
                    "--pattern", name, "--pattern", manifest, "--dir", str(destination),
                    "--clobber"], check=True, timeout=120)
    archive = destination / name
    verify(archive, destination / manifest)
    return archive


def upload(repo, tag, files, *, replace=False):
    command = ["gh", "release", "upload", tag, "--repo", repo, *map(str, files)]
    if replace:
        command.append("--clobber")
    subprocess.run(command, check=True, timeout=120)


def stable_assets(repo, incoming, expected_commit, expected_tag):
    identity = metadata(incoming)
    if identity["channel"] != "stable":
        raise ValueError("only a stable build can attach assets to a stable release")
    tag = "tailfeather-v" + identity["version"]
    if identity["commit"] != expected_commit or tag != expected_tag:
        raise ValueError("stable web artifact does not match the triggering release")
    item = release(repo, tag)
    if item["prerelease"] or item["draft"] or not item["published_at"]:
        raise ValueError("web assets require a published stable Tailfeather release")
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        archive = pack(incoming, folder / ARCHIVE)
        checksum(archive, folder / CHECKSUM)
        previous = download(repo, item, ARCHIVE, CHECKSUM, folder / "previous")
        if previous:
            if previous.read_bytes() != archive.read_bytes():
                raise ValueError("a stable release already has different immutable web assets")
            return
        names = {asset["name"] for asset in item["assets"]}
        if names & {ARCHIVE, CHECKSUM}:
            raise ValueError("partial stable assets require inspection before retry")
        upload(repo, tag, [archive, folder / CHECKSUM])


def accept_preview(repo, identity, event):
    main = gh("api", f"repos/{repo}/git/ref/heads/main")["object"]["sha"]
    pr = event.get("pull_request")
    if not pr:
        return identity["commit"] == main
    current = gh("api", f"repos/{repo}/pulls/{pr['number']}")
    if (current["state"] != "open" or current["user"]["id"] != BOT_ID
            or current["head"]["repo"]["full_name"] != repo
            or current["head"]["ref"] != "release-please--branches--main--tracks--tailfeather"
            or current["head"]["sha"] != identity["commit"]):
        return False
    commit = gh("api", f"repos/{repo}/git/commits/{identity['commit']}")
    return [parent["sha"] for parent in commit["parents"]] == [main]


def latest_stable(repo, destination):
    pages = gh("api", f"repos/{repo}/releases?per_page=100", "--paginate", "--slurp")
    candidates = []
    for page in pages:
        for item in page:
            match = re.fullmatch(r"tailfeather-v(\d+)\.(\d+)\.(\d+)", item["tag_name"])
            names = {asset["name"] for asset in item["assets"]}
            if (match and item["published_at"] and not item["prerelease"]
                    and not item["draft"] and {ARCHIVE, CHECKSUM} <= names):
                candidates.append((tuple(map(int, match.groups())), item))
    if not candidates:
        return None
    item = max(candidates, key=lambda candidate: candidate[0])[1]
    archive = download(repo, item, ARCHIVE, CHECKSUM, destination)
    with tempfile.TemporaryDirectory() as temporary:
        identity = unpack(archive, Path(temporary))
        if identity["channel"] != "stable" or "tailfeather-v" + identity["version"] != item["tag_name"]:
            raise ValueError("stable web assets do not match their release tag")
    return archive


def compose(stable, preview, destination):
    unpack(stable, destination)
    unpack(preview, destination / "main")
    (destination / ".nojekyll").touch()


def publish(repo, incoming, destination, event, expected_commit):
    identity = metadata(incoming)
    if identity["commit"] != expected_commit:
        raise ValueError("tested web artifact belongs to a different commit")
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        item = release(repo, ROLLING, missing=True)
        accepted = identity["channel"] == "main" and accept_preview(repo, identity, event)
        preview = pack(incoming, folder / ARCHIVE) if accepted else (
            download(repo, item, ARCHIVE, CHECKSUM, folder / "previous") if item else None)
        if preview is None:
            if identity["channel"] == "main":
                raise ValueError("no current trusted main preview is available")
            preview = pack(incoming, folder / ARCHIVE)
        stable = latest_stable(repo, folder / "stable")
        if stable is None and item:
            stable = download(repo, item, BOOTSTRAP, BOOTSTRAP_SUM, folder / "bootstrap")
        if stable is None:
            # The historical releases predate the browser. Retain this first
            # tested site until the first Tailfeather release with web assets.
            stable = preview
        compose(stable, preview, destination)
        preview_identity = metadata(destination / "main")
        stable_identity = metadata(destination)
        if item is None:
            gh("api", "--method", "POST", f"repos/{repo}/releases", "--input", "-", body={
                "tag_name": ROLLING, "target_commitish": preview_identity["commit"],
                "name": "Tailfeather main (preview)", "prerelease": True, "make_latest": "false",
            })
        elif accepted:
            gh("api", "--method", "PATCH", f"repos/{repo}/git/refs/tags/{ROLLING}", "--input", "-",
               body={"sha": preview_identity["commit"], "force": True})
        if accepted or item is None:
            # Both filenames are fixed even when the downloaded source was in
            # a different directory, so public download links remain stable.
            public = folder / "public"
            public.mkdir()
            shutil.copyfile(preview, public / ARCHIVE)
            checksum(public / ARCHIVE, public / CHECKSUM)
            upload(repo, ROLLING, [public / ARCHIVE, public / CHECKSUM], replace=True)
        cached = folder / BOOTSTRAP
        shutil.copyfile(stable, cached)
        checksum(cached, folder / BOOTSTRAP_SUM)
        upload(repo, ROLLING, [cached, folder / BOOTSTRAP_SUM], replace=True)
        item = release(repo, ROLLING)
        gh("api", "--method", "PATCH", f"repos/{repo}/releases/{item['id']}", "--input", "-", body={
            "name": "Tailfeather main (preview)", "prerelease": True, "make_latest": "false",
            "body": f"Rolling tested browser build `{preview_identity['version']}` at `{preview_identity['commit']}`.\n\n"
                    "[Open main preview](https://no-std-rs.github.io/tailfeather/main/) · "
                    "[Open stable site](https://no-std-rs.github.io/tailfeather/)\n\n"
                    f"Stable site build: `{stable_identity['version']}`. Stable crate releases keep their own tags and changelogs.",
        })
        print(f"Pages: root={stable_identity['version']}, main={preview_identity['version']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("stamp", "pack", "stable-assets", "publish"))
    parser.add_argument("incoming", type=Path)
    parser.add_argument("destination", nargs="?", type=Path)
    args = parser.parse_args()
    if args.operation == "stamp":
        stamp(args.incoming)
    elif args.operation == "pack":
        if not args.destination:
            parser.error("pack requires an archive destination")
        archive = pack(args.incoming, args.destination)
        checksum(archive, archive.with_name(CHECKSUM))
    elif args.operation == "stable-assets":
        stable_assets(os.environ["GITHUB_REPOSITORY"], args.incoming,
                      os.environ["EXPECTED_COMMIT"], os.environ["EXPECTED_TAG"])
    else:
        if not args.destination:
            parser.error("publish requires a Pages directory")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        publish(os.environ["GITHUB_REPOSITORY"], args.incoming, args.destination,
                event, os.environ["EXPECTED_COMMIT"])


if __name__ == "__main__":
    main()
