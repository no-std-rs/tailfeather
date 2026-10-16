import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from release_test import load

web = load("web-release")


class WebReleaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def build(self, name, version, channel, commit):
        root = self.root / name
        root.joinpath("pkg").mkdir(parents=True)
        root.joinpath("index.html").write_text(version)
        root.joinpath("pkg/tailfeather_web_bg.wasm").write_bytes(b"\0asm" + version.encode())
        root.joinpath(".nojekyll").touch()
        root.joinpath("build.json").write_text(json.dumps({"version": version, "channel": channel, "commit": commit}))
        return root

    def archive(self, build, name):
        return web.pack(build, self.root / name / web.ARCHIVE)

    def test_composed_site_keeps_stable_root_and_main_preview_separate(self):
        stable = self.archive(self.build("stable", "0.1.0", "stable", "a" * 40), "stable-assets")
        preview = self.archive(self.build("preview", "0.2.0-main.bbbbbbbbbbbb", "main", "b" * 40), "preview-assets")
        destination = self.root / "site"
        web.compose(stable, preview, destination)
        self.assertEqual(web.metadata(destination)["version"], "0.1.0")
        self.assertEqual(web.metadata(destination / "main")["version"], "0.2.0-main.bbbbbbbbbbbb")
        self.assertEqual((destination / "index.html").read_text(), "0.1.0")
        self.assertTrue((destination / ".nojekyll").is_file())

    def test_archives_are_reproducible_and_checksums_detect_corruption(self):
        build = self.build("build", "0.1.0", "stable", "a" * 40)
        one = self.archive(build, "one")
        for path in build.rglob("*"):
            path.touch()
        two = self.archive(build, "two")
        self.assertEqual(one.read_bytes(), two.read_bytes())
        manifest = one.with_name(web.CHECKSUM)
        web.checksum(one, manifest)
        web.verify(one, manifest)
        one.write_bytes(one.read_bytes() + b"bad")
        with self.assertRaises(ValueError):
            web.verify(one, manifest)

    def test_archive_pack_rejects_links_to_files_and_directories(self):
        build = self.build("build", "0.1.0", "stable", "a" * 40)
        for target in [build / "index.html", build / "pkg"]:
            link = build / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                self.archive(build, "linked")
            link.unlink()

    def test_path_traversal_links_and_duplicates_are_rejected_before_extraction(self):
        for case in ["../outside", "/outside", "symlink", "duplicate"]:
            archive = self.root / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                item = tarfile.TarInfo(case if case != "duplicate" else "index.html")
                if case == "symlink":
                    item.type = tarfile.SYMTYPE
                    item.linkname = "../outside"
                bundle.addfile(item, io.BytesIO())
                if case == "duplicate":
                    bundle.addfile(item, io.BytesIO())
            with self.assertRaises(ValueError):
                web.unpack(archive, self.root / "unsafe-output")
        self.assertFalse((self.root / "unsafe-output").exists())

    def test_preview_requires_current_main_or_current_bot_release_head(self):
        main, candidate = "a" * 40, "b" * 40
        pr = {"number": 12, "state": "open", "user": {"id": web.BOT_ID},
              "head": {"sha": candidate, "ref": "release-please--branches--main--tracks--tailfeather",
                       "repo": {"full_name": "no-std-rs/tailfeather"}}}

        def gh(*args, **kwargs):
            if args[1].endswith("heads/main"):
                return {"object": {"sha": main}}
            if "/pulls/" in args[1]:
                return pr
            return {"parents": [{"sha": main}]}

        with patch.object(web, "gh", gh):
            self.assertTrue(web.accept_preview("no-std-rs/tailfeather", {"commit": main}, {}))
            self.assertFalse(web.accept_preview("no-std-rs/tailfeather", {"commit": candidate}, {}))
            self.assertTrue(web.accept_preview("no-std-rs/tailfeather", {"commit": candidate}, {"pull_request": pr}))
            pr["user"]["id"] = 1
            self.assertFalse(web.accept_preview("no-std-rs/tailfeather", {"commit": candidate}, {"pull_request": pr}))
            pr["user"]["id"] = web.BOT_ID
            pr["head"]["sha"] = "c" * 40
            self.assertFalse(web.accept_preview("no-std-rs/tailfeather", {"commit": candidate}, {"pull_request": pr}))

    def test_latest_complete_stable_release_wins_in_semantic_version_order(self):
        def item(tag, prerelease=False, complete=True):
            return {"tag_name": tag, "prerelease": prerelease, "draft": False, "published_at": "today",
                    "assets": [{"name": name} for name in [web.ARCHIVE, web.CHECKSUM]] if complete else []}
        releases = [item("tailfeather-v0.9.0"), item("wirefeather-v1.0.0"),
                    item("tailfeather-v0.10.0"), item("tailfeather-v0.11.0", complete=False),
                    item("tailfeather-v1.0.0", prerelease=True)]
        chosen = self.archive(self.build("stable", "0.10.0", "stable", "a" * 40), "chosen")
        with patch.object(web, "gh", return_value=[releases]), patch.object(web, "download", return_value=chosen) as download:
            self.assertEqual(web.latest_stable("repo", self.root), chosen)
            self.assertEqual(download.call_args.args[1]["tag_name"], "tailfeather-v0.10.0")
            releases[2]["tag_name"] = "tailfeather-v0.10.1"
            with self.assertRaisesRegex(ValueError, "do not match their release tag"):
                web.latest_stable("repo", self.root)

    def test_mismatched_artifact_and_immutable_release_are_never_overwritten(self):
        build = self.build("build", "0.1.0", "stable", "a" * 40)
        with patch.object(web, "gh") as gh:
            with self.assertRaises(ValueError):
                web.stable_assets("repo", build, "b" * 40, "tailfeather-v0.1.0")
            gh.assert_not_called()
        previous = self.root / "different.tar.gz"
        previous.write_bytes(b"old immutable asset")
        item = {"prerelease": False, "draft": False, "published_at": "today"}
        with patch.object(web, "release", return_value=item), patch.object(web, "download", return_value=previous), patch.object(web, "upload") as upload:
            with self.assertRaises(ValueError):
                web.stable_assets("repo", build, "a" * 40, "tailfeather-v0.1.0")
            upload.assert_not_called()
        with patch.object(web, "gh") as gh:
            with self.assertRaises(ValueError):
                web.publish("repo", build, self.root / "site", {}, "b" * 40)
            gh.assert_not_called()

    def test_repeated_preview_publication_preserves_stable_until_a_real_release(self):
        releases = {}
        tag_updates = []
        current = "a" * 40

        def gh(*args, body=None, missing=False):
            endpoint = next((value for value in args if value.startswith("repos/")), "")
            if endpoint.endswith("git/ref/heads/main"):
                return {"object": {"sha": current}}
            if "/releases/tags/" in endpoint:
                return releases.get(endpoint.rsplit("/", 1)[1])
            if endpoint.endswith("releases?per_page=100"):
                return [list(releases.values())]
            if body and body.get("tag_name"):
                releases[body["tag_name"]] = {"id": 1, **body, "assets": [], "draft": False, "published_at": "today"}
            elif "/git/refs/" in endpoint:
                tag_updates.append((endpoint, body["sha"]))
            return {}

        def upload(repo, tag, files, replace=False):
            item = releases[tag]
            for path in files:
                saved = self.root / "stored" / tag / path.name
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, saved)
                item["assets"] = [asset for asset in item["assets"] if asset["name"] != path.name]
                item["assets"].append({"name": path.name, "size": saved.stat().st_size, "path": saved})

        def download(repo, item, name, manifest, destination):
            assets = {asset["name"]: asset for asset in item["assets"]}
            if not {name, manifest} <= assets.keys():
                return None
            destination.mkdir(parents=True, exist_ok=True)
            for filename in [name, manifest]:
                shutil.copyfile(assets[filename]["path"], destination / filename)
            web.verify(destination / name, destination / manifest)
            return destination / name

        with patch.object(web, "gh", gh), patch.object(web, "upload", upload), patch.object(web, "download", download):
            first = self.build("first", "0.0.1-main.aaaaaaaaaaaa", "main", current)
            web.publish("repo", first, self.root / "site-one", {}, current)
            current = "b" * 40
            second = self.build("second", "0.1.0-main.bbbbbbbbbbbb", "main", current)
            web.publish("repo", second, self.root / "site-two", {}, current)
            self.assertEqual(web.metadata(self.root / "site-two")["commit"], "a" * 40)
            self.assertEqual(web.metadata(self.root / "site-two/main")["commit"], "b" * 40)
            stable = self.build("released", "0.1.0", "stable", "c" * 40)
            tag = "tailfeather-v0.1.0"
            releases[tag] = {"id": 2, "tag_name": tag, "assets": [], "draft": False, "prerelease": False, "published_at": "today"}
            archive = self.archive(stable, "release-assets")
            web.checksum(archive, archive.with_name(web.CHECKSUM))
            upload("repo", tag, [archive, archive.with_name(web.CHECKSUM)])
            current = "d" * 40
            third = self.build("third", "0.2.0-main.dddddddddddd", "main", current)
            web.publish("repo", third, self.root / "site-three", {}, current)
            self.assertEqual(web.metadata(self.root / "site-three")["channel"], "stable")
            self.assertEqual(web.metadata(self.root / "site-three")["version"], "0.1.0")
            self.assertEqual(web.metadata(self.root / "site-three/main")["commit"], current)
            self.assertTrue(all(endpoint.endswith("/tailfeather-main") for endpoint, _ in tag_updates))


if __name__ == "__main__":
    unittest.main()
