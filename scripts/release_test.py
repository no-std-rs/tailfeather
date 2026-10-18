import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from release_packages import ROOT, PACKAGES, release


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load("prepare-release")
capture = load("package-registry-uploads")
configure = load("configure-runnerless-publishing")


class VersionsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        files = [ROOT / "Cargo.toml", *ROOT.glob("crates/*/Cargo.toml")]
        files += [ROOT / path for path in ["Cargo.lock", "harness/Cargo.toml", "harness/Cargo.lock",
                  "firmware/Cargo.toml", "firmware/Cargo.lock", "web/client/Cargo.toml", "web/client/Cargo.lock",
                  "crates/tailfeather-ssh/probe/Cargo.toml", "crates/tailfeather-ssh/probe/Cargo.lock"]]
        files += list(ROOT.glob("crates/*/version.txt"))
        for source in files:
            target = self.root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.versions = dict(zip(PACKAGES, ["0.1.0", "0.2.0", "0.3.0"]))
        for name, version in self.versions.items():
            self.root.joinpath("crates", name, "version.txt").write_text(version + "\n")

    def manifest(self, relative):
        return tomllib.loads((self.root / relative).read_text())

    def test_independent_versions_and_all_path_dependency_closures(self):
        result = prepare.prepare(self.root, tag="tailfeather-v0.2.0")
        self.assertEqual(result["package"], "tailfeather")
        for name, version in self.versions.items():
            self.assertEqual(self.manifest(f"crates/{name}/Cargo.toml")["package"]["version"], version)
        self.assertEqual(self.manifest("crates/tailfeather/Cargo.toml")["dependencies"]["wirefeather"]["version"], "0.1.0")
        self.assertEqual(self.manifest("crates/tailfeather-testkit/Cargo.toml")["package"]["version"], "0.0.1")
        self.assertEqual(self.manifest("crates/tailfeather-testkit/Cargo.toml")["dependencies"]["tailfeather"]["version"], "0.2.0")
        self.assertEqual(self.manifest("harness/Cargo.toml")["dependencies"]["tailfeather-gateway"]["version"], "0.3.0")
        probe = self.manifest("crates/tailfeather-ssh/probe/Cargo.toml")
        self.assertEqual(probe["package"]["version"], "0.0.1")
        self.assertEqual(probe["patch"]["crates-io"]["tailfeather"]["version"], "0.2.0")
        self.assertEqual(self.manifest("crates/tailfeather-ssh/Cargo.toml")["dependencies"]["tailfeather"]["version"], "0.2.0")
        for relative in ["Cargo.lock", "harness/Cargo.lock", "firmware/Cargo.lock", "web/client/Cargo.lock",
                         "crates/tailfeather-ssh/probe/Cargo.lock"]:
            packages = self.manifest(relative)["package"]
            for package in packages:
                if package["name"] in self.versions:
                    self.assertEqual(package["version"], self.versions[package["name"]])
                    self.assertNotIn("source", package)

    def test_web_preview_and_stable_use_their_own_build_versions(self):
        sha = "a" * 40
        result = prepare.prepare(self.root, web_channel="main", commit=sha)
        self.assertEqual(result["web_version"], "0.2.0-main.aaaaaaaaaaaa")
        self.assertEqual(self.manifest("web/client/Cargo.toml")["package"]["version"], result["web_version"])
        result = prepare.prepare(self.root, tag="tailfeather-v0.2.0", web_channel="stable", commit=sha)
        self.assertEqual(result["web_version"], "0.2.0")
        self.assertEqual(self.manifest("web/client/Cargo.toml")["package"]["version"], "0.2.0")

    def test_invalid_tag_or_registry_package_never_partially_rewrites_files(self):
        original = (self.root / "Cargo.toml").read_bytes()
        for tag in ["tailfeather-main", "tailfeather-v0.1.0", "tailfeather-testkit-v0.1.0", "wirefeather-v0.1.0-rc.1"]:
            with self.assertRaises(ValueError):
                prepare.prepare(self.root, tag=tag)
            self.assertEqual((self.root / "Cargo.toml").read_bytes(), original)
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace('name = "wirefeather"\n', 'name = "wirefeather"\nsource = "registry+https://example.invalid"\n'))
        with self.assertRaises(ValueError):
            prepare.prepare(self.root, tag="wirefeather-v0.1.0")
        self.assertEqual((self.root / "Cargo.toml").read_bytes(), original)

    def test_stable_web_requires_tailfeather_tag_and_a_real_commit_identity(self):
        with self.assertRaises(ValueError):
            prepare.prepare(self.root, tag="wirefeather-v0.1.0", web_channel="stable", commit="a" * 40)
        with self.assertRaises(ValueError):
            prepare.prepare(self.root, web_channel="main", commit="main")

    def test_only_the_three_libraries_can_publish(self):
        public = set()
        for path in ROOT.glob("crates/*/Cargo.toml"):
            package = tomllib.loads(path.read_text())["package"]
            if package.get("publish", True) is not False:
                public.add(package["name"])
                self.assertEqual(package["publish"], ["crates-io", "runnerless-capture"])
        self.assertEqual(public, set(PACKAGES))


class CargoUploadTest(unittest.TestCase):
    def test_upload_identity_lengths_and_dependency_metadata(self):
        metadata = {"name": "wirefeather", "vers": "0.1.0", "deps": [], "features": {}}
        encoded = json.dumps(metadata).encode()
        archive = b"a small Cargo archive"
        body = struct.pack("<I", len(encoded)) + encoded + struct.pack("<I", len(archive)) + archive
        record = json.loads(capture.parse_upload(body, "wirefeather", "0.1.0"))
        self.assertEqual((record["name"], record["vers"]), ("wirefeather", "0.1.0"))
        for name, version in [("tailfeather", "0.1.0"), ("wirefeather", "0.2.0")]:
            with self.assertRaises(ValueError):
                capture.parse_upload(body, name, version)
        with self.assertRaises(ValueError):
            capture.parse_upload(body[:-1], "wirefeather", "0.1.0")


class PublishingConfigurationTest(unittest.TestCase):
    def test_independent_tag_prefixes_and_idempotent_production_setup(self):
        target = {}
        production = None
        writes = []

        def api(method, path, body=None):
            nonlocal target, production
            if method == "GET" and path.endswith("/repositories"):
                return {"repositories": [{"id": "repo", "full_name": configure.REPOSITORY, "state": "adopted"}]}
            if method == "GET" and path.endswith("/publishing"):
                return {"production": production, "registries": [target] if target else []}
            writes.append((method, path, body))
            if method == "PUT":
                target = {**body, "registry": "crates", "package_credentials": []}
                return target
            if method == "POST":
                production = {"id": "production", "enabled": False}
                return production
            if method == "PATCH":
                production["enabled"] = True
                return production
            raise AssertionError((method, path))

        with patch.object(configure, "api", api), patch("builtins.print"):
            configure.configure("org")
            count = len(writes)
            configure.configure("org")
        self.assertEqual(len(writes), count)
        self.assertEqual(target["packages"], list(PACKAGES))
        self.assertEqual(target["package_tag_prefixes"], {name: name + "-v" for name in PACKAGES})
        self.assertTrue(production["enabled"])
        self.assertFalse(target["organization_credential"])


if __name__ == "__main__":
    unittest.main()
