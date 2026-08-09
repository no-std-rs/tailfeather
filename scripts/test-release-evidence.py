#!/usr/bin/env python3
"""Regression tests for the dependency-free release evidence validator."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


COMMIT = "a" * 40
SCRIPT = pathlib.Path(__file__).with_name("validate-release-evidence.py")


class EvidenceValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.evidence = self.root / "release" / "evidence" / f"{COMMIT}.json"
        self.evidence.parent.mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        expectations = self.root / "tests" / "expectations"
        expectations.mkdir(parents=True)
        self.hashes = {}
        for name in ("offline", "headscale", "hosted"):
            content = json.dumps({"target": name}).encode()
            (expectations / f"{name}.json").write_bytes(content)
            self.hashes[name] = hashlib.sha256(content).hexdigest()
        (self.root / "release" / "trademark-review.toml").write_text(
            """schema_version = 1
[wireguard]
status = "approved"
authorization_id = "wg-review"
[tailscale]
status = "approved"
review_id = "ts-review"
"""
        )

    def artifact(self, name: str) -> dict[str, str]:
        content = f"artifact:{name}\n".encode()
        (self.artifacts / name).write_bytes(content)
        return {
            "uri": f"artifacts/{name}",
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def document(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "commit": COMMIT,
            "created_at": "2026-08-09T20:00:00Z",
            "references": {"headscale": "v0.29.3", "tailscaled": "1.94.2"},
            "baseline_hashes": self.hashes,
            "runs": [
                {
                    "kind": kind,
                    "run_id": f"run-{kind}",
                    "artifact": self.artifact(kind),
                    "commit": COMMIT,
                    "result": "pass",
                }
                for kind in ("headscale", "hosted", "hardware", "adversarial")
            ],
            "resources": {
                "ram_bytes": 100_000,
                "image_bytes": 1_000_000,
                "radio_heap_bytes": 65_536,
                "minimum_stack_headroom_percent": 25,
                "artifact": self.artifact("resources"),
            },
            "cleanup": {"result": "pass", "artifact": self.artifact("cleanup")},
            "permission_reviews": {"wireguard": "wg-review", "tailscale": "ts-review"},
        }

    def run_validator(self, document: object) -> subprocess.CompletedProcess[str]:
        self.evidence.write_text(json.dumps(document))
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.evidence), COMMIT],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_complete_same_commit_evidence_passes(self) -> None:
        result = self.run_validator(self.document())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_evidence_fails(self) -> None:
        result = self.run_validator({})
        self.assertNotEqual(result.returncode, 0)

    def test_every_run_must_match_the_candidate_commit(self) -> None:
        document = self.document()
        document["runs"][0]["commit"] = "b" * 40
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the candidate commit", result.stderr)

    def test_every_required_run_kind_must_be_present(self) -> None:
        document = self.document()
        document["runs"] = document["runs"][:-1]
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least four entries", result.stderr)

    def test_placeholder_resources_do_not_satisfy_the_gate(self) -> None:
        document = self.document()
        document["resources"] = {"placeholder": True}
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resources is missing", result.stderr)

    def test_artifacts_are_immutable_references_not_bare_labels(self) -> None:
        document = self.document()
        document["runs"][0]["artifact"] = "artifact-headscale"
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runs[0].artifact must be an object", result.stderr)

    def test_missing_local_artifact_fails(self) -> None:
        document = self.document()
        document["runs"][0]["artifact"]["uri"] = "artifacts/missing"
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not name a regular file", result.stderr)

    def test_artifact_replacement_fails_its_recorded_digest(self) -> None:
        document = self.document()
        (self.artifacts / "hosted").write_text("replacement")
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the referenced artifact", result.stderr)

    def test_local_artifact_cannot_escape_its_directory(self) -> None:
        document = self.document()
        document["runs"][0]["artifact"]["uri"] = "artifacts/../outside"
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes the artifacts directory", result.stderr)

    def test_permission_review_ids_must_match_the_review_file(self) -> None:
        document = self.document()
        document["permission_reviews"]["wireguard"] = "some-other-review"
        result = self.run_validator(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the trademark review", result.stderr)


if __name__ == "__main__":
    unittest.main()
