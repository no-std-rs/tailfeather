#!/usr/bin/env python3
"""Regression tests for the trademark review validator."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("validate-trademark-review.py")


class TrademarkReviewTests(unittest.TestCase):
    def run_validator(self, text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "review.toml"
            path.write_text(text)
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(path)],
                check=False,
                capture_output=True,
                text=True,
            )

    @staticmethod
    def approved() -> str:
        return """schema_version = 1

[wireguard]
status = "approved"
policy = "https://www.wireguard.com/trademark-policy/"
authorization_id = "wg-123"
approved_wording = "WireGuard-compatible"
acknowledgment = "WireGuard is a registered trademark of Jason A. Donenfeld."
non_affiliation_disclaimer = "Not affiliated with the WireGuard project."

[tailscale]
status = "approved"
review_id = "ts-123"
approved_wording = "Tailscale-compatible"
non_affiliation_disclaimer = "Not affiliated with Tailscale Inc."
"""

    def test_complete_approvals_pass(self) -> None:
        result = self.run_validator(self.approved())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_two_approved_statuses_with_empty_records_fail(self) -> None:
        result = self.run_validator(
            self.approved().replace('authorization_id = "wg-123"', 'authorization_id = ""')
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorization_id must be a non-empty string", result.stderr)

    def test_unrelated_approved_status_cannot_replace_an_owner(self) -> None:
        text = self.approved().replace(
            '[tailscale]\nstatus = "approved"', '[unrelated]\nstatus = "approved"'
        )
        result = self.run_validator(text)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing [tailscale] review", result.stderr)


if __name__ == "__main__":
    unittest.main()
