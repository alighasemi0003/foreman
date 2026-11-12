#!/usr/bin/env python3
"""F-037 — synthetic tests for the security policy gate (no live advisory DB)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "script/security/apply_security_gate.py"
POLICY = ROOT / "config/security/scan-policy.yml"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def run_gate(exceptions: Path, reports: list[Path], today: str) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(GATE),
        "--policy",
        str(POLICY),
        "--exceptions",
        str(exceptions),
        "--today",
        today,
    ]
    for r in reports:
        cmd.extend(["--report", str(r)])
    return subprocess.run(cmd, capture_output=True, text=True)


def write_json(path: Path, doc: dict) -> Path:
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


class ApplySecurityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.td = Path(self.tmp.name)
        # empty exceptions
        self.exc_empty = self.td / "exceptions.yml"
        self.exc_empty.write_text("version: 1\nexceptions: []\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_clean_report_succeeds(self) -> None:
        report = write_json(self.td / "clean.json", {"ok": True, "findings": []})
        cp = run_gate(self.exc_empty, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("failures=0", cp.stdout)

    def test_unapproved_high_fails(self) -> None:
        report = write_json(
            self.td / "high.json",
            {
                "ok": True,
                "findings": [
                    {
                        "ecosystem": "ruby",
                        "package": "example",
                        "severity": "high",
                        "ids": ["CVE-2099-0001"],
                        "installed_version": "1.0.0",
                        "fixed_version": "1.0.1",
                        "path": "Gemfile.lock",
                    }
                ],
            },
        )
        cp = run_gate(self.exc_empty, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertIn("FAIL:", cp.stdout)

    def test_valid_exception_allows(self) -> None:
        exc = self.td / "exc.yml"
        exc.write_text(
            """
version: 1
exceptions:
  - id: CVE-2099-0001
    package: example
    ecosystem: ruby
    reason: "synthetic fixture"
    scope: "test"
    impact: "none"
    mitigation: "n/a"
    reviewer_role: "Security Team (proposed)"
    expires_on: "2099-01-01"
    status: accepted
""".lstrip(),
            encoding="utf-8",
        )
        report = write_json(
            self.td / "high.json",
            {
                "ok": True,
                "findings": [
                    {
                        "ecosystem": "ruby",
                        "package": "example",
                        "severity": "high",
                        "ids": ["CVE-2099-0001"],
                    }
                ],
            },
        )
        cp = run_gate(exc, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("EXCEPTION ok", cp.stdout)

    def test_expired_exception_rejected(self) -> None:
        exc = self.td / "exc.yml"
        exc.write_text(
            """
version: 1
exceptions:
  - id: CVE-2099-0001
    package: example
    ecosystem: ruby
    reason: "expired fixture"
    scope: "test"
    impact: "none"
    mitigation: "n/a"
    reviewer_role: "Security Team (proposed)"
    expires_on: "2020-01-01"
    status: accepted
""".lstrip(),
            encoding="utf-8",
        )
        report = write_json(
            self.td / "high.json",
            {
                "ok": True,
                "findings": [
                    {
                        "ecosystem": "ruby",
                        "package": "example",
                        "severity": "high",
                        "ids": ["CVE-2099-0001"],
                    }
                ],
            },
        )
        cp = run_gate(exc, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertIn("expired", cp.stdout.lower() + cp.stderr.lower())

    def test_scanner_error_exit_2(self) -> None:
        report = write_json(
            self.td / "err.json",
            {"ok": False, "findings": [], "message": "advisory DB missing"},
        )
        cp = run_gate(self.exc_empty, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)

    def test_missing_report_exit_2(self) -> None:
        cp = run_gate(self.exc_empty, [self.td / "nope.json"], "2026-11-12")
        self.assertEqual(cp.returncode, 2)

    def test_medium_does_not_fail(self) -> None:
        report = write_json(
            self.td / "med.json",
            {
                "ok": True,
                "findings": [
                    {
                        "ecosystem": "npm",
                        "package": "left-pad",
                        "severity": "medium",
                        "ids": ["CVE-2099-0002"],
                    }
                ],
            },
        )
        cp = run_gate(self.exc_empty, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("WARN:", cp.stdout)

    def test_incomplete_exception_rejected(self) -> None:
        exc = self.td / "bad.yml"
        exc.write_text(
            """
version: 1
exceptions:
  - id: CVE-1
    package: x
    status: accepted
    expires_on: "2099-01-01"
""".lstrip(),
            encoding="utf-8",
        )
        report = write_json(self.td / "clean.json", {"ok": True, "findings": []})
        cp = run_gate(exc, [report], "2026-11-12")
        self.assertEqual(cp.returncode, 2)


if __name__ == "__main__":
    unittest.main()
