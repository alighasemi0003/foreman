#!/usr/bin/env python3
"""F-037 — normalize_reports schema smoke tests (synthetic inputs)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NORM = ROOT / "script/security/normalize_reports.py"


class NormalizeReportsTest(unittest.TestCase):
    def test_npm_and_trivy_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            npm_in = t / "npm.json"
            npm_in.write_text(
                json.dumps(
                    {
                        "vulnerabilities": {
                            "left-pad": {
                                "severity": "high",
                                "via": [{"url": "https://github.com/advisories/GHSA-test-0001"}],
                                "range": "<1.0.0",
                                "fixAvailable": True,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            npm_out = t / "npm.norm.json"
            cp = subprocess.run(
                [sys.executable, str(NORM), "--kind", "npm", "--input", str(npm_in), "--output", str(npm_out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(npm_out.read_text())
            self.assertTrue(doc["ok"])
            self.assertEqual(doc["findings"][0]["package"], "left-pad")
            self.assertEqual(doc["findings"][0]["severity"], "high")

            trivy_in = t / "trivy.json"
            trivy_in.write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Target": "img",
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-2099-1",
                                        "PkgName": "openssl",
                                        "InstalledVersion": "1.0",
                                        "FixedVersion": "1.1",
                                        "Severity": "CRITICAL",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trivy_out = t / "trivy.norm.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(NORM),
                    "--kind",
                    "trivy",
                    "--input",
                    str(trivy_in),
                    "--output",
                    str(trivy_out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            doc = json.loads(trivy_out.read_text())
            self.assertEqual(doc["findings"][0]["ecosystem"], "image")
            self.assertEqual(doc["findings"][0]["id"], "CVE-2099-1")

            missing_out = t / "missing.norm.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(NORM),
                    "--kind",
                    "npm",
                    "--input",
                    str(t / "nope.json"),
                    "--output",
                    str(missing_out),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 2)
            self.assertFalse(json.loads(missing_out.read_text())["ok"])


if __name__ == "__main__":
    unittest.main()
