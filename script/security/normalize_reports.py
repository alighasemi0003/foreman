#!/usr/bin/env python3
# Normalize bundler-audit / npm audit / Trivy JSON into gate findings schema.
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def write(path: Path, findings: List[Dict[str, Any]], ok: bool = True, message: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"ok": ok, "findings": findings, "message": message}
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def from_bundler_audit(raw: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    # bundler-audit 0.9 JSON: {"results":[...]} or list depending on version
    results = raw
    if isinstance(raw, dict):
        if raw.get("error") or raw.get("scanner_error"):
            raise ValueError(str(raw.get("error") or raw.get("scanner_error")))
        results = raw.get("results") or raw.get("vulnerabilities") or []
    if not isinstance(results, list):
        raise ValueError("unexpected bundler-audit schema")
    for item in results:
        if not isinstance(item, dict):
            continue
        # Newer format uses advisory + gem
        adv = item.get("advisory") if isinstance(item.get("advisory"), dict) else item
        gem = item.get("gem") if isinstance(item.get("gem"), dict) else {}
        pkg = gem.get("name") or item.get("gem") or adv.get("gem") or item.get("name")
        if isinstance(pkg, dict):
            pkg = pkg.get("name")
        cve = adv.get("cve") or item.get("cve")
        ghsa = adv.get("ghsa") or item.get("ghsa")
        ids = [i for i in [cve, ghsa, adv.get("id"), item.get("id")] if i]
        crit = (adv.get("criticality") or item.get("criticality") or item.get("severity") or "high")
        # bundler-audit criticality: high/medium/low — map none to high for CVEs
        sev = str(crit).lower()
        if sev in ("none", ""):
            sev = "high"
        findings.append(
            {
                "ecosystem": "ruby",
                "package": pkg,
                "installed_version": gem.get("version") or item.get("version"),
                "fixed_version": (
                    (adv.get("patched_versions") or [None])[0]
                    if isinstance(adv.get("patched_versions"), list)
                    else adv.get("patched_versions")
                ),
                "severity": sev,
                "ids": ids,
                "id": ids[0] if ids else None,
                "path": "Gemfile.lock",
                "title": adv.get("title") or item.get("title"),
            }
        )
    return findings


def from_npm_audit(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ValueError("npm audit JSON must be an object")
    if raw.get("error"):
        # npm sometimes embeds error
        err = raw["error"]
        if isinstance(err, dict) and err.get("summary"):
            raise ValueError(err["summary"])
        raise ValueError(str(err))
    vulns = raw.get("vulnerabilities") or {}
    findings: List[Dict[str, Any]] = []
    if not isinstance(vulns, dict):
        raise ValueError("npm vulnerabilities must be an object")
    for name, meta in vulns.items():
        if not isinstance(meta, dict):
            continue
        sev = meta.get("severity") or "unknown"
        ids: List[str] = []
        via = meta.get("via") or []
        if isinstance(via, list):
            for v in via:
                if isinstance(v, dict):
                    url = str(v.get("url") or "")
                    if "GHSA-" in url.upper():
                        ids.append(url.rstrip("/").split("/")[-1])
                    elif "CVE-" in url.upper():
                        ids.append(url.rstrip("/").split("/")[-1])
                    if v.get("source") is not None and not ids:
                        ids.append(str(v.get("source")))
                    if v.get("cve"):
                        ids.append(str(v["cve"]))
        fix = meta.get("fixAvailable")
        fixed = None
        if isinstance(fix, dict):
            fixed = str(fix)
        elif fix is True:
            fixed = "available"
        findings.append(
            {
                "ecosystem": "npm",
                "package": name,
                "installed_version": meta.get("range"),
                "fixed_version": fixed,
                "severity": sev,
                "ids": ids or [name],
                "id": (ids[0] if ids else name),
                "path": "package-lock.json",
                "title": None,
                "npm_via_count": len(via) if isinstance(via, list) else 0,
            }
        )
    return findings


def from_trivy(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ValueError("trivy JSON must be an object")
    if raw.get("error") or raw.get("scanner_error"):
        raise ValueError(str(raw.get("error") or raw.get("scanner_error")))
    findings: List[Dict[str, Any]] = []
    for result in raw.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vid = vuln.get("VulnerabilityID")
            findings.append(
                {
                    "ecosystem": "image",
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": vuln.get("Severity"),
                    "ids": [vid] if vid else [],
                    "id": vid,
                    "path": target,
                    "title": vuln.get("Title"),
                }
            )
    return findings


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--kind", choices=["bundler-audit", "npm", "trivy"], required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    if not args.input.is_file():
        write(args.output, [], ok=False, message=f"missing input {args.input}")
        print(f"missing input {args.input}", file=sys.stderr)
        return 2

    try:
        raw = json.loads(args.input.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        write(args.output, [], ok=False, message=f"invalid JSON: {e}")
        print(f"invalid JSON: {e}", file=sys.stderr)
        return 2

    try:
        if args.kind == "bundler-audit":
            findings = from_bundler_audit(raw)
        elif args.kind == "npm":
            findings = from_npm_audit(raw)
        else:
            findings = from_trivy(raw)
    except ValueError as e:
        write(args.output, [], ok=False, message=str(e))
        print(str(e), file=sys.stderr)
        return 2

    write(args.output, findings, ok=True)
    print(f"normalized {len(findings)} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
