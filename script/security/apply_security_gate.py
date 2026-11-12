#!/usr/bin/env python3
# F-037 — Apply dependency/container security policy to scan reports.
# Exit codes:
#   0 — pass (no unapproved fail-severity findings; scanners OK)
#   1 — policy failure (unapproved high/critical or equivalent)
#   2 — scanner / report / configuration error (never treat as clean)

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - CI installs pyyaml; tests may vendor minimal
    yaml = None


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "moderate": 2,  # npm
    "low": 1,
    "unknown": 0,
    "negligible": 0,
    "info": 0,
}


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        die("PyYAML is required (pip install pyyaml)")
    if not path.is_file():
        die(f"Missing file: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        die(f"Invalid YAML root in {path}")
    return data


def parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def norm_sev(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    v = str(value).strip().lower()
    if v == "moderate":
        return "medium"
    return v


def active_exceptions(exc_doc: Dict[str, Any], today: date) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    required = {
        "id",
        "package",
        "reason",
        "scope",
        "impact",
        "mitigation",
        "reviewer_role",
        "expires_on",
        "status",
    }
    for i, raw in enumerate(exc_doc.get("exceptions") or []):
        if not isinstance(raw, dict):
            die(f"exceptions[{i}] must be a mapping")
        missing = required - set(raw)
        if missing:
            die(f"exceptions[{i}] missing fields: {sorted(missing)}")
        status = str(raw.get("status", "")).lower()
        if status not in ("accepted", "pending_upgrade"):
            # expired/rejected/draft do not bypass
            continue
        try:
            exp = parse_date(str(raw["expires_on"]))
        except ValueError:
            die(f"exceptions[{i}] invalid expires_on (want YYYY-MM-DD)")
        if exp < today:
            print(f"NOTE: exception {raw.get('id')} for {raw.get('package')} expired {exp}")
            continue
        out.append(raw)
    return out


def exception_covers(exc: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    eco = str(exc.get("ecosystem") or "").lower()
    if eco and eco != str(finding.get("ecosystem", "")).lower():
        return False
    pkg = str(exc.get("package") or "").lower()
    if pkg and pkg != str(finding.get("package") or "").lower():
        return False
    fid = str(exc.get("id") or "").upper()
    advisories = [str(a).upper() for a in finding.get("ids") or []]
    if fid and fid not in advisories and fid != str(finding.get("id") or "").upper():
        # allow package-wide exception only when id matches any advisory OR id field equals
        return False
    return True


def load_normalized_report(path: Path) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Return (findings, error_message). error_message set => scanner failure."""
    if not path.is_file():
        return [], f"report missing: {path}"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [], f"invalid JSON in {path}: {e}"

    if isinstance(raw, dict) and raw.get("scanner_error"):
        return [], str(raw["scanner_error"])
    if isinstance(raw, dict) and raw.get("error"):
        return [], str(raw["error"])

    # Our normalized format
    if isinstance(raw, dict) and "findings" in raw:
        if raw.get("ok") is False:
            return [], str(raw.get("message") or "scanner reported failure")
        findings = raw.get("findings") or []
        if not isinstance(findings, list):
            return [], f"findings must be a list in {path}"
        return findings, None

    return [], f"unrecognized report schema in {path} (expected normalized findings)"


def apply_gate(
    policy: Dict[str, Any],
    exceptions: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> Tuple[int, List[str]]:
    fail_sevs = {norm_sev(s) for s in policy.get("fail_severities") or ["critical", "high"]}
    messages: List[str] = []
    failures: List[Dict[str, Any]] = []
    warns: List[Dict[str, Any]] = []

    for f in findings:
        sev = norm_sev(f.get("severity"))
        f = dict(f)
        f["severity"] = sev
        covered = any(exception_covers(exc, f) for exc in exceptions)
        if sev in fail_sevs:
            if covered:
                messages.append(
                    f"EXCEPTION ok: {sev.upper()} {f.get('package')} {f.get('ids') or f.get('id')}"
                )
            else:
                failures.append(f)
        else:
            warns.append(f)

    for f in failures:
        messages.append(
            "FAIL: {sev} {eco} package={pkg} ids={ids} installed={ver} fixed={fix} path={path}".format(
                sev=str(f.get("severity")).upper(),
                eco=f.get("ecosystem"),
                pkg=f.get("package"),
                ids=f.get("ids") or f.get("id"),
                ver=f.get("installed_version"),
                fix=f.get("fixed_version"),
                path=f.get("path"),
            )
        )
    for f in warns[:20]:
        messages.append(
            "WARN: {sev} {eco} package={pkg} ids={ids}".format(
                sev=str(f.get("severity")).upper(),
                eco=f.get("ecosystem"),
                pkg=f.get("package"),
                ids=f.get("ids") or f.get("id"),
            )
        )
    if len(warns) > 20:
        messages.append(f"WARN: … {len(warns) - 20} more non-gating findings")

    messages.append(
        f"SUMMARY failures={len(failures)} warnings={len(warns)} exceptions_active={len(exceptions)}"
    )
    return (1 if failures else 0), messages


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Apply Foreman F-037 security scan gate")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        type=Path,
        help="Normalized JSON report (repeatable)",
    )
    parser.add_argument(
        "--today",
        default=None,
        help="Override today YYYY-MM-DD (tests)",
    )
    args = parser.parse_args(argv)

    policy = load_yaml(args.policy)
    exc_doc = load_yaml(args.exceptions)
    today = parse_date(args.today) if args.today else date.today()

    if policy.get("on_scanner_error", "fail") != "fail":
        die("policy.on_scanner_error must be 'fail' (no silent success)")

    try:
        active = active_exceptions(exc_doc, today)
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover
        die(str(e))

    all_findings: List[Dict[str, Any]] = []
    if not args.report:
        die("at least one --report is required")

    for report in args.report:
        findings, err = load_normalized_report(report)
        if err:
            print(f"SCANNER_ERROR: {err}", file=sys.stderr)
            # Never treat scanner/DB failure as a clean (zero-vuln) result.
            return 2
        all_findings.extend(findings)

    code, messages = apply_gate(policy, active, all_findings)
    for line in messages:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
