# SCA baseline inventory (F-037)

Snapshot from local scans on branch `security-hardening-5.0` (lab host).
**Not** a claim of zero vulnerabilities. Advisory DBs change over time.

| Field | Value |
|-------|-------|
| Inventory date | 2026-11-12 |
| Ruby scanner | bundler-audit **0.9.2** |
| Ruby advisory DB commit | `4d71b123428e33f694e805ce15351ee3d8d62ef7` (updated 2026-11-11) |
| npm scanner | `npm audit --omit=dev` (Node **22** container) |
| Image scanner | Trivy **0.58.1** (see image section) |
| Policy | `config/security/scan-policy.yml` (fail critical/high) |
| Exceptions applied | **none** (`exceptions.yml` empty) |

## Ruby (`Gemfile.lock`)

| Severity | Count (normalized findings) |
|----------|------------------------------:|
| critical | 1 |
| high | 48 |
| medium | 33 |
| low | 8 |
| **Total** | **90** |

Notable: Rails **7.0.10** stack (`actionpack`/`activestorage`/…) has multiple
high/critical advisories whose patched versions require **7.1+/7.2+/8.x** —
compatible upgrade is a **separate** task (no mass upgrade in F-037).

## npm (`package-lock.json`, omit=dev)

| Severity | Count |
|----------|------:|
| critical | 4 |
| high | 46 |
| moderate | 24 |
| low | 1 |
| **Total** | **75** |

Gate maps npm `moderate` → medium (warn-only). Production audit still reported
**50** critical/high findings — CI gate fails until remediated or specifically
excepted.

## Container image

Target attempted: `foreman-local:security-hardening-5.0`.

| Attempt | Result |
|---------|--------|
| Trivy default DB (`mirror.gcr.io`) | **Failed** — HTTP 403 downloading DB |
| Trivy `ghcr.io/aquasecurity/trivy-db` | **Failed** locally — download interrupted (`unexpected EOF`) |

**Final image was not successfully scanned in this lab environment.** CI workflow
still builds the image and runs Trivy (with `TRIVY_DB_REPOSITORY=ghcr.io/…`).
When the vulnerability DB cannot be downloaded, policy treats this as
**scanner failure** (exit 2), **not** as zero findings.

## Gate result (Ruby + npm, empty exceptions)

```
SUMMARY failures=99 warnings=66 exceptions_active=0
exit 1
```

## Remediation posture

- Do **not** bulk-upgrade in F-037.
- Track Rails/npm upgrades as dedicated change tasks.
- Add time-limited exceptions only with required fields and mitigations.
- Re-scan after each lockfile or base-image change.
