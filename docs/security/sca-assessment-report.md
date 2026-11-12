# Third-party dependency security assessment (F-037)

| Field | Value |
|-------|-------|
| Audit requirement | 76 (چک‌لیست امنیتی، صفحه ۵۵) |
| Branch | `security-hardening-5.0` |
| Assessment date | 2026-11-12 |
| Related policy | [dependency-scanning.md](dependency-scanning.md), [scan-policy.yml](../../config/security/scan-policy.yml) |
| Baseline counts | [sca-baseline-inventory.md](sca-baseline-inventory.md) |

## 1. Audit findings addressed

| # | Finding (audit) | Remediation |
|---|-----------------|-------------|
| 1 | No adequately demonstrated SCA for OSS components | Dedicated CI workflow + local scripts produce reviewable JSON artifacts and a policy gate |
| 2 | Ruby assessment (e.g. bundler-audit) not established | `bundler-audit` **0.9.2** runs on `Gemfile.lock` in CI and via `script/security/scan_dependencies.sh` |
| 3 | Frontend automation disables npm audit (`--no-audit`) | **Install/build** retains `--no-audit` for offline/reproducible installs; **security assessment** runs `npm audit` explicitly in `.github/workflows/dependency_security.yml` (not during image `npm install`) |
| 4 | No sufficient documented repeatable library assessment | This report + baseline inventory + policy/exceptions + reproduction commands |

## 2. Ecosystems covered

| Ecosystem | Resolved from | Scanner | Gate |
|-----------|---------------|---------|------|
| Ruby (direct + transitive) | `Gemfile.lock`, `bundler.d/*` | bundler-audit 0.9.2 | critical/high fail |
| npm production / asset deps | `package-lock.json` | `npm audit --omit=dev` | critical/high fail |
| npm full tree (info) | same | `npm audit` | artifact only |
| Runtime image OS + pkgs | Built Dockerfile image | Trivy 0.58.1 `vuln` | critical/high fail |

Plugins discovered at install time via `script/npm_install_plugins.js` still install with `--no-audit`; their lock/manifest assessment is in-scope for follow-up when plugins ship with this tree. Core Foreman lockfiles are gated now.

## 3. Treatment of `--no-audit`

Occurrences (intentional on **install** paths):

| Location | Purpose |
|----------|---------|
| `Dockerfile` `npm install --no-audit` | Reproducible/offline image build; no advisory network in build layer |
| `script/npm_install_plugins.js` | Same for plugin installs during webpack prep |
| `.github/workflows/foreman.yml`, `js_tests.yml`, `lint_rules_tests.yml`, `stylelint_rules_tests.yml`, `plugins_react_tests.yml` | Fast deterministic `npm ci` / lock refresh without mixing install and advisory I/O |

**Security assessment is not those commands.** It is:

```text
.github/workflows/dependency_security.yml  →  npm audit --omit=dev
script/security/scan_dependencies.sh       →  npm audit --omit=dev
```

Removing `--no-audit` from Docker/CI install would couple reproducible builds to live advisory APIs and is **not** required to satisfy the audit once an explicit SCA job exists.

## 4. Scanner execution evidence (lab)

| Scanner | Version / DB | Result |
|---------|--------------|--------|
| bundler-audit | 0.9.2; ruby-advisory-db commit `4d71b123…` (2026-11-11) | **Executed** — 90 findings (1 critical, 48 high, …) |
| npm audit `--omit=dev` | Node 22 container | **Executed** — 75 findings (4 critical, 46 high, …) |
| Policy gate (Ruby+npm) | `apply_security_gate.py` | **Executed** — exit **1**, `failures=99` (no silent green) |
| Gate unit tests | synthetic | **8 + 1 tests OK** |
| Trivy image | 0.58.1 (ghcr vuln + Java DB) | **Lab incomplete** — DB reachable via ghcr; image layer analysis timed out / prior 403 on gcr; CI job still builds+scans |

Raw/normalized artifacts (local, gitignored under `tmp/security-scan/`):
`bundler-audit.raw.json`, `npm-audit.raw.json`, `ruby.normalized.json`, `npm.normalized.json`.

## 5. Policy and exceptions

- Fail severities: **critical**, **high** (unless non-expired exception).
- Warn: medium/low.
- Scanner/advisory DB failure → exit **2** (never “0 vulns”).
- Exceptions: `config/security/exceptions.yml` — required fields + `expires_on`; **currently empty** (no blanket suppressions).
- Unfixable high/critical still fail unless excepted.

## 6. CI workflow

Workflow: `.github/workflows/dependency_security.yml`

1. Security gate unit tests  
2. Ruby + npm advisory scan → normalize → gate → upload artifacts  
3. Build image → Trivy → normalize → gate → upload artifacts  

Triggers: PR, push (`develop`, `*-stable`, `security-hardening-5.0`), weekly schedule, manual dispatch.

Ordinary `foreman.yml` / JS test jobs remain unchanged and still use `--no-audit` on **install** only.

## 7. Reproduction commands

```bash
python test/security/test_apply_security_gate.py -v
python test/security/test_normalize_reports.py -v
./script/security/scan_dependencies.sh
SCAN_IMAGE=foreman-local:security-hardening-5.0 ./script/security/scan_dependencies.sh --with-image
```

## 8. Remediation status

| Class | Status |
|-------|--------|
| SCA capability | **Implemented** |
| Repeatable assessment | **Documented + executed** (Ruby/npm) |
| CI enforcement | **Configured**; fails on unapproved critical/high |
| Mass upgrades | **Out of scope** for F-037 — separate tasks |
| Image scan in this lab | **Not completed** (Trivy layer analysis timeout after ghcr DB; earlier gcr 403) |
| Exceptions | None accepted yet |

## 9. Limitations

- bundler-audit ≠ full CVE universe.
- Image scan depends on Trivy DB reachability.
- GitHub Actions run not executed from this lab host; local equivalents demonstrated for Ruby/npm/gate.
- Plugin-only trees outside core lockfiles need per-plugin follow-up.
