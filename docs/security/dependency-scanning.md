# Dependency and container security scanning (F-037)

Audit requirement **76** (چک‌لیست امنیتی، صفحه ۵۵). Implements software
composition analysis (SCA) for Ruby gems, npm production dependencies, and the
Foreman container image, with a policy gate and time-limited exceptions.

Formal assessment evidence: [sca-assessment-report.md](sca-assessment-report.md).

## Scope

| Ecosystem | Tool | Input | Gate |
|-----------|------|-------|------|
| Ruby | `bundler-audit` **0.9.2** | `Gemfile.lock` (+ `bundler.d`) | Fail on **critical/high** without valid exception |
| npm | `npm audit --omit=dev` | `package-lock.json` | Fail on **critical/high** in production audit |
| npm (info) | `npm audit` (all) | same | Artifact only; gate uses omit=dev report |
| Container | Trivy **0.58.1** (`vuln` scanner) | Built/deploy image | Fail on **critical/high** without exception |

Transitive dependencies are included via lockfiles / image package inventories.

**Not claimed:** source SAST, secrets scanning as a merge gate, or plugin gemfiles
outside this repository.

## Policy (summary)

Full machine-readable policy: [`config/security/scan-policy.yml`](../../config/security/scan-policy.yml).

- **Fail:** `critical`, `high` unless covered by a non-expired exception.
- **Warn:** `medium`, `low`, `unknown`, `negligible` (do not fail alone).
- **Unfixable** high/critical: still **fail** unless excepted (`unfixable_policy: fail_unless_excepted`).
- **Scanner / advisory DB failure:** exit **2** — never reported as zero vulnerabilities.
- **Dev npm dependencies:** omitted from the gating audit; full audit retained as artifact.
- **Ownership (proposed):** Security Team reviews exceptions; Foreman Development remediates upgrades.

## Treatment of `--no-audit` (audit finding)

`npm ci` / `npm install --no-audit` in Docker and ordinary test workflows keeps
**installation** offline and reproducible. That does **not** waive SCA: the
`dependency_security` workflow runs `npm audit` and fails on unapproved
critical/high findings. Full call-site list:
[sca-assessment-report.md](sca-assessment-report.md) §3.

## Exception workflow

File: [`config/security/exceptions.yml`](../../config/security/exceptions.yml).

Required fields per entry: `id`, `package`, `reason`, `scope`, `impact`,
`mitigation`, `reviewer_role`, `expires_on` (`YYYY-MM-DD`), `status`
(`accepted` | `pending_upgrade`). Optional: `ecosystem` (`ruby`|`npm`|`image`).

Rules:

1. Do **not** invent personal approvals — use role strings (e.g. `Security Team (proposed)`).
2. No broad ignores (“ignore all HIGH”).
3. Max duration **180 days** (policy); renew with reassessment.
4. `expires_on` in the past → exception **ignored**; finding fails the gate again.
5. Incomplete entries → gate exit **2**.

## Local commands

```bash
# Gate unit tests (no network)
pip install 'pyyaml==6.0.2'   # once
python test/security/test_apply_security_gate.py -v

# Full orchestrated scan (uses Docker if local ruby/npm unavailable)
chmod +x script/security/scan_dependencies.sh
./script/security/scan_dependencies.sh

# Include local image (example lab tag)
SCAN_IMAGE=foreman-local:security-hardening-5.0 ./script/security/scan_dependencies.sh --with-image

# Pieces
./script/security/scan_dependencies.sh --ruby-only
./script/security/scan_dependencies.sh --npm-only
```

Artifacts land in `tmp/security-scan/` (gitignored via `tmp/`).

### Manual pieces

```bash
gem install bundler-audit -v 0.9.2 --no-document
bundle-audit update
bundle-audit check --format json > tmp/security-scan/bundler-audit.raw.json

npm audit --omit=dev --json > tmp/security-scan/npm-audit.raw.json

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/tmp/security-scan":/out aquasec/trivy:0.58.1 \
  image --scanners vuln --format json --output /out/trivy.raw.json \
  foreman-local:security-hardening-5.0

python script/security/normalize_reports.py --kind bundler-audit \
  --input tmp/security-scan/bundler-audit.raw.json \
  --output tmp/security-scan/ruby.normalized.json
# … similarly for npm / trivy …

python script/security/apply_security_gate.py \
  --policy config/security/scan-policy.yml \
  --exceptions config/security/exceptions.yml \
  --report tmp/security-scan/ruby.normalized.json \
  --report tmp/security-scan/npm.normalized.json \
  --report tmp/security-scan/image.normalized.json
```

## CI

Workflow: [`.github/workflows/dependency_security.yml`](../../.github/workflows/dependency_security.yml)

Jobs:

1. **Security gate unit tests** — synthetic policy tests.
2. **Ruby + npm advisory scan** — `bundler-audit` + `npm audit --omit=dev` → normalize → gate.
3. **Container image scan** — `docker/build-push-action` (load local tag) → Trivy → gate.

Existing `foreman.yml` / `js_tests.yml` jobs are unchanged (not bypassed).

Artifacts: `dependency-security-reports`, `image-security-reports`.

Schedule: weekly Monday 05:17 UTC plus PR/push to `develop`, `*-stable`, and
`security-hardening-5.0`.

## Reviewing findings

1. Open the job summary / uploaded JSON.
2. Confirm severity, package, installed vs fixed version, production relevance.
3. Prefer upgrading the lockfile in a **dedicated** PR (F-037 does not mass-upgrade).
4. If no compatible fix: add a **specific** exception with expiry and mitigation.
5. Re-run the gate locally before merge.

## Unavailable advisory services

If `bundle-audit update`, npm registry, or Trivy DB download fails, the pipeline
must **fail** (exit 2). Do not merge on “empty” results.

## Known limitations

- Lab/host without Node/Ruby uses containerized scanners; CI uses setup-ruby/node.
- Image job builds the Dockerfile in GHA (long); local lab may scan a pre-built tag instead.
- `bundler-audit` coverage is limited to its advisory DB (not every CVE source).
- npm `audit` depends on the npm advisory API; `--omit=dev` may still flag build-time
  libraries that ship in webpack bundles — treat as production-relevant.
- Trivy OS findings on CentOS Stream 9 may lack fixes; except or rebuild base deliberately.
- Plugin-only manifests outside this repo are not scanned here.
- Some networks block `mirror.gcr.io` Trivy DB/Java-DB (HTTP 403); scripts/CI
  prefer `ghcr.io/aquasecurity/trivy-db` and `trivy-java-db`. Large image
  analysis may still time out in constrained labs — that must fail the gate
  (exit 2), never report a clean image.

## Remediation posture

Classify → check fixed version → compatibility → separate upgrade task → document
residual risk. Do not delete tests or dependencies solely to silence scanners.
