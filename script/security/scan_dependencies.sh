#!/usr/bin/env bash
# F-037 — run dependency/image security scans and apply the policy gate.
# Usage:
#   ./script/security/scan_dependencies.sh              # ruby + npm (+ image if SCAN_IMAGE set)
#   ./script/security/scan_dependencies.sh --ruby-only
#   ./script/security/scan_dependencies.sh --npm-only
#   SCAN_IMAGE=foreman-local:security-hardening-5.0 ./script/security/scan_dependencies.sh --with-image
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUT_DIR="${SECURITY_SCAN_OUT:-$ROOT/tmp/security-scan}"
mkdir -p "$OUT_DIR"

POLICY="$ROOT/config/security/scan-policy.yml"
EXCEPTIONS="$ROOT/config/security/exceptions.yml"
GATE_PY="$ROOT/script/security/apply_security_gate.py"
NORM_PY="$ROOT/script/security/normalize_reports.py"

BUNDLER_AUDIT_VERSION="${BUNDLER_AUDIT_VERSION:-0.9.2}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.58.1}"
RUBY_IMAGE="${RUBY_SCAN_IMAGE:-ruby:3.1-bookworm}"
NODE_IMAGE="${NPM_SCAN_IMAGE:-node:22-bookworm}"

DO_RUBY=1
DO_NPM=1
DO_IMAGE=0
GATE_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --ruby-only) DO_RUBY=1; DO_NPM=0; DO_IMAGE=0 ;;
    --npm-only) DO_RUBY=0; DO_NPM=1; DO_IMAGE=0 ;;
    --with-image) DO_IMAGE=1 ;;
    --image-only) DO_RUBY=0; DO_NPM=0; DO_IMAGE=1 ;;
    --gate-only) GATE_ONLY=1 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
  esac
done

if [[ -n "${SCAN_IMAGE:-}" ]]; then
  DO_IMAGE=1
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }

run_ruby_docker() {
  docker run --rm \
    -v "$ROOT":/app -w /app \
    "$RUBY_IMAGE" \
    bash -lc "
      set -e
      gem install bundler-audit -v ${BUNDLER_AUDIT_VERSION} --no-document
      export PATH=\"\$(ruby -e 'print Gem.bindir'):\$PATH\"
      bundle-audit update
      set +e
      bundle-audit check --format json > /tmp/ba.json 2> /tmp/ba.err
      rc=\$?
      set -e
      if [ ! -s /tmp/ba.json ]; then
        python3 - <<'PY'
import json
err=open('/tmp/ba.err').read()[:500]
print(json.dumps({'scanner_error': 'bundler-audit produced no JSON: '+err}))
PY
      else
        cat /tmp/ba.json
      fi
    " >"$OUT_DIR/bundler-audit.raw.json"
}

scan_ruby() {
  echo "==> Ruby bundler-audit (gem ${BUNDLER_AUDIT_VERSION})"
  # Prefer Docker for reproducible gem+DB; host Ruby is optional.
  if have_cmd docker; then
    run_ruby_docker
  elif have_cmd gem; then
    gem install bundler-audit -v "$BUNDLER_AUDIT_VERSION" --no-document
    export PATH="$(ruby -e 'print Gem.bindir'):${PATH:-}"
    bundle-audit update
    set +e
    bundle-audit check --format json >"$OUT_DIR/bundler-audit.raw.json" 2>"$OUT_DIR/bundler-audit.stderr"
    rc=$?
    set -e
    if [[ ! -s "$OUT_DIR/bundler-audit.raw.json" ]]; then
      printf '{"scanner_error":"bundler-audit produced no JSON (exit %s)"}\n' "$rc" \
        >"$OUT_DIR/bundler-audit.raw.json"
    fi
  else
    echo "ERROR: need docker or gem for Ruby scan" >&2
    exit 2
  fi
  python3 "$NORM_PY" --kind bundler-audit \
    --input "$OUT_DIR/bundler-audit.raw.json" \
    --output "$OUT_DIR/ruby.normalized.json"
}

scan_npm() {
  echo "==> npm audit (omit=dev production gate)"
  local npm_cmd
  if have_cmd node && have_cmd npm; then
    npm_cmd=(npm)
  else
    # Host npm may be a broken Windows shim; use container.
    npm_cmd=(docker run --rm -v "$ROOT":/app -w /app "$NODE_IMAGE" npm)
  fi
  set +e
  "${npm_cmd[@]}" audit --omit=dev --json >"$OUT_DIR/npm-audit.raw.json" 2>"$OUT_DIR/npm-audit.stderr"
  local rc=$?
  set -e
  if [[ ! -s "$OUT_DIR/npm-audit.raw.json" ]] || ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT_DIR/npm-audit.raw.json" 2>/dev/null; then
    printf '{"scanner_error":"npm audit failed or returned non-JSON (exit %s)"}\n' "$rc" \
      >"$OUT_DIR/npm-audit.raw.json"
  fi
  # Informational full audit (non-gating artifact)
  set +e
  "${npm_cmd[@]}" audit --json >"$OUT_DIR/npm-audit-full.raw.json" 2>/dev/null || true
  set -e
  python3 "$NORM_PY" --kind npm \
    --input "$OUT_DIR/npm-audit.raw.json" \
    --output "$OUT_DIR/npm.normalized.json"
}

scan_image() {
  local image="${SCAN_IMAGE:?SCAN_IMAGE required for image scan}"
  echo "==> Trivy image scan (${TRIVY_IMAGE}) target=${image}"
  # Prefer ghcr.io DB mirrors; some environments block mirror.gcr.io (403).
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$OUT_DIR":/out \
    -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db \
    -e TRIVY_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db \
    "$TRIVY_IMAGE" \
    image --scanners vuln --format json --output /out/trivy.raw.json \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --db-repository ghcr.io/aquasecurity/trivy-db \
    --java-db-repository ghcr.io/aquasecurity/trivy-java-db \
    "$image"
  if [[ ! -s "$OUT_DIR/trivy.raw.json" ]]; then
    printf '{"scanner_error":"trivy produced empty output"}\n' >"$OUT_DIR/trivy.raw.json"
  fi
  python3 "$NORM_PY" --kind trivy \
    --input "$OUT_DIR/trivy.raw.json" \
    --output "$OUT_DIR/image.normalized.json"
}

REPORT_ARGS=()

if [[ "$GATE_ONLY" -eq 0 ]]; then
  [[ "$DO_RUBY" -eq 1 ]] && scan_ruby
  [[ "$DO_NPM" -eq 1 ]] && scan_npm
  [[ "$DO_IMAGE" -eq 1 ]] && scan_image
fi

[[ -f "$OUT_DIR/ruby.normalized.json" ]] && REPORT_ARGS+=(--report "$OUT_DIR/ruby.normalized.json")
[[ -f "$OUT_DIR/npm.normalized.json" ]] && REPORT_ARGS+=(--report "$OUT_DIR/npm.normalized.json")
[[ -f "$OUT_DIR/image.normalized.json" ]] && REPORT_ARGS+=(--report "$OUT_DIR/image.normalized.json")

if [[ ${#REPORT_ARGS[@]} -eq 0 ]]; then
  echo "ERROR: no normalized reports to gate" >&2
  exit 2
fi

# Ensure PyYAML available for gate
python3 - <<'PY' || pip3 install --user pyyaml
import yaml
PY

echo "==> Applying security gate"
set +e
python3 "$GATE_PY" --policy "$POLICY" --exceptions "$EXCEPTIONS" "${REPORT_ARGS[@]}"
gate_rc=$?
set -e

echo "Gate exit: $gate_rc (0=pass, 1=policy fail, 2=scanner/config error)"
echo "Artifacts under $OUT_DIR"
exit "$gate_rc"
