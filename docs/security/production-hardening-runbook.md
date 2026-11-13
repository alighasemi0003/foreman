# Production Installation and Security Hardening Runbook

**Foreman 5.0 — security-hardening-5.0**

Audit requirement **84** (چک‌لیست امنیتی، صفحه ۶۰).

| Field | Value |
|-------|--------|
| Document ID | F-045 |
| Project | Foreman 5.0 security-hardening |
| Branch | `security-hardening-5.0` |
| Source commit (at authorship) | `8168935992b5ab81b1c7e295464e72d4704b54fd` |
| Application version | 5.0.0 (`SETTINGS[:version]`) |
| Lab image tag | `foreman-local:security-hardening-5.0` (local build; digest changes per rebuild) |
| Classification | **Operational runbook** — not evidence that production was deployed |
| Related | [threat-model.md](threat-model.md), [threat-control-matrix.md](threat-control-matrix.md), [docker-local.md](../docker-local.md) |

---

## 1. Document control

### 1.1 Scope

This runbook describes how to **install, configure, harden, validate, back up, recover, and accept** a production-oriented deployment of the customized Foreman 5.0 tree on branch `security-hardening-5.0`.

It covers:

- Operating system assumptions (container base and host)
- PostgreSQL
- Redis (cache + Dynflow)
- Puma / Rails application
- Sidekiq workers (orchestrator + worker)
- TLS / reverse-proxy expectations
- Security Settings and environment controls verified in this repository
- Logging / audit / security-event collector (F-041/F-042)
- Backup, rollback, monitoring, and operational procedures

### 1.2 Assumptions

| ID | Assumption | Evidence class |
|----|------------|----------------|
| A1 | Lab Compose stack in `docker-compose.yml` is the **tested** reference architecture | LAB |
| A2 | Production places TLS termination (and optionally a reverse proxy) in front of Puma | **ASSUMED** — not configured in Compose |
| A3 | Production uses strong unique secrets; lab defaults (`foreman`/`foreman`) are forbidden | CODE + LAB docs |
| A4 | Smart Proxy client-certificate auth is configured in production when proxies are used | **ASSUMED** beyond unit/settings defaults |
| A5 | Org SIEM may replace or drain the lab `security-collector` | F-041/F-042 docs |

**Evidence classes:** CODE (source), LAB (Compose/local verification), ASSUMED (typical production; not verified here), RESIDUAL (known gap).

### 1.3 Owner roles (suggested; not signed)

| Role | Responsibility |
|------|----------------|
| Platform / OS admin | Host OS, firewall, TLS certs, volume backups |
| DBA | PostgreSQL, `pg_hba`, DB backups/restore |
| Foreman application owner | Settings, seeds, workers, security feature validation |
| Security reviewer | Hardening checklist, log/collector review, residual risk acceptance |
| Change approver | Production go-live / rollback decisions |

**No production approval is recorded in this document.** Acceptance (§15) must be filled by the deploying organization.

### 1.4 Revision history

| Rev | Date (UTC) | Commit | Change |
|-----|------------|--------|--------|
| 1.0 | 2026-11-12 | `8168935992b5ab81b1c7e295464e72d4704b54fd` | Initial F-045 runbook |

---

## 2. Architecture

### 2.1 Tested lab topology (LAB)

```
                    ┌─────────────────────────────┐
  Operator browser  │  host :3000 (HTTP only)     │
  ─────────────────►│  MY_DOCKER_IP bind          │
                    └──────────────┬──────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
   ┌───────────┐            ┌────────────┐            ┌────────────┐
   │ app       │            │orchestrator│            │ worker     │
   │ Puma      │            │ Sidekiq -c1│            │ Sidekiq -c5│
   │ UID 1001  │            │            │            │            │
   └─────┬─────┘            └─────┬──────┘            └─────┬──────┘
         │                        │                         │
         └────────────┬───────────┴────────────┬────────────┘
                      ▼                        ▼
              ┌──────────────┐         ┌───────────────┐
              │ PostgreSQL 12│         │ redis-cache   │
              │ volume: db   │         │ redis-tasks   │
              └──────────────┘         │ AOF volume    │
                                       └───────────────┘

Optional overlays:
  docker-compose.vnc.yml      → publish 5910–5930 (loopback by default)
  docker-compose.logging.yml  → security-collector UID 1500 + volume security-events
```

Sources: `docker-compose.yml`, `docker-compose.vnc.yml`, `docker-compose.logging.yml`, `Dockerfile`.

### 2.2 Components and trust boundaries

| Component | Role | Trust notes |
|-----------|------|-------------|
| `app` (Puma) | UI / API / GraphQL | Foreman UID `1001`; no mount of collector volume |
| `orchestrator` / `worker` | Dynflow Sidekiq | Same image + `ENCRYPTION_KEY` as app |
| `db` | PostgreSQL 12 | Lab Superuser role `foreman` — **not** least-privilege production pattern |
| `redis-cache` | Rails.cache (rate limits, etc.) | Lab uses floating `redis` tag — **pin in production** |
| `redis-tasks` | Dynflow (`appendonly yes`) | Persistent volume |
| Reverse proxy / TLS | Terminates HTTPS | **ASSUMED** in production; lab sets `FOREMAN_REQUIRE_SSL=false` |
| Smart Proxy | Facts/reports/ENC/console path | Settings `restrict_registered_smart_proxies`, SSL client env |
| VNC gateway | Console ports 5910–5930 | Optional overlay; reauth settings for console |
| `security-collector` | Append-only security events | Separate UID `1500`; F-041/F-042 |

### 2.3 Ports (lab defaults)

| Service | Container | Host (lab default) |
|---------|-----------|--------------------|
| HTTP (Puma) | 3000 | `127.0.0.1:3000` |
| PostgreSQL | 5432 | ephemeral publish (`"5432"`) |
| VNC | 5910–5930 | only with `docker-compose.vnc.yml` → `127.0.0.1:5910-5930` |
| Security collector TCP | 1514 | `127.0.0.1:1514` with logging overlay |

### 2.4 Persistent storage (lab Compose volumes)

| Volume | Contents |
|--------|----------|
| `db` | PostgreSQL data |
| `redis-persistent` | Dynflow Redis AOF |
| `security-events` | Collector JSONL (logging overlay only) |

---

## 3. Prerequisites

### 3.1 OS and runtime

| Layer | Lab-verified | Production requirement |
|-------|--------------|------------------------|
| Container base | CentOS Stream 9 (`quay.io/centos/centos:stream9`) | Same or org-approved EL9-compatible base |
| Host | Docker Engine + Compose v2 (WSL2 lab used for verification) | Hardened Linux host with container runtime |
| Ruby / Node in image | Bundled via Dockerfile multi-stage build | Build from this branch; do not mix untrusted images |

### 3.2 Resource sizing (guidance — not capacity certification)

Lab defaults (see `docs/connection-capacity.md`):

- Puma: 2 workers × 5 threads; AR pool 5 per process
- Sidekiq orchestrator `-c 1`; worker `-c 5`
- Configured DB connection budget ≈ **20** vs Postgres default `max_connections` 100

Production: size CPU/RAM from measured RPS; keep `pool ≥ threads` and `pool ≥ sidekiq -c`; leave ≥20–25% of `max_connections` free.

### 3.3 Network / DNS / time

- DNS: `FOREMAN_FQDN` / `FOREMAN_DOMAIN` must match TLS certificate SANs in production.
- NTP/chrony on all hosts (**ASSUMED** production control).
- Firewall: allow only admin, reverse-proxy, Smart Proxy, and required outbound paths.

### 3.4 Certificates and secrets (placeholders)

- TLS cert + chain + private key for reverse proxy: `/etc/pki/...` (**environment-specific**)
- `ENCRYPTION_KEY` = 64 hex chars **or** `ENCRYPTION_KEY_FILE=/run/secrets/foreman_encryption_key`
- Persist `secret_key_base` across container recreation (lab note: ephemeral under `tmp/` unless persisted — see §8)

### 3.5 Access permissions

- Application process: non-root (image USER `1001`)
- Collector process: UID `1500` (logging overlay)
- Host SSH: dedicated admin accounts; no shared lab passwords

---

## 4. Operating system hardening

> Distinguish **LAB-tested** Docker commands from **platform-dependent examples** labeled ASSUMED.

### 4.1 Patch management

- Rebuild images from this branch after applying base-image updates (`dnf upgrade` in Dockerfile base stage).
- Host: apply vendor security updates on a defined cadence (**ASSUMED**).

### 4.2 Service accounts and least privilege

- Container app user: `foreman` UID **1001**, shell `/sbin/nologin` (Dockerfile).
- Do not run Puma as root.
- Do not mount `security-events` into `app`/`worker`/`orchestrator`.

### 4.3 File permissions (examples)

```bash
# EXAMPLE — host secret file (adapt paths)
umask 077
install -m 600 /dev/null /run/secrets/foreman_encryption_key
# write 64 hex chars; never commit
```

### 4.4 Firewall / SSH / MAC

| Control | Lab | Production |
|---------|-----|------------|
| Publish bind | Loopback default (`MY_DOCKER_IP`) | Restrict to proxy / admin nets |
| SSH | Host-dependent | Key-based, MFA where required (**ASSUMED**) |
| SELinux/AppArmor | Not validated in lab | Enable per org standard (**ASSUMED**) |

### 4.5 Host audit and logging

- Retain container stdout (`RAILS_LOG_TO_STDOUT=true` in image).
- Forward to SIEM; use F-041/F-042 collector or org equivalent.

### 4.6 Time synchronization

Ensure UTC-consistent clocks for lockout windows, rate-limit periods, TLS validity, and audit timestamps (**ASSUMED** chrony/NTP).

---

## 5. PostgreSQL security

### 5.1 Lab vs production credentials

| Item | Lab (`.env.example`) | Production |
|------|----------------------|------------|
| User / password / DB | `foreman` / `foreman` / `foreman` | Unique strong password; never lab defaults |
| Role privileges | Lab role is effectively broad (Superuser observed in lab) | Least privilege: DML on app schema; no Superuser |
| Network | Compose internal DNS `db` | Private network / TLS to DB when required (**ASSUMED**) |

### 5.2 Connection string

```text
DATABASE_URL=postgres://<USER>:<PASSWORD>@<HOST>/<DB>?pool=<N>
```

Keep `pool` aligned with Puma/Sidekiq (§2 / `docs/connection-capacity.md`).

### 5.3 `pg_hba.conf` (example — environment-specific)

```text
# EXAMPLE — allow only app subnet with scram-sha-256
hostssl foreman foreman 10.0.0.0/24 scram-sha-256
```

### 5.4 Audit table immutability

The `audits` table is an **operational** store: the application DB role can UPDATE/DELETE (F-042). Do **not** treat UI read-only Audits as WORM. Forward security events to an independent collector/SIEM.

### 5.5 Backup

```bash
# EXAMPLE — logical backup from lab Compose project (adapt names)
docker compose exec -T db pg_dump -U foreman foreman | gzip > foreman-$(date -u +%Y%m%dT%H%M%SZ).sql.gz
```

Encrypt backup files at rest (**ASSUMED** org control). Verify restore on a non-production instance before relying on backups.

---

## 6. Web server and TLS

### 6.1 HTTPS enforcement (CODE)

- `SETTINGS[:require_ssl]` driven by `Foreman::SslDefaults` / `FOREMAN_REQUIRE_SSL`.
- Lab Compose: `FOREMAN_REQUIRE_SSL=false` (HTTP :3000 only).
- **Production:** omit the opt-out or set `FOREMAN_REQUIRE_SSL=true` so Rails `force_ssl` and Secure cookies apply.

Verification (lab observed):

```bash
docker compose exec app bundle exec rails runner 'puts SETTINGS[:require_ssl]'
# Lab: false — Production must be true behind HTTPS
```

### 6.2 Reverse proxy (ASSUMED)

Configure org proxy (nginx/httpd/etc.) for:

| Control | Guidance |
|---------|----------|
| TLS 1.2+ | Org cipher policy |
| Certificate hostname | Match `FOREMAN_FQDN` |
| `client_max_body_size` | ≥ app limits; recommend align with 10 MiB absolute ceiling |
| Timeouts | Bound slowloris / partial uploads |
| Headers | Pass `X-Forwarded-Proto`, `X-Forwarded-For` only from trusted hops |
| Rate limit | Optional outer limit **in addition to** F-026 |

### 6.3 Trusted proxies (CODE)

`config.action_dispatch.trusted_proxies` from `SETTINGS[:trusted_proxies]` (default loopback). Misconfiguration allows IP spoofing of rate-limit / lockout telemetry.

### 6.4 Application-layer controls (CODE)

| Control | Implementation |
|---------|----------------|
| HSTS | `SETTINGS[:hsts_enabled]` default true when SSL on |
| Unsafe HTTP methods | `Foreman::Middleware::RejectUnsafeHttpMethods` → 405 + `SECURITY_CONTROL_REJECTED` |
| Body size | Puma 10 MiB + middleware path limits (`docs/http-request-body-limits.md`) |
| Rate limit | F-026 (`docs/http-rate-limiting.md`) |
| CSRF | `protect_from_forgery`; events `CSRF_REJECTED` (F-044) |

---

## 7. Foreman security settings

Change via **Administer → Settings** (UI) or Rails console. Restart is **not** required for Setting values stored in DB (effective on next request). Environment/`SETTINGS` changes (`FOREMAN_REQUIRE_SSL`, pools) need process restart.

Verification pattern:

```bash
docker compose exec app bundle exec rails runner 'puts Setting[:captcha_enabled].inspect'
```

### 7.1 Baseline table (verified names)

| Setting | Purpose | Code default | Lab observed* | Production baseline (recommended) | Restart? |
|---------|---------|--------------|---------------|-------------------------------------|----------|
| `captcha_enabled` | Offline login CAPTCHA | `false` | `false` | `true` for internet-facing UI | No |
| `account_lockout_attempts` | Local password failures before lock | `5` | `5` | Keep ≥3; tune to policy | No |
| `account_lockout_window` | Failure counting window (minutes) | `15` | `15` | Per policy | No |
| `account_lockout_duration` | Lock duration (minutes) | `30` | `30` | Per policy | No |
| `failed_login_attempts_limit` | IP bruteforce (5 min window) | `30` | `30` | Keep enabled (>0) | No |
| `idle_timeout` | Idle logout (minutes) | `60` | `60` | ≤60 typical | No |
| `login_history_limit` | Successful login history per user | `20` | (seed-dependent) | 10–20 | No |
| `password_max_age` | Local password max age (days); `0` disables | `0` | (seed-dependent) | Org policy (e.g. 90) | No |
| `password_history_length` | Prior password reuse block | `5` | (seed-dependent) | ≥5 | No |
| `password_hash` | Local hash algorithm | `bcrypt` | `bcrypt` | `bcrypt` | No |
| `reauthentication_window_minutes` | Sensitive-action reauth validity | (see initializer) | lab may be tuned | ≥5 typical; lab may use short window for tests | No |
| `require_reauth_*` | Per-action reauth gates | mostly `true` in hardening | verify in UI | Leave enabled for sensitive ops | No |
| `http_rate_limit_enabled` | F-026 master switch | `true` | enable if unset | `true` | No |
| `http_rate_limit_period` | Window seconds | `60` | — | 60 unless justified | No |
| `http_rate_limit_login` | Login POSTs / IP | `20` | — | Tune for NAT | No |
| `http_rate_limit_api` | API / IP | `300` | — | Size for proxies | No |
| `http_rate_limit_fail_closed` | Cache outage policy | `false` | — | Prefer `true` if denying traffic is acceptable | No |
| `restrict_registered_smart_proxies` | Proxy auth restriction | `true` | — | `true` | No |
| `websockets_encrypt` | VNC/SPICE WS encryption | follows `require_ssl` | `false` in HTTP lab | `true` with cert/key set when consoles used | No |

\*Lab values sampled 2026-11-12 on a running stack; nil/seed-dependent means Setting row may still hold default until read via UI after full seed.

### 7.2 Non-Setting controls (env / code)

| Control | Mechanism |
|---------|-----------|
| HTTPS require | `FOREMAN_REQUIRE_SSL` / `SETTINGS[:require_ssl]` |
| Field encryption | `ENCRYPTION_KEY` / `ENCRYPTION_KEY_FILE` |
| Session ciphertext | `secret_key_base` → encrypted AR session serializer (F-015) |
| Body limits | `FOREMAN_MAX_REQUEST_BODY_BYTES`, `FOREMAN_ABSOLUTE_MAX_REQUEST_BODY_BYTES`, etc. |
| Security event forwarder | `FOREMAN_SECURITY_EVENTS_ENABLED`, `FOREMAN_SECURITY_EVENTS_URL` |
| Concurrent browser sessions | Newer-login-wins (`has_active_session`) — code policy, not a Setting |

Detail docs: `docs/password-*.md`, `docs/browser-session-policy.md`, `docs/session-encryption.md`, `docs/failed-login-notification.md`, `docs/login-history.md`.

---

## 8. Secrets and encryption

### 8.1 `ENCRYPTION_KEY` / `ENCRYPTION_KEY_FILE`

See `docs/encryption-key.md`.

```bash
# Generate once — placeholder output only
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

- Same key on **app, worker, orchestrator**
- Losing the key loses access to ciphertext (LDAP/compute/BMC/JWT secrets, etc.)
- Preflight: `bundle exec rake security:check_encryption_key`

### 8.2 `secret_key_base`

- Used for cookies and **encrypted session blobs** (`ARSESS1:…`, F-015)
- **Separate purpose** from `ENCRYPTION_KEY`
- Lab: may be ephemeral under container `tmp/` across recreate — **production must persist** (volume or secret mount)
- Rotating `secret_key_base` invalidates encrypted sessions (users re-login)

### 8.3 Permissions and backup

- Mode `600` files; exclude from git
- Backup keys with the same protection class as DB backups
- Document key custodian; dual-control where required (**ASSUMED** org process)

### 8.4 Legacy plaintext remediation

`rake security:encrypt_legacy_secrets` (dry-run default) — requires backup path confirmation. Never rotate the key merely to encrypt existing rows.

---

## 9. Application deployment

> Commands below match repository Compose files. Adapt hostnames and secrets for production. **Do not** treat lab passwords as production values.

### 9.1 Obtain verified source / image

```bash
git clone <your-remote-url> foreman
cd foreman
git checkout security-hardening-5.0
git rev-parse HEAD   # record in change ticket
docker compose build app
docker images --digests "${FOREMAN_IMAGE:-foreman-local:security-hardening-5.0}"
```

Require tracked `Gemfile.lock` (frozen bundle in Dockerfile).

### 9.2 Configure environment

```bash
cp .env.example .env
# Set strong POSTGRES_PASSWORD, DATABASE_URL, ENCRYPTION_KEY
# Production: FOREMAN_REQUIRE_SSL=true (or unset opt-out)
# Pin redis image tags in an override file (recommended)
```

### 9.3 Initialize database

```bash
docker compose up -d db redis-cache redis-tasks
docker compose run --rm --no-deps app bundle exec rake db:migrate
docker compose up -d app orchestrator worker
# After first healthy boot (settings registry loaded):
docker compose exec app bundle exec rake db:seed
# Capture one-time admin password from logs if SEED_ADMIN_PASSWORD unset
```

### 9.4 Optional overlays

```bash
# Security collector (lab / verification)
docker compose -f docker-compose.yml -f docker-compose.logging.yml up -d security-collector app

# VNC ports (lab only unless firewalled)
docker compose -f docker-compose.yml -f docker-compose.vnc.yml up -d app
```

### 9.5 Health

```bash
docker compose ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:${FOREMAN_HTTP_PORT:-3000}/users/login
# Production: use https://<FOREMAN_FQDN>/users/login and expect 200
```

---

## 10. Logging and auditing

| Mechanism | Role | Independence |
|-----------|------|--------------|
| Foreman **Audit** UI / `audits` table | Config change history | App DB — mutable by app credentials |
| `Foreman::SecurityEvent` | Structured security telemetry | Local logs + optional forwarder |
| F-041 forwarder | TCP/UDP JSON lines | `FOREMAN_SECURITY_EVENTS_*` |
| F-042 collector | Append-only UID 1500 store + hash chain | Volume not mounted on app |
| Rails / Puma stdout | Operational logs | Host/container logging driver |

Event categories include: `ACCOUNT_LOCKOUT`, `CSRF_REJECTED`, `AUTHORIZATION_DENIED`, `SECURITY_CONTROL_REJECTED`, `HTTP_RATE_LIMIT_*`, `REAUTH_*`, etc.

Docs: `docs/security/centralized-security-events.md`, `tamper-resistant-audit-storage.md`, `account-lockout-events.md`, `security-rejection-events.md`.

**Retention:** collector `SECURITY_COLLECTOR_RETENTION_DAYS` (default 90) for rotated files; org SIEM retention **ASSUMED**.

---

## 11. Backup and recovery

### 11.1 What to back up

1. PostgreSQL (`pg_dump` or volume snapshot)
2. `ENCRYPTION_KEY` / key file
3. Persisted `secret_key_base`
4. Redis tasks volume (Dynflow) if in-flight automation must survive
5. Security-events volume / SIEM export
6. TLS private keys (proxy)
7. Compose/env overlays (without secret values in git)

### 11.2 Backup verification

Restore dump to an isolated instance; boot app with **same** encryption keys; smoke-test login + one encrypted resource (e.g. compute/LDAP) without printing secrets.

### 11.3 Recovery sequence (high level)

1. Restore DB to known-good backup  
2. Restore encryption + `secret_key_base`  
3. Start Redis → migrate if needed → app/workers  
4. Verify `rake security:check_encryption_key`  
5. Verify login, Settings, collector health  
6. Invalidate sessions if key material changed (`sessions` table)

### 11.4 Access control

Only break-glass roles may read backup media; encrypt backups; log restore operations.

---

## 12. Rollback

### 12.1 Pre-deployment snapshot

Record: git SHA, image digest, `pg_dump`, key material escrow, Settings export (non-secret).

### 12.2 Image rollback

Redeploy previous image digest; keep DB compatible.

### 12.3 Schema / migrations

Treat migrations as potentially **irreversible**. Prefer restore-from-backup over `db:rollback` unless a tested down migration exists for the specific change.

### 12.4 Encrypted session serializer (F-015) — special care

| Change | Effect |
|--------|--------|
| Upgrade to encrypted sessions | Legacy Marshal rows still **read**; next write upgrades to `ARSESS1:` |
| Rollback app **before** F-015 while DB has only `ARSESS1:` rows | Old serializer may not read ciphertext → mass logout / errors |
| Rotate `secret_key_base` | All encrypted sessions invalid |

**Safe decision point:** before production cutover, confirm rollback image can read session format present in DB, or plan to `TRUNCATE sessions` / delete session rows during rollback.

### 12.5 Encryption key

Never “roll forward” with a new `ENCRYPTION_KEY` without a decrypt/re-encrypt plan. Rollback must use the key that matches ciphertext.

---

## 13. Production validation checklist

Mark each item with evidence (ticket ID / screenshot / log excerpt). **Do not invent results.**

| # | Control | Procedure (summary) | Status |
|---|---------|---------------------|--------|
| 1 | TLS / hostname | HTTPS to FQDN; cert chain valid; HTTP redirects | ☐ |
| 2 | `require_ssl` | `SETTINGS[:require_ssl] == true` | ☐ |
| 3 | CAPTCHA | Enable; failed CAPTCHA blocks login; no lockout increment | ☐ |
| 4 | Password policy | Aging/history/hash per Settings; change password flow | ☐ |
| 5 | Forced password change | Flag / expiration gates | ☐ |
| 6 | Account lockout | Threshold → one `ACCOUNT_LOCKOUT` event; valid PW denied while locked | ☐ |
| 7 | Reauthentication | Sensitive action prompts; window respected | ☐ |
| 8 | Session terminate | Admin terminate + self logout | ☐ |
| 9 | Concurrent browser session | Second login invalidates first | ☐ |
| 10 | JWT / PAT | Invalidate JWT; PAT independent of password lockout | ☐ |
| 11 | Encryption at rest | `security:check_encryption_key`; secret write fails without key | ☐ |
| 12 | Userdata / unattended | Auth filters; no CSRF on intentional skips | ☐ |
| 13 | Private key export | Reauth + passphrase POST path | ☐ |
| 14 | VNC | Reauth settings; WS encrypt when SSL on | ☐ |
| 15 | Security logging | CSRF/authz/lockout events in logs/collector | ☐ |
| 16 | Rate limits | 429 under burst; independent of lockout | ☐ |
| 17 | Body limits | 413 on oversized body | ☐ |
| 18 | Backup/restore | Restore drill succeeded | ☐ |

---

## 14. Operational monitoring

| Signal | Where |
|--------|-------|
| App health | Compose healthcheck `nc -z 127.0.0.1 3000`; login HTTP(S) probe |
| Postgres connections | `pg_stat_activity` vs budget |
| Puma | Workers/threads env; request queue latency |
| Redis | Cache + tasks ping; AOF disk |
| Collector | Container health; `/verify` hash chain (exec); forwarder `failed`/`dropped` |
| Certificates | Expiry monitoring (**ASSUMED**) |
| Security | Spike in `ACCOUNT_LOCKOUT`, `CSRF_REJECTED`, `HTTP_RATE_LIMIT_EXCEEDED` |
| Disk | DB / Redis / security-events volumes |

---

## 15. Acceptance and signoff

| Item | Value |
|------|--------|
| Application test evidence | _Attach org evidence_ |
| Infrastructure test evidence | _Attach org evidence_ |
| Known limitations | See §16 |
| Residual risks | See threat model / matrix |
| Application owner | _Name_ |
| Security reviewer | _Name_ |
| Acceptance date | _YYYY-MM-DD_ |
| **Production approval status** | **NOT APPROVED IN THIS REPOSITORY** — pending org signoff |

---

## 16. Deployment security baseline matrix

| Component | Control | Expected (prod) | Lab actual | Prod requirement | Verification | Status | Role |
|-----------|---------|-----------------|------------|------------------|--------------|--------|------|
| Host publish | Bind address | Restricted | `127.0.0.1:3000` | No public raw Puma without TLS proxy | `docker compose ps` / firewall | LAB OK / PROD ASSUMED | Platform |
| TLS | HTTPS | Enforced | `FOREMAN_REQUIRE_SSL=false` | `true` + valid certs | `SETTINGS[:require_ssl]`; browser | LAB intentionally off | App + Platform |
| DB creds | Unique strong | Required | `foreman`/`foreman` | Replace defaults | Attempt login with lab creds must fail in prod | LAB only | DBA |
| DB privilege | Least privilege | Non-superuser | Lab Superuser observed | Restrict | `\du` / grants | RESIDUAL in lab pattern | DBA |
| AR pool | ≥ threads/c | pool=5, threads=5, sidekiq 5 | Aligned | Keep formula | Env + `connection_pool.size` | LAB OK | App |
| Redis | Pinned tag + auth if exposed | Pin + network isolate | Floating `redis` tag, no auth | Pin; do not expose | Compose override | LAB weak | Platform |
| Encryption | Key present | Required | Operator-dependent | Required + backup | `rake security:check_encryption_key` | DEPLOYMENT | App |
| Sessions | Encrypted AR | F-015 on | On when key_base present | Persist key_base | Session row prefix `ARSESS1:` | CODE | App |
| Tmp/cache lifecycle | Bounded cleanup | Redis + orphan/FileStore policy (F-020) | Redis active; FileStore empty | Prefer Redis; cron `tmp:cache_lifecycle` | `docs/temp-cache-lifecycle.md` | CODE | App |
| Runtime PID/state/sockets | Liveness-checked cleanup | Entrypoint + Puma harden (F-021) | Compose (no Systemd) | Safe prestart; no blind rm | `docs/runtime-state-lifecycle.md` | CODE | App |
| FIPS / approved crypto | Validated module + policy | Assessment only (F-024) | OpenSSL 3; FIPS provider installed, **inactive**; `fips_mode=false` | Do not claim FIPS without module+policy | `docs/fips-cryptography-assessment.md` | ASSESS | App + Platform |
| Security log severity | Six structured levels | F-030 severity on SecurityEvent | NOTICE/ALERT via payload fields | Search collector by `severity` | `docs/security-logging-severity.md` | CODE | App |
| Security event taxonomy | Category + classification | F-031 Taxonomy policy | Proposed (not org-approved) | Search `event_category` / `data_classification` | `docs/security-event-taxonomy.md` | CODE | App |
| Production source maps | Not publicly served | F-038 webpack+middleware+image strip | Maps were HTTP 200 | `*.map` → 404; UI loads | `docs/production-source-maps.md` | CODE | App |
| Source distribution | No public `.rb`; no Ruby obfuscation | F-039 assessment + slim image | GPL Rails source in image | HTTP `.rb` 404; registry ACL **ASSUMED** | `docs/source-code-protection.md` | ASSESS+CODE | App + Platform |
| DB access model | ORM + least-privilege roles (not SP-only) | F-014 ADR + privilege inventory | Lab `foreman` **SUPERUSER**; 0 app routines | Split migrator/app roles; `rake security:check_database_privileges` | `docs/security/adr-stored-procedures-vs-orm.md` | ASSESS | App + DBA |
| Load priority under classification | Org SLO → queue/proxy shaping | F-029 policy (no speculative scheduler) | F-026/027/028 + equal Sidekiq weights | Approve availability tiers; then tune queues/proxy | `docs/load-management-policy.md` | POLICY | App + Platform |
| Digital signatures | PKCS#7 detached on CSV export | F-032 service + optional `digital_signature=1` | Lab needs signing key/cert files | Provision org signing cert; never reuse ENCRYPTION_KEY | `docs/digital-signatures.md` | CODE | App + PKI |
| Collector | Independent store | Enabled to SIEM | Optional overlay | Enable or SIEM drain | Collector events / SIEM | F-041/042 LAB | SecOps |
| CAPTCHA | On for public UI | Policy | Default off | Enable if exposed | Setting + login test | DEPLOYMENT | App |
| Rate limit | On | Default on | Setting seed-dependent | On; consider fail-closed | 429 test | CODE | App |
| Body limit | 2–10 MiB | Enforced | Enforced in image | Proxy + app | 413 test | CODE | App |
| VNC ports | Firewalled | Optional overlay loopback | Do not expose publicly | Port scan | LAB optional | Platform |
| Audits DB | Immutable? | No — operational | Mutable | Use collector/SIEM | F-042 | RESIDUAL | SecOps |

---

## 17. Operations playbooks (no live secrets)

### 17.1 New user onboarding

Create user with least privilege roles; force password change if policy requires; confirm login history entry.

### 17.2 Password reset

Admin or self-service per org process; respects `password_history_length` / complexity; clears lockout on successful password change paths already implemented for local users.

### 17.3 Account unlock

Wait for `account_lockout_duration`, or admin clears lockout state via successful admin unlock workflows / `reset_failed_login_state!` equivalent in support tooling — prefer documented UI/admin actions; do not invent SQL updates without change control.

### 17.4 Forced password renewal

Set `password_max_age` > 0; users hit renewal gate.

### 17.5 Session termination

UI: terminate user session / terminate all; emits `SESSION_TERMINATE*` SecurityEvents when used.

### 17.6 JWT / PAT

Invalidate registration JWTs via user actions (reauth gated); revoke PATs; PAT auth does not clear password lockout.

### 17.7 Lost encryption key

Treat as major incident: restore key from escrow or restore DB from pre-encryption backup; without key, ciphertext is unrecoverable.

### 17.8 Suspicious events

Query collector/SIEM by `event_id`, `actor`, `client_ip`, `request_id`; preserve evidence; do not delete collector volume.

### 17.9 Backup restoration

Follow §11; validate on isolated project name (`COMPOSE_PROJECT_NAME=…`) before production.

### 17.10 Controlled image upgrade

Build → staging migrate → validation checklist → production; record digests.

### 17.11 Rollback after failed validation

Restore previous image + DB snapshot; heed F-015 session format (§12.4).

### 17.12 Incident escalation

App owner → security reviewer → platform/DBA; include request IDs from SecurityEvents.

---

## 18. Known limitations and residual risks

1. **Production deployment not executed** in this task — lab Compose only.  
2. Lab HTTP without TLS is intentional; production must not copy `FOREMAN_REQUIRE_SSL=false`.  
3. Lab DB role privileges are not a production IAM model.  
4. Floating Redis image tag and unauthenticated Redis on Compose network.  
5. `secret_key_base` persistence must be explicitly engineered for containers.  
6. GraphQL field-level authorization is not fully mirrored as `AUTHORIZATION_DENIED` events (F-044 limitation).  
7. Host root / volume admins can still alter collector storage without external WORM/SIEM.  
8. Full ELK/SIEM and enterprise reverse-proxy configs are **ASSUMED**.

---

## 19. References (repository)

| Document | Topic |
|----------|--------|
| `docs/docker-local.md` | Lab bring-up |
| `docs/connection-capacity.md` | Puma / pool / PG budget |
| `docs/encryption-key.md` | ENCRYPTION_KEY |
| `docs/session-encryption.md` | F-015 |
| `docs/fips-cryptography-assessment.md` | F-024 |
| `docs/http-rate-limiting.md` | F-026 |
| `docs/http-request-body-limits.md` | F-028 |
| `docs/browser-session-policy.md` | Concurrent sessions |
| `docs/security/threat-model.md` | STRIDE |
| `docs/security/threat-control-matrix.md` | Control mapping |
| `docs/security/centralized-security-events.md` | F-041 |
| `docs/security/tamper-resistant-audit-storage.md` | F-042 |
| `docs/security/account-lockout-events.md` | F-043 |
| `docs/security/security-rejection-events.md` | F-044 |
| `docs/security/dependency-scanning.md` | F-037 SCA |

---

*End of runbook.*
