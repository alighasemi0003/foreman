# Centralized security event collection (F-041)

Audit requirement **80** (چک‌لیست امنیتی، صفحات ۵۶–۵۷).

## Audit gap addressed

| Finding | Response |
|---------|----------|
| Internal Audit viewer only / logs on app server | Keep Audit + `SecurityEvent`; **add** structured forwarder |
| Syslog/ELK example commented in `settings.yaml.example` | Optional JSON/syslog still supported natively; lab uses dedicated TCP collector |
| No demonstrated central forwarding | Lab collector receives real JSON events (see verification) |
| Storage not independent of app runtime | Collector has its own Docker volume `security-events` |
| Tamper resistance (F-042) | Collector UID 1500, append-only + hash chain — see `tamper-resistant-audit-storage.md` |

F-043 / F-044 event categories (if not yet on branch): treated as **pending**, not invented.

## Architecture

```
Foreman SecurityEvent.log
  ├─ local Rails logger (existing; app volume / stdout)
  └─ Payload (JSON schema) → Forwarder (async queue)
         └─ TCP/UDP → security-collector (separate container + volume)
```

- **Transport:** `tcp://security-collector:1514` (lab default) or `udp://…`
- **Delivery:** **at-most-once** / best-effort to the collector (bounded queue; drops on overflow or send failure)
- **Local Audit / Rails logs:** unchanged (still available on the app host)
- **Request path:** never blocked on collector I/O (background thread + short timeouts)

## Event schema (JSON line)

| Field | Description |
|-------|-------------|
| `ts` | UTC ISO-8601 |
| `event_type` | always `security` |
| `event_id` | e.g. `REAUTH_SUCCESS`, `HTTP_RATE_LIMIT_EXCEEDED` |
| `status` | SUCCESS / FAILURE / DENIED / … |
| `actor` | sanitized login |
| `actor_id` | optional numeric id |
| `target` | sanitized resource |
| `client_ip` | from arg or Logging MDC |
| `request_id` | correlation id from MDC |
| `operation` | optional action key |
| `reason_code` | optional safe code |
| `source_service` | `foreman` |
| `environment` | Rails.env |
| `app_version` | `Foreman::Version` |
| `details` | sanitized + secret scrub |

**Never logged:** passwords, JWT/PAT, session cookies/ids, CAPTCHA answers, encryption/private keys, full sensitive bodies.

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `FOREMAN_SECURITY_EVENTS_ENABLED` | `false` | Master switch |
| `FOREMAN_SECURITY_EVENTS_URL` | — | `tcp://host:port` or `udp://host:port` |
| `FOREMAN_SECURITY_EVENTS_QUEUE` | `1000` | Bounded in-memory queue |
| `FOREMAN_SECURITY_EVENTS_CONNECT_TIMEOUT` | `1.0` | seconds |
| `FOREMAN_SECURITY_EVENTS_WRITE_TIMEOUT` | `1.0` | seconds |

Production may instead (or also) enable JSON syslog via `settings.yaml` (`:type: syslog`, `:layout: json`) into an org collector — placeholders only; do not commit credentials.

### Lab Compose

```bash
docker compose -f docker-compose.yml -f docker-compose.logging.yml up -d security-collector
# Restart app so ENV + code are active (docker cp code if image not rebuilt):
docker compose -f docker-compose.yml -f docker-compose.logging.yml up -d app
```

Disable test forwarding without touching Audit DB:

```bash
FOREMAN_SECURITY_EVENTS_ENABLED=false
```

## Verify delivery

```bash
# Emit synthetic events inside the app container
docker compose exec app bundle exec rails runner '
  Foreman::SecurityEvent.log(event: "REAUTH_SUCCESS", status: "SUCCESS", actor: "synth-admin",
    details: "password=SHOULD_NOT_APPEAR token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb")
'

# Read collector store (independent volume)
docker compose -f docker-compose.yml -f docker-compose.logging.yml \
  exec security-collector cat /data/events.jsonl | tail
docker compose -f docker-compose.yml -f docker-compose.logging.yml \
  exec security-collector cat /data/stats.json
```

Search by request id / actor / time: filter JSON lines (`jq 'select(.request_id=="…")'`).

## Failure policy

| Condition | Behavior |
|-----------|----------|
| Collector down | Events dropped after timeout; app continues; `failed` counter increments |
| Queue full | Drop newest enqueue (`dropped`); app continues |
| Parse error at collector | Recorded in `/data/parse_errors.jsonl` |
| Alerting | Operator watches collector `stats.json` / container health (lab); production SIEM alerts **ASSUMED** |

## Event categories (current branch)

Delivered when emitted by application code: REAUTH_*, `ACCOUNT_LOCKOUT` (F-043), `CSRF_REJECTED` / `AUTHORIZATION_DENIED` / `SECURITY_CONTROL_REJECTED` (F-044), HTTP_RATE_LIMIT_*, HTTP_BODY_TOO_LARGE, host info export, JWT/registration invalidation paths, session terminate hooks that already call `SecurityEvent.log`.

Login success/failure remain primarily in **Audit** / login_events (by design); SecurityEvent does not replace them.

### ACCOUNT_LOCKOUT (F-043)

Emitted once from `UserAccountLockout#register_failed_login!` when an internal user transitions unlocked → locked (`reason_code=failed_password_threshold`). Target is the locked account login; actor is omitted for anonymous failed-password attempts. Compatible with the F-041 forwarder. Search local logs / collector by `event_id=ACCOUNT_LOCKOUT`, `target`, `client_ip`, `request_id`, time.

## Limitations

- Not exactly-once; duplicates possible if operators replay queues (we do not).
- TLS to collector not enabled in lab TCP receiver — use private network / mesh TLS in production (**ASSUMED**).
- Full ELK not deployed; Python collector proves transport + schema + isolation.
