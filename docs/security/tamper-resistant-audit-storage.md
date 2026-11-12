# Tamper-resistant audit storage (F-042)

Audit requirement **80** (چک‌لیست امنیتی، صفحات ۵۶–۵۷).

## Audit gap addressed

| Finding | Response |
|---------|----------|
| Read-only Audit UI ≠ immutability | UI remains read-only; **not** claimed as the control |
| App can write local logs | Accepted; local logs are operational only |
| Compromised process may alter local logs / DB audits | Protected destination is **outside** the Foreman UID and volume |
| No independent protected store demonstrated | F-041 collector hardened for F-042 append-only + hash chain |

## Existing storage (operational, not immutable)

| Store | Identity | UPDATE/DELETE by app? | Role |
|-------|----------|----------------------|------|
| `audits` PostgreSQL table | DB role `foreman` (lab: Superuser) | **Yes** (INSERT/UPDATE/DELETE granted) | Operational Audit UI |
| Rails log files under app | UID `1001` (`foreman`) | **Yes** (owner-writable) | Debug / local ops |
| SecurityEvent → Rails logger | same | **Yes** | Local telemetry |
| Collector volume `security-events` | UID `1500` (`auditcollector`) | **No** from Foreman UID | **Protected** security-event archive |

Foreman `audits_period` cleanup can delete old DB rows by design — treat DB audits as a **working copy**, not WORM storage. Forward security-relevant events to the collector (F-041).

## Threat model (summary)

| Threat | Control | Residual |
|--------|---------|----------|
| Compromised Foreman process (UID 1001) | No mount of `security-events`; cannot rewrite/delete collector files | May suppress **new** forwards (availability) |
| Compromised DB credentials | Can alter `audits` rows | Protected collector copy remains; reconcile via hash chain |
| Unauthorized Foreman admin | Can use Audit UI read + app config | Cannot mutate sealed collector files without host/collector privilege |
| Collector process compromise (UID 1500) | Can append; sealed rotated files are mode `0440` | Can append false events; hash chain detects **rewrites** of history if tip/backups compared |
| Host root / volume admin | Full control | **Out of scope** unless external WORM/SIEM (**ASSUMED** in production) |

Do **not** claim protection against a fully privileged storage/root administrator without an externally controlled WORM or SIEM trust boundary.

## Protected destination design

```
Foreman (UID 1001)
  └─ TCP append-only submit ──► security-collector (UID 1500)
                                   ├─ /data/events.jsonl          (O_APPEND, 0640)
                                   ├─ /data/events-*.jsonl        (sealed 0440 after rotate)
                                   ├─ /data/chain_tip.json
                                   └─ localhost HTTP GET /verify  (read-only)
```

Properties:

1. App can submit new events (TCP).
2. App cannot modify accepted historical events (no volume mount; wrong UID).
3. App cannot delete accepted historical events (same).
4. Storage owned by separate UID `1500`.
5. Access restricted: volume not on app; HTTP bound to `127.0.0.1` inside collector.
6. Retention: `SECURITY_COLLECTOR_RETENTION_DAYS` (default 90) applies to **rotated** `events-*.jsonl` only.
7. Reviewers: `GET /events`, `GET /verify` via `docker exec`, or host-side volume read by ops role.
8. Errors: `stats.json` / `parse_errors.jsonl` / forwarder `failed` counters (F-041).
9. Transport: private Docker network TCP; optional `SECURITY_COLLECTOR_HMAC_KEY` for HMAC (**placeholder** — do not commit secrets). TLS to SIEM **ASSUMED** in production.
10. Rotation renames + seals; does not rewrite prior bytes in sealed files.

## Integration with F-041

Same compose overlay `docker-compose.logging.yml`, same forwarder env vars. F-042 adds UID separation, append-only open, hash chain, sealed rotation, read-only HTTP, and negative tests.

## Operations

### Enable

```bash
docker compose -f docker-compose.yml -f docker-compose.logging.yml up -d security-collector app
```

### Verify integrity

```bash
docker compose exec security-collector python -c \
  "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/verify')))"
```

### Negative tests

```bash
bash extras/security-collector/negative_tests.sh
```

### Backup / recovery

- Backup volume `security-events` (or SIEM export) with an identity that is **not** the Foreman service account.
- Restore to a new collector volume; run `/verify`.
- Recovering Foreman DB does **not** rebuild the protected archive (and vice versa).

### Separation of duties

| Role | Allowed |
|------|---------|
| Foreman runtime | Submit events only |
| Collector runtime | Append + rotate/seal |
| Audit reviewer | Read/verify |
| Platform admin | Volume backup, retention config (documented residual risk) |

### Monitoring

Alert on: collector unhealthy, rising forwarder `failed`/`dropped`, `/verify` not `ok`, unexpected UID, disk full on `/data`.

## Production limitations / assumptions

- Lab collector is a demonstration trust boundary, not a full SIEM/WORM product.
- Replace or drain into org SIEM with independent IAM, TLS, and retention.
- PostgreSQL `audits` remains mutable by design under the app DB role — do not claim DB immutability.
- Root on the Docker host can still alter volumes — use external immutable object lock / SIEM if required by policy (**ASSUMED**).
