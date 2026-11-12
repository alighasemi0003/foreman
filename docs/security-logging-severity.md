# Security logging severity levels (F-030)

Audit requirement **66** (چک‌لیست امنیتی، صفحات ۴۹–۵۰).

## Audit discrepancy

The checklist marks the control **PASS** while also stating that all six required
security logging levels were **not** demonstrated and that Notice/Alert (or
equivalent) semantics were missing. This task treats that as an open gap — not
as already satisfied.

The audit text does **not** name the six levels. No organizational severity
standard is in-repo. F-030 therefore defines an **explicit proposed mapping**
(Syslog-aligned). F-031 owns broader classification / taxonomy policy; this
document does not invent a certified standard.

## Actual application logger levels

| Source | Levels |
| --- | --- |
| `::Logging::LEVELS` (runtime) | `debug`, `info`, `warn`, `error`, `fatal` |
| Rails.logger methods | same five — **no** `notice` / `alert` / `crit` |
| Prior `SecurityEvent.log` | mostly `:info` / `:warn` only |

Ordinary Rails/Logging levels therefore cannot literally emit six distinct
logger method names. Severity is represented as a **structured field** on
security events, then mapped onto the closest Rails level for local logs.

## Required six-level definition (proposed)

| # | `severity` | Syslog # | Rails logger | Typical use |
| --- | --- | --- | --- | --- |
| 1 | `ALERT` | 1 | `fatal` | Immediate attention (rare; not used for normal auth failures) |
| 2 | `CRITICAL` | 2 | `error` | Security infrastructure / integrity failure |
| 3 | `ERROR` | 3 | `error` | Security-control error path |
| 4 | `WARNING` | 4 | `warn` | Denied/suspicious activity, lockout, rate limit |
| 5 | `NOTICE` | 5 | `info` | Significant expected security state change (reauth success, session terminate) |
| 6 | `INFORMATIONAL` | 6 | `info` | Routine security telemetry |

**Not** in the six: `DEBUG` (dev noise), `EMERGENCY` (folded into CRITICAL alias if passed).

### Orthogonal fields

| Field | Meaning |
| --- | --- |
| `severity` | Urgency of the security event (F-030) |
| `status` | Outcome: SUCCESS / FAILURE / DENIED / LOCKED / … |
| Rails `level` | Local log sink priority (derived or legacy override) |
| Data classification | **F-031 / F-013** — not this control |

Example: `AUTHORIZATION_DENIED` → `status=DENIED`, `severity=WARNING` (not CRITICAL).

## Implementation

- `Foreman::SecurityEvent::Severity` — canonical names + mappings
- `SecurityEvent.log(..., severity:)` — optional; defaults from event id or legacy `level:`
- F-041 payload fields: `severity`, `severity_syslog`, `severity_rails`
- Structured log MDC: `security_severity`
- **No** global Ruby Logger monkey-patch; unknown severity → `INFORMATIONAL`

### Default severity by event (conservative)

| Event | Default severity |
| --- | --- |
| `ACCOUNT_LOCKOUT` | WARNING |
| `CSRF_REJECTED` / `AUTHORIZATION_DENIED` / `SECURITY_CONTROL_REJECTED` | WARNING |
| `HTTP_RATE_LIMIT_*` / `HTTP_BODY_TOO_LARGE` | WARNING |
| `REAUTH_SUCCESS` / `SESSION_TERMINATE*` / JWT invalidate / exports | NOTICE |
| `REAUTH_FAILED` | WARNING |
| `REAUTH_REQUIRED` / `REAUTH_UNSUPPORTED` | INFORMATIONAL |
| Unlisted | INFORMATIONAL |

Callers may pass `severity:` explicitly for synthetic / elevated cases.

## Collector / SIEM

JSON lines already accepted by `security-collector` gain the new keys. Search:

```bash
jq 'select(.severity=="WARNING")' /data/events.jsonl
jq 'select(.severity_syslog <= 4)' /data/events.jsonl
```

Map `severity` or `severity_syslog` to SIEM severities downstream.

## Relation to F-031

F-031 defines classification and event taxonomy (`docs/security-event-taxonomy.md`).
Severity defaults for known events are sourced from `Taxonomy` when loaded.
F-030 ensures the six severity categories are representable, delivered, and searchable.
