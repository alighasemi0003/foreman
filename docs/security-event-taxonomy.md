# Security event taxonomy and classification-aware logging (F-031)

Audit requirement **66** (چک‌لیست امنیتی، صفحات ۴۹–۵۰).

## Audit finding

No documented mapping existed between information sensitivity/classification,
logging severity, security-event categories, and required audit behavior.

## Status of organizational approval

**None supplied.** Labels and mappings below are a **proposed technical policy**
aligned with F-013 output classification names and F-030 severity. They are
**not** claimed as an organizationally approved standard.

## Three distinct concepts

| Concept | Field(s) | Meaning |
| --- | --- | --- |
| **Event severity** | `severity`, `severity_syslog`, `severity_rails` | Urgency (F-030) |
| **Data classification** | `data_classification` | Sensitivity of typical metadata (F-013-aligned) |
| **Event outcome** | `status` | SUCCESS / FAILURE / DENIED / LOCKED / … |

Confidential metadata does **not** imply a critical incident. A collector
integrity failure can be CRITICAL with only `internal` classification.

## Classification scheme (proposed)

Same ladder as F-013: `public` < `internal` < `confidential` < `restricted`.

| Classification | Allowed destinations | Redaction | Notes |
| --- | --- | --- | --- |
| public | Rails log + collector | Standard secret scrub | Rare for security events |
| internal | Rails log + collector | Standard | Default for authz/authn metadata |
| confidential | Rails log + collector (prefer protected store) | Standard; no request bodies | Exports, JWT invalidate metadata |
| restricted | Prefer collector / protected store | Metadata only | Still **never** logs raw secrets |

**Prohibited at every level:** passwords, JWT/PAT values, session cookies/ids,
private keys, encryption keys, CAPTCHA answers, Authorization headers.

## Event categories

`authentication`, `authorization`, `account_password`, `session`, `data_access`,
`security_config`, `crypto_secret`, `security_control_rejection`, `availability`,
`audit_integrity`, `unknown`.

## Central policy

Implemented in `Foreman::SecurityEvent::Taxonomy` (`POLICY_ID=
foreman-security-taxonomy-proposed-v1`).

- Known `event_id` → category, default severity, classification, retention_days
- Unknown `event_id` → safe fallback (`unknown` / INFORMATIONAL / internal); **event still emitted**
- Payload always includes taxonomy fields for F-041 collector / F-042 storage
- Existing event IDs are **not** renamed

## Mapping table (selected events)

| Event ID | Category | Severity | Classification | Retention (days) | Outcome examples |
| --- | --- | --- | --- | --- | --- |
| ACCOUNT_LOCKOUT | account_password | WARNING | internal | 365 | LOCKED |
| CAPTCHA_FAILED | authentication | WARNING | internal | 90 | FAILURE |
| REAUTH_SUCCESS | authentication | NOTICE | internal | 365 | SUCCESS |
| REAUTH_FAILED | authentication | WARNING | internal | 365 | FAILURE |
| REAUTH_REQUIRED | authentication | INFORMATIONAL | internal | 90 | — |
| CSRF_REJECTED | security_control_rejection | WARNING | internal | 180 | DENIED |
| AUTHORIZATION_DENIED | authorization | WARNING | internal | 180 | DENIED |
| SECURITY_CONTROL_REJECTED | security_control_rejection | WARNING | internal | 180 | DENIED |
| HTTP_RATE_LIMIT_EXCEEDED | availability | WARNING | internal | 90 | DENIED |
| HTTP_BODY_TOO_LARGE | security_control_rejection | WARNING | internal | 90 | DENIED |
| SESSION_TERMINATE / _ALL | session | NOTICE | internal | 365 | SUCCESS |
| JWT_INVALIDATE* | crypto_secret | NOTICE | confidential | 365 | SUCCESS |
| HOST_INFO_EXPORT | data_access | NOTICE | confidential | 365 | SUCCESS |
| HOST_INHERITED_PARAMETERS_EXPORT | data_access | NOTICE | confidential | 365 | SUCCESS |
| COLLECTOR_INTEGRITY_FAILURE | audit_integrity | CRITICAL | internal | 730 | FAILURE |
| *(unknown)* | unknown | INFORMATIONAL | internal | 90 | — |

Full catalog: `Foreman::SecurityEvent::Taxonomy.catalog` or
`rake security:event_taxonomy` (if present).

## Required safe metadata

Where available after sanitize: `ts`, `event_id`, `status`, `severity`,
`event_category`, `data_classification`, `actor` / `actor_id`, `target`,
`client_ip`, `request_id`, `operation`, `reason_code`.

## Collector / storage

F-041 forwarder unchanged; new JSON keys are stored with hash-chain integrity
(F-042). Search examples:

```bash
jq 'select(.event_category=="authorization")' /data/events.jsonl
jq 'select(.data_classification=="confidential")' /data/events.jsonl
jq 'select(.severity=="WARNING" and .status=="DENIED")' /data/events.jsonl
```

## Links

- F-030 severities: `docs/security-logging-severity.md`
- F-041/F-042 ops: `docs/security/centralized-security-events.md`,
  `docs/security/tamper-resistant-audit-storage.md`
- F-013 labels: `Foreman::OutputClassification`
