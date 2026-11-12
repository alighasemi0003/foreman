# Security rejection events (F-044)

Audit requirement **82** (چک‌لیست امنیتی، صفحه ۵۹).

## Gap

CSRF failures, authorization denials, and some security-control rejections were ordinary text / exception logs without a consistent structured `SecurityEvent` category.

## Event categories

| Event | Meaning | Typical reason_code |
|-------|---------|---------------------|
| `CSRF_REJECTED` | Request forgery protection failed | `invalid_authenticity_token` |
| `AUTHORIZATION_DENIED` | Authenticated (or session) principal lacked permission | `permission_denied`, `forbidden`, `admin_required` |
| `SECURITY_CONTROL_REJECTED` | Explicit control blocked the request | `unsafe_http_method` |

Ordinary authorization denial is **not** labeled as proven malice. No `SECURITY_TAMPERING_SUSPECTED` is emitted from generic 403/CSRF alone.

## Emission points

- `ApplicationController#handle_unverified_request` / `deny_access` / `render_403`
- `Api::BaseController#handle_unverified_request` / `deny_access` / `require_admin`
- `Api::GraphqlController#handle_unverified_request` (session CSRF when applicable)
- `Foreman::Middleware::RejectUnsafeHttpMethods` (HTTP 405)

At most **one** rejection security event per request (`@_foreman_security_rejection_emitted`).

## Schema (safe fields)

Via `Foreman::SecurityEvent` / F-041 payload: timestamp, event id, status `DENIED`, actor (if logged-in), target `controller#action`, IP, request id, operation, reason_code, details with `control`, `http_status`, `method`, path (sanitized).

**Never logged:** CSRF token values, passwords, cookies/session ids, JWT/PAT, Authorization headers, raw bodies, CAPTCHA solutions.

## Flood policy

- Every rejection may emit one bounded log/forwarder event (no silent drop).
- Metadata is truncated/sanitized; no DB insert per rejection.
- High-volume abusive traffic is primarily constrained by **F-026** HTTP rate limiting and IP bruteforce controls.
- Collector-side sampling remains an operations option; application does not invent “confirmed attack” floods.

## GraphQL

Session CSRF for GraphQL is covered when forgery protection applies. Fine-grained GraphQL field authorization errors remain GraphQL error payloads and are **not** duplicated as `AUTHORIZATION_DENIED` in this task.
