# HTTP / API rate limiting (F-026)

## Enforcement layer

Rails middleware `Foreman::Middleware::HttpRateLimit` after
`ActionDispatch::RemoteIp`, using **Rails.cache** counters.

| Deploy | Shared state |
|--------|----------------|
| Compose / prod with Redis cache | Yes — all Puma workers and app replicas |
| File cache | Per-node only (not cross-host) |
| Test `memory_store` | Per-process |

This does **not** replace reverse-proxy limits. It protects the Rails app when
requests reach Puma. Account lockout, CAPTCHA, and IP bruteforce
(`failed_login_attempts_limit`) remain independent.

## Client identity

- Key: `request.remote_ip` only (trusted_proxies aware).
- **Never** username, password, Authorization header, or PAT plaintext.
- Forged `X-Forwarded-For` from untrusted clients does not replace the client IP
  when `trusted_proxies` is configured correctly (default: loopback).

Shared NAT: one office IP shares one bucket — thresholds are sized accordingly.

## Endpoint policy (defaults)

| Category | Paths (examples) | Limit / period |
|----------|------------------|----------------|
| **login** | `POST /users/login`, extlogin, reauthenticate | 20 / 60s |
| **captcha** | `GET /users/captcha_challenge` | 30 / 60s |
| **graphql** | `POST /api/graphql` | 60 / 60s |
| **api** | `/api/*` (except graphql/ping) | 300 / 60s |
| **unattended** | `/unattended/*`, `/userdata/*` | 180 / 60s |
| **general** | Other UI HTML | 600 / 60s |
| **exempt** | `/assets`, `/webpack`, `/packs`, `/status`, `/api/ping`, `/api/statuses` | none |

Burst capacity equals the per-period limit (fixed window). Tunable via Settings.

Smart Proxy / facts / reports use the **api** bucket (no global IP bypass).
`restrict_registered_smart_proxies` and body-size limits still apply.

## Exceeded limit

- HTTP **429**
- `Retry-After` (seconds until window ends)
- `Cache-Control: no-store`
- Generic JSON/text body (no secrets)
- SecurityEvent `HTTP_RATE_LIMIT_EXCEEDED`

## Cache failure policy

| Setting | Behavior |
|---------|----------|
| `http_rate_limit_fail_closed` = **false** (default) | Fail **open**; log `HTTP_RATE_LIMIT_FAIL_OPEN` |
| `true` | Fail **closed** with 429 |

Choose fail-closed when availability of the limiter is preferred over availability
of the application under cache outage.
