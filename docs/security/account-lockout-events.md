# Account lockout security events (F-043)

Audit requirement **82** (چک‌لیست امنیتی، صفحات ۵۸–۵۹).

## Gap

Account lockout is enforced (`failed_login_attempts` / `locked_until`), but those columns are excluded from ordinary User Audits. The audit required a dedicated structured event for the **transition into lockout**, with target user and reason.

## Event

| Field | Value |
|-------|--------|
| `event` / `event_id` | `ACCOUNT_LOCKOUT` |
| `status` | `LOCKED` |
| `target` | Locked user login |
| `actor` | Omitted (anonymous failed-password path; target ≠ attacker identity) |
| `reason_code` | `failed_password_threshold` |
| `operation` | `account.lockout` |
| `details` | `user_id`, `attempts`, `limit`, `duration_minutes`, `locked_until` (UTC), `source=UserAccountLockout` |
| IP / request_id | From Logging MDC when present (F-041 schema) |

No passwords, hashes, CAPTCHA answers, JWT, or session cookies.

## Emission point

`UserAccountLockout#register_failed_login!` after a successful `update_columns` that newly sets `locked_until`.

- Below threshold → no event
- Already locked → early return → no duplicate event
- Logging/forwarding errors are swallowed; lockout enforcement is unchanged

## Search

Authorized reviewers: Rails security logs / F-041 collector JSON (`event_id=ACCOUNT_LOCKOUT`). Foreman Audit UI does not list these lockout field changes (still ignored on User).
