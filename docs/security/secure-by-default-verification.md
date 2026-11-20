# Secure-by-default verification record

| Field | Value |
| --- | --- |
| Branch | `security-hardening-5.0` |
| Starting HEAD | `b1aa500ee6e5ce2785ed82477b41b61162f00d93` |
| Implementation commit | `69d1bf4f0` |
| Final HEAD (image tag) | `4f548f84c` |
| New image | `foreman-local:security-hardening-5.0-4f548f84c` (`3135e6189dad`, ~741MB) |
| Prior image preserved | `foreman-local:security-hardening-5.0-54be8f4fd` |
| Fresh project | `foreman50-secure-fresh` (`:33001`) |
| Push | **NO** |
| docker cp | **No** |

## Fresh-install effective Settings

| Setting | Value |
| --- | --- |
| captcha_enabled | true |
| password_max_age | 90 |
| idle_timeout | 30 |
| password_history_length | 5 |
| login_history_limit | 20 |
| account_lockout_attempts/window/duration | 5 / 15 / 30 |
| http_rate_limit_enabled | true |
| http_rate_limit_fail_closed | true |
| output_classification_enabled | true |
| require_reauth_users_create | true |
| security_hardening_baseline | 5.0-secure |
| FOREMAN_SECURITY_EVENTS_ENABLED | true (with logging overlay) |

## Runtime checks

| Test | Result |
| --- | --- |
| Seed `015-secure_defaults` applied on empty DB | PASS |
| Login page CAPTCHA challenge | PASS |
| Wrong CAPTCHA rejected | PASS |
| Correct CAPTCHA + credentials | PASS |
| FSC1 encrypted cookie | PASS |
| Source-map blocked | PASS |
| Restart preserves Settings | PASS |
| Recreate preserves Settings + admin | PASS |

## Notes

- Lab HTTP: `FOREMAN_REQUIRE_SSL=false` (explicit).
- Collector host port omitted via `docker-compose.secure-fresh-logging.yml` (Docker Desktop port forward conflicts); collector reachable on compose network.
- `.env` passwords must not contain `#` (comment truncation).
- Existing DBs are not auto-overwritten; use `rake security:secure_defaults APPLY=1`.
