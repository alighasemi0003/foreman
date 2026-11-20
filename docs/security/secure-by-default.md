# Secure-by-default first-boot initialization (Foreman 5.0)

## Goal

A fresh Foreman install with an empty database initializes with the approved
security controls already active. Operators must not need to visit
Administer → Settings to turn on CAPTCHA, password aging, idle timeout, export
classification, or related supported protections.

## Code defaults (SettingManager)

| Setting | New default |
| --- | --- |
| `captcha_enabled` | `true` |
| `password_max_age` | `90` (days) |
| `idle_timeout` | `30` (minutes) |
| `http_rate_limit_fail_closed` | `true` |
| `password_history_length` | `5` (unchanged) |
| `login_history_limit` | `20` (unchanged) |
| `account_lockout_*` | 5 / 15 / 30 (unchanged) |
| `http_rate_limit_enabled` | `true` (unchanged) |
| `output_classification_enabled` | `true` (unchanged) |
| `require_reauth_*` | `true` (unchanged) |

Always-on (no Setting toggle):

- Mandatory first-login password change for new INTERNAL users
- Login responsibility notice (`session[:show_login_responsibility]`)
- Concurrent browser session newer-login-wins
- Encrypted ARSESS1 sessions / FSC1 cookies (when ENCRYPTION_KEY present)
- Source-map blocking / runtime cleanup

## First-install persistence

`db/seeds.d/015-secure_defaults.rb` calls `Foreman::SecureDefaults.apply_first_install!` when:

1. `FOREMAN_APPLY_SECURE_DEFAULTS` is not `false`/`skip`
2. Baseline marker `security_hardening_baseline` is not already `5.0-secure`
3. No interactive admin users exist yet (genuine empty DB)

It persists baseline values and sets `security_hardening_baseline=5.0-secure`.

Existing databases with admins are **not** modified on seed/restart.

## Existing installations

```bash
# Dry-run
bundle exec rake security:secure_defaults

# Apply (upgrades legacy insecure values; skips customized non-legacy values)
bundle exec rake security:secure_defaults APPLY=1

# Overwrite customized values too
bundle exec rake security:secure_defaults APPLY=1 FORCE=1
```

## Docker

- Lab HTTP: `FOREMAN_REQUIRE_SSL=false` (explicit; not production-safe)
- Production: `FOREMAN_REQUIRE_SSL=true` behind TLS
- Fresh secure profile: `docker-compose.secure-fresh.yml` (+ optional `docker-compose.logging.yml`)
- Redis cache is a hard dependency when fail-closed rate limiting is enabled

## Infrastructure-dependent controls

| Control | Default posture | Prerequisite |
| --- | --- | --- |
| HTTPS | Production required | TLS proxy / certs |
| Rate-limit fail-closed | Enabled | Healthy Redis cache |
| Security collector | Enabled when composed | `docker-compose.logging.yml` + URL |
| Digital signing | Off until keys provided | `FOREMAN_SIGNING_*` files |
| VNC gateway | Present in image | Hypervisor + console workflow |
| Provisioning tokens | Prefer token-bound flows | Template/workflow support |
