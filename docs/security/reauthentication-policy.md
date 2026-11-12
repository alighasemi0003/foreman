# Administrator-managed re-authentication policy (F-011)

Audit requirement **27** (چک‌لیست امنیتی، صفحات ۲۶–۲۷).

## What already existed

- `ensure_reauthenticated!` on sensitive controller actions
- Session-bound freshness (`reauthenticated_at` + `reauth_actor_id`)
- Session regeneration after successful step-up
- Fail-secure defaults when settings cannot be read

## Administrator UI

**Administer → Settings → Re-authentication policy**

| Row type | Behavior |
| --- | --- |
| Re-authentication window (minutes) | Configurable (1–30); changing it always requires reauth |
| Mandatory operations | Shown as **read-only** / locked; cannot be disabled |
| Configurable operations | Boolean toggles; default **enabled** |

Changing any of these settings requires step-up reauthentication (`settings.reauthentication.update`).

Permission: `edit_settings` (administrator Settings access). Setting model changes remain audited.

## Closed server-side registry

`Foreman::Reauthentication::OPERATIONS` lists every supported operation:

- Stable key (e.g. `users.impersonate`)
- Human label and description
- Setting name (when toggleable)
- Mandatory vs configurable
- Default enabled

**Arbitrary controller names, URLs, Ruby constants, or user-supplied paths cannot be registered.** Unknown keys are never made executable through Settings. Unrestricted dynamic page registration is rejected because it would allow privilege-sensitive endpoints to be invented or bypassed without a code review.

## Mandatory operations (cannot disable)

| Operation key | Meaning |
| --- | --- |
| `settings.reauthentication.update` | Changing this policy / window |
| `settings.oauth_credentials.update` | Changing OAuth consumer key/secret |

Backend always treats these as enabled even if a setting row were corrupted.

## Configurable operations

All other registered keys (user lifecycle, auth sources, PATs, SSH keys, registration commands, key pairs, consoles) map to `require_reauth_*` booleans. Disabling a toggle removes only the **reauthentication** gate for that operation — authorization and CSRF remain unchanged.

## Backend enforcement

`Foreman::Reauthentication.policy_enabled?` / `required_for?` read the registry + Settings. Controllers call `ensure_reauthenticated!(action_key)`. JWT/PAT machine sessions are not interactive and are not gated by browser freshness.

Missing or erroneous configuration fails closed (reauth still required) for registered and unknown guard keys.
