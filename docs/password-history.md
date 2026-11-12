# Local password history (F-009)

## Policy

| Setting | Type | Default | Range |
| --- | --- | --- | --- |
| `password_history_length` | integer | `5` | `0`–`24` |

Semantics for **N** = `password_history_length`:

- **N** is the maximum number of *previous* password verification records retained
  and checked against a candidate password.
- The **current** password is always rejected by the existing
  `ensure_new_password_differs_from_current` check, even when **N = 0**.
- **N = 0** disables historical checking and prunes stored history on the next
  successful local password change.
- Changing **N** takes effect without restart (Settings registry reload).
- Increasing **N** keeps already-stored prior records (up to the new limit).
- Decreasing **N** drops oldest excess records on the next successful password
  update (storage is not re-expanded retrospectively beyond what was kept).

Applies only to locally managed (`AuthSourceInternal` / `manage_password?`)
users. LDAP / external / SSO accounts are unaffected.

## Storage

Table `user_password_histories`:

- `user_id` (FK, cascade delete)
- `password_hash` / `password_salt` — same material as `users`, verified via
  `Foreman::PasswordHash` (bcrypt / PBKDF2 / SHA1 as encoded in the salt)
- `created_at`

Never stores plaintext, reversible ciphertext, or logs passwords.

## Password-change flow

1. Complexity validation  
2. Current-password reuse rejection (exact hash match)  
3. Minimum edit-distance ≥ 4 when `current_password` is present (F-008)  
4. Historical reuse rejection (last **N** records)  
5. On success (same DB transaction): archive outgoing hash+salt, update current
    password / `password_changed_at`, prune to **N**

Covered paths: self-service change, forced / expired renewal, administrator
reset, API user update — all go through `User` save callbacks.

Hash algorithm upgrades on login (`upgrade_password` / `update_columns`) do not
append history (same secret, new encoding only).
