# Local password hashing (F-022)

## Approved policy

| Use | Algorithms |
| --- | --- |
| **New passwords / upgrades** | `bcrypt` (default) or `pbkdf2sha1` (PBKDF2-HMAC-SHA1) |
| **Legacy verification only** | Raw SHA-1 (`Digest::SHA1.hexdigest(password+salt)`) |

Raw SHA-1 is **not** selectable for new local password storage. If
`Setting[:password_hash]` is somehow still `sha1`, Foreman falls back to
`bcrypt` for create/upgrade and logs a warning.

LDAP / external / SSO passwords are verified by the provider — Foreman does not
hash them.

This is separate from EncryptValue (F-004/F-005) and JWT HS256 (F-023).

## Work factors

| Setting | Default | Notes |
| --- | --- | --- |
| `password_hash` | `bcrypt` | Collection: bcrypt, pbkdf2sha1 |
| `bcrypt_cost` | `10` | Seed `010-calibrate_bcrypt_cost` may raise to ≥50ms latency (min 5) |
| `pbkdf2_cost` | `50000` | Iterations for PBKDF2-HMAC-SHA1 |

Tunable via Settings UI / API. Extremely high costs can slow API basic-auth and
UI login — prefer calibration over unbounded increases.

## Progressive migration

1. `User#matching_password?` detects the stored algorithm from `password_salt`.
2. Verification uses timing-safe comparison (`secure_compare`).
3. On **successful** verify, if the algorithm or work factor is below policy,
   `upgrade_password` rewrites hash+salt with `update_columns`.
4. Failed verify never upgrades.
5. Upgrade does **not** append F-009 password history (same secret, new encoding).

## Password history (F-009)

History rows store whatever hash+salt was outgoing at change time (including
legacy SHA-1). `UserPasswordHistory#matches_password?` detects the format and
verifies with `secure_compare`. Reuse rejection remains algorithm-agnostic.

## SHA-1 elsewhere (not password storage)

- PBKDF2 / bcrypt `calculate_salt(object)` may use `Digest::SHA1` of an object id
  (deterministic material for PATs) — not a password hash.
- LDAP avatar fingerprints, userdata instance-id, etc. — unrelated to auth.
