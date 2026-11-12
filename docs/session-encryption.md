# Database-backed session encryption (F-015)

## Problem

Foreman stores browser sessions in the `sessions` table via
`activerecord-session_store`. The default serializer persists
`Base64(Marshal.dump(session_hash))` in `sessions.data`.

That encoding is **not** encryption. A reader with database access can recover
session keys such as:

- `user` (authenticated user id)
- `reauthenticated_at` / `reauth_actor_id`
- taxonomy and other UI session state
- idle-timeout `expires_at`

Cookie flags (HttpOnly / Secure / SameSite) do not protect this server-side
payload.

## Design

Serializer: `Foreman::SessionStore::EncryptedMarshalSerializer`

| Format | Use |
| --- | --- |
| `ARSESS1:` + `MessageEncryptor#encrypt_and_sign` | All **new** writes |
| Legacy `BAh…` Base64(Marshal) | **Read-only** compatibility |

Cipher suite follows the application MessageEncryptor defaults
(`encrypt_and_sign` → confidentiality + integrity). No custom algorithms.

## Key management

Derived from `secret_key_base` via
`Rails.application.key_generator.generate_key('foreman/active_record_session_store/v1', …)`.

This is **separate** from `ENCRYPTION_KEY` / EncryptValue field encryption
(key separation by purpose). Rotating `secret_key_base` invalidates encrypted
session rows (users must sign in again). Missing `secret_key_base` fails closed
on write (no plaintext session writes).

## Legacy sessions

Existing plaintext Marshal rows remain readable after upgrade. The next session
save rewrites them as `ARSESS1:…`. There is **no** permanent plaintext write
path for new data.

Deliberate mass logout is optional: truncate or delete `sessions` rows if an
administrator prefers immediate invalidation instead of lazy rewrite.

## Failure behavior

Tampered ciphertext, wrong key, or corrupt payloads load as an empty session
(user appears logged out). Errors log the exception **class** only.

## Out of scope

Cookie encryption, TLS, JWT/PAT, and EncryptValue field encryption are unchanged.
