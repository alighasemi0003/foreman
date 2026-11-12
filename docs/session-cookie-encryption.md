# Encrypted authentication session cookies (F-017)

Audit requirements **44** and **57** (چک‌لیست امنیتی، صفحات ۳۵–۳۶ و ۴۴–۴۵).

## Exact finding

The browser `_session_id` cookie held an opaque hexadecimal public session id
and was **not** in Rails encrypted-cookie format. `secret_key_base` and F-015
database payload encryption do **not** encrypt this cookie.

## Security assessment

| Property | Before F-017 | After F-017 |
| --- | --- | --- |
| Random sid unpredictability | Yes (SecureRandom) | Unchanged (sid still random) |
| Cookie confidentiality of sid | TLS + HttpOnly only | + authenticated encryption of cookie value |
| Cookie integrity | None on value | MessageEncryptor signature |
| Server-side session confidentiality | F-015 `ARSESS1:` | Unchanged |
| Session fixation / rotation | Existing Foreman controls | Unchanged |
| Bearer nature of cookie | Still a bearer | Still a bearer (theft of ciphertext still usable) |

Encrypting an opaque id does **not** replace TLS, HttpOnly, or server-side
revocation. It satisfies the audit’s literal encrypted-cookie requirement and
prevents casual correlation of cookie bytes with `sessions.session_id` without
`secret_key_base`.

## Selected implementation

`ActionDispatch::Session::EncryptedActiveRecordStore` subclasses the AR store:

1. Cookie value = `FSC1:` + `MessageEncryptor#encrypt_and_sign(public_sid)`
2. On read, decrypt → `Rack::Session::SessionId` → DB `private_id` lookup
3. Cookie remains non-persistent, HttpOnly, SameSite=Lax, Secure when `require_ssl`
4. `cookie_only: true` (Rack default) — sid not accepted from URL params
5. No client-side session payload; ActiveRecord store preserved

Key: `secret_key_base` via KeyGenerator purpose `foreman/session_cookie/v1`
(separate from F-015 purpose and EncryptValue `ENCRYPTION_KEY`).

## Migration / rollback

| Event | Behavior |
| --- | --- |
| Upgrade to F-017 | Legacy plain hex cookies rejected → empty session → re-login |
| Key / `secret_key_base` rotate | Encrypted cookies invalid → re-login |
| Rollback to pre-F-017 image | New `FSC1:` cookies unreadable by old code → re-login |
| Mixed old/new app workers | **Unsupported** — deploy atomically |

No indefinite plaintext cookie fallback.

## Relation to F-015

| Layer | Mechanism |
| --- | --- |
| Browser cookie | F-017 `FSC1:` encrypted public sid |
| `sessions.data` column | F-015 `ARSESS1:` encrypted Marshal payload |
