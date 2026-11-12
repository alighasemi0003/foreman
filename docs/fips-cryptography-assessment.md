# Cryptographic and FIPS compatibility assessment (F-024)

Audit requirement **55** (چک‌لیست امنیتی، صفحات ۴۳–۴۴).

## Status summary

| Claim | Result |
| --- | --- |
| Production FIPS **validated module** in use | **NOT VERIFIED / not enabled** |
| Algorithm inventory completed | Yes |
| Organizational FIPS policy supplied | **No** (none in repo / task) |
| Automatic FIPS enablement | **Not performed** (out of scope) |
| Crypto source changes in this task | **None** |

**Assessment status: PARTIAL** — remediation findings from F-022/F-023 addressed the named weak-auth items; full FIPS compliance is **not** claimed and would require an approved policy plus OS/module activation outside this application change set.

## Original audit findings vs current code

| Audit item | Current state | Notes |
| --- | --- | --- |
| Legacy SHA-1 password hashing | **Mitigated for new passwords (F-022)** | New/upgrade uses bcrypt (default) or PBKDF2-HMAC-SHA1; raw SHA-1 verify/history only |
| JWT `verify=false` trusted decode | **Mitigated (F-023)** | Auth uses `JWT.decode(..., true, algorithm: HS256)`; `verify=false` is inspection-only for `user_id` lookup |
| FIPS mode disabled | **Still true** | Ruby `OpenSSL.fips_mode=false`; crypto-policies `DEFAULT`; FIPS provider package present but inactive at runtime |
| `password_crypt.rb` non-approved ops | **Context-dependent** | This is **OS/grub provisioning** crypt (`$5$`/`$6$`/optional `$1$`), **not** Foreman login hashing |

Do not re-open F-022/F-023 implementation in this task.

## Actual OpenSSL / FIPS provider state (lab Compose image)

Evidence captured in the `foreman-app-1` container (CentOS Stream 9–based image), **without** enabling host/sysctl FIPS:

| Property | Observed value |
| --- | --- |
| OpenSSL CLI | `OpenSSL 3.5.8` |
| Ruby OpenSSL | Library `3.5.8` / binding reports `3.5.7` headers |
| `OpenSSL.fips_mode` | `false` |
| crypto-policies | `DEFAULT` |
| Active providers (default boot) | `default` only |
| Package `openssl-fips-provider` | Installed (`fips.so` present) |
| Loadable with local `OPENSSL_CONF` | Yes — “Red Hat Enterprise Linux OpenSSL FIPS Provider” activates in a **subprocess** probe |
| Host `/proc/sys/crypto/fips_enabled` | Not applicable / not enabled |

**OpenSSL 3 + FIPS provider package ≠ FIPS-validated operational mode.**  
Algorithm names alone do not establish use of a FIPS-validated cryptographic module.

Isolated subprocess probe (custom `OPENSSL_CONF`, `OpenSSL.fips_mode=true` in-process only):

| Operation | Result under FIPS flag |
| --- | --- |
| AES-256-CBC | OK |
| SHA-256 | OK |
| SHA-1 digest | OK (allowed in this provider probe) |
| PBKDF2-HMAC-SHA1 / SHA-256 | OK |
| JWT HS256 | OK |
| Rails `MessageEncryptor` (aes-256-cbc + sign) | OK |
| bcrypt (Blowfish, non-OpenSSL) | Still hashes (library works) — **not** a FIPS-approved password algorithm |
| Linux `crypt` SHA-512 (`$6$`) | OK |
| OpenSSL DES-ECB | **Fails** (`unsupported`) |
| OpenSSL MD5 | **Fails** |

## Approved policy availability

No organizational document in this repository specifies:

- Mandatory FIPS standard/version (e.g. 140-2 / 140-3)
- Approved CMVP module certificate IDs
- Approved algorithm allow-list / minimum key lengths
- Accepted legacy exceptions (VNC DES, bcrypt, etc.)
- Migration deadlines

Therefore recommendations below are **technical** proposals, not certified compliance.

### Proposed technical baseline (pending org approval)

| Class | Proposed preference | Notes |
| --- | --- | --- |
| Local password **storage** | bcrypt **or** migrate toward PBKDF2-HMAC-SHA256 / Argon2 if policy forbids bcrypt | bcrypt is industry-strong but **not** FIPS; PBKDF2-HMAC-SHA1 is FIPS-adjacent but weaker than SHA-256 variant |
| Field / session AE | AES-256 with integrity (prefer AES-GCM when Rails authenticated message encryption is approved) | Current: aes-256-cbc + HMAC via `MessageEncryptor` |
| JWT | HS256 with ≥256-bit secret | Already pinned (F-023) |
| TLS | TLS 1.2+ with approved suites via crypto-policies / proxy | App lab often HTTP |
| VNC RFB | Protocol DES challenge — **exception or disable consoles** under strict FIPS | Pure-Ruby DES today (F-025) |

## Cryptographic inventory

| Component | Purpose | Algorithm / mode | Key / KDF | Library | Compliance vs proposed baseline | Migration risk |
| --- | --- | --- | --- | --- | --- | --- |
| `Foreman::PasswordHash` bcrypt | New local password hash | Blowfish-based bcrypt | `bcrypt_cost` (default 10) | `bcrypt` gem | **Not FIPS-approved**; strong for non-FIPS | High if forced off without rehash plan |
| `Foreman::PasswordHash` PBKDF2 | Alternate new hash | PBKDF2-HMAC-**SHA1** | `pbkdf2_cost` iterations | OpenSSL | SHA1-based KDF — often discouraged for new FIPS deployments | Medium (setting switch + rehash on login) |
| `Foreman::PasswordHash` SHA1 | Legacy verify only | Raw SHA-1(password∥salt) | — | `Digest` | **Noncompliant** for storage; allowed verify-only (F-022) | Low if progressive upgrade continues |
| `PasswordCrypt` | Host/grub root passwords in templates | glibc `crypt` SHA-512 / SHA-256 / optional MD5; Base64 variants | random salt | libc `crypt` | SHA-512 crypt commonly accepted for **OS** passwords; MD5 crypt noncompliant | Medium for old OS defaults |
| `EncryptValue` | DB secrets at rest | MessageEncryptor encrypt_and_sign → **aes-256-cbc** + HMAC | `ENCRYPTION_KEY` | OpenSSL via Rails | Algorithm OK; module validation **not** active | High if key/cipher changes without re-encrypt |
| Session payload F-015 | `sessions.data` | aes-256-cbc + HMAC (`ARSESS1:`) | `secret_key_base` → KeyGenerator | Rails | Same as above | Medium (logout on key rotate) |
| Session cookie F-017 | `_session_id` cookie | aes-256-cbc + HMAC (`FSC1:`) | `secret_key_base` purpose key | Rails | Same | Medium |
| JWT / registration tokens | API auth | **HS256** | per-user `JwtSecret` | `jwt` gem + OpenSSL | Algorithm OK when module on | Low |
| `KeyPair#export` | Private key download | PEM **aes-256-cbc** + passphrase | user passphrase | OpenSSL | Algorithm OK | Low |
| VNC RFB auth | Console challenge | **DES** ECB (bit-reversed key) | 8-byte password | **Pure Ruby** (`VncDes`) | **Not FIPS-approved**; protocol-mandated | **Blocker** for strict FIPS + VNC |
| TLS | HTTPS | Negotiated suites | cert/key | OpenSSL / proxy | Depends on crypto-policies + terminate point | Ops |
| Randomness | Tokens, salts | OS CSPRNG | — | `SecureRandom` | OK if module seeds approved | Low |
| Non-crypto SHA-1 | Avatars, instance-id, salt derivation helpers | SHA-1 | — | `Digest` | Not password hashing; policy may still restrict | Low–medium |

`config.active_support.use_authenticated_message_encryption = false` intentionally keeps **aes-256-cbc** (not aes-256-gcm) for compatibility with existing ciphertext.

## Compatibility blockers for a FIPS deployment

1. **bcrypt default** — works as a gem under a FIPS OpenSSL flag in probes, but is **outside** the FIPS module and typically **disallowed** by FIPS password policies. Switching to PBKDF2-SHA256 (not currently implemented) or accepting PBKDF2-SHA1 requires product + security approval and login rehash strategy.
2. **VNC DES** — RFB authentication requires DES. OpenSSL DES fails under FIPS provider; Foreman uses pure-Ruby DES so consoles may still work while remaining **non-approved**. Strict FIPS may require disabling VNC/SPICE or an org exception.
3. **MD5** — OpenSSL MD5 fails under FIPS probe; `PasswordCrypt` MD5 option gates on `Foreman::Fips.md5_available?` (already false when MD5 unavailable). Avatar/`Digest::SHA1` paths are separate.
4. **Existing EncryptValue / session ciphertext** — tied to current MessageEncryptor construction; do **not** rotate keys or switch to GCM without an approved migration.
5. **Plugins / external IdPs** — out of app inventory; may introduce additional algorithms.
6. **FIPS module activation** — requires OS/image crypto-policy (`FIPS`), provider config, and often a FIPS-enabled kernel/container runtime. **Not** done on the shared lab host.

## What was intentionally not done

- No host or shared Compose stack switched into FIPS mode
- No bulk key rotation or ciphertext rewrite
- No bcrypt → other algorithm migration
- No JWT verification weakening
- No homemade crypto
- No claim of CMVP validation

## Operator path if org mandates FIPS later

1. Obtain written algorithm + module policy (standard, exceptions for VNC/bcrypt).
2. Build/test an **isolated** image with `crypto-policies` FIPS + OpenSSL FIPS provider; do not flip the shared lab.
3. Re-run: boot, EncryptValue round-trip, sessions, JWT, login (bcrypt + legacy), key export, VNC decision, Sidekiq.
4. Only then implement approved code changes (e.g. PBKDF2-SHA256, GCM migration) with rollback notes.

## Reproducible inventory

```bash
bundle exec rake security:crypto_inventory
```

Optional isolated provider probe (subprocess only; does not enable host FIPS):

```bash
bundle exec rake security:crypto_fips_probe
```

## Residual risks

- Lab and many deploys remain on **non-FIPS** OpenSSL default provider.
- bcrypt and VNC DES remain in the supported product surface.
- aes-256-cbc + HMAC is solid engineering practice but is not evidence of a validated module.
- Production FIPS verification: **NOT PERFORMED**.
