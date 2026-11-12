# Foreman 5.0 Security Threat Model (F-034)

| Field | Value |
|-------|-------|
| Project | Foreman 5.0 security-hardening |
| Branch | `security-hardening-5.0` |
| Baseline HEAD (at authorship) | `075049e9110ee14c0594b1c913eb9721aef14468` |
| Audit requirement | 70 |
| Method | STRIDE on verified data flows |
| Diagrams | [diagrams/foreman-dfd.md](diagrams/foreman-dfd.md) |

## 1. Scope and assumptions

### In scope

- Foreman Rails application on this hardened branch (UI, API, GraphQL).
- Custom middleware and services added by security-hardening commits.
- Local Docker Compose lab architecture as documented in `docs/docker-local.md`
  and `docker-compose.yml`.
- Provisioning (`/unattended`, `/userdata`), Smart Proxy auth filters, compute
  console (VNC path), session/auth/token controls, encryption, exports.

### Out of scope (unless noted as residual deployment risk)

- Production network topology, WAF, or SIEM (not present in repo evidence).
- Smart Proxy product internals beyond Foreman’s client/server auth surface.
- Plugin code not shipped in this repository.
- Physical security, OS hardening of hypervisor hosts.

### Evidence classes

| Label | Meaning |
|-------|---------|
| **CODE** | Confirmed in this branch’s source |
| **LAB** | Confirmed in Compose / local docs |
| **ASSUMED** | Typical production control; **not** verified here |
| **RESIDUAL** | Known gap or policy trade-off |

Do not treat ASSUMED items as closed risks.

### Important architecture assumptions

1. **LAB** Compose binds Foreman HTTP on host port 3000 with
   `FOREMAN_REQUIRE_SSL=false` — TLS is **not** enforced in the lab.
2. **ASSUMED** production places TLS termination and optionally a reverse proxy
   in front of Puma; this repo does not configure Apache/Nginx body limits.
3. **ASSUMED** production Smart Proxy inbound uses client certificates; lab may
   not.
4. Workers (`orchestrator`, `worker`) share the app image and
   `ENCRYPTION_KEY` env (**LAB** / Compose YAML anchor).

---

## 2. System context

**CODE / LAB** components:

| Component | Evidence |
|-----------|----------|
| Puma / Rails app | `bin/rails server`, `config/puma.rb`, `config/puma/production.rb` |
| PostgreSQL | Compose `db` service; ActiveRecord |
| Redis cache | `FOREMAN_RAILS_CACHE_STORE_*`; rate-limit counters |
| Redis tasks + Sidekiq | Dynflow orchestrator/worker |
| ActiveRecord sessions | `config.session_store :active_record_store`, key `_session_id` |
| VNC gateway | `script/foreman-vnc-gateway`, ports 5910–5930 (optional publish) |
| EncryptValue | `docs/encryption-key.md`, Encryptable models |

Custom hardening controls (non-exhaustive): `Foreman::Middleware::{RejectUnsafeHttpMethods,RequestBodyLimit,HttpRateLimit}`, `Foreman::Reauthentication`, `Foreman::SecurityEvent`, `Foreman::UploadSecurity`, `Foreman::SessionStore::EncryptedMarshalSerializer`, `Foreman::ExportSecurity`, JWT HS256 pin, userdata MAC+IP binding, VNC RFB gateway, password policy modules.

---

## 3. Actors

| ID | Actor | Auth mechanism | Trust | Permitted operations (summary) | Sensitive reach | Main abuse scenarios |
|----|-------|----------------|-------|--------------------------------|-----------------|----------------------|
| A1 | Unauthenticated browser | None / login form | Untrusted | Login, CAPTCHA, public assets, status | Login endpoint | Credential stuffing, CAPTCHA bypass attempts |
| A2 | Authenticated ordinary user | Session cookie after login | Low–medium | Permission-scoped UI/API | Host inventory, templates per RBAC | Privilege probing, CSRF (mitigated), export abuse |
| A3 | Foreman administrator | Session + admin flag / roles | High | Users, auth sources, settings, proxies | All app config, user lifecycle | Malicious admin, reauth fatigue |
| A4 | API client (Basic) | HTTP Basic → `User.try_to_login` | Medium | API per permissions | Same as user | Credential stuffing on API |
| A5 | PAT holder | Personal Access Token | Medium | Token-scoped API | API as owning user | Token theft, long-lived token abuse |
| A6 | JWT holder | Bearer JWT (HS256) | Medium | Scoped/registered API | As issued user | Stolen JWT until invalidate; alg confusion (mitigated) |
| A7 | Smart Proxy | Client cert CN/SAN match **or** host/IP/`trusted_hosts` | Medium–high | Facts, reports, features callbacks | Host facts/reports | Spoofing if SSL/restrict disabled |
| A8 | Provisioning host | Provisioning token and/or IP (+ MAC with IP) | Low–medium | Unattended/userdata templates | `root_pw`, params in templates | Impersonation, cross-host userdata |
| A9 | Background worker | Process identity + DB/Redis creds | High | Jobs, compute calls | Encrypted secrets if key present | Compromised worker = key exposure |
| A10 | Infrastructure admin | Host/Compose/OS access | Highest | Containers, volumes, env | All secrets on disk/env | Misconfiguration, secret leak |
| A11 | External auth service | LDAP/SSO protocols | Medium | Asserts identity to Foreman | Directory credentials in EncryptValue | IdP compromise, LDAP bind abuse |
| A12 | Compute provider | Provider API/SSH from Foreman | Medium | VMs, consoles | Provider passwords, SSH keys | Provider-side breach; console misuse |
| A13 | Database administrator | Direct PostgreSQL | Highest | Raw SQL | Hashes, ciphertext, sessions, audits | Offline cracking, audit deletion |
| A14 | Network attacker | None | Untrusted | Reachable ports | Whatever exposure allows | MITM (no TLS), flooding, scanning |
| A15 | Compromised user session | Stolen `_session_id` | As victim | Victim’s RBAC until expiry/logout | Victim data + step-up if reauth window open | Session replay/hijack |

**Actors documented: 15.**

---

## 4. Assets

| ID | Asset | C | I | A | Storage / handling |
|----|-------|---|---|---|--------------------|
| S1 | User password hashes | High | High | Med | `users` table; bcrypt/PBKDF2 (F-022); legacy SHA-1 verify-only |
| S2 | JWT HMAC secrets | High | High | Med | `jwt_secrets.token` via EncryptValue |
| S3 | Application `ENCRYPTION_KEY` | High | High | Med | Env / file / gitignored initializer |
| S4 | Rails `secret_key_base` | High | High | Med | Initializer / lab `tmp/` (**LAB** ephemeral) |
| S5 | Browser session id + DB payload | High | High | Med | Cookie `_session_id`; `sessions.data` ARSESS1 (F-015) |
| S6 | Personal Access Tokens | High | High | Med | Hashed at rest; plaintext shown once at create |
| S7 | Compute SSH private keys | High | High | Med | `key_pairs.secret` EncryptValue; export paths F-018 |
| S8 | VNC tickets / display passwords | High | High | Low | Mode-0600 ticket files; not in browser HTML (F-025) |
| S9 | Provider / LDAP / BMC passwords | High | High | Med | EncryptValue fields |
| S10 | Provisioning templates | Med | High | Med | DB; may render secrets |
| S11 | Host / user inventory | Med | Med | Med | DB; CSV/ENC exports |
| S12 | SecurityEvent + Audit records | Med | High | Med | Logs + `audits` (and login_events) |
| S13 | Database backups | High | High | High | Operator-controlled (**ASSUMED**) |
| S14 | Settings / OAuth consumer secrets | High | High | Med | DB; OAuth updates always reauth |
| S15 | Registration JWT secrets | High | High | Med | EncryptValue on registration facet |
| S16 | Redis rate-limit / cache state | Low | Med | Med | Redis cache DB |

**Assets documented: 16.**

---

## 5. Data flow diagrams

See **[diagrams/foreman-dfd.md](diagrams/foreman-dfd.md)** for Mermaid DFDs covering:

1. System context  
2. Browser login / session  
3. API / PAT / JWT  
4. Reauthentication  
5. EncryptValue persistence  
6. Provisioning / userdata  
7. Smart Proxy  
8. VNC console  
9. Exports  
10. Lab Compose topology  

---

## 6. Trust boundaries

| ID | Boundary | What establishes trust | Notes |
|----|----------|------------------------|-------|
| B1 | Internet/browser ↔ Application | TLS **[ASSUMED]**; session cookie; CSRF token | **LAB** often plain HTTP |
| B2 | Reverse proxy ↔ Puma | Network placement **[ASSUMED]**; `trusted_proxies` for client IP | Not in Compose; forged XFF risk if mis-set |
| B3 | Unauthenticated ↔ Authenticated | Successful login / token verify | Middleware still applies to both |
| B4 | Ordinary user ↔ Administrator | Roles / admin flag + optional reauth | Reauth settings togglable except meta/OAuth |
| B5 | Application ↔ PostgreSQL | DB credentials in `DATABASE_URL` | No app-level row encryption beyond EncryptValue/sessions |
| B6 | Application ↔ Workers | Shared image, Redis, same secrets | Compromise of either is high impact |
| B7 | Application ↔ Smart Proxy | Outbound: client cert + VERIFY_PEER; Inbound: cert CN/SAN or host match | Inbound without SSL ≠ crypto auth |
| B8 | Provisioning client ↔ userdata/unattended | Token and/or IP; MAC requires IP match (F-012) | Network position still matters |
| B9 | Browser ↔ VNC gateway ↔ hypervisor | UI authz + single-use ticket; gateway holds RFB password | Ticket TTL ~ proxy timeout |
| B10 | Foreman ↔ Compute provider | Stored credentials / SSH keys | Provider trust external |
| B11 | Application ↔ External auth | LDAP bind / SSO assertions | Password hashing N/A for external |
| B12 | Runtime config ↔ Secret storage | Env / files / gitignore; fail-closed encrypt | Empty `ENCRYPTION_KEY=` ignored |
| B13 | CI/build ↔ Deployed runtime | Image build from Dockerfile | **LAB** image `foreman-local:security-hardening-5.0` |
| B14 | Rate-limit identity ↔ Client | `request.remote_ip` after RemoteIp | Depends on trusted_proxies correctness |

**Trust boundaries documented: 14.**

---

## 7. Threat scenarios (STRIDE)

Legend: **Threat** = plausible abuse of a real flow. **Finding** = addressed by
hardening on this branch (with evidence). **Hypothetical** = depends on
deployment mistakes outside verified lab.

| ID | STRIDE | Threat | Entry | Preconditions | Status |
|----|--------|--------|-------|---------------|--------|
| T-01 | S/D | Credential stuffing on login/API | `/users/login`, Basic API | Reachable login | Mitigated: lockout, IP bruteforce, CAPTCHA, rate limit (F-026) |
| T-02 | I/T | Weak password storage / offline crack | DB dump | DBA or backup access | Mitigated for new hashes (F-022); legacy SHA-1 verify-only until upgrade |
| T-03 | S | Session hijacking via XSS/network | Cookie `_session_id` | XSS or cleartext HTTP | Mitigated: HttpOnly, SameSite=Lax, CSRF, headers; **RESIDUAL** lab HTTP |
| T-04 | I | Session payload disclosure from DB | `sessions.data` | DB read | Mitigated: ARSESS1 encryption (F-015); legacy Marshal readable until rewrite |
| T-05 | S | Concurrent session reuse | Old cookie | Second login | Mitigated: newer-login-wins (F-016) |
| T-06 | E | Reauthentication bypass | Privileged UI | Interactive session | Mitigated: session+actor-bound window; fail-secure toggles |
| T-07 | S/T | JWT alg confusion / forged JWT | API Bearer | Attacker-chosen alg | Mitigated: verify pinned HS256 (F-023) |
| T-08 | I | Secret disclosure in exports | ENC/YAML/CSV/API | `view_hosts` without `edit_params` | Mitigated: redaction (F-019) |
| T-09 | S | Provisioning host impersonation via MAC only | `/userdata/:mac` | Attacker knows MAC | Mitigated: MAC alone denied (F-012) |
| T-10 | I | Cross-host userdata disclosure | userdata/unattended | Weak binding | Mitigated relative to MAC-only; **RESIDUAL** IP/token model |
| T-11 | I | Private-key exfiltration | `/key_pairs/:id` | Authz + reauth | **RESIDUAL policy**: plaintext GET still allowed after reauth (F-018) |
| T-12 | I | VNC password in browser HTML | Console page | Console permission | Mitigated for VNC path (F-025); SPICE out of scope |
| T-13 | D | Oversized request body DoS | Any POST | Reachable Puma | Mitigated: Puma 10 MiB + Rack path limits (F-028) |
| T-14 | D | API / login flooding | `/api/*`, login | Shared IP NAT | Mitigated: HttpRateLimit (F-026); **RESIDUAL** fail-open default |
| T-15 | D | DB connection exhaustion | Many workers/threads | Mis-tuned pools | Mitigated guidance F-027; operator must keep pools aligned |
| T-16 | E | Unauthorized administrative changes | Users/auth settings | Stolen admin session | Mitigated: RBAC + reauth on sensitive actions |
| T-17 | R/T | Audit / SecurityEvent tampering | DB/logs | DBA or log access | **RESIDUAL**: app cannot stop privileged DB deletes |
| T-18 | S/I | Client-IP spoof / TLS downgrade | Proxy headers / HTTP | Bad trusted_proxies or no TLS | **ASSUMED**/ **RESIDUAL** deployment |
| T-19 | S | Smart Proxy spoofing | Facts/reports endpoints | `restrict_registered_smart_proxies` off or no SSL | **RESIDUAL** without mTLS |
| T-20 | I/T | Secrets stored plaintext on write | Encryptable save | Missing ENCRYPTION_KEY | Mitigated: fail-closed (F-005) |
| T-21 | I | Worker compromise exposes keys | Sidekiq host | Process access | **RESIDUAL** shared secret model |
| T-22 | D | Rate limiter unavailable | Cache outage | Redis down | **RESIDUAL** if fail-open (default) |

**Threat scenarios documented: 22.**

---

## 8. Existing mitigations (control map)

| Threat | Native Foreman | Custom hardening | Deploy control | Evidence |
|--------|----------------|------------------|----------------|----------|
| T-01 | Auth sources, failed login audits | Lockout, CAPTCHA, F-026 rate limit, F-002 notice | Proxy limits **ASSUMED** | `BruteforceProtection`, `HttpRateLimit`, docs |
| T-02 | Password hash setting | F-022 bcrypt/PBKDF2; progressive upgrade | — | `docs/password-hashing.md` |
| T-03 | CSRF, secure cookies when SSL | Headers, RejectUnsafeHttpMethods | TLS **ASSUMED** | `application.rb` session options |
| T-04 | AR session store | F-015 EncryptedMarshalSerializer | Protect DB | `docs/session-encryption.md` |
| T-05 | — | F-016 active session claim | — | `docs/browser-session-policy.md` |
| T-06 | — | Reauthentication module + settings | — | `reauthentication.rb` |
| T-07 | JWT user tokens | F-023 HS256 pin + invalidation | — | `jwt_token.rb` |
| T-08 | `safe_value`, BMC flags | F-019 export redaction + no-store | — | `docs/export-sensitive-data.md` |
| T-09/T-10 | HostFinder token/IP | F-012 MAC requires IP | Network isolation **ASSUMED** | `userdata_controller.rb` |
| T-11 | KeyPair EncryptValue | F-018 reauth, passphrase POST, no-store | Policy decision | `key_pairs_controller.rb` |
| T-12 | Console permissions | F-025 RFB gateway + tickets | Firewall VNC ports | `docs/vnc-console-credentials.md` |
| T-13 | Per-endpoint upload checks | F-028 middleware + Puma ceiling | Proxy `client_max_body_size` **ASSUMED** | `docs/http-request-body-limits.md` |
| T-14 | — | F-026 HttpRateLimit | Proxy rate limits **ASSUMED** | `docs/http-rate-limiting.md` |
| T-15 | AR pool | F-027 pool/thread docs + Compose defaults | PG `max_connections` | `docs/connection-capacity.md` |
| T-16 | RBAC | Reauth on admin/token/key/console | — | ACTION_SETTINGS |
| T-20 | Encryptable | F-004/F-005 key load + fail-closed | Inject ENCRYPTION_KEY | `docs/encryption-key.md` |

Control owners (proposed): **Application security** (code), **Foreman administrator** (settings/RBAC), **Infrastructure administrator** (TLS, proxy, secrets, DB).

---

## 9. Residual risk register

Risk method (reproducible, not CVSS):

- **Likelihood:** Low / Medium / High — based on exposure in default lab + typical prod.
- **Impact:** Low / Medium / High / Critical — confidentiality/integrity/availability of assets.
- **Residual:** after listed mitigations.

| ID | Threat | Asset | Likelihood | Impact | Mitigations in place | Residual | Further action | Owner |
|----|--------|-------|------------|--------|----------------------|----------|----------------|-------|
| R-01 | T-11 | S7 | Medium | High | Reauth; encrypted POST export; audit | Plaintext GET download remains | Resolve product policy (disable GET or mandate passphrase) | Product / AppSec |
| R-02 | T-03/T-18 | S5 | High in lab | High | Secure flag when require_ssl | Lab HTTP; cookie Secure off | Enable TLS / `FOREMAN_REQUIRE_SSL=true` in prod | Infra |
| R-03 | T-13 | A | Medium | Medium | App/Puma limits | No proxy body cap in lab | Configure reverse-proxy limit | Infra |
| R-04 | T-13 | A | Low | Medium | Puma absolute limit | Partial-body CL wait quirk | Proxy + timeouts | Infra / AppSec |
| R-05 | T-14 | A | Medium | Medium | Rate limit | Default fail-open | Set `http_rate_limit_fail_closed` if preferred | Admin |
| R-06 | T-19 | S11 | Medium | High | restrict_registered + cert path | DNS/IP trust without SSL | Require SSL + client certs | Infra |
| R-07 | T-10 | S10/S11 | Medium | High | Token/IP/MAC+IP | Shared L2 / IP spoof | Tokens + network isolation | Infra / Admin |
| R-08 | T-03 | S4/S5 | High in lab | High | Encryption tied to secret_key_base | Ephemeral lab secret | Persist secret_key_base outside tmp | Infra |
| R-09 | T-04 | S5 | Low post-upgrade | Medium | New writes encrypted | Legacy Marshal rows until rewrite | Truncate sessions after key rotate | Admin |
| R-10 | T-17 | S12 | Low | Medium | App logging only | DBA can alter audits | Immutable log shipping **ASSUMED** | Infra |
| R-11 | T-12 | S8 | Low | Medium | VNC gateway | SPICE still password-in-page | Track SPICE follow-up | AppSec |
| R-12 | T-08 | S9/S10 | Medium | High | Export redaction | Template render still needs secrets | Strict template permissions | Admin |
| R-13 | T-21 | S3 | Low | Critical | Process isolation **ASSUMED** | Shared ENCRYPTION_KEY in workers | HSM/KMS **ASSUMED** future | Infra |
| R-14 | T-02 | S1 | Low | High | bcrypt default | Offline crack if cost low / legacy rows | Calibrate bcrypt_cost; migrate leftovers | Admin |

**Residual risks documented: 14.**

---

## 10. Deployment responsibilities

| Responsibility | Role | Code support vs verification |
|----------------|------|------------------------------|
| Terminate TLS; HSTS | Infra | `SETTINGS[:require_ssl]` / `force_ssl` — **ASSUMED** at edge |
| Configure `trusted_proxies` | Infra/Admin | CODE default loopback only |
| Inject `ENCRYPTION_KEY` | Infra | CODE fail-closed without it |
| Persist `secret_key_base` | Infra | CODE loads token; **LAB** may regenerate |
| Smart Proxy mTLS files | Infra | CODE `ssl_certificate`, `ssl_ca_file`, `ssl_priv_key` |
| Reverse-proxy body/rate limits | Infra | Not in Compose |
| Tune Puma/PG pools | Infra/Admin | F-027 docs + Compose defaults |
| RBAC, reauth toggles, password policy | Foreman admin | Settings UI/API |
| Backup encryption & access control | Infra/DBA | Outside app |
| Review SecurityEvent / audits | Admin/SecOps | Logs + Audit models |

---

## 11. Review / version history

| Version | Date | Baseline | Notes |
|---------|------|----------|-------|
| 1.0 | 2026-11-12 | `075049e9110ee14c0594b1c913eb9721aef14468` | Initial F-034 threat model + DFDs through F-028 hardening |

### Evidence sources

- Hardening docs under `docs/*.md` (encryption, sessions, VNC, exports, rate/body limits, passwords, …)
- `docker-compose.yml`, `docs/docker-local.md`
- Controllers: `userdata_controller.rb`, `unattended_controller.rb`, `key_pairs_controller.rb`, `smart_proxy_auth.rb`
- Services: `jwt_token.rb`, `reauthentication.rb`, `security_event.rb`, `upload_security.rb`, `proxy_api/resource.rb`
- Middleware: `request_body_limit.rb`, `http_rate_limit.rb`, `reject_unsafe_http_methods.rb`
- Git history of `security:` commits on this branch

### Missing information (explicit)

- Production reverse-proxy / TLS configuration (not in repo).
- Live Smart Proxy deployment topology.
- Organizational risk acceptance for R-01 (plaintext key GET).
- External IdP hardening beyond Foreman’s LDAP bind secret storage.
- Backup and log-retention controls outside the application.
