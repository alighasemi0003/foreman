# Foreman 5.0 Threat-to-Control Matrix (F-035)

| Field | Value |
|-------|-------|
| Audit requirement | 71 |
| Branch | `security-hardening-5.0` |
| Matrix HEAD (authorship) | `2d06b5863a96350ef5eac5efb1b20c3d92ca4e90` |
| F-034 threat-model baseline | `075049e9110ee14c0594b1c913eb9721aef14468` |
| Matrix version | 1.0 |
| Review date | 2026-11-12 |
| Companion CSV | [threat-control-matrix.csv](threat-control-matrix.csv) |
| Threat model | [threat-model.md](threat-model.md) |

## 1. Methodology

1. **Threat inventory** is taken exclusively from F-034 (`T-01`…`T-22`, residual `R-01`…`R-14`). No second inventory.
2. Each matrix row maps one threat to one **meaningful** control (multiple rows when several controls apply).
3. Control types: **Native**, **Custom**, **Deployment**, or combinations.
4. Remediation IDs (`F-00x`) are preserved from hardening commits/docs.
5. Verification statuses (no fabricated CI PASS):
   - `VERIFIED` — implementation + automated test path exists in tree
   - `RUNTIME VERIFIED` — lab/runtime evidence documented (e.g. F-028 HTTP 413)
   - `CODE IMPLEMENTED — TEST PENDING` — code/docs present; dedicated automated test not located
   - `DEPLOYMENT DEPENDENT` — requires production TLS/proxy/mTLS not in lab Compose
   - `PARTIAL` — control incomplete relative to the threat
   - `NOT IMPLEMENTED` — no application control yet
6. Inherent risk = qualitative Likelihood × Impact from F-034 (not CVSS).
7. Risk state after controls: Mitigated / Partially mitigated / Open / Deployment dependent.
8. Owners are **proposed roles** only; no formal risk acceptance is recorded.

## 2. Evidence gaps

| Gap | Impact |
|-----|--------|
| Original **84-control security audit** workbook/backlog **not found** in this repository | Audit requirement column filled only where known from task briefs (e.g. body size = 61); otherwise blank |
| Production TLS / reverse-proxy / Smart Proxy mTLS | `DEPLOYMENT DEPENDENT` — not production-verified |
| Full test suite not re-run in this F-035 session | Status reflects **file presence** + prior documented runtime checks |
| F-037 | **Absent** from commits/docs — not claimed implemented |

## 3. Identifier schemes

| Kind | Scheme | Source |
|------|--------|--------|
| Threats | `T-01`…`T-22` | F-034 |
| Residual risks | `R-01`…`R-14` | F-034 |
| Controls | `CTL-001`…`CTL-042` | This matrix |
| Tests | `TST-001`…`TST-030` | This matrix → repo paths |
| Remediation | `F-001`…`F-028` etc. | Hardening commits/docs |

## 4. Control catalog

| Control ID | Description | Type | Source / config | Task |
|------------|-------------|------|-----------------|------|
| CTL-001 | Account lockout (per-user) | Custom | `app/models/concerns/user_account_lockout.rb` | — |
| CTL-002 | IP-based BruteforceProtection | Custom | `app/services/foreman/bruteforce_protection.rb` | — |
| CTL-003 | Login CAPTCHA (local/settings) | Custom | `app/services/foreman/captcha.rb` | — |
| CTL-004 | HTTP/API rate limiting | Custom | `lib/foreman/middleware/http_rate_limit.rb` | F-026 |
| CTL-005 | Failed login attempt notification | Custom | `docs/failed-login-notification.md` | F-002 |
| CTL-006 | Successful login history | Custom | `docs/login-history.md` | F-001 |
| CTL-007 | Local password hashing bcrypt/PBKDF2 | Custom | `docs/password-hashing.md` | F-022 |
| CTL-008 | Password complexity policy | Custom | `user password complexity concern` | — |
| CTL-009 | Password history (reuse prevention) | Custom | `docs/password-history.md` | F-009 |
| CTL-010 | Local password expiration | Custom | `docs/password-expiration.md` | F-007 |
| CTL-011 | CSRF protection | Native+Custom | `test/controllers/csrf_protection_test.rb` | — |
| CTL-012 | Security response headers | Custom | `test/controllers/security_headers_test.rb` | — |
| CTL-013 | Reject unsafe HTTP methods | Custom | `lib/foreman/middleware/reject_unsafe_http_methods.rb` | — |
| CTL-014 | Session cookie HttpOnly/SameSite/Secure | Custom | `config/application.rb` | — |
| CTL-015 | DB session payload encryption ARSESS1 | Custom | `docs/session-encryption.md` | F-015 |
| CTL-016 | Concurrent browser session policy | Custom | `docs/browser-session-policy.md` | F-016 |
| CTL-017 | Step-up reauthentication | Custom | `app/services/foreman/reauthentication.rb` | — |
| CTL-018 | JWT verify pinned HS256 | Custom | `app/services/jwt_token.rb` | F-023 |
| CTL-019 | JWT invalidation enforcement | Custom | `jwt_invalidation_enforcement_test.rb` | — |
| CTL-020 | Export/ENC sensitive data redaction | Custom | `docs/export-sensitive-data.md` | F-019 |
| CTL-054 | Temporary file and cache lifecycle | Custom | `docs/temp-cache-lifecycle.md` | F-020 |
| CTL-054b | Runtime PID/state/socket lifecycle | Custom | `docs/runtime-state-lifecycle.md` | F-021 |
| CTL-055 | Cryptographic / FIPS assessment | Custom | `docs/fips-cryptography-assessment.md` | F-024 |
| CTL-066 | Security logging severity coverage | Custom | `docs/security-logging-severity.md` | F-030 |
| CTL-066b | Security event taxonomy / classification logging | Custom | `docs/security-event-taxonomy.md` | F-031 |
| CTL-078 | Production JS source map exposure | Custom | `docs/production-source-maps.md` | F-038 |
| CTL-078b | Source-code distribution / obfuscation assessment | Custom | `docs/source-code-protection.md` | F-039 |
| CTL-043 | DB least-privilege / SP architecture assessment | Custom | `docs/security/adr-stored-procedures-vs-orm.md` | F-014 |
| CTL-061 | Classification-aware load / availability policy | Custom | `docs/load-management-policy.md` | F-029 |
| CTL-067 | Application-level PKCS#7 digital signatures | Custom | `docs/digital-signatures.md` | F-032 |
| CTL-068 | CMS/PKCS#7 interoperability for signed exports | Custom | `docs/cms-pkcs7-compatibility.md` | F-033 |
| CTL-075 | Dead-code analysis process (non-destructive) | Custom | `docs/dead-code-analysis.md` | F-036 |
| CTL-021 | Userdata MAC requires IP/token binding | Custom | `userdata_controller.rb` | F-012 |
| CTL-022 | Unattended HostFinder token/IP | Native+Custom | `unattended_controller.rb` | — |
| CTL-023 | Key-pair export reauth + passphrase POST | Custom | `key_pairs_controller.rb` | F-018 |
| CTL-024 | KeyPair / JwtSecret EncryptValue at rest | Native+Custom | `docs/encryption-key.md` | F-004 |
| CTL-025 | VNC RFB gateway (password server-side) | Custom | `docs/vnc-console-credentials.md` | F-025 |
| CTL-026 | Console permission + optional reauth | Custom | `console_common.rb` | F-025 |
| CTL-027 | HTTP request body size limits | Custom | `docs/http-request-body-limits.md` | F-028 |
| CTL-028 | UploadSecurity field/payload validators | Custom | `upload_security.rb` | — |
| CTL-029 | Puma/AR/PG connection capacity alignment | Custom | `docs/connection-capacity.md` | F-027 |
| CTL-030 | RBAC authorize filters | Native | `ApplicationController#authorize` | — |
| CTL-031 | SecurityEvent structured logging | Custom | `security_event.rb` | — |
| CTL-032 | Audit trail (audited) | Native | `audits` | — |
| CTL-033 | EncryptValue fail-closed without key | Custom | `docs/encryption-key.md` | F-005 |
| CTL-034 | Smart Proxy inbound auth filter | Native+Custom | `smart_proxy_auth.rb` | — |
| CTL-035 | ProxyAPI outbound client cert VERIFY_PEER | Native | `proxy_api/resource.rb` | — |
| CTL-036 | force_ssl / FOREMAN_REQUIRE_SSL | Native+Custom | `config/application.rb` | — |
| CTL-037 | trusted_proxies for client IP | Native+Custom | `config/application.rb` | — |
| CTL-038 | Reverse-proxy TLS / body / rate limits | Deployment | `Not in docker-compose.yml` | — |
| CTL-039 | Immutable / shipped audit logs | Deployment | `Outside application` | — |
| CTL-040 | HSM/KMS for ENCRYPTION_KEY | Deployment | `NOT IMPLEMENTED` | — |
| CTL-041 | SPICE console password-in-page fix | Custom | `NOT IMPLEMENTED` | — |
| CTL-042 | Template/generate permission hygiene | Native+Admin | `RBAC / operations` | — |

## 5. Test / evidence catalog

| Test ID | Evidence location |
|---------|-------------------|
| TST-001 | `test/controllers/users_controller_captcha_test.rb` |
| TST-002 | `test/controllers/password_complexity_enforcement_test.rb` |
| TST-003 | `test/unit/foreman/password_hash_test.rb` |
| TST-004 | `test/controllers/password_history_enforcement_test.rb` |
| TST-005 | `test/controllers/password_expiration_enforcement_test.rb` |
| TST-006 | `test/controllers/browser_session_policy_test.rb` |
| TST-007 | `test/unit/foreman/session_store/encrypted_marshal_serializer_test.rb` |
| TST-008 | `test/controllers/users_controller_reauthentication_test.rb and related *reauthentication*_test.rb` |
| TST-009 | `test/unit/jwt_token_test.rb` |
| TST-010 | `test/controllers/api/v2/jwt_authentication_enforcement_test.rb` |
| TST-011 | `test/controllers/jwt_invalidation_enforcement_test.rb` |
| TST-012 | `test/unit/foreman/export_security_test.rb` |
| TST-013 | `test/controllers/userdata_controller_test.rb` |
| TST-014 | `test/controllers/key_pairs_controller_test.rb; key_pairs_controller_reauthentication_test.rb` |
| TST-015 | `test/controllers/hosts_controller_console_security_test.rb` |
| TST-016 | `test/unit/foreman/console/ws_gateway_security_test.rb` |
| TST-017 | `test/unit/foreman/middleware/request_body_limit_test.rb` |
| TST-018 | `test/unit/foreman/middleware/http_rate_limit_test.rb; http_rate_limit_test.rb` |
| TST-019 | `test/controllers/api/v2/upload_payload_size_test.rb; template_upload_security_test.rb` |
| TST-020 | `test/controllers/security_headers_test.rb` |
| TST-021 | `test/controllers/csrf_protection_test.rb` |
| TST-022 | `test/controllers/https_enforcement_test.rb` |
| TST-023 | `test/controllers/smart_proxy_auth_test.rb` |
| TST-024 | `test/unit/foreman/encryption_legacy_test.rb` |
| TST-025 | `test/unit/foreman/security_event_test.rb` |
| TST-026 | `users_controller_login_history_test.rb; users_controller_failed_login_notice_test.rb` |
| TST-027 | `docs/connection-capacity.md + docker-compose.yml (config inspection)` |
| TST-028 | `docs/http-request-body-limits.md + F-028 lab runtime 413 observations` |
| TST-029 | `test/controllers/http_method_and_disclosure_test.rb` |
| TST-030 | `test/controllers/injection_protection_test.rb` |

## 6. Threat rollup (consistency with F-034)

| Threat | Inherent | Controls | Worst risk state | Residual IDs |
|--------|----------|----------|------------------|--------------|
| T-01 | Critical | CTL-001, CTL-002, CTL-003, CTL-004, CTL-005, CTL-006, CTL-038 | Deployment dependent | R-05 |
| T-02 | High | CTL-007, CTL-008, CTL-009, CTL-010 | Partially mitigated | R-14 |
| T-03 | High | CTL-011, CTL-012, CTL-013, CTL-014, CTL-036, CTL-038 | Deployment dependent | R-02, R-02/R-08 |
| T-04 | High | CTL-015 | Partially mitigated | R-09 |
| T-05 | Medium | CTL-016 | Mitigated | — |
| T-06 | High | CTL-017 | Mitigated | — |
| T-07 | High | CTL-018, CTL-019, CTL-024 | Mitigated | — |
| T-08 | High | CTL-020, CTL-042 | Partially mitigated | R-12 |
| T-09 | High | CTL-021 | Mitigated | — |
| T-10 | High | CTL-021, CTL-022, CTL-038 | Deployment dependent | R-07 |
| T-11 | High | CTL-017, CTL-023, CTL-024 | Partially mitigated | R-01 |
| T-12 | High | CTL-025, CTL-026, CTL-041 | Open | R-11 |
| T-13 | Medium | CTL-027, CTL-028, CTL-038 | Deployment dependent | R-03, R-03/R-04 |
| T-14 | Medium | CTL-004, CTL-038 | Deployment dependent | R-05 |
| T-15 | High | CTL-029 | Partially mitigated | — |
| T-16 | High | CTL-017, CTL-030 | Mitigated | — |
| T-17 | Medium | CTL-031, CTL-032, CTL-039 | Open | R-10 |
| T-18 | Critical | CTL-004, CTL-036, CTL-037, CTL-038 | Deployment dependent | R-02 |
| T-19 | High | CTL-034, CTL-035, CTL-036 | Deployment dependent | R-06 |
| T-20 | Critical | CTL-024, CTL-033 | Mitigated | — |
| T-21 | Critical | CTL-033, CTL-040 | Open | R-13 |
| T-22 | Medium | CTL-004 | Partially mitigated | R-05 |

## 7. Full traceability matrix

Machine-readable full columns: [threat-control-matrix.csv](threat-control-matrix.csv).

| Threat ID | Threat | Asset | Actor | Entry | Boundary | L | I | Inherent | Control | Type | Source | Task | Evidence | Status | Owner | Residual | Action | Risk state | Reviewed |
|-----------|--------|-------|-------|-------|----------|---|---|----------|---------|------|--------|------|----------|--------|-------|----------|--------|------------|----------|
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-001 | Custom | `app/models/concerns/user_account_lockout.rb` | — | TST-026; user_account_lockout | VERIFIED | Foreman Development | — | Maintain lockout settings | Mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-002 | Custom | `app/services/foreman/bruteforce_protection.rb` | — | bruteforce_protection + API/login includes | VERIFIED | Foreman Development | — | Keep failed_login_attempts_limit sized for NA | Mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-003 | Custom | `app/services/foreman/captcha.rb; users_contro` | — | TST-001 | VERIFIED | Foreman Development | — | Keep CAPTCHA enabled for interactive login | Mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-004 | Custom | `lib/foreman/middleware/http_rate_limit.rb; do` | F-026 | TST-018; docs/http-rate-limiting.md | VERIFIED | Foreman Development | R-05 | Consider fail-closed where needed | Partially mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-005 | Custom | `docs/failed-login-notification.md` | F-002 | TST-026; docs/failed-login-notification.md | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-006 | Custom | `docs/login-history.md` | F-001 | TST-026; docs/login-history.md | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-01 | Credential stuffing on login/API | S1/S6 | A1/A4/A14 | /users/login, Basic API | B3 | High | High | Critical | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Not in Compose | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-05 | Add edge rate limits in production | Deployment dependent | 2026-11-12 |
| T-02 | Weak password storage / offline crack | S1 | A13 | DB dump / backups | B5 | Low | High | High | CTL-007 | Custom | `docs/password-hashing.md; app/services/forema` | F-022 | TST-003; docs/password-hashing.md | VERIFIED | Foreman Development | R-14 | Calibrate bcrypt_cost; migrate legacy SHA-1 r | Partially mitigated | 2026-11-12 |
| T-02 | Weak password storage / offline crack | S1 | A13 | DB dump / backups | B5 | Low | High | High | CTL-008 | Custom | `test/models/concerns/user_password_complexity` | — | TST-002 | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-02 | Weak password storage / offline crack | S1 | A13 | DB dump / backups | B5 | Low | High | High | CTL-009 | Custom | `docs/password-history.md` | F-009 | TST-004; docs/password-history.md | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-02 | Weak password storage / offline crack | S1 | A13 | DB dump / backups | B5 | Low | High | High | CTL-010 | Custom | `docs/password-expiration.md` | F-007 | TST-005; docs/password-expiration.md | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-011 | Native+Custom | `test/controllers/csrf_protection_test.rb` | — | TST-021 | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-012 | Custom | `test/controllers/security_headers_test.rb` | — | TST-020 | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-013 | Custom | `lib/foreman/middleware/reject_unsafe_http_met` | — | TST-029; reject_unsafe_http_methods | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-014 | Custom | `config/application.rb session_store` | — | config/application.rb session_store flags | VERIFIED | Foreman Development | R-02 | Secure flag only when require_ssl | Partially mitigated | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-036 | Native+Custom | `config/application.rb; config/settings.rb` | — | TST-022; FOREMAN_REQUIRE_SSL lab=false | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-02/R-08 | Enable TLS + persist secret_key_base in prod | Deployment dependent | 2026-11-12 |
| T-03 | Session hijacking via XSS/network | S5 | A14/A15 | Cookie _session_id | B1 | Medium | High | High | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Not in Compose | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-02 | Terminate TLS at edge | Deployment dependent | 2026-11-12 |
| T-04 | Session payload disclosure from DB | S5 | A13 | sessions.data | B5 | Medium | High | High | CTL-015 | Custom | `docs/session-encryption.md` | F-015 | TST-007; docs/session-encryption.md | VERIFIED | Foreman Development | R-09 | Truncate sessions after key rotation | Partially mitigated | 2026-11-12 |
| T-05 | Concurrent session reuse | S5 | A15 | Old session cookie | B3 | Medium | Medium | Medium | CTL-016 | Custom | `docs/browser-session-policy.md` | F-016 | TST-006; docs/browser-session-policy.md | VERIFIED | Foreman Development | — | PAT/JWT out of scope by design | Mitigated | 2026-11-12 |
| T-06 | Reauthentication bypass | S14/S6/S7 | A15/A2 | Privileged UI actions | B4 | Low | High | High | CTL-017 | Custom | `app/services/foreman/reauthentication.rb` | — | TST-008 | VERIFIED | Foreman Development | — | Keep fail-secure defaults on toggles | Mitigated | 2026-11-12 |
| T-07 | JWT alg confusion / forged JWT | S2 | A14/A6 | API Bearer JWT | B3 | Low | High | High | CTL-018 | Custom | `app/services/jwt_token.rb` | F-023 | TST-009; TST-010 | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-07 | JWT alg confusion / forged JWT | S2 | A14/A6 | API Bearer JWT | B3 | Low | High | High | CTL-019 | Custom | `test/controllers/jwt_invalidation_enforcement` | — | TST-011 | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-07 | JWT alg confusion / forged JWT | S2 | A14/A6 | API Bearer JWT | B3 | Low | High | High | CTL-024 | Native+Custom | `docs/encryption-key.md` | F-004 | TST-024; JwtSecret EncryptValue | VERIFIED | Foreman Development | — | Keep ENCRYPTION_KEY provisioned | Mitigated | 2026-11-12 |
| T-08 | Secret disclosure in exports | S9/S11/S7 | A2 | ENC/YAML/CSV/API | B4 | Medium | High | High | CTL-020 | Custom | `docs/export-sensitive-data.md` | F-019 | TST-012; docs/export-sensitive-data.md | VERIFIED | Foreman Development | R-12 | Restrict template generate permissions | Partially mitigated | 2026-11-12 |
| T-08 | Secret disclosure in exports | S9/S11/S7 | A2 | ENC/YAML/CSV/API | B4 | Medium | High | High | CTL-042 | Native+Admin | `RBAC on templates; operational` | — | RBAC template permissions (operational) | PARTIAL | Operations (proposed) | R-12 | Review who can render provisioning templates | Partially mitigated | 2026-11-12 |
| T-09 | Provisioning host impersonation via MAC only | S10/S11 | A8/A14 | /userdata/:mac | B8 | Medium | High | High | CTL-021 | Custom | `app/controllers/userdata_controller.rb` | F-012 | TST-013; userdata_controller authorize_found_host | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-10 | Cross-host userdata disclosure | S10/S11 | A8/A14 | userdata/unattended | B8 | Medium | High | High | CTL-021 | Custom | `app/controllers/userdata_controller.rb` | F-012 | TST-013 | VERIFIED | Foreman Development | R-07 | Prefer provisioning tokens; isolate build net | Partially mitigated | 2026-11-12 |
| T-10 | Cross-host userdata disclosure | S10/S11 | A8/A14 | userdata/unattended | B8 | Medium | High | High | CTL-022 | Native+Custom | `app/controllers/unattended_controller.rb` | — | unattended HostFinder paths | VERIFIED | Foreman Development | R-07 | Same as above | Partially mitigated | 2026-11-12 |
| T-10 | Cross-host userdata disclosure | S10/S11 | A8/A14 | userdata/unattended | B8 | Medium | High | High | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Network isolation ASSUMED | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-07 | Segment provisioning VLAN | Deployment dependent | 2026-11-12 |
| T-11 | Private-key exfiltration | S7 | A2/A3/A15 | /key_pairs/:id | B4 | Medium | High | High | CTL-023 | Custom | `app/controllers/key_pairs_controller.rb` | F-018 | TST-014; key_pairs_controller | VERIFIED | Foreman Development | R-01 | Decide policy: disable plaintext GET or manda | Partially mitigated | 2026-11-12 |
| T-11 | Private-key exfiltration | S7 | A2/A3/A15 | /key_pairs/:id | B4 | Medium | High | High | CTL-024 | Native+Custom | `docs/encryption-key.md` | F-004 | EncryptValue KeyPair.secret | VERIFIED | Foreman Development | R-01 | — | Partially mitigated | 2026-11-12 |
| T-11 | Private-key exfiltration | S7 | A2/A3/A15 | /key_pairs/:id | B4 | Medium | High | High | CTL-017 | Custom | `app/services/foreman/reauthentication.rb` | — | key_pairs.download reauth | VERIFIED | Foreman Development | R-01 | — | Partially mitigated | 2026-11-12 |
| T-12 | VNC password in browser HTML | S8 | A2/A15 | Console HTML/WS | B9 | Low | High | High | CTL-025 | Custom | `docs/vnc-console-credentials.md` | F-025 | TST-015; TST-016; docs/vnc-console-credentials.md | VERIFIED | Foreman Development | R-11 | SPICE still embeds password — track follow-up | Partially mitigated | 2026-11-12 |
| T-12 | VNC password in browser HTML | S8 | A2/A15 | Console HTML/WS | B9 | Low | High | High | CTL-026 | Custom | `app/controllers/concerns/foreman/controller/c` | F-025 | console reauth settings | VERIFIED | Foreman Development | R-11 | — | Partially mitigated | 2026-11-12 |
| T-12 | VNC password in browser HTML | S8 | A2/A15 | Console HTML/WS | B9 | Low | High | High | CTL-041 | Custom | `NOT IMPLEMENTED (out of F-025 VNC scope)` | — | NOT IMPLEMENTED | NOT IMPLEMENTED | Security Team (proposed) | R-11 | Implement SPICE credential handling akin to V | Open | 2026-11-12 |
| T-13 | Oversized request body DoS | Avail | A14 | Any POST body | B1 | Medium | Medium | Medium | CTL-027 | Custom | `docs/http-request-body-limits.md` | F-028 | TST-017; TST-028; docs/http-request-body-limits.md | RUNTIME VERIFIED | Foreman Development | R-03/R-04 | Add proxy client_max_body_size; timeouts for  | Partially mitigated | 2026-11-12 |
| T-13 | Oversized request body DoS | Avail | A14 | Any POST body | B1 | Medium | Medium | Medium | CTL-028 | Custom | `app/services/foreman/upload_security.rb` | — | TST-019 | VERIFIED | Foreman Development | — | Preserve field validators | Mitigated | 2026-11-12 |
| T-13 | Oversized request body DoS | Avail | A14 | Any POST body | B1 | Medium | Medium | Medium | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Not in Compose | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-03 | Configure reverse-proxy body limit | Deployment dependent | 2026-11-12 |
| T-14 | API / login flooding | Avail/S16 | A14 | /api/*, login | B1/B14 | Medium | Medium | Medium | CTL-004 | Custom | `lib/foreman/middleware/http_rate_limit.rb; do` | F-026 | TST-018; docs/http-rate-limiting.md | VERIFIED | Foreman Development | R-05 | Tune buckets; optional fail-closed | Partially mitigated | 2026-11-12 |
| T-14 | API / login flooding | Avail/S16 | A14 | /api/*, login | B1/B14 | Medium | Medium | Medium | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Not in Compose | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-05 | Edge rate limits | Deployment dependent | 2026-11-12 |
| T-15 | DB connection exhaustion | Avail | A14/A10 | Puma/Sidekiq load | B5/B6 | Medium | High | High | CTL-029 | Custom | `docs/connection-capacity.md; docker-compose.y` | F-027 | TST-027; docs/connection-capacity.md; compose pool | CODE IMPLEMENTED — TEST PENDING | DevOps / Infrastructure (proposed) | — | Keep pool ≥ threads; monitor PG max_connectio | Partially mitigated | 2026-11-12 |
| T-16 | Unauthorized administrative changes | S14/S1 | A15/A2 | Users/auth/settings UI | B4 | Medium | High | High | CTL-030 | Native | `ApplicationController authorize` | — | Native authorize (broad suite) | VERIFIED | Foreman Development | — | — | Mitigated | 2026-11-12 |
| T-16 | Unauthorized administrative changes | S14/S1 | A15/A2 | Users/auth/settings UI | B4 | Medium | High | High | CTL-017 | Custom | `app/services/foreman/reauthentication.rb` | — | TST-008; ACTION_SETTINGS | VERIFIED | Foreman Development | — | Do not disable always-on OAuth/meta reauth | Mitigated | 2026-11-12 |
| T-17 | Audit / SecurityEvent tampering | S12 | A13 | DB/logs | B5 | Low | Medium | Medium | CTL-031 | Custom | `app/services/foreman/security_event.rb` | — | TST-025 | VERIFIED | Foreman Development | R-10 | App logging only — cannot stop DBA deletes | Partially mitigated | 2026-11-12 |
| T-17 | Audit / SecurityEvent tampering | S12 | A13 | DB/logs | B5 | Low | Medium | Medium | CTL-032 | Native | `audits table; AuditsController` | — | Native audits | VERIFIED | Foreman Development | R-10 | — | Partially mitigated | 2026-11-12 |
| T-17 | Audit / SecurityEvent tampering | S12 | A13 | DB/logs | B5 | Low | Medium | Medium | CTL-039 | Deployment | `Outside application (ASSUMED)` | — | NOT in application | NOT IMPLEMENTED | DevOps / Infrastructure (proposed) | R-10 | Ship immutable logs / WORM storage | Open | 2026-11-12 |
| T-18 | Client-IP spoof / TLS downgrade | S5/S16 | A14 | XFF / cleartext HTTP | B1/B2/B14 | High (lab) | High | Critical | CTL-036 | Native+Custom | `config/application.rb; config/settings.rb` | — | TST-022; lab FOREMAN_REQUIRE_SSL=false | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-02 | Enable require_ssl in production | Deployment dependent | 2026-11-12 |
| T-18 | Client-IP spoof / TLS downgrade | S5/S16 | A14 | XFF / cleartext HTTP | B1/B2/B14 | High (lab) | High | Critical | CTL-037 | Native+Custom | `config/application.rb trusted_proxies` | — | config/application.rb default loopback | VERIFIED | DevOps / Infrastructure (proposed) | R-02 | Set trusted_proxies to real proxy CIDRs only | Partially mitigated | 2026-11-12 |
| T-18 | Client-IP spoof / TLS downgrade | S5/S16 | A14 | XFF / cleartext HTTP | B1/B2/B14 | High (lab) | High | Critical | CTL-038 | Deployment | `Not in docker-compose.yml (ASSUMED prod)` | — | Not in Compose | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-02 | TLS termination + correct Forwarded headers | Deployment dependent | 2026-11-12 |
| T-18 | Client-IP spoof / TLS downgrade | S5/S16 | A14 | XFF / cleartext HTTP | B1/B2/B14 | High (lab) | High | Critical | CTL-004 | Custom | `lib/foreman/middleware/http_rate_limit.rb; do` | F-026 | Rate limit uses remote_ip after RemoteIp | VERIFIED | Foreman Development | R-02 | Depends on trusted_proxies correctness | Partially mitigated | 2026-11-12 |
| T-19 | Smart Proxy spoofing | S11 | A14 | facts/reports endpoints | B7 | Medium | High | High | CTL-034 | Native+Custom | `app/controllers/concerns/foreman/controller/s` | — | TST-023 | VERIFIED | Foreman Development | R-06 | Without SSL, host/DNS match ≠ crypto auth | Partially mitigated | 2026-11-12 |
| T-19 | Smart Proxy spoofing | S11 | A14 | facts/reports endpoints | B7 | Medium | High | High | CTL-035 | Native | `app/services/proxy_api/resource.rb ssl_auth_p` | — | proxy_api/resource.rb ssl_auth_params | VERIFIED | Foreman Development | R-06 | Outbound mTLS when cert settings present | Partially mitigated | 2026-11-12 |
| T-19 | Smart Proxy spoofing | S11 | A14 | facts/reports endpoints | B7 | Medium | High | High | CTL-036 | Native+Custom | `config/application.rb; config/settings.rb` | — | require_ssl for inbound cert path | DEPLOYMENT DEPENDENT | DevOps / Infrastructure (proposed) | R-06 | Require SSL + client certs for proxies | Deployment dependent | 2026-11-12 |
| T-20 | Secrets stored plaintext on write | S2/S7/S9 | A10 | Encryptable save | B12 | Medium | Critical | Critical | CTL-033 | Custom | `docs/encryption-key.md` | F-005 | docs/encryption-key.md; fail-closed writes | VERIFIED | Foreman Development | — | Always inject ENCRYPTION_KEY in deploy | Mitigated | 2026-11-12 |
| T-20 | Secrets stored plaintext on write | S2/S7/S9 | A10 | Encryptable save | B12 | Medium | Critical | Critical | CTL-024 | Native+Custom | `docs/encryption-key.md` | F-004 | TST-024 | VERIFIED | Foreman Development | — | Run security:encrypt_legacy_secrets as needed | Mitigated | 2026-11-12 |
| T-21 | Worker compromise exposes keys | S3 | A9/A10 | Sidekiq host | B6 | Low | Critical | Critical | CTL-033 | Custom | `docs/encryption-key.md` | F-005 | Shared ENCRYPTION_KEY via Compose anchor | PARTIAL | DevOps / Infrastructure (proposed) | R-13 | Process isolation only; no app HSM | Partially mitigated | 2026-11-12 |
| T-21 | Worker compromise exposes keys | S3 | A9/A10 | Sidekiq host | B6 | Low | Critical | Critical | CTL-040 | Deployment | `NOT IMPLEMENTED in app` | — | NOT IMPLEMENTED | NOT IMPLEMENTED | DevOps / Infrastructure (proposed) | R-13 | Evaluate KMS/HSM for key material | Open | 2026-11-12 |
| T-22 | Rate limiter unavailable (fail-open) | Avail | A14 | Redis cache outage | B14 | Low | Medium | Medium | CTL-004 | Custom | `lib/foreman/middleware/http_rate_limit.rb; do` | F-026 | docs/http-rate-limiting.md fail_closed setting | VERIFIED | Operations (proposed) | R-05 | Set http_rate_limit_fail_closed=true if prefe | Partially mitigated | 2026-11-12 |

### Control descriptions (lookup)

See §4 for full `CTL-*` descriptions. CSV column `control_description` carries the text on every row.

## 8. Unmitigated / open threat register

| Threat | Open control | Action | Proposed owner | Residual |
|--------|--------------|--------|----------------|----------|
| T-12 | CTL-041 (SPICE console password-in-page fix) | Implement SPICE credential handling akin to VNC gateway | Security Team (proposed) | R-11 |
| T-17 | CTL-039 (Immutable / shipped audit logs) | Ship immutable logs / WORM storage | DevOps / Infrastructure (proposed) | R-10 |
| T-21 | CTL-040 (HSM/KMS for ENCRYPTION_KEY) | Evaluate KMS/HSM for key material | DevOps / Infrastructure (proposed) | R-13 |

Note: Many threats are **Partially mitigated** with residual `R-*` entries from F-034; those are not “unmitigated,” but remain in the residual register of the threat model.

## 9. Partial / pending verification

| Threat | Control | Verification | Action |
|--------|---------|--------------|--------|
| T-08 | CTL-042 | PARTIAL | Review who can render provisioning templates |
| T-12 | CTL-041 | NOT IMPLEMENTED | Implement SPICE credential handling akin to VNC gateway |
| T-15 | CTL-029 | CODE IMPLEMENTED — TEST PENDING | Keep pool ≥ threads; monitor PG max_connections |
| T-17 | CTL-039 | NOT IMPLEMENTED | Ship immutable logs / WORM storage |
| T-21 | CTL-033 | PARTIAL | Process isolation only; no app HSM |
| T-21 | CTL-040 | NOT IMPLEMENTED | Evaluate KMS/HSM for key material |

## 10. Deployment-dependent controls

| Threat | Control | Residual | Required action | Proposed owner |
|--------|---------|----------|-----------------|----------------|
| T-01 | CTL-038 | R-05 | Add edge rate limits in production | DevOps / Infrastructure (proposed) |
| T-03 | CTL-036 | R-02/R-08 | Enable TLS + persist secret_key_base in prod | DevOps / Infrastructure (proposed) |
| T-03 | CTL-038 | R-02 | Terminate TLS at edge | DevOps / Infrastructure (proposed) |
| T-10 | CTL-038 | R-07 | Segment provisioning VLAN | DevOps / Infrastructure (proposed) |
| T-13 | CTL-038 | R-03 | Configure reverse-proxy body limit | DevOps / Infrastructure (proposed) |
| T-14 | CTL-038 | R-05 | Edge rate limits | DevOps / Infrastructure (proposed) |
| T-18 | CTL-036 | R-02 | Enable require_ssl in production | DevOps / Infrastructure (proposed) |
| T-18 | CTL-038 | R-02 | TLS termination + correct Forwarded headers | DevOps / Infrastructure (proposed) |
| T-19 | CTL-036 | R-06 | Require SSL + client certs for proxies | DevOps / Infrastructure (proposed) |

## 11. Test evidence gaps

| Item | Notes |
|------|-------|
| CTL-029 / F-027 | Docs + Compose defaults; no dedicated automated unit test → `CODE IMPLEMENTED — TEST PENDING` |
| CTL-038 / CTL-039 / CTL-040 | Deployment / future — nothing in-app to unit-test |
| CTL-041 | SPICE credential fix not implemented |
| Fresh full CI run | Not executed for F-035 |
| 84-control audit spreadsheet | Missing locally |

## 12. Responsible roles (proposed)

| Role | Scope |
|------|-------|
| Foreman Development | Application controls and tests |
| Security Team | F-018 policy, SPICE follow-up |
| DevOps / Infrastructure | TLS, proxy, mTLS, secret persistence, KMS |
| Operations | Rate-limit fail-closed, template RBAC reviews |
| Database Administrator | Backup/DB access (T-17 residual) |
| Product | F-018 plaintext key GET policy (R-01) |

## 13. Consistency checks

| Check | Result |
|-------|--------|
| Every F-034 threat T-01…T-22 mapped | PASS (22/22) |
| Matrix rows | 58 |
| Control refs real or explicit gap | PASS |
| Cited primary test `*.rb` paths exist | PASS at generation |
| No fabricated CI PASS labels | PASS |
| High residuals have owner/action | PASS |
| F-00x IDs preserved; F-037 not claimed | PASS |
| Aligned with F-034 residual IDs | PASS |

## 14. Review / version history

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-12 | Initial F-035 matrix from F-034 through F-028 |

