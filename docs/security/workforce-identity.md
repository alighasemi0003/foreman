# Workforce / personnel identity (F-010)

Audit requirement **18** (چک‌لیست امنیتی، صفحات ۲۰–۲۱).

## Exact meaning of the requirement

The control asks whether the product prevents **multiple unauthorized application
accounts from binding to the same workforce / personnel identity** (for example
an employee number), independently of the **login** string.

It is **not** a finding that `User.login` uniqueness is missing.

## Existing login uniqueness (already implemented)

| Control | Status |
| --- | --- |
| Model validation `validates :login, uniqueness: { case_sensitive: false }` | Present |
| Column `lower_login` + unique DB index `index_users_on_lower_login` | Present |
| Lookup via `User.find_by_login` → `lower_login` | Present |
| Local password hashes for internal users | Present |

Login uniqueness alone does **not** satisfy requirement 18 when login ≠ personnel ID.

## Investigation summary (Foreman 5.0)

- `users` has **no** `employee_id`, `personnel_code`, `staff_id`, `employee_no`,
  or equivalent column.
- API / UI user parameters expose login, name, mail, description, roles, taxonomy,
  password — **not** a workforce identifier.
- Mail is validated as email format only; it is **not** uniquely constrained and
  must not be treated as a personnel number.
- External authentication maps identity to Foreman **only through login**:
  - LDAP: `attr_login` (default `uid`) → `User.login`
  - OIDC: JWT `preferred_username` → `User.login`
  - Login delegation: `REMOTE_USER` → `User.login`
- `User.find_or_create_external_user` keys on login; there is no separate stored
  IdP subject / employeeNumber field.
- Built-in system accounts (`foreman_admin`, `foreman_api_admin`,
  `foreman_console_admin` on `AuthSourceHidden`) are **not** workforce identities.
- Lab inventory (read-only): internal and hidden users only; no LDAP/external rows
  and **zero** employee-like columns.

## Account-type separation

| Account class | Personnel ID applicable? | Current Foreman key |
| --- | --- | --- |
| Human local (`AuthSourceInternal`) | Only if org assigns a workforce ID | `login` |
| Human LDAP / SSO | Only if IdP supplies an authoritative personnel attribute | `login` from IdP username |
| API / machine / service | Typically **no** | `login` |
| Built-in hidden system | **No** | fixed anonymous logins |

A login is **not** automatically a personnel number.

## Applicability decision

**Blocked pending organizational policy.** There is no authoritative personnel-ID
source, approved format, lifecycle, or mapping rules in this deployment.

Therefore this branch **does not**:

- invent or auto-generate personnel codes,
- make a mandatory global personnel field,
- backfill fictitious employee IDs,
- merge/delete/disable accounts to force uniqueness,
- weaken or replace login uniqueness.

Pretending login uniqueness satisfies requirement 18 would be incorrect.
Shipping an empty optional column without a source would not enforce the control
for existing human accounts and would misrepresent audit completion.

## Prerequisites before any implementation

1. **Authoritative source** — HR system, FreeIPA/AD attribute (e.g. `employeeNumber`),
   or approved SSO claim, with ownership of issuance and revocation.
2. **Format and normalization** — allowed charset, case/whitespace policy, max length.
3. **Scope** — which account types must carry the ID; which may remain null
   (service, hidden, break-glass).
4. **Uniqueness scope** — global vs organization/location; collision rules across
   tenants.
5. **Who may set/change** — administrators only vs sync from IdP; prohibit
   self-service rebinding (impersonation risk).
6. **Backfill authority** — manual assignment plan for existing human users;
   dry-run inventory; no automatic merge/delete.
7. **External sync** — whether LDAP/OIDC should map a dedicated attribute into
   Foreman instead of overloading `login`.

## Candidate design (not implemented)

If prerequisites are approved, a minimal design consistent with Foreman would be:

- Nullable string column (e.g. `workforce_identity`) on `users`.
- Normalize (strip + case fold) into a companion `lower_workforce_identity`.
- Partial unique index on the normalized column **where not null** (PostgreSQL),
  so multiple service accounts may omit the value.
- Model validation + admin/API-only permit; audited changes; safe duplicate error.
- Optional LDAP/OIDC attribute mapping for populate-on-login — never invent values.
- Preserve existing `login` / `lower_login` / password hashes unchanged.

Until the prerequisites above exist, implementation remains out of scope for F-010.

## Operational alternatives (no schema change)

Organizations that already treat the directory username as the personnel key can:

- Configure LDAP `attr_login` (or SSO username) to the unique workforce attribute,
  and rely on existing case-insensitive login uniqueness; or
- Prohibit creating a second local account for the same person via process/policy.

Those are **deployment/policy** choices, not a Foreman personnel-ID subsystem.

## Verification performed

- Branch `security-hardening-5.0`; no user-row mutations for this investigation.
- Confirmed unique `lower_login` index and case-insensitive login collision rejection.
- Confirmed absence of employee-like columns and permitted parameters.
- Confirmed external user path is login-keyed only.

No authentication, password, lockout, login-history, or forced-change behavior was
altered for F-010.
