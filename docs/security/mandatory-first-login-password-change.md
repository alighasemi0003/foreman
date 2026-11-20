# Mandatory first-login password change

## Policy

Every newly created **INTERNAL** (local-password) user must change their initial
password after the first successful interactive login, before accessing protected
application functionality.

Administrators cannot opt out. There is no Create User / Edit User checkbox and
no request parameter that disables the requirement.

LDAP / external / SSO users are unchanged: Foreman does not manage their passwords.

## Storage

Column: `users.password_change_required` (boolean, default `false`).

This is an internal security control, not an administrator preference.

## Enforcement points

| Layer | Behavior |
| --- | --- |
| `User#sanitize_password_change_required` | New local users → flag `true`. Admin (non-self) password assignment → flag `true`. External auth → flag `false`. Mass-assignment cannot clear a pending flag. |
| Parameter filter | `:password_change_required` is **not** permitted from UI or API. |
| Create / Edit User form | Checkbox removed; no hidden field. |
| `PasswordChangeRequired` concern | Interactive sessions with the flag are limited to password change, logout, and essential assets. |
| Successful self-service change | `update_column(:password_change_required, false)` after persist; session ended; fresh login required. |

## Trusted exceptions

| Path | Exception |
| --- | --- |
| Seed first interactive admin (`db/seeds.d/035-admin.rb`) | `skip_mandatory_password_change = true` so bootstrap credentials remain usable. |
| Anonymous / hidden auth_source users | `can_set_password?` is false → flag cleared. |
| FactoryBot `:user` (tests) | Skips on create only; cleared after create so admin-reset tests still enforce. |
| Successful password change | Clears via `update_column` (bypasses validations intentionally). |

Do **not** introduce a Setting to disable this policy.

## Admin password reset

When an administrator sets a new password for another local user, the model sets
`password_change_required = true` unconditionally. Non-password profile edits do
not touch the flag.

## Compatibility

Preserves F-007 expiration, F-008 similarity, F-009 history, F-015/F-017 session
and cookie encryption, reauthentication, and bcrypt hashing.
