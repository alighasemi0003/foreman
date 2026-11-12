# Local password expiration (F-007)

## Policy

Locally managed (internal AuthSource) passwords may expire after a configurable
maximum age. LDAP / external / SSO password lifecycle is not managed here.

| Setting | Type | Default | Range |
| --- | --- | --- | --- |
| `password_max_age` | integer (days) | `0` | `0`–`3650` |

`0` disables expiration (explicit supported policy). Changes apply without restart
via the normal Settings registry reload on each request.

## Timestamp

`users.password_changed_at` (UTC) records the last successful local password
assignment or change:

| Event | Updates `password_changed_at`? |
| --- | --- |
| User created with a password | Yes |
| Admin sets / resets password | Yes |
| User changes own password | Yes |
| Mandatory / expired renewal succeeds | Yes |
| Failed password change | No |
| Profile / non-password attribute edits | No |
| Reauthentication / session refresh | No |
| Hash algorithm upgrade on login | No (`update_columns` bypass) |

Expiration is computed as:

`Time.now.utc >= password_changed_at + password_max_age.days`

No separate expiration column is stored.

## Existing users (migration)

On migrate, internal users with a `password_hash` receive
`password_changed_at = UTC now`. That starts the aging clock without inventing a
historical change date and without locking everyone out the moment an
administrator enables `password_max_age`.

If policy is enabled and a local user somehow still has a NULL timestamp, the
account is treated as expired (fail closed).

## Enforcement

`User#password_change_required?` is true when the persisted force flag is set
**or** the password is expired. Existing `PasswordChangeRequired` controller
hooks then:

- Redirect interactive UI to the minimal forced-change form
- Forbid session-backed API / notification chrome
- Allow only `users#edit`, `users#update`, and logout
- Leave PAT / JWT / non-interactive API token auth unchanged

Successful renewal updates `password_changed_at`, clears the force flag when
present, ends the browser session, and requires a fresh login (existing flow).
