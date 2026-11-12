# Successful login history (F-001)

Foreman keeps a bounded per-user history of **successful interactive logins**.

## Event boundary

A history row is created when a user successfully establishes a UI session:

- Local/LDAP password form → `UsersController#login_user`
- External / REMOTE_USER `extlogin` → `login_user`
- Other UI SSO session establishment → `Foreman::Controller::Authentication#set_current_user`

**Not** recorded:

- Failed password or CAPTCHA attempts
- Reauthentication for sensitive actions
- Page refreshes / existing session reuse
- API Basic / PAT / JWT authentication
- Impersonation start (separate audit action)

`users.last_login_on` continues to update via `User#post_successful_login` (including API/PAT paths that already updated it).

## Stored fields

| Column | Meaning |
| --- | --- |
| `user_id` | Authenticated user |
| `logged_in_at` | Server UTC timestamp |
| `remote_ip` | `request.remote_ip` (Rails trusted-proxy aware) |
| `request_host` | Application host the client contacted (`request.host`) |
| `auth_method` | `password`, `ldap`, `external`, or `sso` |
| `auth_source_name` | Auth source name when available |

No passwords, hashes, cookies, session ids, JWTs, PATs, or headers are stored.

**Domain:** only the Foreman request host is stored. Client reverse-DNS / browser domain is not inferred (unreliable / spoofable).

## Retention

Setting `login_history_limit` (default **20**, max **100**) caps rows **per user**.
After each insert, older rows for that user are deleted. Cleanup failures are
logged and do not remove the new row.

## SecurityEvent / Audit

`Audit` login/logout/failed_login events remain unchanged.
`Foreman::SecurityEvent` remains log-oriented (e.g. reauth) and is not the
durable login-history store.

## Retrieval

Model API: `user.login_events.recent_first`. UI listing is deferred to F-003.
Authorization must scope by user / `view_users` when exposing remotely.
