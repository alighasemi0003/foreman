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
| `failed_attempts_before_login` | Prior local password failures in the lockout window (F-002) |

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

## Retrieval (F-003)

| Surface | Path / location |
|---------|-----------------|
| Full history page | `GET /users/:id/login_history` |
| My Account tab | User edit → **Login history** (preview of 5) |
| User menu | **Login history** → current user |

Authorization (server-side):

- Self: `User#editing_self?` includes `login_history` (public `my_account` permission).
- Others: requires `view_users`.
- Forced password-change users cannot open the page (same gate as the rest of the UI).

Display labels:

- **Request host** = Foreman application host (`request.host`), *not* client reverse-DNS.
- **Failed attempts before login** = F-002 snapshot on that successful login row.
- Times rendered with Foreman timezone helpers; UTC ISO stored value shown as secondary text.

Model API remains `user.login_events.recent_first`.
