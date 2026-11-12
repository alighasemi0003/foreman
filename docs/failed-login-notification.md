# Failed login attempt notification (F-002)

## Problem

Local account lockout tracks `failed_login_attempts` on the user row.
Successful authentication calls `reset_failed_login_state!` inside
`User#post_successful_login`, clearing the counter before the UI can tell the
user how many failures preceded the login.

## Counting semantics

The reported number is:

> Unsuccessful **local password** authentication attempts recorded on the user
> account in the **current lockout window**, captured immediately before the
> successful-login reset.

| Event | Affects count? |
| --- | --- |
| Wrong password for an existing internal user | Yes (`register_failed_login!`) |
| CAPTCHA failure | No (credentials never checked) |
| Unknown username | No (no user row to increment; existence not disclosed) |
| LDAP / external / SSO auth | No (lockout applies to internal auth only) |
| Reauthentication failure | Uses lockout helpers but is not an interactive login notice |
| Expired lock auto-clear | Resets window to zero before auth |
| Password change / admin unlock reset | Clears counter without a login notice |

## Mechanism

1. `post_successful_login` sets `user.failed_attempts_before_login` then resets lockout.
2. Interactive `UserLoginEvent` stores `failed_attempts_before_login` (F-001 table).
3. `login_user` / UI SSO queues `session[:failed_login_notice_count]` (+ owner id).
4. Next authenticated HTML request consumes the session keys into a one-shot
   `flash.now[:info]` for the account owner only.
5. Page refresh does not re-show the notice (`flash.now` + session keys deleted).

API / PAT / JWT success may still reset lockout for password logins via
`try_to_login`, but no browser notification is shown for those paths.
