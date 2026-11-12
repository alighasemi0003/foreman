# Interactive browser session policy (F-016)

## Policy: newer-login-wins

For **interactive browser** sessions (ActiveRecord session store + `session[:user]`):

1. A successful login claims `users.has_active_session`.
2. Other stored session rows for that user are **deleted**, keeping only the
   current Rack private session id.
3. Older browser cookies therefore cannot load an authenticated session.
4. Logout or administrator “terminate session(s)” clears `has_active_session`
   and deletes stored sessions for the user(s). Remaining cookies are rejected
   by `check_active_session`.

Concurrent interactive sessions for the **same** user are not permitted after
the newer login completes.

## Out of scope

- Personal Access Tokens
- JWT / registration tokens
- Non-interactive API basic auth (`api_authenticated_session`)
- Background jobs

Failed password / CAPTCHA attempts do not claim or replace the active session.
Reauthentication is not a new login and does not invalidate other sessions.
