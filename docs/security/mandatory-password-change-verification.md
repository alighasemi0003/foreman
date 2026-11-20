# Mandatory first-login password change — verification record

| Field | Value |
| --- | --- |
| Branch | `security-hardening-5.0` |
| Starting HEAD | `f469eee3525fe755aa55dad00098098b311c65fb` |
| Final HEAD | `54be8f4fd37daff4eac1aabb647c3794da0c13f7` |
| Commits | `a692414f5` (enforce), `54be8f4fd` (tests) |
| Push | **NO** |
| Previous image (preserved) | `foreman-local:security-hardening-5.0-1c304efa5` (`3744901085f3`) |
| **New image** | `foreman-local:security-hardening-5.0-54be8f4fd` |
| Image ID | `sha256:5a079d6b6e242aff445c9e9f18afdc8970f206239cfb49c4a241fc2e22679b1e` |
| Image size | ~741MB |
| Compose project | `foreman50-final-verify` |
| docker cp for app source | **No** |

## Backend unit/integration (docker-compose.test.yml)

| Suite | Result |
| --- | --- |
| `user_password_change_required_test` | PASS |
| `users_controller_password_change_required_form_test` | PASS |
| `users_controller_password_change_required_test` | PASS |
| `users_controller_create_reauthentication_test` | PASS (9/9) |
| API users password_change_required cases | PASS |
| Password expiration / history / gate suites | PASS |

## Runtime (final-verify image)

| Check | Result |
| --- | --- |
| Checkbox absent in `/users/new` HTML | PASS |
| Model create forces flag; forged false ignored | PASS |
| Weak change rejected; strong clears flag | PASS |
| Admin reset re-enables flag | PASS |
| First login → `/users/:id/edit` forced form | PASS |
| Dashboard/Hosts/Settings blocked while pending | PASS |
| Successful change → login; old password rejected | PASS |
| FSC1 encrypted session cookie | PASS |
| App restart healthy on new image | PASS |

Technical exception: seed bootstrap admin uses `skip_mandatory_password_change` (documented in `mandatory-first-login-password-change.md`).
