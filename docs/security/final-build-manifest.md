# Final security-hardening build manifest (F-FINAL)

| Field | Value |
| --- | --- |
| Branch | `security-hardening-5.0` |
| Starting HEAD (this task) | `f469eee3525fe755aa55dad00098098b311c65fb` |
| Final HEAD | `54be8f4fd37daff4eac1aabb647c3794da0c13f7` |
| Build timestamp (UTC) | From image `BUILD_TIME` (~2026-11-20) |
| Base image | `quay.io/centos/centos:stream9` |
| Ruby | 3.0.7p220 (in image) |
| Bundler | 2.2.33 (frozen `Gemfile.lock`) |
| Previous known-good image | `foreman-local:security-hardening-5.0-1c304efa5` (`3744901085f3`) — **preserved** |
| Intermediate SHA builds | `…-7f0f549a0`, `…-1c304efa5` — **preserved** |
| **Authoritative final image** | `foreman-local:security-hardening-5.0-54be8f4fd` |
| Final image ID | `sha256:5a079d6b6e242aff445c9e9f18afdc8970f206239cfb49c4a241fc2e22679b1e` |
| Final image size | ~741MB |
| Convenience alias | (optional) retag locally; prior `-final` still points at `1c304efa5` |
| Registry digest | local-only (not pushed) |
| Isolated Compose project | `foreman50-final-verify` (`docker-compose.final-verify.yml`) |
| Uncommitted at start | `?? docker-backups/` only (not discarded; not in image) |
| Push | **NO** |
| Mandatory password-change | See `docs/security/mandatory-first-login-password-change.md` and `mandatory-password-change-verification.md` |

Credentials and private keys are **not** recorded in this manifest.
