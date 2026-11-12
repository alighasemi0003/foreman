# Runtime PID, state and socket lifecycle (F-021)

Audit requirement **54** (چک‌لیست امنیتی، صفحات ۴۲–۴۳) — runtime artifacts
portion. General temporary/cache cleanup is **F-020**
(`docs/temp-cache-lifecycle.md`).

## Exact finding

The audit observed residual Puma state, test reporter files
(`foreman_minitest_reporters_*`), leftover Unix sockets, and missing documented
shutdown / Systemd `ExecStopPost` / `tmpfiles.d` policy.

## Runtime environment (this lab)

| Property | Value |
| --- | --- |
| Deployment | Docker Compose (`docker-compose.yml`) |
| PID 1 | Puma / `bin/rails server` (not Systemd) |
| Systemd in container | **No** |
| Packaged Systemd units | `extras/systemd/*` (for RPM/host installs only) |

Do **not** assume Systemd hooks run under Compose. Compose relies on:

1. Container **entrypoint** pre-start cleanup
2. Puma SIGTERM on `docker stop` (`stop_grace_period: 30s`)
3. Rails `after_initialize` maintenance
4. Daily rake `tmp:runtime_state`

## Artifact inventory

| Artifact | Path | Producer | Permissions (target) | Lifecycle | Safe removal |
| --- | --- | --- | --- | --- | --- |
| PID file | `tmp/pids/server.pid` | Puma / Rails server | dir `0750`, file `0644` | Process lifetime | Only if PID dead or not a Foreman/Puma cmdline |
| Puma state | `tmp/puma.state` | Puma | `0640` | Process lifetime | Only if embedded pid dead / not ours |
| Control socket | `tmp/sockets/pumactl.sock` | Puma | dir `0750`, sock `0660` | Process lifetime | Only if unused (no fd / connect fails) |
| Test reporters | `tmp/test/foreman_minitest_reporters_*` | Minitest (test only) | `0640` area | Test runs | Age ≥ 24h |
| Cache | `tmp/cache/` | F-020 | — | — | F-020 |
| Secret token | `tmp/secret_token` | Boot | `0600` | Persistent | **Never** by F-021 |
| Logs / audits | `log/`, DB, collector | Logging | — | Policy | **Never** |

## Cleanup mechanisms

| Stage | Tool | Behavior |
| --- | --- | --- |
| Container start | `entrypoint.sh` → `safe_clean_runtime_state.rb` | `prestart_cleanup!` before `exec` server |
| Puma boot | `config/puma/production.rb` | Ensure dirs; `pidfile`; `state_permission 0640`; `on_booted` harden modes |
| Rails boot | `runtime_state_lifecycle` initializer | `runtime_maintenance!` (preserves live PID/socket) |
| Daily cron | `tmp:runtime_state` | Same maintenance |
| Compose stop | SIGTERM + `stop_grace_period: 30s` | Puma releases artifacts |
| Systemd (packaged) | `ExecStartPre` + optional `foreman-tmpfiles.conf` | Not used in Compose lab |

### Safeguards

- No `rm -rf tmp`
- No process kill from cleanup
- Symlink entries skipped (no escape)
- Active PID (alive + cmdline looks like puma/rails) preserved
- Active sockets preserved
- `FOREMAN_SKIP_RUNTIME_STATE_CLEANUP=1` disables cleaners

## Operator commands

```bash
# Manual maintenance (preserves live state)
bundle exec rake tmp:runtime_state

# Pre-start style cleanup (entrypoint equivalent)
ruby extras/containers/safe_clean_runtime_state.rb /path/to/foreman
```

## Systemd vs Compose

| Concern | Compose lab | Systemd package |
| --- | --- | --- |
| Init | Docker + entrypoint | Systemd |
| Stale cleanup | entrypoint script | `ExecStartPre=…safe_clean_runtime_state.rb` |
| Volatile dirs | `tmp/` in container FS | Optional `tmpfiles.d` → `/run/foreman` |
| Stop | `docker stop` SIGTERM | `KillMode=mixed` + `TimeoutStopSec=30` |

## Tests

`test/unit/foreman/runtime_state_lifecycle_test.rb`
