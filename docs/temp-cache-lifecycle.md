# Temporary file and cache lifecycle (F-020)

Audit requirement **54** (چک‌لیست امنیتی، صفحات ۴۲–۴۳).

## Exact finding

The audit observed:

- Correct `Tempfile.open` block usage in places, but temporary/cache artifacts
  remaining after process termination
- ~23 MiB FileStore cache (3399 files) under `tmp/cache` in the **audited**
  environment
- No demonstrated shutdown cleanup hooks or periodic retention policy

Runtime PID / state / sockets are **out of scope** here (F-021).

## Current Docker Compose runtime (lab)

| Item | Value |
| --- | --- |
| Cache backend | `RedisCacheStore` (`FOREMAN_RAILS_CACHE_STORE_TYPE=redis`) |
| Redis URL | `redis://redis-cache:6379/0` (namespace `foreman`) |
| `tmp/cache` FileStore tree | Present but **empty** (not the active store) |
| Audited FileStore 23 MiB finding | **Does not apply** to this runtime unchanged |

FileStore remains the **fallback** when Redis is not configured
(`config/application.rb`).

## Artifact classification

| Class | Location | Owner | Lifetime | Sensitive? | Cleanup |
| --- | --- | --- | --- | --- | --- |
| Request / provision tempfiles | `Rails.root/tmp/<Tempfile>` | App | Request / orchestration step | Yes (finish templates, CA PEM) | Explicit `close!` / `Tempfile.create`; orphan age ≥1h |
| Regenerable FileStore cache | `tmp/cache/` | Rails FileStore | Default `expires_in` 12h | Generally non-secret UI/API cache; treat as regenerable | `Rails.cache.cleanup` + hard age 7d |
| Redis application cache | redis-cache DB | Rails RedisCacheStore | Per-key `expires_in` | Rate-limit counters, facts snippets, etc. | Writer TTL only — **no FLUSH** |
| Runtime PID / sockets / puma.state | `tmp/pids`, `tmp/sockets`, `puma.state` | Puma | Process lifetime | Low | **F-021** (`docs/runtime-state-lifecycle.md`) — preserved by F-020 |
| Secret token file | `tmp/secret_token` | App boot | Persistent across restart | Yes | **Never deleted** by F-020 |
| Logs / audits | `log/`, DB audits, collector | Logging | Policy-specific | Yes | Untouched |
| Business data | PostgreSQL | App | Persistent | Yes | Untouched |

## Cleanup policy

| Mechanism | When | Scope |
| --- | --- | --- |
| `Tempfile.create` (CA bundle) | End of block | Immediate unlink |
| SSH provision `ensure` / `del*` | After deploy or rollback | Finish-template tempfile `close!` |
| Startup `Foreman::TempCacheLifecycle.startup_cleanup!` | Web boot (`after_initialize`) | Orphans under `tmp/` older than 1h; FileStore `cleanup` + 7d hard prune |
| Daily cron `tmp:cache_lifecycle` | `Foreman::Cron` daily | Same as periodic cleanup |
| FileStore default `expires_in: 12.hours` | On write without explicit TTL | Bounds fallback FileStore only |
| Redis | N/A for mass delete | Keys use writer `expires_in`; live Redis not pruned |

### Safeguards

- Cleanup roots must resolve under `Rails.root/tmp` (realpath containment)
- Symlink entries are skipped (no follow / no escape)
- Preserved: `pids/`, `sockets/`, `secret_token`, `restart.txt`, `puma.state`, and
  the `cache/` directory tree except via FileStore APIs / hard prune of regular
  files under the FileStore path
- No recursive wipe of all of `tmp/`
- No Docker volume prune, no Redis `FLUSHDB`
- `FOREMAN_SKIP_TMP_CACHE_CLEANUP=1` disables startup/periodic runners
- Startup skips when top-level rake is `db:` / `assets:` / `webpack:` / `plugin:`
- `at_exit` is **not** relied on (SIGKILL / crash → startup + cron recovery)

## Observability

Structured app log lines:

- `F020_TMP_CLEANUP source=… backend=… orphans_removed=… …`
- `F020_SSH_TEMPFILE_CLEANUP` on unexpected unlink errors
- Rake prints the report hash

## Operator commands

```bash
# Manual / cron entry (also registered as daily Foreman::Cron task)
bundle exec rake tmp:cache_lifecycle

# Disable automatic cleanup
export FOREMAN_SKIP_TMP_CACHE_CLEANUP=1
```

## Relation to Redis vs FileStore

| Backend | Retention |
| --- | --- |
| Redis (lab / recommended prod) | Per-key TTL from callers; F-020 does not delete keys |
| FileStore (fallback) | Default 12h expiry + `cleanup` + 7-day hard prune of stale files |

## Tests

See `test/unit/foreman/temp_cache_lifecycle_test.rb`.
