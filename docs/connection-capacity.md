# Puma, ActiveRecord pool, and PostgreSQL capacity (F-027)

## Rule

For **each** Ruby process that uses ActiveRecord:

```text
max concurrent DB checkouts needed  ≤  ActiveRecord pool size
```

- **Puma worker:** `FOREMAN_PUMA_THREADS_MAX` (falls back to `RAILS_MAX_THREADS`) ≤ `pool`
- **Sidekiq:** `-c` / concurrency ≤ `pool`
- Each Puma **worker** is a separate process with its **own** pool (not shared)

## Local Compose budget (defaults)

| Process | Count | Pool | Concurrency knobs | Max connections |
|---------|------:|-----:|-------------------|----------------:|
| App (Puma workers) | 2 | 5 | `FOREMAN_PUMA_THREADS_MAX=5` | 10 |
| Orchestrator (Sidekiq) | 1 | 5 | `-c 1` | 5 |
| Worker (Sidekiq) | 1 | 5 | `FOREMAN_SIDEKIQ_CONCURRENCY=5` | 5 |
| **Configured total** | | | | **20** |
| PostgreSQL `max_connections` (image default) | | | | **100** |
| **Headroom** | | | | **~80** |

App replicas: **1** in `docker-compose.yml`. Multiplying app services multiplies the app row.

Formula:

```text
app_demand   = replicas × FOREMAN_PUMA_WORKERS × pool
bg_demand    = Σ (sidekiq_processes × pool)
total_budget = app_demand + bg_demand + admin/migrate/monitor headroom
total_budget ≤ PostgreSQL max_connections − reserved_superuser
```

## Mismatch that F-027 fixed

Before alignment on this lab stack:

| Setting | Value | Problem |
|---------|-------|---------|
| `DATABASE_URL` pool | 5 | |
| `RAILS_MAX_THREADS` | 5 | Not read by Puma previously |
| `FOREMAN_PUMA_THREADS_MAX` | unset → **16** | Threads ≫ pool → checkout waits / timeouts under burst |
| Sidekiq worker `-c` | **15** | Concurrency ≫ pool |

After: Puma max threads fall back to `RAILS_MAX_THREADS`; Compose sets
`FOREMAN_PUMA_THREADS_MAX=5` and Sidekiq worker concurrency **5**.

## Production sizing (separate from lab)

1. Measure CPU/RAM and expected RPS.
2. Choose `workers` ≈ CPU cores (with headroom), `threads` for IO-bound mix.
3. Set `pool ≥ threads` (Puma) and `pool ≥ sidekiq -c`.
4. Sum all Foreman processes connecting to the same Postgres.
5. Keep **≥20–25%** of `max_connections` free for migrations, admin, failover.
6. Raise `max_connections` only after checking Postgres RAM (`shared_buffers`,
   work_mem × connections). Prefer fewer fat processes over unbounded pools.
7. PgBouncer is optional and **not** required for this lab alignment.

## Environment variables

| Variable | Role |
|----------|------|
| `DATABASE_URL` `?pool=` | ActiveRecord pool per process |
| `RAILS_MAX_THREADS` | Fallback for Puma max threads |
| `FOREMAN_PUMA_THREADS_MIN` / `_MAX` | Puma thread range |
| `FOREMAN_PUMA_WORKERS` | Puma cluster workers |
| `FOREMAN_SIDEKIQ_CONCURRENCY` | Compose worker Sidekiq `-c` |

## What this does not claim

Lab defaults are for **local verification**, not production capacity certification.
Hardware limits may be lower than the Postgres `max_connections` ceiling.
