# Separated application / database deployment (F-040)

Audit requirement **79** (چک‌لیست امنیتی، صفحه ۵۶).

| Field | Value |
| --- | --- |
| Status | **DEPLOYMENT DEPENDENT** — architecture + isolated remote connectivity validated; **not** a production dual-server cutover |
| Lab topology | App + PostgreSQL as Compose services on **one** Docker host |
| Compliance note | Two containers on the same host **do not** satisfy separate physical/virtual servers |

## Exact audit finding

Foreman and PostgreSQL ran on the same server. The requirement expects application
and database layers on **separate** physical or virtual servers.

## Phase 1 — Actual lab topology (this branch)

| Component | Lab placement | Uses PostgreSQL? |
| --- | --- | --- |
| `app` (Puma) | Compose service on shared host | Yes — `DATABASE_URL` → `db` |
| `orchestrator` / `worker` (Sidekiq/Dynflow) | Same Compose project | Yes — same URL |
| Migrations / rake | `docker compose run app` | Yes |
| `db` (postgres:12) | Same host, volume `db` | N/A |
| Redis cache/tasks | Same host | No |

| Lab property | Observed |
| --- | --- |
| `DATABASE_URL` default | `postgres://foreman:foreman@db/foreman?pool=5` |
| Auth | Password (`md5`); weak lab defaults |
| `ssl` | **off** |
| `pg_hba` | loopback `trust`; remote `host all all all md5` |
| Role `foreman` | **SUPERUSER** (not production-ready) — see F-014 |
| Host port | Ephemeral publish of `5432` |
| Capacity | F-027 budget ≈ 20 configured connections vs `max_connections` 100 |

**Do not** treat this lab as the production baseline.

## Phase 2 — Proposed production topology

```text
                    ┌─────────────────────────────┐
  Users/proxies ──► │  App tier (VM/host A)       │
                    │  Puma + Sidekiq workers     │
                    │  Redis (or managed cache)   │
                    └─────────────┬───────────────┘
                                  │ TCP 5432 + TLS
                                  │ (allowlist only)
                    ┌─────────────▼───────────────┐
                    │  DB tier (VM/host B)        │
                    │  PostgreSQL only            │
                    │  no Foreman app processes   │
                    └─────────────────────────────┘
```

| Tier | Role |
| --- | --- |
| **Application** | Foreman image: `app`, `orchestrator`, `worker`; reverse proxy/TLS terminator |
| **Database** | Dedicated PostgreSQL VM/cluster; no application containers |
| **Network boundary** | Private DB subnet / security group: **only** app-tier CIDRs → `:5432` |
| **Transport** | `sslmode=verify-full` (or org-approved equivalent) with server CA |
| **DB roles** | `foreman_app` (runtime DML) + `foreman_migrator` (DDL window) — **no** SUPERUSER runtime |
| **Backup** | DB-tier responsibility (`pg_basebackup` / snapshots); encrypted off-host |

Compose multi-service on one host remains a **lab/dev** pattern only.

## Network / firewall matrix

| Source | Destination | Port | Action |
| --- | --- | --- | --- |
| App-tier hosts | DB VIP/host | 5432/tcp | Allow (TLS) |
| Internet / user LAN | DB | 5432 | **Deny** |
| DB tier | App HTTP | 3000/443 | Not required |
| Admin bastion | DB | 5432 | Allow (break-glass, audited) |
| Monitoring | DB metrics exporter | org-defined | Allow |

DNS: stable DB hostname in `DATABASE_URL`. NTP/chrony on both tiers.

## Secure connectivity checklist

1. PostgreSQL `listen_addresses` bound to private interface (not public).
2. `pg_hba.conf`: `hostssl` + scram/md5 for app CIDR only; no `trust` for remote.
3. TLS certs on DB; app URL includes `sslmode=verify-full&sslrootcert=...`.
4. Secrets via env/file mounts — never commit passwords.
5. Runtime role: CONNECT + schema USAGE + table DML + sequences; **no** SUPERUSER.
6. Migrator role used only during controlled migrate jobs.
7. Pool sizing per F-027; `max_connections` headroom ≥20–25%.
8. Auth failure → app fails closed (no silent fallback to local socket DB).
9. Backups encrypted; restore tested on non-prod.
10. Monitor connections, replication lag (if any), disk, TLS errors.

Templates: `deploy/postgres/` and `docker-compose.remote-db.example.yml`.

## Capacity / latency

Reuse F-027 formulas with **network RTT** added:

- Keep `pool ≥ threads` / `pool ≥ sidekiq -c` **per process**.
- Prefer same AZ/region for app and DB to limit latency.
- Optional PgBouncer on DB tier for large replica counts — not required for small deployments.

## Migration / backup / rollback (planning only)

| Step | Owner | Notes |
| --- | --- | --- |
| Provision DB VM + TLS + roles | DBA / Platform | Synthetic/empty DB first |
| `pg_dump` / base backup of source | DBA | Encrypted transport |
| Restore to new DB | DBA | Validate checksums |
| Point staging app at new DSN | App | `sslmode=verify-full` |
| `db:migrate` with **migrator** role | App/CI | Disposable/staging only until approved |
| Cutover | Change control | **Explicit approval required** |
| Rollback | Restore prior DSN + DB snapshot | Prefer restore over `db:rollback` |

**This task does not perform production cutover** and must not delete/migrate the live lab volume.

## Isolated validation evidence (lab)

Performed **without** modifying the live `foreman` Compose DB volume:

| Check | Result |
| --- | --- |
| Separate Compose project `foreman-f040` PostgreSQL | Started on distinct Docker network/volume |
| App container TCP connect to remote hostname | **OK** (`foreman_app` @ `172.23.0.2`) |
| Least-privilege: DML OK, `CREATE TABLE` denied after `REVOKE CREATE … FROM PUBLIC` | **OK** |
| TLS in disposable probe | `ssl_in_use=false` (TLS required in production templates) |
| Live `foreman-db-1` | Remained healthy; no `-v` teardown |
| True separate **hypervisor/VM** servers | **Not tested** → DEPLOYMENT DEPENDENT |

Probe refused DSN hosts `@db/`, `@localhost`, `@127.0.0.1` to avoid silent local fallback.

Re-run connectivity helper: `script/security/f040_remote_db_connectivity_check.sh` (requires an already-reachable remote DSN).

## Production acceptance evidence

Before claiming requirement 79 **PASS**:

1. App and PostgreSQL on distinct VMs/hosts (documented inventory IDs).
2. Firewall proof: DB port unreachable from non-app networks.
3. `DATABASE_URL` with TLS verify; `SHOW ssl` / connection `ssl_in_use` true.
4. Runtime role non-superuser; migrator separated.
5. Login, sessions, Sidekiq job, and migrate on staging remote DB.
6. Backup/restore drill with synthetic data.
7. Outage test: DB stop → app errors visibly (no local DB fallback).

## Remaining risks

- Lab remains co-located (Compose) until platform provisions two tiers.
- Lab SUPERUSER and cleartext DB password must not ship to production.
- TLS not exercised end-to-end in the disposable probe (templates document required settings).

## Related

- [database-privilege-inventory.md](database-privilege-inventory.md) (F-014)
- [connection-capacity.md](../connection-capacity.md) (F-027)
- [production-hardening-runbook.md](production-hardening-runbook.md)
- [adr-stored-procedures-vs-orm.md](adr-stored-procedures-vs-orm.md)
