# Database privilege inventory (F-014)

Lab evidence for Foreman 5.0 on branch `security-hardening-5.0`.
Does **not** revoke production privileges automatically.

## Connection and network

| Item | Lab observation |
| --- | --- |
| URL | `postgres://foreman@db/foreman` (`DATABASE_URL`) |
| Auth | Role password (`md5`); Compose defaults `foreman`/`foreman` |
| `pg_hba` | Local/loopback `trust`; remote `host all all all md5` |
| Listen | `*` inside container network |
| Host publish | Ephemeral `"5432"` — restrict in production |
| App audit of DDL | `log_statement=none` — enable platform DB audit separately |

## Runtime role attributes (lab)

Queried as `current_user=foreman`:

| Attribute | Value | Runtime expectation |
| --- | --- | --- |
| `rolsuper` | **true** | Must be **false** in production runtime |
| `rolcreaterole` | true | false |
| `rolcreatedb` | true | false |
| `rolreplication` | true | false |
| `rolbypassrls` | true | false |
| `rolcanlogin` | true | true (app) |

**Gap:** lab role equals cluster superuser. Documented in the production
hardening runbook; **not** least-privilege.

## Schema and table grants (lab)

| Privilege class | Observation |
| --- | --- |
| Database `CONNECT` / `CREATE` / `TEMP` | All true for `foreman` |
| Schema `public` USAGE / CREATE | Both true |
| Table DML on `public` (89 tables) | SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER |
| Sequences | Owned/usable via table owner (superuser) |
| Extensions | `plpgsql` only |

## Stored routines

| Kind | Count in non-system schemas |
| --- | --- |
| Functions / procedures | **0** |
| User triggers | **0** |
| `GRANT EXECUTE` on app routines | **N/A** (none exist) |

Foreman does not ship application stored procedures. Raw SQL usage is limited
(e.g. advisory locks via `pg_advisory_*`, occasional migration DDL) — still
through the ORM connection, not custom routines.

## Sensitive operations (application layer)

| Operation class | Where enforced today |
| --- | --- |
| User/password changes | Rails models + bcrypt/history policies |
| Role/permission grants | Foreman RBAC (`Authorizable`) |
| Host/ENC/sensitive export | App services + redaction (F-019) |
| Schema migrations | `db:migrate` (needs elevated/migrator role) |
| Session payload | Encrypted AR sessions (F-015) |

**Do not** move these into `SECURITY DEFINER` SQL without a reviewed design.

## Migrator vs runtime (target pattern)

| Role | Purpose | Privileges |
| --- | --- | --- |
| `foreman_migrator` | CI/CD migrate window | DDL on app schema; not used by Puma/Sidekiq |
| `foreman_app` | Puma + Dynflow workers | CONNECT; USAGE on schema; DML + sequences on app tables; **no** SUPERUSER; **no** CREATE on schema in steady state |
| Admin / DBA | Break-glass | Separate human/SSO-backed role; audited |

Application config should point `DATABASE_URL` at `foreman_app` only.

## Validation

```bash
# Advisory inventory (does not change grants)
bundle exec rake security:check_database_privileges

# Optional isolated PoC (creates then drops synthetic schema/roles)
psql "$DATABASE_URL" -f script/security/f014_stored_procedure_poc.sql
```

## Relationship to requirement 37

- Literal SP + `GRANT EXECUTE` for all CRUD: **not implemented** (by design).
- Compensating control: least-privilege ORM roles + network isolation + app RBAC.
- See [adr-stored-procedures-vs-orm.md](adr-stored-procedures-vs-orm.md).

## Related

- [separated-database-deployment.md](separated-database-deployment.md) (F-040)
