# ADR: Stored procedures vs ActiveRecord (F-014 / requirement 37)

| Field | Value |
| --- | --- |
| Status | **Accepted compensating baseline**; full SP rewrite **ARCHITECTURE DECISION REQUIRED** |
| Date | 2026-11-13 |
| Branch | `security-hardening-5.0` |
| Audit | Requirement 37 (چک‌لیست، صفحات ۳۱–۳۲) |
| Companion | [database-privilege-inventory.md](database-privilege-inventory.md) |

## Context

The audit expects database interaction through stored procedures with restricted
`GRANT EXECUTE` privileges. Foreman 5.0 persists through **ActiveRecord**
(~228 models, ~408 migrations, 89 tables in the lab DB). No application
user-defined functions, procedures, or triggers exist in the live database.

This is an **architectural** requirement. ActiveRecord alone is not treated as
proof of a vulnerability; moving authorization into SQL without a reviewed
design would be a larger risk.

## Decision drivers

- Upstream Foreman and plugins assume ORM CRUD, associations, and callbacks.
- Application RBAC (`Authorizable`, taxonomy scopes) lives in Ruby, not SQL.
- Rails migrations, seeds, and Dynflow workers need schema/DML access patterns
  incompatible with a sudden procedure-only boundary.
- PostgreSQL functions default to `PUBLIC EXECUTE` unless revoked — cosmetic
  procedures without privilege design do not improve security.
- `SECURITY DEFINER` without locked `search_path` and audited grants can bypass
  intended authorization.

## Options considered

| Option | Summary | Verdict |
| --- | --- | --- |
| **A. Full stored-procedure-only access** | Replace all ORM DML with routines + revoke table grants | **Rejected for this task** — breaks upstream compatibility, plugins, migrations, Dynflow; multi-year rewrite; no approved architecture |
| **B. Selective procedures for sensitive ops** | Few audited routines (e.g. credential rotation) with INVOKER + tight EXECUTE | **Optional future** — only with named operations, tests, and RBAC still in app |
| **C. ORM + least-privilege roles** | Separate migrator vs runtime roles; CONNECT/USAGE + table DML only; no SUPERUSER at runtime | **Selected baseline** |
| **D. Views / RLS** | Restrict columns/rows in PostgreSQL | **Deferred** — possible later; RLS must not contradict Foreman taxonomy/RBAC |

### Evaluation (requirement-facing)

| Criterion | A | B | C | D |
| --- | --- | --- | --- | --- |
| Feasibility now | Very low | Medium | High | Medium |
| Upstream compatibility | Breaks | Localized risk | Preserved | Needs design |
| Migration complexity | Extreme | Moderate | Moderate (ops) | High |
| Authorization semantics | Easy to diverge from app RBAC | Must stay app-led | App RBAC retained | Dual models |
| Security benefit | Unproven vs cost | Targeted | Real (privilege reduction) | Targeted |
| Upgrade / plugin impact | Severe | Contained | Low if roles correct | Medium |

## Decision

1. **Do not** rewrite ActiveRecord to stored-procedure-only access in this
   hardening branch.
2. Treat requirement 37’s SP mandate as **not met literally**; document the
   **deviation** and **compensating controls** (option C).
3. Prefer **native PostgreSQL least privilege**:
   - Runtime app role: `CONNECT`, schema `USAGE`, table `SELECT/INSERT/UPDATE/DELETE`,
     sequence `USAGE/SELECT` — **no** `SUPERUSER`, `CREATEDB`, `CREATEROLE`,
     `BYPASSRLS`, or routine DDL.
   - Migrator / admin role: schema changes only during controlled migrate windows.
4. Any future selective function (**B**) must be:
   - `SECURITY INVOKER` by default
   - `SET search_path` fixed
   - `REVOKE ALL … FROM PUBLIC` then explicit `GRANT EXECUTE`
   - Covered by tests proving unauthorized roles fail
   - Never a substitute for Foreman authorization checks
5. Full SP architecture remains an **organization architecture decision** if
   policy insists on procedure-only access despite Foreman’s design.

## Consequences

- Lab Compose currently uses a **SUPERUSER** `foreman` role — documented gap;
  production must not copy this pattern (see privilege inventory).
- Compliance checklists that require SP-only CRUD will show a documented
  **deviation** until an approved rewrite or formal acceptance of option C.
- Incident response and upgrades remain supportable (plain SQL via ORM).

## Evidence

- Live inventory: 0 user functions/procedures/triggers; extension `plpgsql` only.
- Synthetic PoC (cleaned up): `f014_poc.insert_item` with INVOKER, PUBLIC
  EXECUTE revoked, authorized role succeeds, unauthorized role denied — proves
  PostgreSQL can enforce `GRANT EXECUTE` **when** routines exist; it does not
  justify converting Foreman CRUD.

## Related

- [database-privilege-inventory.md](database-privilege-inventory.md)
- Production hardening runbook § DB role notes
- F-015 session encryption (data-at-rest for sessions — orthogonal to SP access)
