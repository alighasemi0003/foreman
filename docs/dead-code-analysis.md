# Dead-code analysis process (F-036)

Audit requirement **75** (چک‌لیست امنیتی، صفحات ۵۴–۵۵).

| Field | Value |
| --- | --- |
| Status | **ANALYSIS COMPLETE** — reproducible process; **no** bulk deletion |
| Production code removed this task | **None** (no confirmed-unused candidates established) |
| Automation | Advisory report only |

## Exact audit findings

1. No demonstrated automated process for identifying/cleaning unused methods.
2. Unused-related RuboCop rules disabled/ignored in `.rubocop_todo.yml`.
3. Many public controller methods without explicit route mappings (~3484 historically).

These indicate **insufficient analysis**, not proof that reported methods are unused.

## Why Rails defeats naive unused-method counts

Public methods may be reached via:

- Routes (including engines/plugins)
- `before_action` / `after_action` / `around_action`
- `method_missing` / `send` / `public_send` / `constantize`
- ActiveSupport::Concern inclusion
- ActiveRecord callbacks and reflections
- Serializers, GraphQL, Apipie
- Dynflow/Sidekiq / rake
- Plugin extension points and overrides
- Tests and factories

**Lack of a textual reference does not prove dead code.**  
**Absence from `rails routes` does not prove a public method is unused.**

## RuboCop baseline (this branch)

| Cop | `.rubocop_todo.yml` | Rationale for current state |
| --- | --- | --- |
| `Lint/UnusedBlockArgument` | **Enabled: false** | High noise; many intentional ignored args in blocks |
| `Lint/UnusedMethodArgument` | **Enabled: false** | Same — interface/override signatures |

Re-enabling these globally would create large CI failure sets without proving
methods are unreachable. Prefer incremental, file-scoped cleanup PRs.

CI already runs `bundle exec rubocop -P` (`.github/workflows/foreman.yml`).

## Tooling (preferred: in-repo)

| Tool | Role |
| --- | --- |
| `rake security:dead_code_report` | Non-destructive JSON report: RuboCop unused-cop status, route counts, controller action **candidates** |
| RuboCop | Style/lint; unused-arg cops remain off until curated |
| Manual review + runtime/tests | Required before any deletion |

Do **not** add heavyweight unused-method gems that misunderstand Rails dynamics
without a clear benefit.

## Candidate categories

| Category | Meaning | Auto-delete? |
| --- | --- | --- |
| `confirmed_unused` | Human + tests + routes/callbacks prove unreachable | Manual PR only |
| `probably_unused_review_required` | Scanner candidate (e.g. public method ∉ routes) | **No** |
| `dynamically_used` | Known send/callback/plugin use | **No** |
| `public_extension_api` | Plugin/override contract | **No** |
| `deprecated_compatibility` | Kept for compatibility | **No** |
| `unknown` | Insufficient evidence | **No** |

## Safe cleanup checklist (confirmed_unused only)

1. Smallest isolated removal.
2. Grep for dynamic references (`send`, symbols, strings).
3. Check routes, permissions, Apipie, GraphQL.
4. Run targeted tests; boot app; `rails routes` smoke.
5. Security regression for touched authz/crypto/session paths — **do not**
   remove untested security failure branches.
6. Separate commit; document evidence in the commit body.
7. Never combine with unrelated refactors.

## Continuous prevention

```bash
# Advisory — exit 0; does not delete code
bundle exec rake security:dead_code_report
```

Optional: schedule in CI as a **report artifact** (do not fail on thousands of
`probably_unused_review_required` rows). Fail CI only on explicit policy after
curated `confirmed_unused` handling — not on raw scanner volume.

`FOREMAN_DEAD_CODE_ENFORCE=1` only surfaces a warning when the confirmed
inventory is non-empty (still no deletion).

## Lab baseline snapshot

Captured on `security-hardening-5.0` (order-of-magnitude; re-run the rake for
current numbers):

| Metric | Observation |
| --- | --- |
| Routed controller actions | ~749 |
| Audit historical “3484 unused” | **Not treated as accurate** for this tree |
| Confirmed unused removed | 0 |

HostsController example: own public methods can be **fewer** than routed
actions (inheritance). Route-less public names are often accessors/helpers —
high false-positive risk.

## Remaining uncertainty

Until org capacity exists for method-by-method confirmation, the large set of
route-less public methods remains **review-required**, not deleted. Security
hardening methods introduced on this branch are treated as **dynamically used /
required** unless proven otherwise.
