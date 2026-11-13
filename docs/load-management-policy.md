# Classification-aware load management (F-029)

Audit requirement **61** (چک‌لیست امنیتی، صفحه ۴۷) — finding **4** only.
Findings 1–3 are covered by **F-026** (rate limits), **F-027** (connection
capacity), and **F-028** (request body limits).

| Field | Value |
| --- | --- |
| Status | **POLICY REQUIRED** — no approved availability-tier / SLO policy |
| Branch | `security-hardening-5.0` |
| Enforcement shipped | Admission/capacity controls only (F-026/027/028 + Dynflow queues) |
| Speculative request scheduler | **Not implemented** |

## Audit finding (scope)

Requirement 61 expects availability management under load **in proportion to
classification levels**. The audit noted no mechanism prioritizing requests by
user/data classification under heavy load.

This document defines the policy boundary, inventories workloads, and records
the architecture decision. It does **not** invent an organizational priority
hierarchy or implement a global Rails request scheduler.

## Policy boundary — do not conflate labels

| Concept | Meaning in this repo | Drives CPU/queue priority? |
| --- | --- | --- |
| **Data / output classification** (F-013) | `public` / `internal` / `confidential` / `restricted` on exports | **No** — confidentiality labeling |
| **Security-event classification** (F-031) | Metadata sensitivity on SecurityEvent | **No** |
| **User RBAC / admin role** | Authorization | **No** (auth ≠ urgency) |
| **Business / operational criticality** | How urgently a workload must stay available | **Yes** — if org defines tiers |
| **Availability tier / SLO** | Latency/error budgets under load | **Yes** — prerequisite for enforcement |

**Confidential data does not automatically deserve more CPU than public data.**
Separating confidentiality from request urgency is mandatory.

### Organizational prerequisite (missing)

No organization-approved:

- Availability tiers
- Service Level Objectives (interactive vs batch)
- Mapping from “classification” in the checklist to Foreman workloads

Until those exist, any in-app priority scheduler would be **speculative**.
Per task gate: **document and stop**; do not ship arbitrary scheduling.

## Existing load / availability controls

| Control | Task | Layer | Effect |
| --- | --- | --- | --- |
| HTTP rate limiting | F-026 | Rails middleware + Redis | Per-IP buckets (login/API/UI/unattended) |
| Puma/AR/PG budget | F-027 | Compose/env | Threads ≤ pool; Sidekiq `-c` ≤ pool |
| Request body limits | F-028 | Puma + middleware | Oversized bodies → 413 |
| Dynflow orchestrator | native | Sidekiq `-q dynflow_orchestrator` `-c 1` | Isolates orchestration |
| Worker queues | native | `-q default,1 -q remote_execution,1` | Equal weight today (configurable) |
| Reverse-proxy shaping | deployment | ASSUMED | Edge RPS / timeouts / body limits |

Lab evidence: worker
`sidekiq … -c 5 -q default,1 -q remote_execution,1`; orchestrator
`-c 1 -q dynflow_orchestrator`. No client `X-*-Priority` headers are honored.

## Workload inventory (lab-oriented)

Candidate **operational** classes below are **engineering proposals** for when
an org SLO exists. They are **not** an approved classification policy.

| Workload | Criticality (proposed) | Callers | Cost | Existing protections | Degradation |
| --- | --- | --- | --- | --- | --- |
| Interactive auth / reauth | Highest availability | Users | Low–med | F-026 login bucket; lockout | 429 / lockout — preserve fairness |
| Ordinary UI | High | Users | Med | F-026 general | Slow pages; rate limit |
| Administrative API | High | Admins/automation | Med–high | F-026 api; RBAC | 429; no self-priority |
| Host provisioning / unattended | High (ops) | Hosts/proxies | Med | F-026 unattended; proxy auth | Delayed build |
| Smart Proxy / facts / reports ingest | High (ops) | Proxies | High burst | F-026 api; body limits | Back-pressure via 429/413 |
| Background orchestration (Dynflow) | High | System | Med | Dedicated orchestrator queue | Queue lag observable |
| Remote execution / bulk jobs | Medium | Admins | High | `remote_execution` queue | Worker saturation; do not steal all Puma |
| Inventory CSV / bulk export | Low–med | Authorized users | High IO | F-013 labels; F-019 redact; rate limit | Accept delayed export |
| Long reports / RSS / maintenance | Low | System/admins | High | Background only | Defer under pressure |

**Current SLO:** none recorded for this deployment (latency targets unknown).

## Architecture decision

### Chosen mechanism (when policy is approved)

Smallest Foreman-compatible approach:

1. **Keep** F-026/027/028 as the primary admission and capacity envelope.
2. **Use** Dynflow/Sidekiq **queue isolation and weights** for background
   criticality (e.g. raise weight or dedicated workers for orchestration /
   provisioning-related queues; cap low-priority export workers).
3. **Use** reverse-proxy request shaping for interactive vs batch HTTP paths
   (deployment) — not an in-process global scheduler.
4. **Optional later:** separate Puma process pools only if measured contention
   justifies the ops cost.

### Explicitly rejected now

| Approach | Why rejected |
| --- | --- |
| Priority from F-013 data labels | Confuses confidentiality with urgency |
| Client-supplied priority headers | Trivial DoS / escalation |
| Global Rails controller scheduler | Wrong layer; hurts plugins; hard to reason |
| New message broker | Undemonstrated need |
| Starvation of low priority without SLO | Undefined fairness |

### Security rules for any future priority control

1. Priority assigned **server-side** only (path/role/queue config by operators).
2. Authorization unchanged.
3. Clients cannot escalate via headers/params.
4. Critical interactive paths keep a reserved budget; low priority not starved
   indefinitely (fair weights or min concurrency).
5. Bursts cannot exhaust PG connections (F-027 remains binding).
6. F-026 and F-028 remain active.
7. Queue lag and rejection rates must be observable (metrics/logs).

## Implementation gate result

| Gate question | Answer |
| --- | --- |
| Approved availability classification / SLO? | **No** |
| Implement speculative scheduler? | **No** |
| Deliverable for F-029 | This policy + recommendation |
| Pass criterion for “priority mechanism demonstrated”? | **Not met** until org policy + configured queues/proxy exist |

### Acceptance tests (deferred until policy)

When an org maps workloads → tiers, verify under **bounded** load:

- High-tier interactive traffic retains capacity
- Low-tier exports remain serviceable (not dead)
- Priority headers ignored / ineffective
- DB connections stay within F-027 budget
- F-026 429 and F-028 413 still fire
- Dynflow queue depths visible; no lost critical orchestration plans

Do **not** run destructive stress against the shared lab database.

## Deployment requirements (production)

1. Adopt org SLO / availability tiers (external decision).
2. Map tiers → Sidekiq queue weights / worker pools + proxy limits.
3. Document operator-only config (Compose/Helm values — not end-user settings
   that raise priority).
4. Monitor Puma queue time, Sidekiq latency, PG connections, 429/413 rates.

## Remaining risks

- Under load, all HTTP work still shares Puma workers equally (aside from rate
  limits) until proxy or process-pool separation is deployed.
- Equal Sidekiq weights (`default` vs `remote_execution`) do not encode org
  priority until operators change them under an approved policy.
- Checklist wording “classification” may be misread as F-013; this ADR rejects
  that mapping.

## Related

- [http-rate-limiting.md](http-rate-limiting.md) (F-026)
- [connection-capacity.md](connection-capacity.md) (F-027)
- [http-request-body-limits.md](http-request-body-limits.md) (F-028)
- [output-classification.md](output-classification.md) (F-013 — confidentiality only)
- [security/production-hardening-runbook.md](security/production-hardening-runbook.md)
