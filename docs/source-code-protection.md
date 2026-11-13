# Source-code protection and distribution assessment (F-039)

Audit requirement **78** (چک‌لیست امنیتی، صفحه ۵۶).

Frontend production source maps are covered by **F-038**
(`docs/production-source-maps.md`). This document addresses backend Ruby
readability, obfuscation, and classified-source expectations.

## Status summary

| Claim | Result |
| --- | --- |
| Backend Ruby readable as plaintext in the runtime image | **Yes** (required for Rails) |
| Backend Ruby publicly downloadable over HTTP | **No** (verified 404) |
| Production source maps publicly downloadable | **No** after F-038 |
| Source-code encryption / protected compilation | **Not implemented** — and **not selected** as baseline |
| Organizational classified-source policy | **Not supplied** |
| Assessment status | **POLICY REQUIRED** for classified encryption; **PASS** for proportionate open-source baseline |

## Original audit finding

- Backend Ruby stored in readable plaintext
- No backend obfuscation / protected compilation demonstrated
- Frontend source maps facilitated inspection (F-038)
- No source-code encryption demonstrated
- Requirement expects reverse-engineering resistance and extra protection for
  classified/secret systems

## Distribution architecture (this lab)

| Element | Observation |
| --- | --- |
| License | GNU GPL (and related notices in `LICENSE`) — open-source Foreman |
| Runtime image | Contains application Ruby under `/home/foreman` (UID **1001** `foreman`) |
| Final Dockerfile stage | `COPY .` then overlays `vendor/ruby` + `public` from builder |
| Public web root | `public/` — webpack bundles, assets; **0** `.rb` files observed |
| HTTP static serving | `RAILS_SERVE_STATIC_FILES=true` serves **only** `public/` |
| Test tree in older images | Present (~7 MiB); excluded going forward (`.dockerignore` + image `rm`) |
| Secrets in image | `encryption_key.rb` / `local_secret_token.rb` excluded via `.dockerignore` |

**Readable to a container filesystem reader ≠ publicly served over HTTP.**

## Threat model

| Attacker | Can obtain Ruby source? | Primary control |
| --- | --- | --- |
| Unauthenticated web user | **No** (HTTP 404 for `/app/**/*.rb`) | Do not put source under `public/`; middleware deny |
| Authenticated ordinary user | **No** via HTTP | Same |
| Foreman admin (UI) | Not via normal UI file download | RBAC; no source browser |
| Compromised app UID (1001) | **Yes** — full tree on disk | Host/K8s isolation; secrets not in tree |
| Image registry recipient | **Yes** if they can pull the image | Private registry + access control |
| Host root | **Yes** | Host hardening; encrypted disks (infra) |
| Insider with git access | **Yes** | Repo ACL; GPL already publishes upstream |

### Sensitive assets (distinct)

| Asset | Protection approach |
| --- | --- |
| Upstream / fork source | GPL transparency; not “secret” |
| Proprietary local patches | Repo ACL + private image registry (org decision) |
| Secrets / keys | Env / secret mounts — **never** in source or image layers |
| Operational topology | Network / RBAC / logging policy |
| Debug artifacts | F-038 maps; strip from `public/` |

**Obfuscation does not protect embedded secrets.** Secrets must not ship in source or layers.

## Organizational classification

**No approved policy** in-repo requiring encrypted source distribution for this
deployment. Do **not** invent a secrecy classification.

If a classified system **mandates** encrypted source, the org must approve:

- Encryption boundary (at rest in registry vs at rest on disk vs transit)
- Key ownership and escrow
- Runtime decryption (who decrypts, where keys live)
- Threats covered vs residual (memory disclosure after load)
- Rollback / patching workflow
- Licensing obligations for GPL-derived code (corresponding source)

Until then: **do not** implement home-grown Ruby encryption/decryption.

## Controls evaluated

| Control | Threat reduction | Complexity | Selected? |
| --- | --- | --- | --- |
| F-038 remove/block public maps | High vs web RE of frontend | Low | **Yes** (done) |
| Exclude test/dev from runtime image | Low–med vs image dump size | Low | **Yes** |
| Block source-like HTTP paths | Low (defense in depth) | Low | **Yes** |
| Least-privilege UID 1001 | Baseline | Low | Already |
| Private registry / image ACL | High vs unauthorized image pull | Ops | **Document** |
| Image signing | Integrity, not confidentiality | Ops | **Document** |
| Ruby obfuscation | Weak vs determined reader; hurts IR/debug; GPL source still required on distribution | High | **No** |
| Homemade source encryption | False sense of security; key-in-image fails open | Very high | **No** |
| Compile-only packaging | Incompatible with Rails autoload/plugins | Very high | **No** |

## Selected baseline (proportionate)

1. Keep Rails Ruby source in the image (required to boot).
2. Ensure source is **not** HTTP-reachable (verify + middleware).
3. Keep production maps non-public (F-038).
4. Slim the runtime image (exclude `test/` / CI debris).
5. Keep secrets out of build context (existing `.dockerignore`).
6. Document registry access and signing as **platform** responsibilities.
7. Treat classified source-encryption as **POLICY REQUIRED** — external decision.

## Minimal changes in this task

- `.dockerignore` — exclude `test/`, `spec/`, `docker-backups/`, `jenkins/`
- Dockerfile final stage — `rm -rf test spec …` and scrub stray `public/**/*.rb`
- Expand `BlockSourceMaps` to deny source-tree URL prefixes and source extensions under static paths
- `rake security:check_public_source_exposure` — fail if debug/source files appear under `public/`
- This assessment document

## Verification evidence (lab)

| Check | Result |
| --- | --- |
| `GET /app/models/user.rb` | 404 |
| `GET /config/application.rb` | 404 |
| `GET /webpack/*.map` | 404 (`X-Foreman-SourceMap: blocked`) |
| `public/**/*.rb` count | 0 |
| `/users/login` | 200 |
| App UID | 1001 |

## Remaining risks

- Anyone who can pull or exec into the image can read Ruby (by design for Rails + GPL).
- Obfuscation was **not** applied and would not meet a true classified encryption mandate.
- Platform must enforce private registries, host filesystem ACLs, and secret injection.
- Full image rebuild required for `.dockerignore` / Dockerfile slim-down to appear in new images; running lab containers may still contain `test/` until recreated.
