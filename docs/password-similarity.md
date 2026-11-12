# Minimum password-change difference (F-008)

Audit requirement **15**, subrequirement **4** (چک‌لیست امنیتی، صفحات ۱۷–۱۸).

## Requirement

A new local password must differ from the **previous** password by at least
**four characters**. The audit rejects a check that only forbids exact equality
(`ensure_new_password_differs_from_current`).

The audit mentions Levenshtein distance as an example and does **not** mandate
one algorithm. This branch adopts:

> **Unicode character Levenshtein edit distance ≥ 4**
> (insertions, deletions, and substitutions each count as one edit).

Comparison is **character-based** (`String#each_char` / UTF-8 codepoints), not
byte-based. Inputs are truncated to **256** characters for the distance matrix
only (bounded CPU); complexity and history rules still apply to the full string.

## Password secrecy

Stored passwords remain one-way hashes. This rule **never** recovers a password
from a hash and **never** stores plaintext for later comparison.

| Path | Prior plaintext available? | Similarity (edit distance) | Identity (hash) | History (F-009) |
|------|----------------------------|----------------------------|-----------------|-----------------|
| Self-service / forced change / API self-update with `current_password` | Yes (request field, verified) | **Enforced** | Enforced | Enforced |
| Administrator reset of another user (no `current_password`) | No | **Not applicable** (documented limitation) | Enforced | Enforced |
| New user create | No prior password | Skipped | Skipped | Skipped |
| LDAP / external | `manage_password?` false | Skipped | Skipped | Skipped |

## Interaction with other controls

Order of local password validations (conceptual):

1. Complexity (F-006 family)
2. Current hash non-identity (`ensure_new_password_differs_from_current`)
3. Edit-distance ≥ 4 when `current_password` present (F-008)
4. Password history (F-009)

Appending three characters to a near-identical password yields distance 3 and is
**rejected**. Distance 4+ still must satisfy complexity and history.

## User-facing error

`The new password must differ from the current password by at least 4 characters.`

Does not echo the current or candidate password.
