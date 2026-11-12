# Output information classification (F-013)

Audit requirement **34** (چک‌لیست امنیتی، صفحه ۳۰).

Complements **F-019** field redaction (`docs/export-sensitive-data.md`). Classification
labels mark **outputs**; they do not replace authorization or redaction.

## Organizational policy assumption

No organization-approved classification scheme is embedded in Foreman. This branch
ships a **proposed** four-level policy that administrators may map to local
standards. Setting `output_classification_enabled` (General) toggles labeling.

| ID | Display label | Typical Foreman outputs |
| --- | --- | --- |
| `public` | Public | Reserved (core exports are not public) |
| `internal` | Internal | Host/hostgroup/fact/report CSV; template ERB export; UI HTML |
| `confidential` | Confidential | Host ENC/YAML and inherited parameters with secrets redacted |
| `restricted` | Restricted | ENC/YAML with secrets revealed; compute SSH private key PEM |

Mixed-sensitivity outputs use the **highest** applicable level.

## Format-specific representation

| Format | Label mechanism |
| --- | --- |
| HTTP (all labeled downloads / UI HTML) | `X-Foreman-Classification`, `X-Foreman-Classification-Label`, `X-Foreman-Classification-Policy` |
| CSV | Headers only — **no** preamble rows (keeps parsers intact) |
| JSON ENC / inherited parameters | Headers only — response schema unchanged |
| YAML host export | Comment preamble above the document + headers |
| Printable HTML | Meta tags + print-only banner (CSS `@media print`) |
| PDF | Not a core Foreman export format — **unsupported** (report plugins may add later) |
| PEM key download | Headers + existing no-store cache policy |

Clients **cannot** lower classification by passing request parameters.

## Third-party / integration transfers

- Smart-proxy and provisioning template **render** paths remain operational (F-019
  category 3) and are not re-labeled as public.
- API ENC / inventory CSV downloads carry classification headers for consuming
  systems that honor them.
- Systems that ignore HTTP headers still receive F-019 redaction on general exports.

## Redaction compatibility

F-019 continues to redact hidden parameters for unauthorized viewers. Revealing
secrets (authorized `edit_params`) raises the label from confidential to
restricted; it does not mark the export public.
