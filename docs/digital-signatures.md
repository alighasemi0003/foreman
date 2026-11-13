# Application-level digital signatures (F-032)

Audit requirement **67** (چک‌لیست امنیتی، صفحه ۵۰).
Coordinates with **F-033** (CMS/PKCS#7 compatibility).

| Field | Value |
| --- | --- |
| Status | **Implemented** for a narrow export use case (lab keys required) |
| Format | CMS/PKCS#7 **detached** signature (`OpenSSL::PKCS7`) |
| Digest | SHA-256 |
| Default unsigned exports | **Unchanged** |

TLS protects transit only. This control signs **application data bytes**.

## Applicable use case

| Item | Choice |
| --- | --- |
| Document | Inventory / report **CSV export** bytes (exact body that would be downloaded) |
| Trigger | `digital_signature=1` (or `true`) on CSV export actions using `CsvResponder` |
| Unsigned path | Default streaming `text/csv` — no signature, no format change |
| Signed path | `application/vnd.foreman.signed-export+json` envelope with payload + detached PKCS#7 |
| Not in scope | Automatic signing of all HTTP/API responses |

## Architecture

```
authorized CSV export → materialize exact UTF-8 CSV bytes
                     → OpenSSL::PKCS7.sign(DETACHED|BINARY, SHA-256)
                     → JSON envelope (payload_base64 + signature_pem + cert PEM)
                     → SecurityEvent DIGITAL_SIGNATURE_CREATED
```

Verifier reconstructs the file from `payload_base64` and checks the PEM with
OpenSSL (independent of Rails):

```bash
base64 -d payload.b64 > hosts.csv
# signature_pem → hosts.csv.p7s ; certificate_pem → signer.crt
openssl smime -verify -in hosts.csv.p7s -inform PEM -content hosts.csv \
  -CAfile signer.crt -binary -noverify   # or proper CA store in production
```

Ruby: `Foreman::DigitalSignature.verify(payload, signature_pem, certificate_pem: ...)`.

## Signer identity and keys

| Topic | Policy |
| --- | --- |
| Signer | Organization **signing certificate** subject (not the end-user) |
| Authorization | Authenticated user; `admin` or `view_hosts` (export already authorized) |
| Private key | `FOREMAN_SIGNING_KEY_FILE` (PEM) — **never** in browser/Git |
| Certificate | `FOREMAN_SIGNING_CERT_FILE` (PEM) |
| Enable flag | `FOREMAN_SIGNING_ENABLED=true` (optional gate for ops visibility) |
| Forbidden | Reuse of `ENCRYPTION_KEY` / `secret_key_base` as signing key |
| Rotation | Replace key+cert files; restart app; old signatures verify with old cert archive |
| Expired cert | Signing **rejected** (`InvalidCertificate`) — no false success |

Lab/demo keys: generate with `script/security/f032_generate_signing_cert.sh` (self-signed).
Production: org PKI / HSM-backed key; document trust anchors for verifiers.

**Legal non-repudiation** is **not** claimed — that needs org identity, custody, and
legal policy. This provides technical authenticity/integrity of the export bytes.

## Canonical bytes

The signature covers the **exact CSV octet string** produced by `CsvExporter`
(UTF-8, `CSV.generate_line` newlines). Classification remains in F-013 headers /
envelope field — not rewritten into CSV rows (preserves parsers). Changing any
payload byte invalidates the signature.

## Configuration (Compose example)

```yaml
environment:
  FOREMAN_SIGNING_ENABLED: "true"
  FOREMAN_SIGNING_KEY_FILE: /run/secrets/foreman_signing.key
  FOREMAN_SIGNING_CERT_FILE: /run/secrets/foreman_signing.crt
```

## Audit

| Event | When |
| --- | --- |
| `DIGITAL_SIGNATURE_CREATED` | Successful sign (fingerprint + payload SHA-256 only) |
| `DIGITAL_SIGNATURE_FAILED` | OpenSSL failure (error class name only — no key material) |

## F-033 / FIPS

- Wire format is standard **PKCS#7/CMS detached** (F-033-ready).
- Algorithms: RSA (or whatever the org cert uses) + SHA-256 via OpenSSL.
- F-024: FIPS-validated mode is **not** claimed; use org-approved module/policy.

## Remaining limitations

- Only CSV responder path is wired; other exports can call the same service later.
- Org must provision real signing certs; lab self-signed is for verification demos.
- Detached signature is delivered in a JSON envelope when requested — not a
  separate `.p7s` browser download (bytes are openssl-verifiable after extract).
