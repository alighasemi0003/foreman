# CMS / PKCS#7 compatibility for Foreman signatures (F-033)

Audit requirement **68** (چک‌لیست امنیتی، صفحات ۵۰–۵۱).
Depends on **F-032** (`docs/digital-signatures.md`).

| Field | Value |
| --- | --- |
| Prerequisite | F-032 signing use case (**PASS** — CSV export PKCS#7) |
| Status | **PASS** when independent OpenSSL CLI verifies Foreman output |
| Library presence alone | **Not** sufficient — runtime artifacts required |

## F-032 integration

Foreman generates detached CMS/PKCS#7 SignedData over exact CSV export bytes via
`OpenSSL::PKCS7.sign(..., DETACHED | BINARY)`. F-033 confirms that artifact is
interoperable with a non-Ruby validator (`openssl cms` / `openssl smime`).

## Interoperability contract (supported)

| Feature | Supported? | Notes |
| --- | --- | --- |
| CMS / PKCS#7 **SignedData** | **Yes** | OpenSSL PKCS7 API |
| **Detached** signature | **Yes** | Content external; signed octets unchanged |
| Attached (embedded content) | **No** | Not generated |
| **PEM** encoding | **Yes** | `signature_pem` / `.p7s` |
| **DER** encoding | **Yes** | `signature_der` / `signature_der_base64` |
| Digest | SHA-256 | |
| Signature algorithm | `rsa-sha256` (lab RSA keys); ECDSA if org EC key | |
| Signer certificate in SignedData | **Yes** | Included by `PKCS7.sign` |
| Full CA chain packaging | **Partial** | Signer cert included; extra intermediates not auto-bundled |
| Multiple signers | **No** | Single org signing identity |
| Default CRL/OCSP revocation | **No** | Verifier policy / deployment |
| Trust-chain validation | **Verifier-side** | Supply `-CAfile` / trust store; lab demos may use `-noverify` for crypto-only |

### Explicit non-claims

- Not every CMS optional attribute or CAdES profile.
- Mathematical signature OK ≠ organizational trust/revocation complete.
- Legal non-repudiation not claimed (same as F-032).

## Artifact shape

Signed export JSON (`application/vnd.foreman.signed-export+json`) includes:

- `payload_base64` — exact signed content
- `signature_pem` / `signature_der_base64` — CMS SignedData detached
- `certificate_pem` — public signer cert for trust-anchor setup
- `digest_algorithm`, `signature_algorithm`, `cms_certificates_included`
- `attached_content: false`, `detached_content: true`

Extracted files for CLI tools:

| File | Role |
| --- | --- |
| `document.csv` | Detached content |
| `document.p7s` | PEM PKCS#7 |
| `document.p7s.der` | DER PKCS#7 |
| `document-signer.crt` | Trust anchor (lab self-signed) |

## Independent verification

Crypto-only (signature + content integrity; chain not enforced):

```bash
openssl cms -verify -in document.p7s -inform PEM -content document.csv \
  -CAfile document-signer.crt -binary -noverify
openssl cms -verify -in document.p7s.der -inform DER -content document.csv \
  -CAfile document-signer.crt -binary -noverify
```

With trust check (self-signed: CAfile must be the signer / issuing CA):

```bash
openssl cms -verify -in document.p7s -inform PEM -content document.csv \
  -CAfile document-signer.crt -binary
```

Negative cases: alter `document.csv`, corrupt `.p7s`, or use the wrong cert → verify fails.

Automation: `rake security:cms_pkcs7_interop` (requires `FOREMAN_SIGNING_*` files).

## Certificate / trust policy

| Check | Who |
| --- | --- |
| Cert not expired at sign time | Foreman (`InvalidCertificate`) |
| Crypto verify of SignedData | Foreman Ruby + OpenSSL CLI |
| Chain to org trust anchor | Downstream verifier |
| Revocation | Downstream / PKI policy |

## Remaining limitations

- Intermediates beyond the leaf are not automatically attached; deployers should
  publish the trust chain to consumers.
- Consumers must understand **detached** content (do not expect embedded CSV).
- FIPS-validated module still governed by F-024 / org policy.
