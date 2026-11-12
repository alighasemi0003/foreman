# Sensitive data in reports, templates and exports (F-019)

## Classification

| Category | Examples | Default treatment |
|----------|----------|-------------------|
| **Secret** | Hidden host/group/org parameters, BMC passwords, compute SSH private keys, PATs/JWT, registration secrets | Exclude or redact from general exports |
| **Confidential** | User PII in ENC (`foreman_users`), build tokens, hashed `root_pw`, CA file contents | Authorized viewers only; no public cache |
| **Internal** | Host inventory CSV columns, config-report CSV | `view_*` permissions |
| **Public** | N/A in Foreman core exports | — |

## Export categories

### 1. General report / inventory export

- Host index CSV, config-report CSV, fact CSV
- Host YAML / API ENC for callers **without** `edit_params`
- Inherited-parameters API without `show_hidden_parameters`

**Policy:** hidden parameter values → `*****`. BMC password omitted unless
`bmc_credentials_accessible`. No file-level encryption. Cache-Control
`private, no-store` on ENC/YAML and inherited-parameters responses.

### 2. Explicitly authorized sensitive export

- Host YAML / API ENC when the user has `edit_params` (optional
  `show_hidden_parameters=false` forces redaction)
- Parameters API with `show_hidden_parameters=true` + `edit_params`
- Compute key-pair download (F-018: reauth, optional passphrase encryption,
  no-store headers)

**Policy:** secrets may appear; require the matching permission; audit without
storing secret values (`HOST_INFO_EXPORT` security events; key-pair audit
comments).

### 3. Operational template rendering

- Provisioning / finish / user_data templates (`host_param`, `host_enc`,
  `root_pass`)
- Report templates that intentionally call those macros

**Policy:** raw values remain available to the renderer. Do not globally redact
`Host#info` — consumers need secrets for provisioning. Access is gated by
template/generate permissions.

### 4. Automated machine-to-machine

- Smart-proxy fact upload (separate auth)
- ENC consumers using an account with `edit_params` (full ENC)
- Accounts with only `view_hosts` receive redacted hidden parameters

File-level encryption is **not** applied to ENC/YAML/CSV (would break Puppet
and inventory tooling). At-rest encryption of credentials remains EncryptValue
(F-004/F-005).

## Confirmed protections (pre-existing)

- Parameters / settings API `safe_value` + `show_hidden*`
- BMC `to_export` password gated by `bmc_credentials_accessible` (default false)
- Key-pair export reauth + cache headers (F-018)
- Host CSV column allowlist (no passwords/params)

## Gaps closed by F-019

- ENC JSON and host YAML no longer dump hidden parameter values to
  `view_hosts`-only callers
- `GET /api/hosts/:id/inherited_parameters` uses `safe_value` by default
- Sensitive export responses set no-store cache headers
- Export audit metadata does not include secret values
