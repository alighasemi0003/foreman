# Final security-hardening build manifest (F-FINAL)

| Field | Value |
| --- | --- |
| Branch | `security-hardening-5.0` |
| Starting HEAD | `7f0f549a0c2abc5c8561df78083fd36dfb0f9553` |
| Final HEAD | `1c304efa5f540d9124e77ed5aede9c26a1865882` |
| Build timestamp (UTC) | From image `BUILD_TIME` (~2026-11-20) |
| Base image | `quay.io/centos/centos:stream9` |
| Ruby | 3.0.7p220 (in image) |
| Bundler | 2.2.33 (frozen `Gemfile.lock`) |
| Gemfile.lock SHA-256 | `ddf8f1f5db8ffff783eb57e783946a557829752f24a9a1656a4270fcc5ec3efa` |
| package.json SHA-256 | `da32c6e28e768e30b242ea5b106782bf08a1ab9962a04e0d862f9210f24fb658` |
| package-lock.json | Not tracked (upstream npm install semantics) |
| Previous known-good image | `foreman-local:security-hardening-5.0` (`a29c987c7115`) — **preserved** |
| Intermediate SHA build | `foreman-local:security-hardening-5.0-7f0f549a0` (`02b740646245`) |
| **Authoritative final image** | `foreman-local:security-hardening-5.0-1c304efa5` |
| Final image ID | `sha256:3744901085f32e9ec4a3cedc29db1996bcd391d59d291a82f62063fa1842700c` |
| Final image size | ~741MB |
| Convenience alias | `foreman-local:security-hardening-5.0-final` (same ID) |
| Registry digest | local-only (not pushed) |
| Isolated Compose project | `foreman50-final-verify` (`docker-compose.final-verify.yml`) |
| Uncommitted at start | `?? docker-backups/` only (not discarded; not in image) |
| Push | **NO** |

Credentials and private keys are **not** recorded in this manifest.
