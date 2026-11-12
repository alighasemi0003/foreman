# HTTP request body size limits (F-028)

## Enforcement layers

| Layer | Role |
|-------|------|
| **Puma** `http_content_length_limit` | Absolute ceiling (default **10 MiB**) before Rack → 413 (`config/puma.rb` + `config/puma/production.rb`) |
| **Rack middleware** `Foreman::Middleware::RequestBodyLimit` | Path-aware limits (default **2 MiB**; facts/reports **10 MiB**) via Content-Length + streamed `rack.input` count |
| **Controller** `RequestBodySizeLimit` | Facts / config_reports still enforce UploadSecurity caps |
| **Model / field validators** | Templates, CACERT, avatars (unchanged) |
| Reverse proxy | Recommended outer `client_max_body_size` in production — not in lab Compose |

## Limits

| Path class | Limit | Constant / override |
|------------|------:|---------------------|
| Puma absolute ceiling | **10 MiB** | `FOREMAN_ABSOLUTE_MAX_REQUEST_BODY_BYTES` |
| Default (API, GraphQL, forms, templates, auth) | **2 MiB** | `MAX_DEFAULT_REQUEST_BODY_BYTES` or `FOREMAN_MAX_REQUEST_BODY_BYTES` |
| `POST …/api(/v2)/hosts/facts` | **10 MiB** | `MAX_FACTS_BODY_BYTES` |
| `POST …/api(/v2)/(config_)reports` | **10 MiB** | `MAX_CONFIG_REPORT_BODY_BYTES` |
| Template field (after parse) | **1 MiB** | `MAX_TEMPLATE_BYTES` |
| Avatar binary | **100 KiB** | `MAX_AVATAR_BYTES` |
| CACERT attribute | **256 KiB** | `MAX_CACERT_BYTES` |

Exceptions are path-scoped — they are not a global bypass.

## Content-Length, chunked, and missing length

1. If `Content-Length` > path limit → Rack middleware returns **413** immediately (body not read by the app).
2. Otherwise `rack.input` is wrapped; each read increments a counter.
3. Exceeding the limit mid-stream raises `Foreman::HttpBodyTooLarge` → **413**.
4. Incorrect smaller Content-Length still cannot deliver more than the limit once read.
5. Chunked / missing Content-Length: byte count during read enforces the path limit.
6. Puma absolute ceiling: when the delivered body (or declared length, once Puma re-enters the client read loop) exceeds **10 MiB**, Puma returns **413** (`Payload Too Large`) before Rack.

**Lab note:** Puma may wait for more socket data before re-checking an oversized Content-Length if only a partial body arrived in the first packet. Prefer a reverse-proxy `client_max_body_size` in production; request timeouts bound hung partial uploads.

Bodies are not logged. Middleware error JSON is generic (`Request body is too large.`).

## Relation to F-026

Rate limiting and body-size limits are independent. Oversized requests are rejected
with **413**, not 429.
