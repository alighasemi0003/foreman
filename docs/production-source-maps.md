# Production JavaScript source maps (F-038)

Audit requirement **78** (چک‌لیست امنیتی، صفحه ۵۶).

## Finding

Production webpack builds emitted `.map` files under `public/webpack/` with
`sourceMappingURL` references. With `RAILS_SERVE_STATIC_FILES=true`, an
unauthenticated client could retrieve maps containing original `sources` /
`sourcesContent`.

Backend source-tree protection is **F-039** (out of scope here).

## Policy

| Environment | Behavior |
| --- | --- |
| Development | `eval-cheap-module-source-map` retained for debugging |
| Production (default) | `devtool: false` — no public maps |
| Production diagnostic | `FOREMAN_WEBPACK_SOURCEMAP=hidden` may emit maps **without** `sourceMappingURL`; image build still deletes `*.map` from the public web root |
| Private retention | Keep diagnostic maps outside deploy images / web root; upload to error monitoring via an authorized pipeline only |

## Controls

1. **Webpack** (`config/webpack.config.js`) — production default `devtool: false`
2. **Dockerfile** — `find … -name '*.map' -delete` after webpack
3. **Middleware** `Foreman::Middleware::BlockSourceMaps` — HTTP 404 for
   `/webpack/*.map` and `/assets/*.map` (and `.map.gz`)

## Verification

```bash
# Must be 404 (middleware and/or missing file)
curl -sI "http://localhost:3000/webpack/<bundle>.js.map"

# UI still loads
curl -sI "http://localhost:3000/users/login"
```

## Limitations

- A reverse proxy that serves `public/` without Rails middleware must also deny
  `*.map` (or receive an image with maps already deleted).
- Full image rebuild is required for webpack default change to take effect in
  freshly built assets; middleware + map deletion protect running lab images.
