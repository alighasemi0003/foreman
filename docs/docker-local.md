# Local Docker stack (security-hardening-5.0)

Portable **lab / verification** compose stack — not a production deployment.

## Prerequisites

- Docker Engine with Compose v2
- Git
- Enough disk for a multi-stage CentOS Stream 9 image build (gems + npm + webpack)
- Host port free for HTTP (default `3000`; override with `FOREMAN_HTTP_PORT`)

## 1. Clone

```bash
git clone <your-remote-url> foreman
cd foreman
git checkout security-hardening-5.0
```

**Required on the branch before handoff:** tracked `Gemfile.lock`, plus the Docker freeze
updates to `Dockerfile`, `.dockerignore`, and `.gitignore`. Without `Gemfile.lock`,
`docker compose build` fails the frozen Bundler step or resolves gems differently.

## 2. Optional env file

```bash
cp .env.example .env
# edit FOREMAN_HTTP_PORT / DB password / etc. if needed
```

`.env` is gitignored. Do not commit real secrets.

## 3. Build

```bash
docker compose build app
```

First build is long (Ruby gems, npm, webpack). Do not use `--no-cache` unless you
intentionally want a full rebuild.

## 4. Start dependencies, migrate, then app

Migrations are **manual**. A brand-new empty DB cannot boot the Rails server until
`db:migrate` has run (`PG::UndefinedTable` crash loop otherwise).

```bash
docker compose up -d db redis-cache redis-tasks

# One-shot migrate (does not require the app service to be healthy yet):
docker compose run --rm --no-deps app bundle exec rake db:migrate

docker compose up -d app
```

Optional Dynflow processes:

```bash
docker compose up -d orchestrator worker
```

Optional VNC console host ports (`5910–5930`):

```bash
docker compose -f docker-compose.yml -f docker-compose.vnc.yml up -d app
```

## 5. Create first admin (seed)

Prefer seeding **after** the app has booted once (settings registry must be loaded).
`db:seed` alone right after migrate can fail on `bcrypt_cost` setting registration.

```bash
docker compose exec app bundle exec rake db:seed
```

- If `SEED_ADMIN_PASSWORD` is **unset**, Foreman generates a **random** admin password
  and prints `Login credentials: admin / <password>` to stdout / container logs.
- Do **not** ship a shared default password.
- Lab-only known password:

```bash
docker compose exec \
  -e SEED_ADMIN_PASSWORD='choose-a-strong-lab-only-password' \
  app bundle exec rake db:seed
```

Seeding may also run automatically on later boots when seed content changes
(`config/initializers/seeds.rb`), but only after migrations are applied.

## 6. Health check

```bash
docker compose ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:${FOREMAN_HTTP_PORT:-3000}/users/login
```

Expect app `healthy` and HTTP `200` from the login page.

## 7. Login URL

```text
http://127.0.0.1:3000/users/login
```

(Use your `FOREMAN_HTTP_PORT` if overridden.)

## 8. Stop

```bash
docker compose stop
# or
docker compose down
```

`down` without `-v` keeps named volumes (`db`, `redis-persistent`).

## 9. Reset local environment (disposable labs only)

**Warning:** volume deletion destroys the Postgres data for **this Compose project only**.
Never run this against a shared or production database.

```bash
docker compose down
docker compose down -v   # deletes project volumes — local/lab only
```

Validate without touching an existing stack (separate project + HTTP port):

```bash
cp .env.example .env.handoff
# set FOREMAN_HTTP_PORT=13000 in .env.handoff
COMPOSE_PROJECT_NAME=foreman-handoff docker compose --env-file .env.handoff up -d db redis-cache redis-tasks
COMPOSE_PROJECT_NAME=foreman-handoff docker compose --env-file .env.handoff run --rm --no-deps app bundle exec rake db:migrate
COMPOSE_PROJECT_NAME=foreman-handoff docker compose --env-file .env.handoff up -d app
COMPOSE_PROJECT_NAME=foreman-handoff docker compose --env-file .env.handoff exec app bundle exec rake db:seed
# …verify http://127.0.0.1:13000/users/login …
COMPOSE_PROJECT_NAME=foreman-handoff docker compose --env-file .env.handoff down -v
```

## Notes

| Topic | Behavior |
| --- | --- |
| DB create | Postgres image creates `POSTGRES_DATABASE` on first volume init |
| Migrations | Manual — use `compose run … db:migrate` before first `up app` |
| Admin user | Created by `db:seed` (random password unless `SEED_ADMIN_PASSWORD` set) |
| CAPTCHA | Offline CAPTCHA code is in the image; enable via Foreman settings after login |
| `docker cp` | **Not** required when running an image built from this branch |
| SSL | `FOREMAN_REQUIRE_SSL=false` is for local HTTP only |
| VNC ports | Not published by default; use `docker-compose.vnc.yml` overlay if needed |
| Secrets | Rails `secret_key_base` is auto-generated under `tmp/` inside the container (ephemeral across recreate unless you persist it) |
| npm lockfile | Intentionally untracked (upstream Foreman 5.0); image build runs `npm install` inside Docker |
| Redis tag | Floating `redis` image tag — pin (e.g. `redis:7`) for stricter lab reproducibility |

## Classification

- **Portable local / lab stack:** yes (after Gemfile.lock + Docker freeze commits are on the branch)
- **Production-ready:** no
