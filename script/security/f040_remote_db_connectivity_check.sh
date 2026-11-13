#!/usr/bin/env bash
# F-040: verify Foreman can use a REMOTE PostgreSQL DSN (no silent local fallback).
# Does not migrate or modify the live lab database volume.
# Usage:
#   PROBE_DSN='postgres://foreman_app:…@db-host:5432/foreman_f040' \
#     ./script/security/f040_remote_db_connectivity_check.sh
set -euo pipefail

DSN="${PROBE_DSN:-${DATABASE_URL:-}}"
if [[ -z "$DSN" ]]; then
  echo "Set PROBE_DSN or DATABASE_URL to a remote PostgreSQL DSN" >&2
  exit 2
fi

case "$DSN" in
  *@db/*|*@db:*|*@127.0.0.1*|*@localhost*|*@::1*)
    echo "Refusing local/lab Compose DSN (no silent fallback to co-located db)" >&2
    exit 3
    ;;
esac

if [[ -n "${FOREMAN_APP_CONTAINER:-}" ]]; then
  exec docker exec -e PROBE_DSN="$DSN" "$FOREMAN_APP_CONTAINER" \
    bash -lc 'cd /home/foreman && bundle exec ruby -e "
require \"pg\"
require \"json\"
dsn = ENV.fetch(\"PROBE_DSN\")
c = PG.connect(dsn)
row = c.exec(\"SELECT current_user AS u, current_database() AS db, inet_server_addr()::text AS server_addr\").first
ddl_blocked = begin
  c.exec(\"CREATE TABLE f040_should_not_exist(id int)\")
  false
rescue PG::InsufficientPrivilege
  true
ensure
  begin
    c.exec(\"DROP TABLE IF EXISTS f040_should_not_exist\")
  rescue StandardError
    nil
  end
end
puts({ ok: true, ssl_in_use: c.ssl_in_use?, ddl_blocked: ddl_blocked, user: row[\"u\"], db: row[\"db\"], server_addr: row[\"server_addr\"] }.inspect)
c.close
"'
fi

# Host-side check with dockerized psql if no app container specified
docker run --rm --network "${PROBE_DOCKER_NETWORK:-bridge}" postgres:12 \
  bash -lc "psql \"$DSN\" -v ON_ERROR_STOP=1 -c \"SELECT current_user, current_database();\""
