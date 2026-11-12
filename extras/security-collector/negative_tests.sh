#!/usr/bin/env bash
# F-042 negative tests — run on the lab host with compose stack up.
# Does not delete Docker volumes or historical DB audits.
set -euo pipefail

APP="${APP_CONTAINER:-foreman-app-1}"
COLLECTOR="${COLLECTOR_CONTAINER:-foreman-security-collector-1}"
APP_UID="${APP_UID:-1001}"
COLLECTOR_UID="${COLLECTOR_UID:-1500}"

pass=0
fail=0
check() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS  $name"
    pass=$((pass + 1))
  else
    echo "FAIL  $name"
    fail=$((fail + 1))
  fi
}

echo "== F-042 tamper-resistance checks =="

# 1) Submit new event from application identity path
docker exec "$APP" bash -lc 'cd /home/foreman && RAILS_ENV=production bundle exec rails runner "
Foreman::SecurityEvent.log(event: \"F042_SUBMIT\", status: \"SUCCESS\", actor: \"f042\",
  details: \"password=NoLeak token=eyJhbGciOi.fake.sig\")
sleep 0.8
puts \"ok\"
"' >/tmp/f042_submit.out
check "app submits new security event" grep -q ok /tmp/f042_submit.out

# 2) Collector accepted it
check "collector accepted F042_SUBMIT" \
  docker exec "$COLLECTOR" bash -lc 'grep -q F042_SUBMIT /data/events.jsonl'

# 3) Collector *process* runs as dedicated UID (docker exec defaults to root)
cuid=$(docker exec "$COLLECTOR" bash -lc "ps -o uid=,args= -C python | awk '/receiver.py/ {print \$1; exit}'")
if [ -z "$cuid" ]; then
  # busybox/ps variants — fall back to /proc
  cuid=$(docker exec "$COLLECTOR" bash -lc "for p in /proc/[0-9]*; do tr '\\0' ' ' <\$p/cmdline 2>/dev/null | grep -q receiver.py || continue; awk '/^Uid:/ {print \$2; exit}' \$p/status; break; done")
fi
check "collector process uid is $COLLECTOR_UID (got ${cuid:-empty})" test "${cuid:-}" = "$COLLECTOR_UID"

# 4) App container does not mount protected volume
check "app has no /data mount" \
  bash -lc "! docker exec \"$APP\" bash -lc 'test -f /data/events.jsonl' 2>/dev/null"

# 5) Application UID cannot edit accepted event inside collector namespace
check "app UID cannot rewrite events.jsonl" \
  bash -lc "! docker exec -u $APP_UID \"$COLLECTOR\" bash -lc 'echo TAMPER > /data/events.jsonl' 2>/dev/null"

# 6) Application UID cannot delete accepted event file
check "app UID cannot delete events.jsonl" \
  bash -lc "! docker exec -u $APP_UID \"$COLLECTOR\" rm -f /data/events.jsonl 2>/dev/null"

# 7) Application UID cannot chmod sealed storage
check "app UID cannot chmod data dir" \
  bash -lc "! docker exec -u $APP_UID \"$COLLECTOR\" chmod 777 /data 2>/dev/null"

# 8) HTTP rejects mutation verbs
check "HTTP DELETE rejected" \
  docker exec "$COLLECTOR" python -c "
import urllib.request
from urllib.error import HTTPError
try:
  urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/events', method='DELETE'))
  raise SystemExit(1)
except HTTPError as e:
  raise SystemExit(0 if e.code == 405 else 1)
"

# 9) Hash chain verifies
check "integrity chain ok" \
  docker exec "$COLLECTOR" python -c "
import json, urllib.request
v=json.load(urllib.request.urlopen('http://127.0.0.1:8080/verify'))
assert v['ok'] and v['records'] >= 1
"

# 10) Secret redaction on protected copy
check "no raw password in protected store" \
  docker exec "$COLLECTOR" bash -lc '! grep -E "password=NoLeak|fake.sig" /data/events.jsonl'

# 11) Local app log wipe would not remove protected records (simulate: count before/after touch)
before=$(docker exec "$COLLECTOR" bash -lc 'wc -l < /data/events.jsonl')
docker exec "$APP" bash -lc 'rm -f /home/foreman/log/*.log 2>/dev/null; true'
after=$(docker exec "$COLLECTOR" bash -lc 'wc -l < /data/events.jsonl')
check "protected records survive local log deletion ($before -> $after)" test "$before" = "$after"

# 12) Detect tampering: copy, alter as root in a temp file, verify algorithm catches it
check "tamper detection on altered payload" \
  docker exec "$COLLECTOR" python -c "
import json, hashlib, copy
from pathlib import Path
lines=Path('/data/events.jsonl').read_text().splitlines()
obj=json.loads(lines[0])
prev=obj['_integrity']['prev']
bare={k:v for k,v in obj.items() if k!='_integrity'}
bare['status']='TAMPERED'
body=json.dumps(bare, sort_keys=True, separators=(',',':'))
new_hash=hashlib.sha256((prev+'\n'+body).encode()).hexdigest()
# Original stored hash must not match recomputation over tampered body with claimed prev
assert obj['_integrity']['hash'] != new_hash
# Recompute expected for original — must match
body0=json.dumps({k:v for k,v in obj.items() if k!='_integrity'}, sort_keys=True, separators=(',',':'))
expect=hashlib.sha256((prev+'\n'+body0).encode()).hexdigest()
assert expect == obj['_integrity']['hash']
"

# 13) Unauthorized network peer: app can open TCP submit (allowed) but not read HTTP (bound 127.0.0.1)
check "app cannot reach collector HTTP from docker network" \
  bash -lc "! docker exec \"$APP\" bash -lc 'python3 -c \"import socket;s=socket.create_connection((\\\"security-collector\\\",8080),2)\"' 2>/dev/null"

echo "== summary: pass=$pass fail=$fail =="
test "$fail" -eq 0
