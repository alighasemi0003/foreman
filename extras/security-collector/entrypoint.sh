#!/bin/sh
# F-042 — ensure /data ownership then start receiver (receiver drops to UID 1500).
set -eu
UID_N="${SECURITY_COLLECTOR_UID:-1500}"
GID_N="${SECURITY_COLLECTOR_GID:-1500}"
DATA="${SECURITY_COLLECTOR_DATA:-/data}"

mkdir -p "$DATA"

if [ "$(id -u)" = "0" ]; then
  # Numeric ownership only — works with read_only rootfs (no useradd).
  chown -R "$UID_N:$GID_N" "$DATA" || true
fi

exec python -u /collector/receiver.py
