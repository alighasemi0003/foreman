#!/bin/bash
set -e

export PATH=~/bin:${GEM_HOME}/bin:${PATH}

# F-021: remove stale PID/state/sockets only after liveness checks.
# Do not blindly rm active runtime state. Skippable via FOREMAN_SKIP_RUNTIME_STATE_CLEANUP=1.
APP_ROOT="${FOREMAN_APP_ROOT:-${HOME:-/home/foreman}}"
if [[ -x /usr/bin/safe_clean_runtime_state.rb ]]; then
  /usr/bin/safe_clean_runtime_state.rb "${APP_ROOT}" || true
elif [[ -f "${APP_ROOT}/extras/containers/safe_clean_runtime_state.rb" ]]; then
  ruby "${APP_ROOT}/extras/containers/safe_clean_runtime_state.rb" "${APP_ROOT}" || true
else
  # Minimal fallback: drop server.pid only when process is dead (Compose lab).
  pidfile="${APP_ROOT}/tmp/pids/server.pid"
  if [[ -f "${pidfile}" && ! -L "${pidfile}" ]]; then
    oldpid="$(tr -d '[:space:]' < "${pidfile}" || true)"
    if [[ -n "${oldpid}" && "${oldpid}" =~ ^[0-9]+$ ]]; then
      if ! kill -0 "${oldpid}" 2>/dev/null; then
        rm -f "${pidfile}"
      fi
    else
      rm -f "${pidfile}"
    fi
  fi
fi

# Then exec the container's main process (what's set as CMD in the Dockerfile).
exec "$@"
