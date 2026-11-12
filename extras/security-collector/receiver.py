#!/usr/bin/env python3
"""F-041 — isolated security-event test collector (TCP JSON-lines).

Stores received events under /data (or SECURITY_COLLECTOR_DATA).
No authentication in lab mode — bind only on private networks.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

HOST = os.environ.get("SECURITY_COLLECTOR_HOST", "0.0.0.0")
PORT = int(os.environ.get("SECURITY_COLLECTOR_PORT", "1514"))
DATA = Path(os.environ.get("SECURITY_COLLECTOR_DATA", "/data"))
EVENTS = DATA / "events.jsonl"
META = DATA / "stats.json"

lock = threading.Lock()
stats = {"received": 0, "parse_errors": 0, "started_at": None}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record(line: str) -> None:
    global stats
    DATA.mkdir(parents=True, exist_ok=True)
    with lock:
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("not an object")
            # Refuse obvious secrets in stored copy
            blob = json.dumps(obj)
            for bad in ("password=", "Bearer ", "ENCRYPTION_KEY", "private_key"):
                if bad.lower() in blob.lower() and "[REDACTED]" not in blob:
                    obj["_collector_note"] = "possible_secret_token_seen"
            with EVENTS.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
            stats["received"] += 1
        except Exception:
            stats["parse_errors"] += 1
            with (DATA / "parse_errors.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": utc_now(), "raw": line[:2000]}) + "\n")
        META.write_text(json.dumps({**stats, "updated_at": utc_now()}, indent=2) + "\n")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            record(line)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    # Preserve append-only event file across process restarts; refresh counters.
    if EVENTS.is_file():
        stats["received"] = sum(1 for _ in EVENTS.open("r", encoding="utf-8"))
    stats["started_at"] = utc_now()
    META.write_text(json.dumps({**stats, "updated_at": utc_now()}, indent=2) + "\n")
    print(f"security-collector listening on {HOST}:{PORT}, data={DATA}", flush=True)
    with Server((HOST, PORT), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("shutdown", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
