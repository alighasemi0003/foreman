#!/usr/bin/env python3
"""F-041/F-042 — isolated, append-only security-event collector.

Trust boundary:
  - Accepts new JSON-line events over TCP (append only).
  - Stores under /data owned by a dedicated non-root UID (default 1500).
  - Does not expose UPDATE/DELETE of historical records.
  - Hash-chains each accepted record for tamper detection.
  - Optional localhost HTTP is read/verify only.

The Foreman application identity must not mount /data and must not share
this UID. Local Audits DB remains an operational store, not the protected
destination.
"""

from __future__ import annotations

import hashlib
import json
import os
import socketserver
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("SECURITY_COLLECTOR_HOST", "0.0.0.0")
PORT = int(os.environ.get("SECURITY_COLLECTOR_PORT", "1514"))
HTTP_HOST = os.environ.get("SECURITY_COLLECTOR_HTTP_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("SECURITY_COLLECTOR_HTTP_PORT", "8080"))
DATA = Path(os.environ.get("SECURITY_COLLECTOR_DATA", "/data"))
EVENTS = DATA / "events.jsonl"
META = DATA / "stats.json"
CHAIN = DATA / "chain_tip.json"
UID = int(os.environ.get("SECURITY_COLLECTOR_UID", "1500"))
GID = int(os.environ.get("SECURITY_COLLECTOR_GID", "1500"))
MAX_BYTES = int(os.environ.get("SECURITY_COLLECTOR_ROTATE_BYTES", str(10 * 1024 * 1024)))
RETENTION_DAYS = int(os.environ.get("SECURITY_COLLECTOR_RETENTION_DAYS", "90"))
HMAC_KEY = os.environ.get("SECURITY_COLLECTOR_HMAC_KEY", "").encode("utf-8")

lock = threading.Lock()
stats: dict[str, Any] = {
    "received": 0,
    "parse_errors": 0,
    "rotated": 0,
    "retention_deleted": 0,
    "started_at": None,
}
chain_tip = "GENESIS"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def drop_privileges() -> None:
    """Own /data as the collector identity, then drop root if present."""
    DATA.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        try:
            os.chown(DATA, UID, GID)
            for path in DATA.iterdir():
                try:
                    os.chown(path, UID, GID)
                except OSError:
                    pass
        except OSError as exc:
            print(f"chown failed: {exc}", flush=True)
            raise
        os.setgid(GID)
        os.setuid(UID)
    # Ensure we are the expected identity for negative tests / ops.
    if os.geteuid() != UID:
        print(
            f"WARNING: running as uid={os.geteuid()} expected {UID}",
            flush=True,
        )


def quarantine_broken_chain() -> None:
    """If existing hashed files fail chain verify, seal them without deletion.

    Preserves bytes under events-quarantine-*.jsonl (mode 0440) and starts a
    new GENESIS chain for subsequent appends. Used when upgrading or after
    lab misconfiguration (e.g. same-second rotation collisions).
    """
    files = [
        p
        for p in sorted(DATA.glob("events*.jsonl"))
        if p.is_file() and "legacy" not in p.name and "quarantine" not in p.name
    ]
    if not files:
        return
    result = verify_all()
    if result["ok"] or result["records"] == 0:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    for i, path in enumerate(files):
        dest = DATA / f"events-quarantine-{stamp}-{i}-{path.name}"
        path.rename(dest)
        os.chmod(dest, 0o440)
    global chain_tip
    chain_tip = "GENESIS"
    write_chain_tip(chain_tip)
    print(
        f"quarantined broken chain ({result['records']} records, "
        f"{len(result['errors'])} errors); new GENESIS tip",
        flush=True,
    )


def seal_legacy_unhashed_events() -> None:
    """If active events.jsonl lacks integrity metadata (pre-F-042), seal it.

    Does not delete records — renames to events-legacy-*.jsonl mode 0440 and
    starts a new hash-chained active file.
    """
    if not EVENTS.is_file() or EVENTS.stat().st_size == 0:
        return
    needs_seal = False
    with EVENTS.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                needs_seal = True
                break
            if "_integrity" not in obj:
                needs_seal = True
                break
    if not needs_seal:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    dest = DATA / f"events-legacy-{stamp}.jsonl"
    n = 0
    while dest.exists():
        n += 1
        dest = DATA / f"events-legacy-{stamp}-{n}.jsonl"
    EVENTS.rename(dest)
    os.chmod(dest, 0o440)
    print(f"sealed legacy events without integrity -> {dest.name}", flush=True)


def load_chain_tip() -> str:
    if CHAIN.is_file():
        try:
            return json.loads(CHAIN.read_text(encoding="utf-8")).get("tip", "GENESIS")
        except Exception:
            return "GENESIS"
    # Recover tip from last sealed/active line if tip file missing.
    tip = "GENESIS"
    for path in sorted(DATA.glob("events*.jsonl")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    tip = obj.get("_integrity", {}).get("hash", tip)
        except Exception:
            continue
    return tip


def write_chain_tip(tip: str) -> None:
    CHAIN.write_text(json.dumps({"tip": tip, "updated_at": utc_now()}, indent=2) + "\n")


def integrity_fields(payload: dict[str, Any], prev: str) -> dict[str, str]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = (prev + "\n" + body).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    fields = {"prev": prev, "hash": digest, "alg": "sha256"}
    if HMAC_KEY:
        fields["hmac"] = hashlib.sha256(HMAC_KEY + material).hexdigest()
        fields["alg"] = "sha256+hmac"
    return fields


def verify_chain(path: Path = EVENTS) -> dict[str, Any]:
    """Validate hash chain for one file. Returns summary."""
    prev = "GENESIS"
    # For rotated files after the first, prev should continue from prior tip;
    # per-file verify starts at GENESIS only for the first events.jsonl generation.
    # Full verify walks all files in order.
    count = 0
    errors: list[str] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:
            errors.append(f"{path.name}:{idx}: parse {exc}")
            continue
        integ = obj.get("_integrity") or {}
        stored_prev = integ.get("prev")
        stored_hash = integ.get("hash")
        bare = {k: v for k, v in obj.items() if k != "_integrity"}
        expected = integrity_fields(bare, stored_prev or "")
        if stored_prev != prev and count > 0:
            # Allow first record of a rotated file to continue from external tip
            # only when verifying a single mid-chain file in isolation.
            pass
        if count == 0:
            prev = stored_prev or "GENESIS"
        if stored_prev != prev:
            errors.append(f"{path.name}:{idx}: prev mismatch")
        if stored_hash != expected["hash"]:
            errors.append(f"{path.name}:{idx}: hash mismatch")
        if HMAC_KEY and integ.get("hmac") != expected.get("hmac"):
            errors.append(f"{path.name}:{idx}: hmac mismatch")
        prev = stored_hash or prev
        count += 1
    return {"file": path.name, "records": count, "ok": not errors, "errors": errors, "tip": prev}


def verify_all() -> dict[str, Any]:
    # Skip legacy / quarantine archives — retained but not part of the active chain.
    files = sorted(
        p
        for p in DATA.glob("events*.jsonl")
        if p.is_file() and "legacy" not in p.name and "quarantine" not in p.name
    )
    prev = "GENESIS"
    errors: list[str] = []
    total = 0
    for path in files:
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception as exc:
                errors.append(f"{path.name}:{idx}: parse {exc}")
                continue
            integ = obj.get("_integrity") or {}
            bare = {k: v for k, v in obj.items() if k != "_integrity"}
            expected = integrity_fields(bare, integ.get("prev") or "")
            if integ.get("prev") != prev:
                errors.append(f"{path.name}:{idx}: prev mismatch (expected {prev[:12]}…)")
            if integ.get("hash") != expected["hash"]:
                errors.append(f"{path.name}:{idx}: hash mismatch")
            if HMAC_KEY and integ.get("hmac") != expected.get("hmac"):
                errors.append(f"{path.name}:{idx}: hmac mismatch")
            prev = integ.get("hash") or prev
            total += 1
    return {
        "ok": not errors,
        "records": total,
        "files": [p.name for p in files],
        "errors": errors[:50],
        "tip": prev,
        "checked_at": utc_now(),
    }


def apply_retention() -> None:
    """Delete sealed rotated files older than retention. Never deletes active events.jsonl."""
    if RETENTION_DAYS <= 0:
        return
    cutoff = time.time() - (RETENTION_DAYS * 86400)
    deleted = 0
    for path in DATA.glob("events-*.jsonl"):
        # Never retention-delete legacy/quarantine archives or the active file.
        if "legacy" in path.name or "quarantine" in path.name:
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                deleted += 1
        except OSError:
            continue
    if deleted:
        stats["retention_deleted"] = int(stats.get("retention_deleted", 0)) + deleted


def rotate_if_needed() -> None:
    if not EVENTS.is_file():
        return
    size = EVENTS.stat().st_size
    if size < MAX_BYTES:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    dest = DATA / f"events-{stamp}.jsonl"
    # Never replace an existing sealed file (clock collision guard).
    n = 0
    while dest.exists():
        n += 1
        dest = DATA / f"events-{stamp}-{n}.jsonl"
    EVENTS.rename(dest)
    # Seal rotated file: owner read-only (collector UID cannot rewrite content
    # without chmod; app UID cannot write at all).
    os.chmod(dest, 0o440)
    stats["rotated"] = int(stats.get("rotated", 0)) + 1
    apply_retention()


def open_append(path: Path):
    """Append-only open. Creates file with 0640 if missing."""
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o640,
    )
    return os.fdopen(fd, "a", encoding="utf-8")


def record(line: str) -> None:
    global stats, chain_tip
    DATA.mkdir(parents=True, exist_ok=True)
    with lock:
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError("not an object")
            # Never accept client-supplied integrity fields.
            obj.pop("_integrity", None)
            blob = json.dumps(obj)
            for bad in ("password=", "Bearer ", "ENCRYPTION_KEY", "private_key"):
                if bad.lower() in blob.lower() and "[REDACTED]" not in blob:
                    obj["_collector_note"] = "possible_secret_token_seen"
            integ = integrity_fields(obj, chain_tip)
            obj["_integrity"] = integ
            rotate_if_needed()
            with open_append(EVENTS) as fh:
                fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            chain_tip = integ["hash"]
            write_chain_tip(chain_tip)
            stats["received"] += 1
        except Exception:
            stats["parse_errors"] = int(stats.get("parse_errors", 0)) + 1
            with open_append(DATA / "parse_errors.jsonl") as fh:
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


class ReadOnlyHTTP(BaseHTTPRequestHandler):
    """Authorized reviewer surface — GET only. No mutation verbs."""

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("http " + (fmt % args) + "\n")

    def _send(self, code: int, body: dict[str, Any] | list[Any] | str, ctype: str = "application/json") -> None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body, indent=2).encode("utf-8")
        else:
            data = str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, {"status": "ok", "uid": os.geteuid(), "gid": os.getegid()})
            return
        if parsed.path == "/stats":
            self._send(200, {**stats, "uid": os.geteuid()})
            return
        if parsed.path == "/verify":
            self._send(200, verify_all())
            return
        if parsed.path == "/events":
            qs = parse_qs(parsed.query)
            tail = int(qs.get("tail", ["50"])[0])
            tail = max(1, min(tail, 1000))
            if not EVENTS.is_file():
                self._send(200, [])
                return
            lines = EVENTS.read_text(encoding="utf-8").splitlines()[-tail:]
            out = []
            for line in lines:
                try:
                    out.append(json.loads(line))
                except Exception:
                    out.append({"_raw_error": line[:200]})
            self._send(200, out)
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, {"error": "method_not_allowed"})

    def do_PUT(self) -> None:  # noqa: N802
        self._send(405, {"error": "method_not_allowed"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send(405, {"error": "method_not_allowed"})

    def do_PATCH(self) -> None:  # noqa: N802
        self._send(405, {"error": "method_not_allowed"})


def start_http() -> None:
    httpd = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), ReadOnlyHTTP)
    thr = threading.Thread(target=httpd.serve_forever, name="collector-http", daemon=True)
    thr.start()
    print(f"read-only HTTP on {HTTP_HOST}:{HTTP_PORT}", flush=True)


def main() -> int:
    global chain_tip, stats
    drop_privileges()
    DATA.mkdir(parents=True, exist_ok=True)
    seal_legacy_unhashed_events()
    quarantine_broken_chain()
    # Recount durable events; tip from chain file or rebuild.
    received = 0
    for path in sorted(DATA.glob("events*.jsonl")):
        with path.open("r", encoding="utf-8") as fh:
            received += sum(1 for line in fh if line.strip())
    stats["received"] = received
    # After a legacy seal with no hashed active file, start a new GENESIS chain.
    hashed_files = [
        p
        for p in sorted(DATA.glob("events*.jsonl"))
        if p.is_file() and "legacy" not in p.name
    ]
    if not hashed_files or all(p.stat().st_size == 0 for p in hashed_files):
        chain_tip = "GENESIS"
    else:
        chain_tip = load_chain_tip()
    write_chain_tip(chain_tip)
    stats["started_at"] = utc_now()
    META.write_text(json.dumps({**stats, "updated_at": utc_now()}, indent=2) + "\n")
    start_http()
    print(
        f"security-collector listening on {HOST}:{PORT}, data={DATA}, "
        f"uid={os.geteuid()} gid={os.getegid()} tip={chain_tip[:16]}…",
        flush=True,
    )
    with Server((HOST, PORT), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("shutdown", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
