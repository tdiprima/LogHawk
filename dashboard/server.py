#!/usr/bin/env python3
"""
LogHawk Dashboard — single pane of glass for fleet log monitoring.

Runs on the central log server. Serves a web UI and JSON API that
aggregates log data from all monitored hosts under log_base.

Access from any browser on the network:
    http://<central-server>:8080

Usage:
    sudo python3 dashboard/server.py
    sudo python3 dashboard/server.py --port 9090 --bind 0.0.0.0
    sudo python3 dashboard/server.py --jsonl /var/log/loghawk-alerts.jsonl
"""

from __future__ import annotations

import argparse
import functools
import glob
import http.server
import json
import logging
import os
import re
import signal
import socketserver
import sys
import time
from collections import Counter
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ── Path setup ───────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
STATIC_DIR = SCRIPT_DIR / "static"

TOOLS_DIR = os.environ.get("LOGHAWK_TOOLS_DIR", str(PROJECT_ROOT / "tools"))
sys.path.insert(0, TOOLS_DIR)

try:
    from alert_patterns import ALERT_PATTERNS
    from loghawk_config import load_config, ConfigError
except ImportError:
    print(
        f"ERROR: Cannot import LogHawk tools from {TOOLS_DIR}.\n"
        "Set LOGHAWK_TOOLS_DIR or run from the project root.",
        file=sys.stderr,
    )
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("loghawk-dashboard")

COMPILED_PATTERNS = [
    (re.compile(p), sev, desc, cat)
    for p, sev, desc, cat in ALERT_PATTERNS
]

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ── Module-level state (set once in main) ────────────────────────────
_config: dict = {}
_jsonl_path: str | None = None

# ── Timestamp parsing ────────────────────────────────────────────────
_ISO_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)
_TRAD_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def parse_timestamp(line: str) -> datetime | None:
    """Parse ISO 8601 or traditional syslog timestamp from a log line."""
    match = _ISO_TS.match(line)
    if match:
        with suppress(ValueError):
            return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))

    match = _TRAD_TS.match(line)
    if match:
        with suppress(ValueError):
            now = datetime.now(timezone.utc)
            raw = f"{match.group(1)} {now.year}"
            dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y").replace(
                tzinfo=timezone.utc
            )
            if dt - now > timedelta(days=1):
                dt = dt.replace(year=dt.year - 1)
            return dt

    return None


# ── Response cache ───────────────────────────────────────────────────
_cache: dict = {}


def cached(ttl: int = 10):
    """Cache function results for ttl seconds to avoid redundant disk reads."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = (func.__name__, args, tuple(sorted(kwargs.items())))
            now = time.time()
            entry = _cache.get(key)
            if entry:
                result, timestamp = entry
                if now - timestamp < ttl:
                    return result
            result = func(*args, **kwargs)
            _cache[key] = (result, now)
            return result
        return wrapper
    return decorator


# ── File utilities ───────────────────────────────────────────────────
def tail_lines(filepath: str, max_bytes: int = 65536) -> list[str]:
    """Read the tail of a file efficiently by seeking near the end."""
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "r", errors="replace") as fh:
            if file_size > max_bytes:
                fh.seek(file_size - max_bytes)
                fh.readline()  # discard partial first line
            return fh.readlines()
    except OSError:
        return []


def file_age_minutes(filepath: str) -> int:
    """Seconds since file was last modified, converted to minutes. -1 on error."""
    try:
        return int((time.time() - os.path.getmtime(filepath)) / 60)
    except OSError:
        return -1


# ── Data collectors ──────────────────────────────────────────────────
def list_hosts() -> list[str]:
    """Return sorted list of hostnames under log_base."""
    log_base = _config["log_base"]
    if not os.path.isdir(log_base):
        return []
    return sorted(
        entry for entry in os.listdir(log_base)
        if os.path.isdir(os.path.join(log_base, entry))
    )


@cached(ttl=10)
def get_pipeline() -> dict:
    """Per-host log file freshness — mirrors check-log-pipeline.sh logic."""
    log_base = _config["log_base"]
    stale_minutes = _config["stale_minutes"]
    expected_logs = _config["expected_logs"]
    hosts = []

    for hostname in list_hosts():
        host_dir = os.path.join(log_base, hostname)
        logs = []
        overall = "OK"

        for log_name in expected_logs:
            log_path = os.path.join(host_dir, log_name)

            if not os.path.isfile(log_path):
                logs.append({
                    "name": log_name, "status": "MISS",
                    "age_minutes": -1, "size_bytes": 0,
                })
                if overall == "OK":
                    overall = "MISS"
                continue

            age = file_age_minutes(log_path)
            try:
                size = os.path.getsize(log_path)
            except OSError:
                size = 0
            status = "STALE" if age > stale_minutes else "OK"

            if status == "STALE" and overall == "OK":
                overall = "STALE"

            logs.append({
                "name": log_name, "status": status,
                "age_minutes": age, "size_bytes": size,
            })

        hosts.append({"name": hostname, "status": overall, "logs": logs})

    return {"stale_minutes": stale_minutes, "hosts": hosts}


@cached(ttl=10)
def get_alerts(hours: int = 24) -> dict:
    """Recent alerts — reads JSONL alert file if available, else scans logs."""
    if _jsonl_path and os.path.isfile(_jsonl_path):
        return _read_jsonl_alerts(hours)
    return _scan_log_alerts(hours)


def _derive_host(source_file: str) -> str:
    """Extract hostname from a log path under log_base."""
    log_base = _config["log_base"]
    try:
        rel = os.path.relpath(source_file, log_base)
        parts = rel.split(os.sep)
        if len(parts) >= 2:
            return parts[0]
    except (ValueError, TypeError):
        pass
    return "unknown"


def _read_jsonl_alerts(hours: int) -> dict:
    """Read pre-processed alerts from the watch-alerts JSONL output."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    alerts = []

    for line in tail_lines(_jsonl_path, max_bytes=262144):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            ts = datetime.fromisoformat(record["timestamp"])
            if ts < since:
                continue
            record["host"] = _derive_host(record.get("source_file", ""))
            record["log_file"] = os.path.basename(
                record.get("source_file", "")
            )
            alerts.append(record)
        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return {"alerts": alerts[:500], "total": len(alerts),
            "hours": hours, "source": "jsonl"}


def _scan_log_alerts(hours: int) -> dict:
    """Scan log file tails for alert pattern matches."""
    log_base = _config["log_base"]
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    alerts = []

    for hostname in list_hosts():
        host_dir = os.path.join(log_base, hostname)
        for log_file in glob.glob(os.path.join(host_dir, "*.log")):
            log_name = os.path.basename(log_file)
            for line in tail_lines(log_file):
                ts = parse_timestamp(line)
                if ts and ts < since:
                    continue

                for compiled_re, severity, description, category in COMPILED_PATTERNS:
                    if compiled_re.search(line):
                        alerts.append({
                            "timestamp": ts.isoformat() if ts else None,
                            "severity": severity,
                            "description": description,
                            "category": category,
                            "host": hostname,
                            "log_file": log_name,
                            "raw_line": line.strip(),
                        })
                        break

    alerts.sort(key=lambda a: a.get("timestamp") or "", reverse=True)
    return {"alerts": alerts[:500], "total": len(alerts),
            "hours": hours, "source": "scan"}


@cached(ttl=10)
def get_overview(hours: int = 24) -> dict:
    """Fleet-wide summary: host health, alert counts, host list."""
    pipeline = get_pipeline()
    alerts_data = get_alerts(hours=hours)

    severity_counts = Counter(a["severity"] for a in alerts_data["alerts"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hosts": {
            "total": len(pipeline["hosts"]),
            "healthy": sum(1 for h in pipeline["hosts"] if h["status"] == "OK"),
            "stale": sum(1 for h in pipeline["hosts"] if h["status"] == "STALE"),
            "missing": sum(1 for h in pipeline["hosts"] if h["status"] == "MISS"),
        },
        "alerts": {
            sev: severity_counts.get(sev, 0)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "alert_total": alerts_data["total"],
        "host_list": [h["name"] for h in pipeline["hosts"]],
        "hours_scanned": hours,
        "log_base": _config["log_base"],
    }


def search_logs(
    query: str,
    host: str | None = None,
    log_name: str | None = None,
    limit: int = 200,
) -> dict:
    """Search across log file tails for a literal string (case-insensitive)."""
    if not query or len(query) > 500:
        return {"query": query, "results": [], "total": 0,
                "truncated": False, "error": "Query must be 1-500 characters"}

    log_base = _config["log_base"]
    escaped = re.escape(query)
    try:
        pattern = re.compile(escaped, re.IGNORECASE)
    except re.error:
        return {"query": query, "results": [], "total": 0,
                "truncated": False, "error": "Invalid search pattern"}

    results = []
    total = 0
    hosts = [host] if host else list_hosts()

    for hostname in hosts:
        host_dir = os.path.join(log_base, hostname)
        if not os.path.isdir(host_dir):
            continue

        log_files = glob.glob(os.path.join(host_dir, "*.log"))
        if log_name:
            log_files = [
                f for f in log_files if os.path.basename(f) == log_name
            ]

        for log_file in log_files:
            fname = os.path.basename(log_file)
            for line in tail_lines(log_file, max_bytes=131072):
                if pattern.search(line):
                    total += 1
                    if len(results) < limit:
                        ts = parse_timestamp(line)
                        results.append({
                            "host": hostname,
                            "file": fname,
                            "timestamp": ts.isoformat() if ts else None,
                            "line": line.strip(),
                        })

    return {
        "query": query, "results": results,
        "total": total, "truncated": total > limit,
    }


# ── MIME types ───────────────────────────────────────────────────────
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


# ── HTTP handler ─────────────────────────────────────────────────────
class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Routes requests to static files or JSON API endpoints."""

    server_version = "LogHawk-Dashboard/1.0"

    def log_message(self, format, *args):
        log.info("%s %s", self.address_string(), format % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._serve_static("index.html")
        elif path.startswith("/api/"):
            self._handle_api(path, parse_qs(parsed.query))
        else:
            self._serve_static(path.lstrip("/"))

    def _handle_api(self, path: str, params: dict):
        try:
            if path == "/api/overview":
                hours = self._int_param(params, "hours", 24)
                data = get_overview(hours=hours)
            elif path == "/api/alerts":
                hours = self._int_param(params, "hours", 24)
                data = get_alerts(hours=hours)
            elif path == "/api/pipeline":
                data = get_pipeline()
            elif path == "/api/search":
                query = params.get("q", [""])[0]
                host = params.get("host", [None])[0]
                log_name = params.get("log", [None])[0]
                limit = self._int_param(params, "limit", 200)
                data = search_logs(
                    query, host=host, log_name=log_name,
                    limit=min(limit, 500),
                )
            else:
                self.send_error(404)
                return

            self._json_response(data)
        except Exception as err:
            log.error("API error on %s: %s", path, err, exc_info=True)
            self._json_response({"error": str(err)}, status=500)

    def _int_param(self, params: dict, name: str, default: int) -> int:
        raw = params.get(name, [str(default)])[0]
        try:
            return max(1, min(int(raw), 720))
        except ValueError:
            return default

    def _json_response(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, filename: str):
        filepath = (STATIC_DIR / filename).resolve()

        # Block path traversal
        try:
            filepath.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self.send_error(403)
            return

        if not filepath.is_file():
            self.send_error(404)
            return

        content_type = MIME_TYPES.get(
            filepath.suffix.lower(), "application/octet-stream"
        )
        try:
            content = filepath.read_bytes()
        except OSError:
            self.send_error(500)
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── Main ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="LogHawk Dashboard — fleet log monitoring in a browser."
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Listen port (default: 8080).",
    )
    parser.add_argument(
        "--bind", default="0.0.0.0",
        help="Bind address (default: 0.0.0.0). Use 127.0.0.1 for local only.",
    )
    parser.add_argument(
        "--jsonl", default=None, metavar="PATH",
        help="Path to JSONL alert file from watch-alerts daemon.",
    )
    parser.add_argument(
        "--config", default=None, metavar="PATH",
        help="Path to loghawk.conf (default: /etc/loghawk/loghawk.conf).",
    )
    args = parser.parse_args()

    global _config, _jsonl_path
    try:
        _config = load_config(args.config)
    except ConfigError as err:
        log.error("%s", err)
        sys.exit(1)

    _jsonl_path = args.jsonl

    server = ThreadedServer((args.bind, args.port), DashboardHandler)

    def shutdown_handler(signum, frame):
        log.info("Shutting down.")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    log.info(
        "LogHawk Dashboard listening on http://%s:%d",
        args.bind, args.port,
    )
    log.info("Log base: %s", _config["log_base"])
    if _jsonl_path:
        log.info("Alert JSONL: %s", _jsonl_path)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
