#!/usr/bin/env python3
"""Capability-protected loopback service for read-only Memory Explorer."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import threading
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlsplit
import webbrowser

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
# A store may explicitly be the source checkout. Keep imports read-only there.
sys.dont_write_bytecode = True

from _explorer_preview import PreviewError, run_preview
from _explorer_store import ExplorerError, ExplorerStore

MAX_BODY = 16 * 1024
MAX_PATH = 8192
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
ASSET_DIR = BIN_DIR.parent / "web" / "explorer"


class ExplorerHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def __init__(self, store: ExplorerStore):
        self.store = store
        self.lock = threading.Lock()
        self.capability = secrets.token_urlsafe(32)
        self.worker_slots = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", 0), ExplorerHandler)
        self.origin = "http://127.0.0.1:%d" % self.server_port

    def process_request(self, request, client_address):
        if not self.worker_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.worker_slots.release()

    def handle_error(self, request, client_address):
        # Broken clients and timed-out reads are expected at this boundary.
        # The stdlib default prints a traceback and client address to stderr.
        pass


class ExplorerHandler(BaseHTTPRequestHandler):
    server: ExplorerHTTPServer
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(2.0)

    def log_message(self, _format, *args):
        # BaseHTTPRequestHandler's default includes URLs and can leak queries.
        pass

    def handle_expect_100(self):
        self._error(417, "Request expectation is unsupported.")
        return False

    def _headers(self, status: int, content_type: str, size: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _authorize(self, *, api: bool) -> bool:
        expected_host = "127.0.0.1:%d" % self.server.server_port
        if self.headers.get_all("Host", []) != [expected_host]:
            self._error(403, "Request origin is forbidden.")
            return False
        origin = self.headers.get("Origin")
        if (len(self.headers.get_all("Origin", [])) > 1 or
                (origin is not None and origin != self.server.origin) or
                self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site"):
            self._error(403, "Request origin is forbidden.")
            return False
        if api and self.headers.get_all("Authorization", []) != ["Bearer " + self.server.capability]:
            self._error(403, "Access is forbidden.")
            return False
        return True

    def _route(self):
        if len(self.path) > MAX_PATH:
            self._error(413, "Request path is too large.")
            return None
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            self._error(404, "Route was not found.")
            return None
        return parsed

    def do_GET(self):
        parsed = self._route()
        if parsed is None:
            return
        path = parsed.path
        if path in ASSETS and not parsed.query:
            if not self._authorize(api=False):
                return
            name, content_type = ASSETS[path]
            try:
                data = (ASSET_DIR / name).read_bytes()
            except OSError:
                self._error(404, "Route was not found.")
                return
            self._headers(200, content_type, len(data))
            self.wfile.write(data)
            return
        if path not in {"/api/summary", "/api/records", "/api/record"}:
            self._error(404, "Route was not found.")
            return
        if not self._authorize(api=True):
            return
        try:
            params = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True,
                              max_num_fields=10) if parsed.query else {}
        except ValueError:
            self._error(400, "Query parameters are invalid.")
            return
        if any(len(values) != 1 for values in params.values()):
            self._error(400, "Query parameters are invalid.")
            return
        allowed = {
            "/api/summary": set(),
            "/api/records": {"query", "kind", "lifecycle", "collection", "offset", "limit"},
            "/api/record": {"handle", "snapshot_id"},
        }[path]
        if not set(params).issubset(allowed):
            self._error(400, "Query parameters are invalid.")
            return
        one = {key: values[0] for key, values in params.items()}
        if len(one.get("query", "")) > MAX_PATH:
            self._error(413, "Search query is too large.")
            return
        try:
            with self.server.lock:
                if path == "/api/summary":
                    result = self.server.store.summary()
                elif path == "/api/records":
                    for key, default in (("offset", "0"), ("limit", "50")):
                        value = one.get(key, default)
                        if not re.fullmatch(r"[0-9]{1,9}", value):
                            raise ExplorerError("Pagination is invalid.")
                        one[key] = int(value)
                    if one["limit"] > 100:
                        raise ExplorerError("Pagination is invalid.")
                    result = self.server.store.list_records(**one)
                else:
                    if not one.get("handle") or not one.get("snapshot_id"):
                        raise ExplorerError("Record request is invalid.")
                    if one["snapshot_id"] != self.server.store.snapshot_id:
                        self._error(409, "Snapshot is stale; refresh the page.")
                        return
                    result = self.server.store.detail(one["handle"])
                    if result is None:
                        self._error(404, "Record was not found.")
                        return
        except (ExplorerError, TypeError, ValueError):
            self._error(400, "Request parameters are invalid.")
            return
        except Exception:
            self._error(503, "Memory snapshot is unavailable.")
            return
        self._json(200, result)

    def do_POST(self):
        parsed = self._route()
        if parsed is None:
            return
        if parsed.path not in {"/api/refresh", "/api/preview"} or parsed.query:
            self._error(404, "Route was not found.")
            return
        if not self._authorize(api=True):
            return
        if self.headers.get("Transfer-Encoding") is not None or len(self.headers.get_all("Content-Length", [])) != 1:
            self._error(400, "Request body is invalid.")
            return
        raw_length = self.headers.get("Content-Length", "")
        if not re.fullmatch(r"[0-9]{1,6}", raw_length):
            self._error(400, "Request body is invalid.")
            return
        length = int(raw_length)
        if length > MAX_BODY:
            self.close_connection = True
            self._error(413, "Request body is too large.")
            return
        if self.headers.get_content_type() != "application/json":
            self._error(400, "Request body must be JSON.")
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("short body")
            body = json.loads(raw)
        except (OSError, UnicodeError, ValueError):
            self.close_connection = True
            self._error(400, "Request body is invalid.")
            return
        if not isinstance(body, dict):
            self._error(400, "Request body must be an object.")
            return
        try:
            with self.server.lock:
                if parsed.path == "/api/refresh":
                    if body:
                        raise ExplorerError("Refresh request is invalid.")
                    result = self.server.store.refresh()
                else:
                    if set(body) != {"query", "budget", "snapshot_id"}:
                        raise ExplorerError("Preview request is invalid.")
                    if not isinstance(body["snapshot_id"], str):
                        raise ExplorerError("Preview request is invalid.")
                    if body["snapshot_id"] != self.server.store.snapshot_id:
                        self._error(409, "Snapshot is stale; refresh the page.")
                        return
                    if self.server.store.summary().get("state") == "unreadable":
                        self._error(503, "Preview snapshot is unreadable.")
                        return
                    result = run_preview(self.server.store.snapshot_dir,
                                         body["query"], body["budget"])
        except PreviewError as exc:
            status = 504 if str(exc) == "Preview timed out." else 400
            if str(exc) in {"Preview could not be completed.", "Preview snapshot is unreadable.",
                            "Preview snapshot is unavailable."}:
                status = 503
            self._error(status, str(exc))
            return
        except (ExplorerError, TypeError, ValueError):
            if parsed.path == "/api/refresh" and not body:
                self._error(503, "Memory refresh failed; the previous snapshot remains active.")
            else:
                self._error(400, "Request parameters are invalid.")
            return
        except Exception:
            self._error(503, "Memory snapshot is unavailable.")
            return
        self._json(200, result)


def create_server(store: ExplorerStore) -> ExplorerHTTPServer:
    return ExplorerHTTPServer(store)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local Memory Explorer")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="open a fictitious Willow Workshop demo")
    mode.add_argument("--store", type=Path, help="explicit directory containing facts.json")
    parser.add_argument("--verify-key", type=Path, help="explicit public verification file")
    parser.add_argument("--open", action="store_true", help="open the local page in a browser")
    args = parser.parse_args(argv)
    if not args.demo and args.store is None:
        parser.print_help()
        return 0
    if os.environ.get("NOCKBRAIN_STORE", "").strip().lower() == "sqlite":
        print("SQLite backend is unsupported by Memory Explorer.", file=sys.stderr)
        return 2
    try:
        with ExplorerStore(store=args.store, demo=args.demo, verify_key=args.verify_key) as store:
            server = create_server(store)
            stopped = threading.Event()
            old_handlers = {}

            def stop(_signum, _frame):
                stopped.set()

            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, stop)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = server.origin + "/#token=" + server.capability
            print(url, flush=True)
            if args.open:
                webbrowser.open(url)
            try:
                stopped.wait()
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()
                for signum, previous in old_handlers.items():
                    signal.signal(signum, previous)
        return 0
    except ExplorerError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError:
        print("Memory Explorer could not start.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
