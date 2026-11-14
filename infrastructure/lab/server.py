"""Loopback-only Phase 1 service probes.

This is a synthetic lab simulation, not a vessel service or network security boundary.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from infrastructure.lab.pki import CA, SERVER_CERT, SERVER_KEY

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())
STARTED = time.monotonic()


def gpu_status() -> dict[str, object]:
    tool = shutil.which("nvidia-smi")
    if tool is None:
        return {"available": False, "reason": "nvidia-smi not installed"}
    try:
        result = subprocess.run(
            [tool, "--query-gpu=name,utilization.gpu,memory.used,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2, check=True,
        )
        return {"available": True, "sample": result.stdout.strip().splitlines()}
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "reason": "nvidia-smi query failed"}


def metrics(service: str, requests: int, errors: int, durations_ms: list[float]) -> dict[str, object]:
    disk = shutil.disk_usage(ROOT)
    return {
        "service": service,
        "uptime_seconds": round(time.monotonic() - STARTED, 3),
        "requests_total": requests,
        "errors_total": errors,
        "request_duration_ms_last": durations_ms[-1] if durations_ms else None,
        "request_duration_ms_max": max(durations_ms) if durations_ms else None,
        "cpu_load_1m": os.getloadavg()[0] if hasattr(os, "getloadavg") else None,
        "storage_free_bytes": disk.free,
        "storage_total_bytes": disk.total,
        "gpu": gpu_status(),
    }


def make_handler(service: str):
    class Handler(BaseHTTPRequestHandler):
        requests = 0
        errors = 0
        durations_ms: list[float] = []

        def log_message(self, format_string: str, *args: object) -> None:
            # The default HTTP logger includes raw paths and headers. Never use it.
            pass

        def do_GET(self) -> None:
            begin = time.monotonic()
            path = urlsplit(self.path).path
            code = 200
            content_type = "application/json"
            if path == "/health":
                body = json.dumps({"service": service, "status": "ok",
                                   "mode": "synthetic-loopback"}).encode()
            elif path == "/metrics":
                body = json.dumps(metrics(service, Handler.requests,
                                          Handler.errors, Handler.durations_ms)).encode()
            elif path == "/" and service == "console":
                content_type = "text/html; charset=utf-8"
                body = (ROOT / "apps/console/index.html").read_bytes()
            elif path == "/lab-status" and service == "console":
                status: dict[str, object] = {}
                for peer, port in TOPOLOGY["services"].items():
                    if peer == "console":
                        status[peer] = {"status": "ok", "metrics": metrics(
                            service, Handler.requests, Handler.errors, Handler.durations_ms)}
                        continue
                    try:
                        context = ssl.create_default_context(cafile=str(CA))
                        with urlopen(f"https://127.0.0.1:{port}/metrics",
                                     timeout=0.5, context=context) as reply:
                            status[peer] = {"status": "ok", "metrics": json.load(reply)}
                    except (URLError, TimeoutError, ValueError, OSError):
                        status[peer] = {"status": "down"}
                body = json.dumps({"mode": "synthetic-loopback", "services": status}).encode()
            elif path == "/events" and service == "wazuh-simulator":
                content_type = "application/x-ndjson"
                body = (ROOT / TOPOLOGY["synthetic_events"]).read_bytes()
            else:
                code = 404
                body = b'{"error":"not found"}'
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            elapsed = round((time.monotonic() - begin) * 1000, 3)
            Handler.requests += 1
            Handler.errors += int(code >= 400)
            Handler.durations_ms.append(elapsed)
            Handler.durations_ms[:] = Handler.durations_ms[-100:]
            print(json.dumps({"service": service, "event": "http_request",
                              "route": path if path in ("/", "/health", "/metrics", "/events", "/lab-status")
                              else "unmatched",
                              "status": code, "duration_ms": elapsed,
                              "timestamp": time.time()}), file=sys.stderr, flush=True)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=TOPOLOGY["services"])
    args = parser.parse_args()
    host = TOPOLOGY["bind"]
    if host != "127.0.0.1":
        raise SystemExit("Phase 1 lab only permits 127.0.0.1")
    port = TOPOLOGY["services"][args.service]
    with ThreadingHTTPServer((host, port), make_handler(args.service)) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(json.dumps({"service": args.service, "event": "started",
                          "host": host, "port": port}), file=sys.stderr, flush=True)
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
