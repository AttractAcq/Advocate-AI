"""Temporary loopback HTTPS bridge for the synthetic Fleet browser rehearsal.

Only the built Fleet portal's local HTTP port is forwarded. The process is
started with sudo solely to bind the standard HTTPS port on a CI runner.
"""

from __future__ import annotations

import argparse
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl


class Bridge(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.forward()

    def do_POST(self) -> None:
        self.forward()

    def do_OPTIONS(self) -> None:
        self.forward()

    def forward(self) -> None:
        if self.headers.get("Host") != "fleet.example.invalid":
            self.send_error(421)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size > 65536:
            self.send_error(413)
            return
        request_body = self.rfile.read(size) if size else None
        connection = HTTPConnection("127.0.0.1", 18080, timeout=15)
        try:
            headers = {name: value for name, value in self.headers.items()
                       if name.lower() not in ("connection", "transfer-encoding", "content-length")}
            connection.request(self.command, self.path, body=request_body, headers=headers)
            result = connection.getresponse()
            body = result.read(2_000_001)
            if len(body) > 2_000_000:
                raise ValueError("synthetic portal response exceeded limit")
            self.send_response(result.status)
            for name, value in result.getheaders():
                if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server = ThreadingHTTPServer(("127.0.0.2", 443), Bridge)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
