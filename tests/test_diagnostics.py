import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import httpx

from infrastructure.diagnostics import DiagnosticConfigError, diagnose


class DiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "lab-ca.pem").write_text("test-only CA placeholder")
        self.check = {
            "name": "core", "kind": "https", "url": "https://127.0.0.1:18081/health",
            "ca_file": "lab-ca.pem", "expected_service": "core",
        }
        self.config = {"schema": 1, "mode": "synthetic-loopback",
                       "allowed_cidrs": ["127.0.0.0/8"], "checks": [self.check]}

    def test_healthy_response_and_metadata_only_report(self) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(
            200, stream=httpx.ByteStream(json.dumps(
                {"service": "core", "status": "ok", "secret": "must-not-print"}).encode()),
        ))
        report = diagnose(self.config, self.base, transport=transport)
        self.assertTrue(report["all_ok"])
        self.assertEqual(report["checks"][0]["reason"], "verified")
        self.assertNotIn("must-not-print", json.dumps(report))
        self.assertNotIn("127.0.0.1", json.dumps(report))

    def test_public_redirect_and_oversize_fail_without_following(self) -> None:
        calls = []

        def redirect(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(302, headers={"Location": "https://example.com/"})

        report = diagnose(self.config, self.base, transport=httpx.MockTransport(redirect))
        self.assertFalse(report["all_ok"])
        self.assertEqual(report["checks"][0]["reason"], "http_status")
        self.assertEqual(len(calls), 1)
        report = diagnose(self.config, self.base, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=httpx.ByteStream(b"x" * 5000))))
        self.assertEqual(report["checks"][0]["reason"], "response_too_large")

    def test_unsafe_endpoint_is_rejected_before_any_probe(self) -> None:
        calls = []
        transport = httpx.MockTransport(lambda request: calls.append(request) or httpx.Response(200))
        for url in ("https://example.com/health", "http://127.0.0.1:18081/health",
                    "https://127.0.0.1:18081/other", "https://127.0.0.1:18081/health?token=x",
                    "https://127.0.0.1:18081/health#fragment"):
            with self.subTest(url=url):
                self.config["checks"] = [{**self.check, "url": url}]
                with self.assertRaises(DiagnosticConfigError):
                    diagnose(self.config, self.base, transport=transport)
        self.assertEqual(calls, [])

    def test_read_only_sqlite_integrity_and_missing_file(self) -> None:
        path = self.base / "knowledge.db"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE entries (id INTEGER PRIMARY KEY)")
        self.config["checks"] = [{"name": "knowledge_store", "kind": "sqlite", "path": "knowledge.db"}]
        self.assertTrue(diagnose(self.config, self.base)["all_ok"])
        path.unlink()
        report = diagnose(self.config, self.base)
        self.assertFalse(report["all_ok"])
        self.assertEqual(report["checks"][0]["reason"], "database_missing")


if __name__ == "__main__":
    unittest.main()
