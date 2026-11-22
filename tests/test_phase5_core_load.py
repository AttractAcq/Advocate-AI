from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from scripts.phase5_core_load import CASES, DENIAL, auth_headers, core_url, exercise, percentile


class CoreLoadHarnessTests(unittest.TestCase):
    def test_endpoint_and_private_token_intake(self) -> None:
        self.assertEqual(core_url("http://127.0.0.1:18080/"), "http://127.0.0.1:18080")
        self.assertEqual(core_url("https://10.8.0.7:8443"), "https://10.8.0.7:8443")
        for url in ("http://10.8.0.7:8443", "https://8.8.8.8:443",
                    "https://192.0.2.7:8443",
                    "https://user:secret@10.8.0.7:8443", "https://example.com:8443"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                core_url(url)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tokens.json"
            path.write_text(json.dumps({user: user + "-synthetic-access-token" for user in CASES}))
            path.chmod(0o600)
            self.assertEqual(set(auth_headers(path)), set(CASES))
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                auth_headers(path)
            path.write_text('{"lab-captain-1":"first","lab-captain-1":"second"}')
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                auth_headers(path)

    def test_percentile_and_full_role_schedule(self) -> None:
        self.assertIsNone(percentile([], 95))
        self.assertEqual(percentile([1, 2, 3, 4, 5], 95), 5)

        async def run(break_denial: bool) -> dict[str, object]:
            def handler(request: httpx.Request) -> httpx.Response:
                user = request.headers["Authorization"].removeprefix("Bearer ")
                question = json.loads(request.content)["message"]
                expected = next(expected for _, text, expected in CASES[user] if text == question)
                if break_denial and expected is None and user == "lab-deckhand-1":
                    expected = "ENG-006"
                citations = [{"document_id": expected}] if expected else []
                return httpx.Response(200, json={"answer": "supported" if expected else DENIAL,
                                                 "citations": citations})

            async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                         base_url="http://core.invalid") as client:
                headers = {user: {"Authorization": "Bearer " + user} for user in CASES}
                return await exercise(client, headers, requests_per_role=2, duration_seconds=0)

        passed = asyncio.run(run(False))
        self.assertEqual((passed["attempts"], passed["passed"], passed["failed"]), (10, 10, 0))
        self.assertEqual({row["user"] for row in passed["samples"]}, set(CASES))
        failed = asyncio.run(run(True))
        self.assertEqual(failed["failed"], 1)
        self.assertNotIn("Authorization", json.dumps(failed))


if __name__ == "__main__":
    unittest.main()
