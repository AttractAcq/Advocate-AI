from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from scripts.phase5_core_load import (CASES, DENIAL, auth_headers, checked_gpu_binary,
                                      core_url, exercise, expected_sources, gpu_sample,
                                      gpu_coverage, monitor_gpu, parse_gpu_sample, percentile,
                                      run_remote)

GPU_UUID = "GPU-00000000-0000-0000-0000-000000000001"


class CoreLoadHarnessTests(unittest.TestCase):
    def test_pinned_read_only_gpu_sampling(self) -> None:
        sample = f"{GPU_UUID}, 62, 210.5, 6144, 87\n".encode()
        self.assertEqual(parse_gpu_sample(sample, GPU_UUID)["temperature_c"], 62)
        for bad in (sample.replace(b"62", b"N/A"),
                    sample.replace(b"210.5", b"nan"),
                    sample.replace(GPU_UUID.encode(), b"GPU-wrong")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_gpu_sample(bad, GPU_UUID)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "nvidia-smi"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' '" + sample.decode().strip() + "'\n")
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual(checked_gpu_binary(binary, digest), digest)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                checked_gpu_binary(binary, "0" * 64)
            self.assertEqual(asyncio.run(gpu_sample(binary, GPU_UUID))["power_w"], 210.5)

            async def sample_once() -> dict[str, object]:
                stop = asyncio.Event()
                stop.set()
                return await monitor_gpu(binary, GPU_UUID, stop)

            report = asyncio.run(sample_once())
            self.assertEqual(report["sample_count"], 1)
            self.assertEqual(report["error_count"], 0)
            self.assertFalse(report["truncated"])
            self.assertEqual(report["memory_max_mib"], 6144)
            self.assertTrue(gpu_coverage(report, 0)[0])
            sparse = {**report, "monitor_seconds": 1800.0}
            self.assertFalse(gpu_coverage(sparse, 1800)[0])
            self.assertEqual(gpu_coverage(sparse, 1800)[1], 1800.0)

            tokens = Path(directory) / "tokens.json"
            tokens.write_text(json.dumps({user: user + "-synthetic-access-token"
                                          for user in CASES}))
            tokens.chmod(0o600)
            sources = expected_sources()

            def handler(request: httpx.Request) -> httpx.Response:
                if request.url.path == "/health":
                    return httpx.Response(200)
                user = request.headers["Authorization"].removeprefix("Bearer ")
                user = user.removesuffix("-synthetic-access-token")
                question = json.loads(request.content)["message"]
                expected = next(document_id for _, text, document_id in CASES[user]
                                if text == question)
                citations = [{**sources[expected], "ordinal": 0}] if expected else []
                return httpx.Response(200, json={"answer": "supported" if expected else DENIAL,
                                                 "citations": citations})

            result = asyncio.run(run_remote(
                "https://10.8.0.7:8443", tokens, 2, 0, None,
                binary, digest, GPU_UUID, httpx.MockTransport(handler)))
            self.assertEqual((result["attempts"], result["passed"]), (10, 10))
            self.assertTrue(result["health_after"])
            self.assertEqual(result["gpu_telemetry"]["sample_count"], 1)
            self.assertEqual(result["gpu_telemetry"]["binary_sha256"], digest)
            self.assertTrue(result["gpu_telemetry"]["coverage_ok"])

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

        sources = expected_sources()

        async def run(break_kind: str | None) -> dict[str, object]:
            def handler(request: httpx.Request) -> httpx.Response:
                user = request.headers["Authorization"].removeprefix("Bearer ")
                question = json.loads(request.content)["message"]
                expected = next(expected for _, text, expected in CASES[user] if text == question)
                if break_kind == "malformed":
                    return httpx.Response(200, json=[])
                if break_kind == "denial" and expected is None and user == "lab-deckhand-1":
                    expected = "ENG-006"
                citations = [{**sources[expected], "ordinal": 0}] if expected else []
                if citations and break_kind in ("sha256", "version", "collection", "ordinal"):
                    citations[0][break_kind] = "wrong"
                return httpx.Response(200, json={"answer": "supported" if expected else DENIAL,
                                                 "citations": citations})

            async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                         base_url="http://core.invalid") as client:
                headers = {user: {"Authorization": "Bearer " + user} for user in CASES}
                return await exercise(client, headers, requests_per_role=2, duration_seconds=0)

        passed = asyncio.run(run(None))
        self.assertEqual((passed["attempts"], passed["passed"], passed["failed"]), (10, 10, 0))
        self.assertEqual({row["user"] for row in passed["samples"]}, set(CASES))
        failed = asyncio.run(run("denial"))
        self.assertEqual(failed["failed"], 1)
        self.assertNotIn("Authorization", json.dumps(failed))
        self.assertEqual(asyncio.run(run("malformed"))["failed"], 10)
        for field in ("sha256", "version", "collection", "ordinal"):
            with self.subTest(field=field):
                self.assertEqual(asyncio.run(run(field))["failed"], 6)


if __name__ == "__main__":
    unittest.main()
