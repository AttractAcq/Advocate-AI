from __future__ import annotations

import asyncio
import json
import unittest

import httpx

from scripts.phase5_inference_stream_probe import measure, run


def stream(*, finish: str = "stop", tokens: int = 310, content: str = "synthetic") -> bytes:
    events = [
        {"choices": [{"delta": {"content": content}, "finish_reason": None}]},
        {"choices": [{"delta": {}, "finish_reason": finish}]},
        {"choices": [], "usage": {"completion_tokens": tokens}},
    ]
    return ("".join("data: " + json.dumps(item) + "\n\n" for item in events)
            + "data: [DONE]\n\n").encode()


class InferenceStreamProbeTests(unittest.TestCase):
    def test_streaming_measurement_and_300_token_qualification(self) -> None:
        async def exercise() -> tuple[dict[str, object], dict[str, object]]:
            def handler(request: httpx.Request) -> httpx.Response:
                if request.url.path == "/v1/models":
                    return httpx.Response(200, json={"data": [{"id": "synthetic-model"}]})
                payload = json.loads(request.content)
                self.assertEqual(payload["max_tokens"], 480)
                self.assertIn("30 numbered observations", payload["messages"][1]["content"])
                return httpx.Response(200, content=stream())

            transport = httpx.MockTransport(handler)
            report = await run("http://127.0.0.1:11434/v1", "synthetic-model", 2,
                               transport=transport)
            async with httpx.AsyncClient(base_url="http://127.0.0.1:11434/v1",
                                         transport=transport) as client:
                sample = await measure(client, "synthetic-model", 1)
            return report, sample

        report, sample = asyncio.run(exercise())
        self.assertEqual(report["summary"]["complete_300_token_answers"], 2)
        self.assertIsNotNone(report["summary"]["first_content_p95_seconds"])
        self.assertEqual(sample["completion_tokens"], 310)
        self.assertTrue(sample["complete_300_token_answer"])
        self.assertNotIn("synthetic\"", json.dumps(report))

    def test_incomplete_or_truncated_stream_is_not_a_300_token_answer(self) -> None:
        async def exercise(body: bytes) -> dict[str, object]:
            async with httpx.AsyncClient(base_url="http://127.0.0.1:11434/v1",
                                         transport=httpx.MockTransport(
                                             lambda _: httpx.Response(200, content=body))) as client:
                return await measure(client, "synthetic-model", 1)

        result = asyncio.run(exercise(stream(finish="length")))
        self.assertFalse(result["complete_300_token_answer"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            asyncio.run(exercise(stream().replace(b"data: [DONE]\n\n", b"")))


if __name__ == "__main__":
    unittest.main()
