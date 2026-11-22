"""Measure local model streaming separately from the non-streaming Core path."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import time

import httpx

from apps.api.model import validate_local_endpoint
from scripts.evidence import stamp
from scripts.phase5_core_load import percentile

PROMPT = (
    "Write exactly 25 numbered observations about a fictional paper boat in a "
    "synthetic lab. Each observation must be an independent sentence of roughly "
    "ten words. Continue until all 25 are complete. Do not mention real vessels, "
    "networks or equipment."
)
MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_CONTENT_CHARS = 16 * 1024


def _unambiguous_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inference response field")
        result[key] = value
    return result


async def _events(response: httpx.Response):
    pending = bytearray()
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_STREAM_BYTES:
            raise ValueError("inference stream exceeds size limit")
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, remaining = pending.partition(b"\n")
            pending = bytearray(remaining)
            if len(line) > MAX_LINE_BYTES:
                raise ValueError("inference stream line exceeds size limit")
            line = line.rstrip(b"\r")
            if line.startswith(b"data:"):
                payload = line[5:].strip()
                if payload == b"[DONE]":
                    yield None
                elif payload:
                    yield json.loads(payload, object_pairs_hook=_unambiguous_object)
        if len(pending) > MAX_LINE_BYTES:
            raise ValueError("inference stream line exceeds size limit")
    if pending.strip():
        raise ValueError("incomplete inference stream line")


async def measure(client: httpx.AsyncClient, model: str, sample: int) -> dict[str, object]:
    started = time.monotonic()
    first: float | None = None
    finish: str | None = None
    completion_tokens: int | None = None
    digest = hashlib.sha256()
    chars = 0
    done = False
    payload = {"model": model, "stream": True,
               "stream_options": {"include_usage": True},
               "messages": [{"role": "system", "content": "Synthetic local performance probe."},
                            {"role": "user", "content": PROMPT}],
               "max_tokens": 400, "temperature": 0.1, "reasoning_effort": "none"}
    async with client.stream("POST", "/chat/completions", json=payload) as response:
        response.raise_for_status()
        async for event in _events(response):
            if event is None:
                done = True
                break
            if not isinstance(event, dict):
                raise ValueError("malformed inference event")
            usage = event.get("usage")
            if isinstance(usage, dict):
                value = usage.get("completion_tokens")
                if type(value) is int and 0 <= value <= 400:
                    completion_tokens = value
            choices = event.get("choices", [])
            if not isinstance(choices, list):
                raise ValueError("malformed inference choices")
            for choice in choices:
                if not isinstance(choice, dict):
                    raise ValueError("malformed inference choice")
                if choice.get("finish_reason") is not None:
                    finish = choice["finish_reason"]
                delta = choice.get("delta", {})
                if not isinstance(delta, dict):
                    raise ValueError("malformed inference delta")
                content = delta.get("content")
                if content is not None:
                    if not isinstance(content, str):
                        raise ValueError("invalid inference content")
                    if content:
                        first = first if first is not None else time.monotonic() - started
                        chars += len(content)
                        if chars > MAX_CONTENT_CHARS:
                            raise ValueError("inference content exceeds size limit")
                        digest.update(content.encode())
    elapsed = time.monotonic() - started
    if not done or first is None or not isinstance(finish, str):
        raise ValueError("incomplete inference completion")
    return {"sample": sample, "first_content_seconds": round(first, 3),
            "total_seconds": round(elapsed, 3), "completion_tokens": completion_tokens,
            "finish_reason": finish, "content_chars": chars,
            "content_sha256": digest.hexdigest(),
            "complete_300_token_answer": (completion_tokens is not None
                                           and completion_tokens >= 300 and finish == "stop")}


async def run(endpoint: str, model: str, samples: int, *,
              transport: httpx.AsyncBaseTransport | None = None) -> dict[str, object]:
    endpoint = validate_local_endpoint(endpoint)
    if not 1 <= samples <= 5 or not model or len(model) > 100 or "/" in model:
        raise ValueError("invalid probe configuration")
    async with httpx.AsyncClient(base_url=endpoint, timeout=180, trust_env=False,
                                 transport=transport) as client:
        advertisement = await client.get("/models")
        advertisement.raise_for_status()
        if len(advertisement.content) > 64 * 1024:
            raise ValueError("model advertisement exceeds size limit")
        models = advertisement.json().get("data")
        if not isinstance(models, list) or not any(isinstance(item, dict) and item.get("id") == model
                                                   for item in models):
            raise ValueError("model is not already served locally")
        results = await asyncio.gather(*(measure(client, model, number)
                                         for number in range(1, samples + 1)))
    qualifying = [float(row["total_seconds"]) for row in results
                  if row["complete_300_token_answer"]]
    return {"schema": 1, **stamp(), "host": {"system": platform.system(),
                                             "machine": platform.machine()},
            "endpoint": endpoint, "model": model,
            "prompt_sha256": hashlib.sha256(PROMPT.encode()).hexdigest(),
            "samples": results, "summary": {"requested": samples,
                                              "first_content_p95_seconds": percentile(
                                                  [float(row["first_content_seconds"]) for row in results], 95),
                                              "complete_300_token_answers": len(qualifying),
                                              "complete_300_token_p95_seconds": percentile(qualifying, 95)},
            "limits": ["direct local inference probe, not end-to-end Core or Console timing",
                       "first content delta is a proxy for first token",
                       "requires reported completion token count and stop finish for 300-token result",
                       "target GPU, process and network evidence remain separate"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--model", default="qwen3.5:2b")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(run(args.endpoint, args.model, args.samples))
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
