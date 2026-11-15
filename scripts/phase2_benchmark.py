#!/usr/bin/env python3
"""Measure the already-installed local Ollama model on synthetic prompts."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import subprocess
import time
from urllib.parse import urlsplit

import httpx

from scripts.evidence import stamp

ROOT = Path(__file__).resolve().parents[1]


def _loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("benchmark endpoint must be numeric loopback") from exc
    if parsed.scheme != "http" or not address.is_loopback or not parsed.port or parsed.path not in ("", "/"):
        raise ValueError("benchmark endpoint must be an HTTP loopback service")
    return value.rstrip("/")


def _memory_bytes() -> int | None:
    if platform.system() != "Darwin":
        return None
    result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=False)
    return int(result.stdout.strip()) if result.returncode == 0 else None


async def measure(client: httpx.AsyncClient, model: str, name: str, prompt: str) -> dict[str, object]:
    started = time.monotonic()
    reply = await client.post("/api/chat", json={
        "model": model,
        "stream": False,
        "think": False,
        "messages": [{"role": "system", "content": "Synthetic lab benchmark. Answer concisely."},
                     {"role": "user", "content": prompt}],
        "options": {"num_predict": 120, "temperature": 0.1},
    })
    reply.raise_for_status()
    result = reply.json()
    answer = result.get("message", {}).get("content", "")
    assert isinstance(answer, str) and answer.strip()
    elapsed = time.monotonic() - started
    tokens = result.get("eval_count") or 0
    generation_ns = result.get("eval_duration") or 0
    return {
        "task": name,
        "wall_seconds": round(elapsed, 3),
        "prompt_tokens": result.get("prompt_eval_count"),
        "output_tokens": tokens,
        "prompt_seconds": round((result.get("prompt_eval_duration") or 0) / 1e9, 3),
        "generation_seconds": round(generation_ns / 1e9, 3),
        "output_tokens_per_second": round(tokens / (generation_ns / 1e9), 3) if generation_ns else None,
        "load_seconds": round((result.get("load_duration") or 0) / 1e9, 3),
        "answer_sha256": hashlib.sha256(answer.encode()).hexdigest(),
    }


async def run(endpoint: str, model: str) -> dict[str, object]:
    endpoint = _loopback_url(endpoint)
    source = (ROOT / "fixtures/sources/ENG-001.txt").read_text(encoding="utf-8")
    async with httpx.AsyncClient(base_url=endpoint, timeout=180, trust_env=False) as client:
        tags = (await client.get("/api/tags")).json()["models"]
        installed = next((item for item in tags if item.get("name") == model), None)
        if not installed:
            raise ValueError("model is not already installed locally; benchmark will not download it")
        before = (await client.get("/api/ps")).json().get("models", [])
        loaded_before = any(item.get("name") == model for item in before)
        first = await measure(client, model, "warm_short" if loaded_before else "cold_short",
                              "Reply with the word READY.")
        second = await measure(client, model, "source_question",
                               f"Source:\n{source}\n\nWhat is the verification marker?")
        started = time.monotonic()
        parallel = await asyncio.gather(
            measure(client, model, "concurrent_source", f"Source:\n{source}\n\nSummarize the required action."),
            measure(client, model, "concurrent_general", "Explain why a fictional lab should avoid changing live equipment."),
        )
        running = (await client.get("/api/ps")).json().get("models", [])
        active = next((item for item in running if item.get("name") == model), {})
    return {
        "schema": 1,
        **stamp(),
        "endpoint": endpoint,
        "host": {"system": platform.system(), "machine": platform.machine(),
                 "processor": platform.processor(), "memory_bytes": _memory_bytes()},
        "model": {"name": model, "digest": installed.get("digest"), "size_bytes": installed.get("size"),
                  "details": installed.get("details")},
        "installed_before_run": True,
        "loaded_before_run": loaded_before,
        "context_size_configured": active.get("context_length"),
        "model_memory_bytes": active.get("size_vram"),
        "runner": active.get("runner"),
        "single_samples": [first, second],
        "concurrent_two": {"wall_seconds": round(time.monotonic() - started, 3), "samples": parallel},
        "wan_disconnected": False,
        "network_capture": None,
        "target_nvidia_host": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen3.5:2b")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = asyncio.run(run(args.endpoint, args.model))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
