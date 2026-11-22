"""Bounded five-user synthetic Core load rehearsal for AT-18 preparation.

The report contains timing, status and citation outcomes, never tokens, prompts
or answer bodies. A target run still needs GPU, route and process evidence.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import secrets
import ssl
import stat
import tempfile
import time
from urllib.parse import urlsplit

import httpx

from apps.api.main import Settings, create_app
from scripts.evidence import stamp

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "phase-3/approved-sources.json"
DATABASE = ROOT / "infrastructure/lab/runtime/phase3-knowledge/index.sqlite3"
DENIAL = "No matching permitted source was found. I cannot answer from vessel documents."
CASES = {
    "lab-captain-1": (("visitor", "According to the Visitor arrival procedure, what actions are required?", "MAN-001"),
                      ("hvac", "What actions does the HVAC intake procedure require?", "ENG-006")),
    "lab-chief_engineer-1": (("hvac", "What actions does the HVAC intake procedure require?", "ENG-006"),
                             ("deny-visitor", "What actions does the Visitor arrival procedure require?", None)),
    "lab-chief_stewardess-1": (("table", "What actions does the Table setting procedure require?", "INT-009"),
                               ("deny-hvac", "What actions does the HVAC intake procedure require?", None)),
    "lab-deckhand-1": (("line", "What actions does the Line inspection procedure require?", "DEC-001"),
                       ("deny-hvac", "What actions does the HVAC intake procedure require?", None)),
    "lab-avit_admin-1": (("line", "What actions does the Line inspection procedure require?", "DEC-001"),
                         ("deny-visitor", "What actions does the Visitor arrival procedure require?", None)),
}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _unambiguous_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate token map entry")
        result[key] = value
    return result


def core_url(value: str) -> str:
    """Allow only loopback HTTP or private numeric HTTPS with no URL extras."""
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("Core URL must use a numeric address") from exc
    private = address.is_loopback or any(address in network for network in PRIVATE_NETWORKS)
    if (not parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.username or parsed.password or parsed.scheme not in ("http", "https")
            or (parsed.scheme == "http" and not address.is_loopback)
            or (parsed.scheme == "https" and not private)):
        raise ValueError("Core URL must be loopback HTTP or private HTTPS")
    return value.rstrip("/")


def _private_file(path: Path, maximum: int) -> bytes:
    if not path.is_absolute():
        raise ValueError("evidence input path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
                or not 0 < info.st_size <= maximum):
            raise ValueError("unsafe evidence input file")
        payload = stream.read(maximum + 1)
    if not 0 < len(payload) <= maximum:
        raise ValueError("invalid evidence input size")
    return payload


def auth_headers(path: Path) -> dict[str, dict[str, str]]:
    """Read exact five synthetic test tokens without placing them in output."""
    data = json.loads(_private_file(path, 32 * 1024), object_pairs_hook=_unambiguous_object)
    if not isinstance(data, dict) or set(data) != set(CASES):
        raise ValueError("token file must contain exactly the five synthetic users")
    if any(not isinstance(token, str) or not 20 <= len(token) <= 8192
           or any(ord(char) < 33 or ord(char) > 126 for char in token)
           for token in data.values()):
        raise ValueError("invalid synthetic access token")
    return {user: {"Authorization": "Bearer " + token} for user, token in data.items()}


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    if not 0 < percent <= 100:
        raise ValueError("percentile out of bounds")
    ordered = sorted(values)
    return round(ordered[math.ceil(percent * len(ordered) / 100) - 1], 3)


async def exercise(client: httpx.AsyncClient, headers: dict[str, dict[str, str]], *,
                   requests_per_role: int, duration_seconds: float) -> dict[str, object]:
    """Schedule each of five named users independently and retain bounded results."""
    if not 1 <= requests_per_role <= 50 or not 0 <= duration_seconds <= 3600:
        raise ValueError("load schedule out of bounds")
    if set(headers) != set(CASES):
        raise ValueError("five named synthetic users required")
    start = time.monotonic()

    async def one_role(user: str) -> list[dict[str, object]]:
        rows = []
        choices = CASES[user]
        for number in range(requests_per_role):
            due = start + (number * duration_seconds / max(1, requests_per_role - 1))
            await asyncio.sleep(max(0, due - time.monotonic()))
            case_id, question, expected = choices[number % len(choices)]
            began = time.monotonic()
            try:
                response = await client.post("/api/chat", headers=headers[user],
                                             json={"message": question, "mode": "documents"})
                elapsed = time.monotonic() - began
                payload = response.json() if response.status_code == 200 else {}
                citations = payload.get("citations", [])
                cited = ([item.get("document_id") for item in citations]
                         if isinstance(citations, list) else [])
                passed = (response.status_code == 200 and
                          cited == ([expected] if expected else []) and
                          (expected is not None or payload.get("answer") == DENIAL))
                status = response.status_code
            except (httpx.HTTPError, ValueError, TypeError):
                elapsed = time.monotonic() - began
                passed, status = False, None
            rows.append({"user": user, "case_id": case_id, "number": number + 1,
                         "latency_seconds": round(elapsed, 3), "http_status": status,
                         "expected_outcome": "citation" if expected else "denial",
                         "outcome_pass": passed})
        return rows

    grouped = await asyncio.gather(*(one_role(user) for user in CASES))
    rows = [row for group in grouped for row in group]
    wall = time.monotonic() - start
    latency = [float(row["latency_seconds"]) for row in rows]
    return {"requests_per_role": requests_per_role, "scheduled_seconds": duration_seconds,
            "wall_seconds": round(wall, 3), "attempts": len(rows),
            "passed": sum(row["outcome_pass"] is True for row in rows),
            "failed": sum(row["outcome_pass"] is not True for row in rows),
            "throughput_per_second": round(len(rows) / wall, 3) if wall else None,
            "latency_p50_seconds": percentile(latency, 50),
            "latency_p95_seconds": percentile(latency, 95),
            "latency_p99_seconds": percentile(latency, 99), "samples": rows}


async def run_local(requests_per_role: int, duration_seconds: float) -> dict[str, object]:
    if not DATABASE.is_file():
        raise RuntimeError("build the synthetic Phase 3 index before load rehearsal")
    password = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="sovereign-core-load-") as directory:
        app = create_app(Settings(fixture_root=FIXTURES, lab_password=password,
                                  knowledge_manifest=MANIFEST, knowledge_db=DATABASE,
                                  audit_path=Path(directory) / "audit.jsonl"))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://core.invalid", timeout=120,
                                     trust_env=False) as client:
            headers = {}
            for user in CASES:
                login = await client.post("/api/login", json={"user_id": user, "password": password})
                login.raise_for_status()
                headers[user] = {"Authorization": "Bearer " + login.json()["access_token"]}
            result = await exercise(client, headers, requests_per_role=requests_per_role,
                                    duration_seconds=duration_seconds)
    return result


async def run_remote(url: str, tokens: Path, requests_per_role: int,
                     duration_seconds: float, ca_bundle: Path | None) -> dict[str, object]:
    url = core_url(url)
    if ca_bundle is not None:
        context = ssl.create_default_context(cadata=_private_file(ca_bundle, 64 * 1024).decode("ascii"))
    else:
        context = True
    async with httpx.AsyncClient(base_url=url, timeout=120, verify=context,
                                 trust_env=False, follow_redirects=False) as client:
        before = await client.get("/health")
        before.raise_for_status()
        result = await exercise(client, auth_headers(tokens), requests_per_role=requests_per_role,
                                duration_seconds=duration_seconds)
        try:
            after = await client.get("/health")
            result["health_after"] = after.status_code == 200
        except httpx.HTTPError:
            result["health_after"] = False
    result["health_before"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests-per-role", type=int, default=50)
    parser.add_argument("--duration-seconds", type=float, default=1800)
    parser.add_argument("--core-url", help="private numeric HTTPS endpoint; omit for local in-process Core")
    parser.add_argument("--tokens-file", type=Path, help="owner-only five-user token map for remote Core")
    parser.add_argument("--ca-bundle", type=Path, help="owner-only private CA for remote Core")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.core_url) != bool(args.tokens_file) or (args.ca_bundle and not args.core_url):
        parser.error("remote Core requires both --core-url and --tokens-file")
    if not 1 <= args.requests_per_role <= 50 or not 0 <= args.duration_seconds <= 3600:
        parser.error("load schedule out of bounds")
    if args.core_url:
        result = asyncio.run(run_remote(args.core_url, args.tokens_file,
                                        args.requests_per_role, args.duration_seconds,
                                        args.ca_bundle))
    else:
        result = asyncio.run(run_local(args.requests_per_role, args.duration_seconds))
    report = {"schema": 1, **stamp(),
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "mode": "remote-private-core" if args.core_url else "local-in-process-core",
              "host": {"system": platform.system(), "machine": platform.machine()},
              "fixture_manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
              "corpus_sha256": hashlib.sha256(json.dumps(CASES, sort_keys=True).encode()).hexdigest(),
              "result": result,
              "ttft_seconds": None, "model_300_token_p95_seconds": None,
              "gpu_thermals": None, "oom_or_restart_observation": None,
              "limits": ["Core uses non-streaming chat; time to first token is not observable here",
                         "no 300-token workload or GPU telemetry in this Core-only run",
                         "target packet capture, process observation and independent review remain"]}
    if args.output.exists():
        parser.error("output file already exists")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"attempts": result["attempts"], "passed": result["passed"],
                      "failed": result["failed"], "latency_p95_seconds": result["latency_p95_seconds"]}))
    if result["failed"] or result.get("health_after") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
