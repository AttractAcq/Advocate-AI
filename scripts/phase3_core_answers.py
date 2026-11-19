"""Record synthetic generated answers and Core's structured citation evidence."""

from __future__ import annotations

import asyncio
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile

import httpx

from apps.api.main import Settings, create_app

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "phase-3/approved-sources.json"
DATABASE = ROOT / "infrastructure/lab/runtime/phase3-knowledge/index.sqlite3"
OUT = ROOT / "docs/phase-3/core-answer-evaluation.json"


async def run() -> dict[str, object]:
    if not DATABASE.is_file():
        raise RuntimeError("build the synthetic Phase 3 index before evaluating Core")
    with (FIXTURES / "evaluation.csv").open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    password = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="sovereign-core-eval-") as directory:
        app = create_app(Settings(fixture_root=FIXTURES, lab_password=password,
                                  knowledge_manifest=MANIFEST, knowledge_db=DATABASE,
                                  audit_path=Path(directory) / "audit.jsonl"))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://core.invalid") as client:
            tokens = {}
            for user in ("lab-captain-1", "lab-captain-2", "lab-deckhand-1"):
                login = await client.post("/api/login", json={"user_id": user,
                                                               "password": password})
                login.raise_for_status()
                tokens[user] = login.json()["access_token"]
            results = []
            for number, case in enumerate(cases):
                user = ("lab-deckhand-1" if case["user_role"] == "deckhand" else
                        f"lab-captain-{number % 2 + 1}")
                headers = {"Authorization": f"Bearer {tokens[user]}"}
                reply = await client.post("/api/chat", headers=headers,
                                          json={"message": case["question"],
                                                "mode": "documents"})
                reply.raise_for_status()
                turn = reply.json()
                passages = []
                for citation in turn["citations"]:
                    preview = await client.get(
                        f"/api/sources/{citation['document_id']}/preview",
                        params={"ordinal": citation["ordinal"]}, headers=headers)
                    preview.raise_for_status()
                    source = preview.json()
                    if any(source[key] != citation[key] for key in
                           ("document_id", "version", "sha256", "ordinal")):
                        raise RuntimeError("Core citation changed before preview")
                    passages.append({"citation": citation, "excerpt": source["excerpt"]})
                expected = case["expected_document_id"]
                results.append({
                    "question_id": case["question_id"], "role": case["user_role"],
                    "question": case["question"], "expected_document_id": expected,
                    "answer": turn["answer"], "citations": passages,
                    "expected_marker_in_answer": (case["expected_answer"] in turn["answer"]
                                                  if expected != "DENY" else None),
                    "expected_source_cited": (any(item["citation"]["document_id"] == expected
                                                  and case["expected_answer"] in item["excerpt"]
                                                  for item in passages)
                                              if expected != "DENY" else None),
                    "no_answer_denial": (not passages and turn["answer"] ==
                                         "No matching permitted source was found. I cannot answer from vessel documents."
                                         if expected == "DENY" else None),
                })
    allowed = [item for item in results if item["expected_document_id"] != "DENY"]
    denied = [item for item in results if item["expected_document_id"] == "DENY"]
    summary = {"cases": len(results), "allowed": len(allowed), "denied": len(denied),
               "expected_marker_answers": sum(item["expected_marker_in_answer"] is True for item in allowed),
               "expected_source_citations": sum(item["expected_source_cited"] is True for item in allowed),
               "no_answer_denials": sum(item["no_answer_denial"] is True for item in denied)}
    report = {
        "schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                  cwd=ROOT, text=True).strip(),
        "host": {"system": platform.system(), "machine": platform.machine()},
        "model": "qwen3.5:2b", "fixture_manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        "summary": summary, "cases": results,
        "limits": ["synthetic fixtures and lab authentication only",
                   "Core API citations and previews captured after each answer",
                   "no independent claim-support or production identity assessment"],
    }
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run())["summary"], sort_keys=True))
