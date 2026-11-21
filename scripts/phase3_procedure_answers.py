"""Record non-marker procedure answers and Core's exact citation previews."""

from __future__ import annotations

import asyncio
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
OUT = ROOT / "docs/phase-3/procedure-answer-evaluation.json"
CASES = (
    ("P-MAN-001", "lab-captain-1", "According to the Visitor arrival procedure, what actions are required?", "MAN-001"),
    ("P-ENG-006", "lab-captain-1", "What actions does the HVAC intake procedure require?", "ENG-006"),
    ("P-INT-009", "lab-captain-1", "What actions does the Table setting procedure require?", "INT-009"),
    ("P-DEC-001", "lab-captain-1", "What actions does the Line inspection procedure require?", "DEC-001"),
    ("P-DENY-ENG-006", "lab-deckhand-1", "What actions does the HVAC intake procedure require?", None),
)


def require_expected_outcomes(results: list[dict[str, object]]) -> None:
    """Refuse to publish a passing-looking report with missing or extra sources."""
    failures = []
    for item in results:
        expected = item["expected_document_id"]
        cited = {entry["citation"]["document_id"] for entry in item["citations"]}
        if expected is None:
            if item["no_answer_denial"] is not True or cited:
                failures.append(str(item["case_id"]))
        elif cited != {expected} or item["expected_source_cited"] is not True:
            failures.append(str(item["case_id"]))
    if failures:
        raise RuntimeError("procedure evaluation failed: " + ", ".join(failures))


async def run() -> dict[str, object]:
    if not DATABASE.is_file():
        raise RuntimeError("build the synthetic Phase 3 index before evaluating Core")
    password = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="sovereign-procedure-eval-") as directory:
        app = create_app(Settings(fixture_root=FIXTURES, lab_password=password,
                                  knowledge_manifest=MANIFEST, knowledge_db=DATABASE,
                                  audit_path=Path(directory) / "audit.jsonl"))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://core.invalid", timeout=120) as client:
            headers = {}
            for user in {case[1] for case in CASES}:
                login = await client.post("/api/login", json={"user_id": user, "password": password})
                login.raise_for_status()
                headers[user] = {"Authorization": "Bearer " + login.json()["access_token"]}
            results = []
            for identifier, user, question, expected in CASES:
                reply = await client.post("/api/chat", headers=headers[user],
                                          json={"message": question, "mode": "documents"})
                reply.raise_for_status()
                turn = reply.json()
                citations = []
                for citation in turn["citations"]:
                    preview = await client.get(
                        f"/api/sources/{citation['document_id']}/preview",
                        params={"ordinal": citation["ordinal"]}, headers=headers[user])
                    preview.raise_for_status()
                    source = preview.json()
                    if any(source[key] != citation[key] for key in
                           ("document_id", "version", "sha256", "ordinal")):
                        raise RuntimeError("Core citation changed before preview")
                    citations.append({"citation": citation, "excerpt": source["excerpt"]})
                matched = (any(item["citation"]["document_id"] == expected
                               for item in citations) if expected else None)
                denied = (not citations and turn["answer"] ==
                          "No matching permitted source was found. I cannot answer from vessel documents.")
                results.append({"case_id": identifier, "role": user, "question": question,
                                "expected_document_id": expected, "answer": turn["answer"],
                                "citations": citations, "expected_source_cited": matched,
                                "no_answer_denial": denied if expected is None else None})
    require_expected_outcomes(results)
    allowed = [item for item in results if item["expected_document_id"]]
    denied = [item for item in results if not item["expected_document_id"]]
    report = {
        "schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                  cwd=ROOT, text=True).strip(),
        "host": {"system": platform.system(), "machine": platform.machine()},
        "model": "qwen3.5:2b", "fixture_manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        "summary": {"cases": len(results), "expected_source_citations": sum(
            item["expected_source_cited"] is True for item in allowed),
                    "no_answer_denials": sum(item["no_answer_denial"] is True for item in denied)},
        "cases": results,
        "limits": ["fictional procedures and local lab identity only",
                   "claim support requires manual reading of each answer and excerpt",
                   "no independent assessment or target vessel evidence"],
    }
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run())["summary"], sort_keys=True))
