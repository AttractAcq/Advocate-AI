"""Evaluate generated synthetic answers against the fixed 50-question corpus."""

from __future__ import annotations

import asyncio
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess

from apps.api.model import LocalModel
from services.knowledge.indexed_retrieval import search_index

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "phase-3/approved-sources.json"
DATABASE = ROOT / "infrastructure/lab/runtime/phase3-knowledge/index.sqlite3"
OUT = ROOT / "docs/phase-3/answer-evaluation.json"


async def run() -> dict[str, object]:
    with (FIXTURES / "evaluation.csv").open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    model = LocalModel("http://127.0.0.1:11434/v1", "qwen3.5:2b")
    semaphore = asyncio.Semaphore(2)

    async def evaluate(case: dict[str, str]) -> dict[str, object]:
        async with semaphore:
            user = "lab-captain-1" if case["user_role"] == "captain" else "lab-deckhand-1"
            context = search_index(FIXTURES, MANIFEST, DATABASE, user, case["question"])
            if context:
                answer = await model.complete(case["question"], context)
            else:
                answer = "No matching permitted source was found. I cannot answer from vessel documents."
            expected = case["expected_document_id"]
            has_source = bool(context) and context[0]["document_id"] == expected
            marker_present = case["expected_answer"] in answer if expected != "DENY" else not context
            citation_in_answer = expected in answer and ("v1" in answer or "version 1" in answer)
            return {"question_id": case["question_id"], "expected_document_id": expected,
                    "retrieved_document_ids": [item["document_id"] for item in context],
                    "answer": answer, "expected_marker_present": marker_present,
                    "expected_source_selected": has_source if expected != "DENY" else not context,
                    "source_label_in_answer": citation_in_answer if expected != "DENY" else not context}

    results = await asyncio.gather(*(evaluate(case) for case in cases))
    allowed = [item for item in results if item["expected_document_id"] != "DENY"]
    denied = [item for item in results if item["expected_document_id"] == "DENY"]
    summary = {"cases": len(results), "allowed": len(allowed), "denied": len(denied),
               "expected_marker_answers": sum(item["expected_marker_present"] for item in allowed),
               "source_labels_in_answers": sum(item["source_label_in_answer"] for item in allowed),
               "no_answer_denials": sum(item["expected_marker_present"] for item in denied)}
    report = {"schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "host": {"system": platform.system(), "machine": platform.machine()},
              "model": "qwen3.5:2b", "summary": summary, "cases": results,
              "interpretation": "Marker and source-label checks are automated proxies; a human assessor must review claim support and uncertainty."}
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run())["summary"], sort_keys=True))
