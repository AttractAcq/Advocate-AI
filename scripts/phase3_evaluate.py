"""Run the synthetic Phase 3 ingestion and retrieval evaluation locally."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import subprocess

from services.knowledge.embedding import LocalEmbedder, build_vectors, vector_search
from services.knowledge.ingestion import sync_manifest
from services.knowledge.indexed_retrieval import search_index

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "phase-3/approved-sources.json"
DATABASE = ROOT / "infrastructure/lab/runtime/phase3-knowledge/index.sqlite3"
OUT = ROOT / "docs/phase-3/evaluation.json"


def run() -> dict[str, object]:
    ingestion = sync_manifest(FIXTURES, MANIFEST, DATABASE)
    embedder = LocalEmbedder()
    embedded = build_vectors(DATABASE, embedder)
    with (FIXTURES / "evaluation.csv").open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    results = []
    for case in cases:
        user = "lab-captain-1" if case["user_role"] == "captain" else "lab-deckhand-1"
        lexical = search_index(FIXTURES, MANIFEST, DATABASE, user, case["question"])
        vector = vector_search(FIXTURES, MANIFEST, DATABASE, user, case["question"], embedder)
        results.append({"question_id": case["question_id"], "expected": case["expected_document_id"],
                        "lexical": lexical[0]["document_id"] if lexical else "DENY",
                        "vector": vector[0]["document_id"] if vector else "DENY"})
    summary = {"cases": len(results),
               "lexical_correct": sum(item["lexical"] == item["expected"] for item in results),
               "guarded_vector_correct": sum(item["vector"] == item["expected"] for item in results),
               "no_answer_cases": sum(item["expected"] == "DENY" for item in results),
               "no_answer_lexical": sum(item["expected"] == item["lexical"] == "DENY" for item in results),
               "no_answer_vector": sum(item["expected"] == item["vector"] == "DENY" for item in results)}
    if summary != {"cases": 50, "lexical_correct": 50, "guarded_vector_correct": 50,
                   "no_answer_cases": 10, "no_answer_lexical": 10, "no_answer_vector": 10}:
        raise RuntimeError(f"Phase 3 retrieval evaluation failed: {summary}")
    report = {
        "schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "fixture_manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        "embedding_model": embedder.model,
        "ingestion": {key: sorted(value) for key, value in ingestion.items()},
        "new_vectors": embedded,
        "summary": summary, "cases": results,
        "limits": ["synthetic data only", "guarded vector search requires exact query terms",
                   "this tests retrieval selection, not generated-answer correctness or vessel ACLs"],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    report = run()
    print(json.dumps(report["summary"], sort_keys=True))
