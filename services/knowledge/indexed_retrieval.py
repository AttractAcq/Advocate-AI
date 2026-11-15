"""Permission-filtered retrieval from the local Phase 3 passage index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3

from services.knowledge.acl import source_access

_WORDS = re.compile(r"[a-z0-9]{3,}")
_STOP = {"what", "which", "who", "when", "where", "why", "how", "the", "and", "for",
         "with", "from", "into", "about", "that", "this", "are", "can", "does", "did",
         "tell", "please", "there", "their", "your"}


def _terms(text: str) -> set[str]:
    return set(_WORDS.findall(text.casefold())) - _STOP


def approved_rows(root: Path, manifest: Path, database: Path, user_id: str) -> list[dict[str, str]]:
    """Recheck current manifest, policy and source bytes before exposing metadata."""
    base = root.resolve(strict=True)
    policy = json.loads((base / "roles.json").read_text(encoding="utf-8"))
    current = json.loads(manifest.read_text(encoding="utf-8"))
    if current.get("schema") != 1 or not isinstance(current.get("sources"), list):
        raise ValueError("source manifest unavailable")
    listed = {item.get("document_id"): item for item in current["sources"] if isinstance(item, dict)}
    approved = []
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute("SELECT * FROM sources WHERE state='ready'"):
            source = dict(row)
            manifest_row = listed.get(source["document_id"])
            if not isinstance(manifest_row, dict) or any(
                    str(manifest_row.get(key, "")) != source[key] for key in
                    ("relative_path", "collection", "classification", "owner", "version", "sha256", "source_type")):
                continue
            if not source_access(user_id, source, policy):
                continue
            relative = source["relative_path"]
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                continue
            path = (base / relative).resolve()
            if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
                continue
            approved.append(source)
    return approved


def search_index(
    root: Path, manifest: Path, database: Path, user_id: str, query: str,
    *, limit: int = 3, document_ids: set[str] | None = None,
    collections: set[str] | None = None,
) -> list[dict[str, object]]:
    if not isinstance(query, str) or not query.strip() or len(query) > 1000:
        raise ValueError("query must contain 1–1000 characters")
    if not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")
    wanted = _terms(query)
    if not wanted:
        return []
    candidates = [row for row in approved_rows(root, manifest, database, user_id)
                  if (document_ids is None or row["document_id"] in document_ids)
                  and (collections is None or row["collection"] in collections)]
    if not candidates:
        return []
    hits: list[tuple[float, str, int, dict[str, object]]] = []
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        for source in candidates:
            for ordinal, passage in db.execute(
                    "SELECT ordinal,text FROM passages WHERE document_id=? ORDER BY ordinal",
                    (source["document_id"],)):
                present = _terms(passage)
                common = wanted & present
                if not common:
                    continue
                score = len(common) / len(wanted)
                if score < 1.0:
                    continue
                hit = {"document_id": source["document_id"], "version": source["version"],
                       "collection": source["collection"], "classification": source["classification"],
                       "owner": source["owner"], "sha256": source["sha256"],
                       "ordinal": ordinal, "excerpt": passage[:2000], "score": score}
                hits.append((score, source["document_id"], ordinal, hit))
    hits.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [hit for _, _, _, hit in hits[:limit]]


def preview_index(root: Path, manifest: Path, database: Path, user_id: str,
                  document_id: str, ordinal: int = 0) -> dict[str, object] | None:
    if ordinal < 0 or ordinal > 10000:
        return None
    source = next((row for row in approved_rows(root, manifest, database, user_id)
                   if row["document_id"] == document_id), None)
    if source is None:
        return None
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        row = db.execute("SELECT text FROM passages WHERE document_id=? AND ordinal=?",
                         (document_id, ordinal)).fetchone()
    if row is None:
        return None
    return {"document_id": document_id, "version": source["version"], "sha256": source["sha256"],
            "ordinal": ordinal, "excerpt": row[0][:2000]}
