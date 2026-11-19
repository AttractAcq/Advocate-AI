"""Permission-filtered retrieval from the local Phase 3 passage index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3

from services.knowledge.acl import source_access
from services.knowledge.paths import source_path
from services.knowledge.manifest_io import read_manifest_bytes

_WORDS = re.compile(r"[a-z0-9]{3,}")
_STOP = {"what", "which", "who", "when", "where", "why", "how", "the", "and", "for",
         "with", "from", "into", "about", "that", "this", "are", "can", "does", "did",
         "tell", "please", "there", "their", "your"}


class SourceManifestError(ValueError):
    """An approved-source manifest is unusable; no indexed row may be exposed."""


def _terms(text: str) -> set[str]:
    return set(_WORDS.findall(text.casefold())) - _STOP


def approved_rows(root: Path, manifest: Path, database: Path, user_id: str) -> list[dict[str, str]]:
    """Recheck current manifest, policy and source bytes before exposing metadata."""
    base = root.resolve(strict=True)
    try:
        policy = json.loads((base / "roles.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceManifestError("source policy unavailable") from exc
    if not isinstance(policy, dict):
        raise SourceManifestError("source policy unavailable")
    try:
        current = json.loads(read_manifest_bytes(manifest))
    except (OSError, ValueError, UnicodeError) as exc:
        raise SourceManifestError("source manifest unavailable") from exc
    if not isinstance(current, dict) or current.get("schema") != 1 or not isinstance(current.get("sources"), list):
        raise SourceManifestError("source manifest unavailable")
    listed = {}
    for item in current["sources"]:
        if not isinstance(item, dict):
            raise SourceManifestError("source manifest malformed")
        document_id = item.get("document_id")
        if not isinstance(document_id, str) or not document_id or document_id in listed:
            raise SourceManifestError("source manifest has invalid or duplicate IDs")
        listed[document_id] = item
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
            try:
                path = source_path(base, relative)
            except (OSError, ValueError):
                continue
            if path.stat().st_size > 8 * 1024 * 1024:
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
