"""Permission-filtered search over the generated text fixtures.

This module is a Phase 2 local prototype, not a production ingestion pipeline.
It intentionally has no NAS adapter, parser, vector store, or model dependency.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import re

from services.knowledge.acl import source_access
from services.knowledge.paths import source_path

_WORDS = re.compile(r"[a-z0-9]{3,}")
_STOPWORDS = {"what", "which", "who", "when", "where", "why", "how", "the", "and", "for",
              "with", "from", "into", "about", "that", "this", "are", "can", "does", "did",
              "tell", "please", "there", "their", "your"}
_MAX_DOCUMENT_BYTES = 64 * 1024
_MAX_QUERY_CHARS = 1000


def _terms(value: str) -> set[str]:
    return set(_WORDS.findall(value.casefold())) - _STOPWORDS


def search_fixture_documents(
    fixture_root: Path,
    user_id: str,
    query: str,
    *,
    limit: int = 3,
    document_ids: set[str] | None = None,
    collections: set[str] | None = None,
) -> list[dict[str, object]]:
    """Return matched, authorised, hash-verified fixture excerpts and citations.

    The manifest and policy are loaded per request so fixture permission changes
    and deletions take effect immediately. An invalid source is skipped closed.
    """
    if not isinstance(query, str) or not query.strip() or len(query) > _MAX_QUERY_CHARS:
        raise ValueError("query must contain 1–1000 characters")
    if not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")
    base = fixture_root.resolve(strict=True)
    manifest = base / "manifest.csv"
    policy = json.loads((base / "roles.json").read_text(encoding="utf-8"))
    wanted = _terms(query)
    if not wanted:
        return []

    matches: list[tuple[int, str, dict[str, object]]] = []
    with manifest.open(newline="", encoding="utf-8") as stream:
        for source in csv.DictReader(stream):
            # Authorise metadata before opening the content file.
            if not source_access(user_id, source, policy):
                continue
            if document_ids is not None and source.get("document_id") not in document_ids:
                continue
            if collections is not None and source.get("collection") not in collections:
                continue
            relative = source.get("relative_path", "")
            if not relative.endswith(".txt"):
                continue
            try:
                path = source_path(base, relative)
            except (OSError, ValueError):
                continue
            if path.stat().st_size > _MAX_DOCUMENT_BYTES:
                continue
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != source["sha256"]:
                continue
            try:
                body = payload.decode("utf-8")
            except UnicodeDecodeError:
                continue
            present = _terms(body)
            if not wanted.issubset(present):
                continue
            score = len(wanted)
            hit: dict[str, object] = {
                "document_id": source["document_id"],
                "version": source["version"],
                "collection": source["collection"],
                "sha256": source["sha256"],
                "excerpt": body[:2000],
                "score": score,
            }
            matches.append((score, source["document_id"], hit))
    matches.sort(key=lambda item: (-item[0], item[1]))
    return [hit for _, _, hit in matches[:limit]]
