"""Local-only embedding adapter and permission-filtered vector ranking."""

from __future__ import annotations

from array import array
import ipaddress
import math
from pathlib import Path
import sqlite3
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from services.knowledge.indexed_retrieval import _terms, approved_rows


class Embedder(Protocol):
    model: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class LocalEmbedder:
    def __init__(self, endpoint: str = "http://127.0.0.1:11434", model: str = "embeddinggemma:300m") -> None:
        parsed = urlsplit(endpoint)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("embedding endpoint must be numeric loopback") from exc
        if (parsed.scheme != "http" or not address.is_loopback or not parsed.port or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("embedding endpoint must be HTTP loopback")
        if not model or len(model) > 100 or "/" in model:
            raise ValueError("invalid embedding model")
        self.endpoint = endpoint.rstrip("/")
        self.model = model

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts or len(texts) > 32 or any(not isinstance(t, str) or not t or len(t) > 8000 for t in texts):
            raise ValueError("invalid embedding batch")
        with httpx.Client(timeout=120, trust_env=False, follow_redirects=False) as client:
            response = client.post(f"{self.endpoint}/api/embed", json={"model": self.model, "input": texts})
            response.raise_for_status()
            vectors = response.json()["embeddings"]
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise ValueError("embedding response count mismatch")
        size = len(vectors[0])
        if not 64 <= size <= 4096 or any(len(v) != size or any(not math.isfinite(x) for x in v) for v in vectors):
            raise ValueError("invalid embedding values")
        return vectors


def _pack(values: list[float]) -> bytes:
    return array("f", values).tobytes()


def _unpack(payload: bytes) -> array:
    vector = array("f")
    vector.frombytes(payload)
    return vector


def build_vectors(database: Path | str, embedder: Embedder) -> int:
    """Embed indexed passages. Source changes delete old vectors transactionally."""
    if isinstance(database, str) and database.startswith("postgresql://"):
        from services.knowledge.postgres_index import build_vectors_pg
        return build_vectors_pg(database, embedder)
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS vectors (
                document_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                model TEXT NOT NULL, vector BLOB NOT NULL,
                PRIMARY KEY (document_id,ordinal),
                FOREIGN KEY (document_id,ordinal) REFERENCES passages(document_id,ordinal) ON DELETE CASCADE
            );
        """)
        rows = db.execute("""SELECT p.document_id,p.ordinal,p.text FROM passages p
            LEFT JOIN vectors v ON p.document_id=v.document_id AND p.ordinal=v.ordinal
            WHERE v.document_id IS NULL OR v.model<>? ORDER BY p.document_id,p.ordinal""",
            (embedder.model,)).fetchall()
        total = 0
        for start in range(0, len(rows), 32):
            batch = rows[start:start + 32]
            vectors = embedder.embed([row[2] for row in batch])
            db.executemany("INSERT OR REPLACE INTO vectors VALUES (?,?,?,?)",
                           [(row[0], row[1], embedder.model, _pack(vector))
                            for row, vector in zip(batch, vectors, strict=True)])
            total += len(batch)
        return total


def vector_search(root: Path, manifest: Path, database: Path | str, user_id: str, query: str,
                  embedder: Embedder, *, limit: int = 3,
                  document_ids: set[str] | None = None,
                  collections: set[str] | None = None) -> list[dict[str, object]]:
    """Authorise sources before reading or scoring passage vectors."""
    if isinstance(database, str) and database.startswith("postgresql://"):
        from services.knowledge.postgres_index import vector_search_pg
        return vector_search_pg(root, manifest, database, user_id, query, embedder,
                                limit=limit, document_ids=document_ids, collections=collections)
    if not query.strip() or len(query) > 1000 or not 1 <= limit <= 10:
        raise ValueError("invalid vector query")
    wanted = _terms(query)
    if not wanted:
        return []
    allowed = {row["document_id"]: row for row in approved_rows(root, manifest, database, user_id)
               if (document_ids is None or row["document_id"] in document_ids)
               and (collections is None or row["collection"] in collections)}
    if not allowed:
        return []
    needle = embedder.embed([query])[0]
    needle_norm = math.sqrt(sum(x*x for x in needle))
    if not needle_norm:
        return []
    scores = []
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        for document_id in allowed:
            for ordinal, passage, payload in db.execute("""SELECT p.ordinal,p.text,v.vector
                FROM passages p JOIN vectors v USING (document_id,ordinal)
                WHERE p.document_id=? AND v.model=?""", (document_id, embedder.model)):
                if not wanted.issubset(_terms(passage)):
                    continue
                vector = _unpack(payload)
                if len(vector) != len(needle):
                    continue
                norm = math.sqrt(sum(x*x for x in vector))
                if not norm:
                    continue
                score = sum(a*b for a, b in zip(needle, vector, strict=True)) / (needle_norm * norm)
                source = allowed[document_id]
                scores.append((score, document_id, ordinal, {
                    "document_id": document_id, "version": source["version"],
                    "collection": source["collection"], "classification": source["classification"],
                    "owner": source["owner"], "sha256": source["sha256"],
                    "ordinal": ordinal, "excerpt": passage[:2000], "score": score,
                }))
    scores.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [item[3] for item in scores[:limit]]
