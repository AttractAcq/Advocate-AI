"""Synthetic PostgreSQL/pgvector knowledge index with live source authorisation.

The database holds a searchable projection, never the authority for access.
Every read still checks the current role policy, approved manifest and source
bytes before a passage can be returned to Core or an embedding request.
"""

from __future__ import annotations

import math
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from psycopg.rows import dict_row

from services.knowledge.indexed_retrieval import _terms, live_approved_rows
from services.knowledge.ingestion import (_parse_verified_bytes, _valid_source,
                                          chunks, parse_local)
from services.knowledge.manifest_io import load_manifest
from services.policy.policy_file import load_policy


class PostgresIndexUnavailable(OSError):
    """The configured local index cannot be read safely."""


def _connect(dsn: str) -> psycopg.Connection:
    parsed = urlsplit(dsn)
    if (parsed.scheme != "postgresql" or parsed.hostname not in ("127.0.0.1", "::1")
            or not parsed.path.strip("/") or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.username):
        raise ValueError("PostgreSQL index requires a passwordless numeric loopback URI")
    try:
        return psycopg.connect(dsn, connect_timeout=3,
                               options="-c statement_timeout=10000", row_factory=dict_row)
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL index unavailable") from exc


def initialize_schema(dsn: str) -> None:
    """Provision once with a migration role after pgvector is installed."""
    try:
        with _connect(dsn) as db:
            if db.execute("SELECT 1 FROM pg_extension WHERE extname='vector'").fetchone() is None:
                raise PostgresIndexUnavailable("pgvector extension unavailable")
            db.execute("""CREATE TABLE IF NOT EXISTS knowledge_sources (
                document_id text PRIMARY KEY, relative_path text NOT NULL,
                collection text NOT NULL, classification text NOT NULL,
                owner text NOT NULL, version text NOT NULL, sha256 text NOT NULL,
                source_type text NOT NULL, state text NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS knowledge_passages (
                document_id text NOT NULL REFERENCES knowledge_sources(document_id) ON DELETE CASCADE,
                ordinal integer NOT NULL, text text NOT NULL,
                PRIMARY KEY (document_id, ordinal))""")
            db.execute("""CREATE TABLE IF NOT EXISTS knowledge_quarantine (
                document_id text PRIMARY KEY, reason text NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS knowledge_vectors (
                document_id text NOT NULL, ordinal integer NOT NULL,
                model text NOT NULL, embedding vector NOT NULL,
                PRIMARY KEY (document_id, ordinal),
                FOREIGN KEY (document_id, ordinal) REFERENCES knowledge_passages(document_id, ordinal)
                    ON DELETE CASCADE)""")
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL schema unavailable") from exc


def verify_knowledge_snapshot(root: Path, manifest: Path, dsn: str,
                              *, expected_model: str | None = None,
                              parser=parse_local) -> dict[str, int]:
    """Check every indexed passage against the approved source bytes and policy.

    This is intended for a stopped or writer-locked recovery capture and a
    clean restore, not as a per-request query path. Quarantined or missing
    sources deny this complete recovery-set candidate.
    """
    base = root.resolve(strict=True)
    if not isinstance(load_policy(base / "roles.json"), dict):
        raise ValueError("source policy unavailable")
    payload = load_manifest(manifest)
    if (not isinstance(payload, dict) or payload.get("schema") != 1
            or not isinstance(payload.get("sources"), list)
            or len(payload["sources"]) > 10000):
        raise ValueError("invalid approved manifest")
    listed = payload["sources"]
    ids = [item.get("document_id") for item in listed if isinstance(item, dict)]
    if len(ids) != len(listed) or any(not isinstance(value, str) for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("duplicate or invalid approved source")
    try:
        with _connect(dsn) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            sources = {row["document_id"]: row for row in db.execute("SELECT * FROM knowledge_sources")}
            if set(sources) != set(ids) or db.execute("SELECT 1 FROM knowledge_quarantine LIMIT 1").fetchone():
                raise ValueError("knowledge index source set or quarantine mismatch")
            total_passages = 0
            for item in listed:
                identifier = item["document_id"]
                suffix, digest, source_bytes = _valid_source(base, item)
                metadata = {key: str(item[key]) for key in
                            ("relative_path", "collection", "classification", "owner", "version", "source_type")}
                metadata["sha256"] = digest
                source = sources[identifier]
                if source["state"] != "ready" or any(source[key] != value for key, value in metadata.items()):
                    raise ValueError("knowledge source metadata mismatch")
                expected = chunks(_parse_verified_bytes(source_bytes, suffix, parser))
                actual = db.execute("""SELECT ordinal,text FROM knowledge_passages
                    WHERE document_id=%s ORDER BY ordinal""", (identifier,)).fetchall()
                if [(row["ordinal"], row["text"]) for row in actual] != list(enumerate(expected)):
                    raise ValueError("knowledge passage mismatch")
                total_passages += len(expected)
            if expected_model is not None:
                vectors = db.execute("""SELECT document_id,ordinal,model,
                    vector_dims(embedding) AS dimensions FROM knowledge_vectors""").fetchall()
                if (len(vectors) != total_passages or any(
                        row["model"] != expected_model or not 1 <= row["dimensions"] <= 4096
                        for row in vectors)):
                    raise ValueError("knowledge vector set mismatch")
            return {"sources": len(sources), "passages": total_passages}
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL snapshot verification unavailable") from exc


def sync_manifest_pg(root: Path, manifest: Path, dsn: str, parser=parse_local) -> dict[str, object]:
    """Reconcile the approved manifest, including deletions and failed sources."""
    base = root.resolve(strict=True)
    payload = load_manifest(manifest)
    if not isinstance(payload, dict) or payload.get("schema") != 1 or not isinstance(payload.get("sources"), list):
        raise ValueError("invalid ingestion manifest")
    sources = payload["sources"]
    if len(sources) > 10000:
        raise ValueError("manifest too large")
    ids = [item.get("document_id") for item in sources if isinstance(item, dict)]
    if len(ids) != len(sources) or any(not isinstance(value, str) for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("duplicate or invalid source entries")
    result: dict[str, object] = {"indexed": [], "unchanged": [], "quarantined": [], "deleted": []}
    try:
        with _connect(dsn) as db:
            db.execute("SELECT pg_advisory_xact_lock(153352001)")
            existing = {row["document_id"]: row for row in db.execute("SELECT * FROM knowledge_sources")}
            active_ids = set(ids)
            for old in existing.keys() - active_ids:
                db.execute("DELETE FROM knowledge_sources WHERE document_id=%s", (old,))
                db.execute("DELETE FROM knowledge_quarantine WHERE document_id=%s", (old,))
                result["deleted"].append(old)
            seen_hashes: set[str] = set()
            for item in sources:
                document_id = item["document_id"]
                try:
                    suffix, digest, source_bytes = _valid_source(base, item)
                    if digest in seen_hashes:
                        raise ValueError("duplicate source payload")
                    seen_hashes.add(digest)
                    metadata = (item["relative_path"], item["collection"], item["classification"],
                                item["owner"], str(item["version"]), digest, item["source_type"])
                    previous = existing.get(document_id)
                    keys = ("relative_path", "collection", "classification", "owner", "version", "sha256", "source_type")
                    if previous and previous["state"] == "ready" and tuple(previous[key] for key in keys) == metadata:
                        result["unchanged"].append(document_id)
                        continue
                    passages = chunks(_parse_verified_bytes(source_bytes, suffix, parser))
                    db.execute("DELETE FROM knowledge_sources WHERE document_id=%s", (document_id,))
                    db.execute("""INSERT INTO knowledge_sources VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,'ready')""", (document_id, *metadata))
                    for ordinal, text in enumerate(passages):
                        db.execute("INSERT INTO knowledge_passages VALUES (%s,%s,%s)",
                                   (document_id, ordinal, text))
                    db.execute("DELETE FROM knowledge_quarantine WHERE document_id=%s", (document_id,))
                    result["indexed"].append(document_id)
                except (OSError, ValueError, UnicodeError, RuntimeError, ImportError) as exc:
                    db.execute("DELETE FROM knowledge_sources WHERE document_id=%s", (document_id,))
                    db.execute("""INSERT INTO knowledge_quarantine VALUES (%s,%s)
                        ON CONFLICT (document_id) DO UPDATE SET reason=excluded.reason""",
                               (document_id, type(exc).__name__))
                    result["quarantined"].append(document_id)
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL sync unavailable") from exc
    return result


def approved_rows_pg(root: Path, manifest: Path, dsn: str, user_id: str) -> list[dict[str, str]]:
    try:
        with _connect(dsn) as db:
            rows = db.execute("SELECT * FROM knowledge_sources WHERE state='ready'").fetchall()
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL source index unavailable") from exc
    return live_approved_rows(root, manifest, rows, user_id)


def _allowed(root: Path, manifest: Path, dsn: str, user_id: str,
             document_ids: set[str] | None, collections: set[str] | None) -> dict[str, dict[str, str]]:
    return {row["document_id"]: row for row in approved_rows_pg(root, manifest, dsn, user_id)
            if (document_ids is None or row["document_id"] in document_ids)
            and (collections is None or row["collection"] in collections)}


def _hit(source: dict[str, str], ordinal: int, passage: str, score: float) -> dict[str, object]:
    return {"document_id": source["document_id"], "version": source["version"],
            "collection": source["collection"], "classification": source["classification"],
            "owner": source["owner"], "sha256": source["sha256"], "ordinal": ordinal,
            "excerpt": passage[:2000], "score": score}


def search_index_pg(root: Path, manifest: Path, dsn: str, user_id: str, query: str, *,
                    limit: int = 3, document_ids: set[str] | None = None,
                    collections: set[str] | None = None) -> list[dict[str, object]]:
    if not isinstance(query, str) or not query.strip() or len(query) > 1000:
        raise ValueError("query must contain 1–1000 characters")
    if not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")
    wanted = _terms(query)
    if not wanted:
        return []
    allowed = _allowed(root, manifest, dsn, user_id, document_ids, collections)
    if not allowed:
        return []
    hits = []
    try:
        with _connect(dsn) as db:
            for row in db.execute("""SELECT p.document_id,p.ordinal,p.text,s.sha256
                FROM knowledge_passages p JOIN knowledge_sources s USING (document_id)
                WHERE p.document_id = ANY(%s) ORDER BY p.document_id,p.ordinal""", (list(allowed),)):
                if (row["sha256"] == allowed[row["document_id"]]["sha256"]
                        and wanted.issubset(_terms(row["text"]))):
                    source = allowed[row["document_id"]]
                    hits.append(_hit(source, row["ordinal"], row["text"], 1.0))
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL passage index unavailable") from exc
    current = _allowed(root, manifest, dsn, user_id, document_ids, collections)
    return [hit for hit in hits if hit["document_id"] in current and
            hit["sha256"] == current[hit["document_id"]]["sha256"]][:limit]


def preview_index_pg(root: Path, manifest: Path, dsn: str, user_id: str,
                     document_id: str, ordinal: int = 0) -> dict[str, object] | None:
    if ordinal < 0 or ordinal > 10000:
        return None
    source = _allowed(root, manifest, dsn, user_id, {document_id}, None).get(document_id)
    if source is None:
        return None
    try:
        with _connect(dsn) as db:
            row = db.execute("""SELECT p.text,s.sha256 FROM knowledge_passages p
                JOIN knowledge_sources s USING (document_id)
                WHERE p.document_id=%s AND p.ordinal=%s""", (document_id, ordinal)).fetchone()
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL passage index unavailable") from exc
    if row is None or row["sha256"] != source["sha256"]:
        return None
    current = _allowed(root, manifest, dsn, user_id, {document_id}, None).get(document_id)
    if current is None or current["sha256"] != source["sha256"]:
        return None
    return {"document_id": document_id, "version": source["version"],
            "sha256": source["sha256"], "ordinal": ordinal, "excerpt": row["text"][:2000]}


def _vector_literal(values: list[float]) -> str:
    if not 1 <= len(values) <= 4096 or any(not isinstance(x, (float, int)) or not math.isfinite(x) for x in values):
        raise ValueError("invalid embedding values")
    return "[" + ",".join(str(float(value)) for value in values) + "]"


def build_vectors_pg(dsn: str, embedder) -> int:
    try:
        with _connect(dsn) as db:
            db.execute("SELECT pg_advisory_xact_lock(153352001)")
            rows = db.execute("""SELECT p.document_id,p.ordinal,p.text FROM knowledge_passages p
                LEFT JOIN knowledge_vectors v USING (document_id,ordinal)
                WHERE v.document_id IS NULL OR v.model<>%s ORDER BY p.document_id,p.ordinal""",
                              (embedder.model,)).fetchall()
            for start in range(0, len(rows), 32):
                batch = rows[start:start + 32]
                vectors = embedder.embed([row["text"] for row in batch])
                if len(vectors) != len(batch):
                    raise ValueError("embedding response count mismatch")
                for row, vector in zip(batch, vectors, strict=True):
                    db.execute("""INSERT INTO knowledge_vectors VALUES (%s,%s,%s,%s::vector)
                        ON CONFLICT (document_id,ordinal) DO UPDATE
                        SET model=excluded.model, embedding=excluded.embedding""",
                               (row["document_id"], row["ordinal"], embedder.model, _vector_literal(vector)))
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL vector index unavailable") from exc
    return len(rows)


def vector_search_pg(root: Path, manifest: Path, dsn: str, user_id: str, query: str,
                     embedder, *, limit: int = 3, document_ids: set[str] | None = None,
                     collections: set[str] | None = None) -> list[dict[str, object]]:
    if not isinstance(query, str) or not query.strip() or len(query) > 1000 or not 1 <= limit <= 10:
        raise ValueError("invalid vector query")
    wanted = _terms(query)
    if not wanted:
        return []
    allowed = _allowed(root, manifest, dsn, user_id, document_ids, collections)
    if not allowed:
        return []
    needle = _vector_literal(embedder.embed([query])[0])
    hits = []
    try:
        with _connect(dsn) as db:
            rows = db.execute("""SELECT p.document_id,p.ordinal,p.text,s.sha256,
                1 - (v.embedding <=> %s::vector) AS score
                FROM knowledge_passages p JOIN knowledge_vectors v USING (document_id,ordinal)
                JOIN knowledge_sources s USING (document_id)
                WHERE p.document_id = ANY(%s) AND v.model=%s
                  AND vector_dims(v.embedding)=vector_dims(%s::vector)
                ORDER BY v.embedding <=> %s::vector, p.document_id, p.ordinal""",
                (needle, list(allowed), embedder.model, needle, needle)).fetchall()
            for row in rows:
                if (row["sha256"] == allowed[row["document_id"]]["sha256"]
                        and wanted.issubset(_terms(row["text"])) and row["score"] is not None):
                    hits.append(_hit(allowed[row["document_id"]], row["ordinal"],
                                     row["text"], float(row["score"])))
    except psycopg.Error as exc:
        raise PostgresIndexUnavailable("PostgreSQL vector index unavailable") from exc
    current = _allowed(root, manifest, dsn, user_id, document_ids, collections)
    return [hit for hit in hits if hit["document_id"] in current and
            hit["sha256"] == current[hit["document_id"]]["sha256"]][:limit]
