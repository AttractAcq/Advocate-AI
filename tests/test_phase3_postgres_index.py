"""Run with SOVEREIGN_TEST_PG_DSN against a disposable local pgvector database."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from urllib.parse import urlsplit

import httpx

from apps.api.main import Settings, create_app

from services.knowledge.ingestion import sync_manifest
from services.knowledge.indexed_retrieval import approved_rows, preview_index, search_index
from services.knowledge.embedding import build_vectors, vector_search
from services.knowledge.postgres_index import (_connect, _schema_state, initialize_schema,
                                               migrate_unversioned_schema,
                                               PostgresIndexUnavailable, verify_schema_version,
                                               verify_knowledge_snapshot)


class FakeEmbedder:
    model = "synthetic-pgvector"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float("generator" in text.casefold()),
                 float("deck" in text.casefold())] for text in texts]


class FakeModel:
    async def complete(self, question: str, context: list[dict[str, object]], *, general: bool = False) -> str:
        return "Synthetic answer [ENG-001 v1]"


class ConstantEmbedder:
    model = "synthetic-generic-query"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0] for _ in texts]


class SchemaVersionBoundaryTests(unittest.TestCase):
    def test_unversioned_existing_table_requires_explicit_migration(self) -> None:
        db = Mock()
        db.execute.return_value.fetchone.side_effect = [
            {"present": False}, {"present": True},
            {"present": False}, {"present": False}, {"present": False},
        ]
        with self.assertRaisesRegex(PostgresIndexUnavailable, "unversioned"):
            _schema_state(db)
        self.assertFalse(db.execute.return_value.fetchall.called)

    def test_future_version_is_not_accepted_as_current(self) -> None:
        db = Mock()
        db.execute.return_value.fetchone.side_effect = [{"present": True}] * 5
        db.execute.return_value.fetchall.return_value = [
            {"singleton": True, "version": 2}]
        with self.assertRaisesRegex(PostgresIndexUnavailable, "unsupported"):
            _schema_state(db)


@unittest.skipUnless(os.environ.get("SOVEREIGN_TEST_PG_DSN"), "local pgvector database not configured")
class PostgresKnowledgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dsn = os.environ["SOVEREIGN_TEST_PG_DSN"]
        if urlsplit(self.dsn).path != "/sovereign_pgvector_test":
            raise ValueError("pgvector integration tests require the disposable test database")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "sources").mkdir()
        self.manifest = self.root / "approved.json"
        self.policy = {"users": [{"id": "engineer", "role": "chief_engineer", "status": "active"},
                                 {"id": "deckhand", "role": "deckhand", "status": "active"}],
                       "allow": {"chief_engineer": ["engineering", "deck"], "deckhand": ["deck"]},
                       "document_rules": {}}
        self.rows = []
        self.add_source("ENG-001", "engineering", "generator inspection secret marker")
        self.add_source("DEC-001", "deck", "deck line inspection marker")
        initialize_schema(self.dsn)
        with _connect(self.dsn) as db:
            db.execute("DELETE FROM knowledge_sources")
            db.execute("DELETE FROM knowledge_quarantine")
        self.save()

    def add_source(self, identifier: str, collection: str, body: str) -> None:
        relative = f"sources/{identifier}.txt"
        payload = body.encode()
        (self.root / relative).write_bytes(payload)
        self.rows.append({"document_id": identifier, "relative_path": relative,
                          "collection": collection, "classification": f"C0_SYNTHETIC_{collection.upper()}",
                          "owner": "lab", "version": "1", "sha256": hashlib.sha256(payload).hexdigest(),
                          "source_type": "synthetic-local"})

    def save(self) -> dict[str, object]:
        self.manifest.write_text(json.dumps({"schema": 1, "sources": self.rows}))
        (self.root / "roles.json").write_text(json.dumps(self.policy))
        return sync_manifest(self.root, self.manifest, self.dsn)

    def test_permission_revocation_deletion_and_vector_ranking(self) -> None:
        self.assertEqual([hit["document_id"] for hit in search_index(
            self.root, self.manifest, self.dsn, "engineer", "generator inspection")], ["ENG-001"])
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "deckhand", "generator inspection"), [])
        self.assertIsNone(preview_index(self.root, self.manifest, self.dsn, "deckhand", "ENG-001"))
        self.assertEqual(build_vectors(self.dsn, FakeEmbedder()), 2)
        self.assertEqual(build_vectors(self.dsn, FakeEmbedder()), 0)
        self.assertEqual(verify_knowledge_snapshot(self.root, self.manifest, self.dsn,
                                                   expected_model=FakeEmbedder.model),
                         {"sources": 2, "passages": 2})
        self.assertEqual([hit["document_id"] for hit in vector_search(
            self.root, self.manifest, self.dsn, "engineer", "generator", FakeEmbedder())], ["ENG-001"])
        self.assertEqual(vector_search(self.root, self.manifest, self.dsn,
                                       "deckhand", "generator", FakeEmbedder()), [])
        self.policy["document_rules"] = {"ENG-001": {"deny_users": ["engineer"]}}
        (self.root / "roles.json").write_text(json.dumps(self.policy))
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "engineer", "generator inspection"), [])
        self.policy["document_rules"] = {}
        (self.root / "roles.json").write_text(json.dumps(self.policy))
        (self.root / "sources/ENG-001.txt").unlink()
        self.assertEqual(approved_rows(self.root, self.manifest, self.dsn, "engineer")[0]["document_id"], "DEC-001")
        result = self.save()
        self.assertIn("ENG-001", result["quarantined"])
        self.assertEqual(vector_search(self.root, self.manifest, self.dsn,
                                       "engineer", "generator", FakeEmbedder()), [])

    def test_generic_query_requires_selected_document(self) -> None:
        self.add_source("ENG-002", "engineering",
                        "HVAC intake procedure. Required action: Isolate the test equipment.")
        self.save()
        question = "What actions are required?"
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "engineer", question), [])
        self.assertEqual([hit["document_id"] for hit in search_index(
            self.root, self.manifest, self.dsn, "engineer", question,
            document_ids={"ENG-002"})], ["ENG-002"])
        build_vectors(self.dsn, ConstantEmbedder())
        self.assertEqual(vector_search(self.root, self.manifest, self.dsn,
                                       "engineer", question, ConstantEmbedder()), [])
        self.assertEqual([hit["document_id"] for hit in vector_search(
            self.root, self.manifest, self.dsn, "engineer", question, ConstantEmbedder(),
            document_ids={"ENG-002"})], ["ENG-002"])
        overview = "Summarize this"
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "engineer", overview), [])
        self.assertEqual([hit["document_id"] for hit in search_index(
            self.root, self.manifest, self.dsn, "engineer", overview,
            document_ids={"ENG-002"})], ["ENG-002"])
        self.assertEqual([hit["document_id"] for hit in vector_search(
            self.root, self.manifest, self.dsn, "engineer", overview, ConstantEmbedder(),
            document_ids={"ENG-002"})], ["ENG-002"])
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "deckhand", overview, document_ids={"ENG-002"}), [])

    def test_manifest_failure_and_replacement_invalidate_results(self) -> None:
        original = dict(self.rows[0])
        self.manifest.write_text(json.dumps({"schema": 1, "sources": [original, original]}))
        with self.assertRaises(ValueError):
            approved_rows(self.root, self.manifest, self.dsn, "engineer")
        self.manifest.write_text(json.dumps({"schema": 1, "sources": [original]}))
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "engineer", "deck line"), [])
        (self.root / "sources/ENG-001.txt").write_text("changed source")
        self.assertEqual(search_index(self.root, self.manifest, self.dsn,
                                      "engineer", "generator inspection"), [])

    def test_explicit_legacy_migration_checks_sources_and_table_shape(self) -> None:
        with _connect(self.dsn) as db:
            db.execute("DROP TABLE public.knowledge_schema_version")
        with self.assertRaisesRegex(PostgresIndexUnavailable, "unversioned"):
            verify_schema_version(self.dsn)
        original = (self.root / "sources/ENG-001.txt").read_bytes()
        (self.root / "sources/ENG-001.txt").write_text("altered source")
        with self.assertRaises(ValueError):
            migrate_unversioned_schema(self.root, self.manifest, self.dsn)
        (self.root / "sources/ENG-001.txt").write_bytes(original)
        with _connect(self.dsn) as db:
            db.execute("ALTER TABLE public.knowledge_sources ADD COLUMN injected text")
        with self.assertRaisesRegex(PostgresIndexUnavailable, "table shape"):
            migrate_unversioned_schema(self.root, self.manifest, self.dsn)
        with _connect(self.dsn) as db:
            db.execute("ALTER TABLE public.knowledge_sources DROP COLUMN injected")
        self.assertEqual(migrate_unversioned_schema(self.root, self.manifest, self.dsn),
                         {"sources": 2, "passages": 2, "schema_version": 1})
        self.assertEqual(verify_schema_version(self.dsn), 1)
        with self.assertRaisesRegex(PostgresIndexUnavailable, "already versioned"):
            migrate_unversioned_schema(self.root, self.manifest, self.dsn)

    def test_invalid_connection_never_falls_back_to_sqlite(self) -> None:
        with self.assertRaises(ValueError):
            search_index(self.root, self.manifest,
                         "postgresql://postgres:secret@127.0.0.1:55439/postgres",
                         "engineer", "generator inspection")

    def test_snapshot_verifier_rejects_fabricated_passage(self) -> None:
        with _connect(self.dsn) as db:
            db.execute("""UPDATE knowledge_passages SET text='fabricated secret'
                WHERE document_id='ENG-001' AND ordinal=0""")
        with self.assertRaisesRegex(ValueError, "passage mismatch"):
            verify_knowledge_snapshot(self.root, self.manifest, self.dsn)

    def test_snapshot_verifier_rejects_missing_vector(self) -> None:
        build_vectors(self.dsn, FakeEmbedder())
        with _connect(self.dsn) as db:
            db.execute("""DELETE FROM knowledge_vectors
                WHERE document_id='ENG-001' AND ordinal=0""")
        with self.assertRaisesRegex(ValueError, "vector set mismatch"):
            verify_knowledge_snapshot(self.root, self.manifest, self.dsn,
                                      expected_model=FakeEmbedder.model)

    def test_recovery_digest_detects_same_count_vector_change(self) -> None:
        build_vectors(self.dsn, FakeEmbedder())
        before = verify_knowledge_snapshot(
            self.root, self.manifest, self.dsn,
            expected_model=FakeEmbedder.model, include_digest=True)
        self.assertEqual(set(before), {"sources", "passages", "knowledge_sha256"})
        self.assertEqual(len(before["knowledge_sha256"]), 64)
        with _connect(self.dsn) as db:
            db.execute("""UPDATE knowledge_vectors SET embedding='[0.25,0.75]'::vector
                WHERE document_id='ENG-001' AND ordinal=0""")
        after = verify_knowledge_snapshot(
            self.root, self.manifest, self.dsn,
            expected_model=FakeEmbedder.model, include_digest=True)
        self.assertEqual((before["sources"], before["passages"]),
                         (after["sources"], after["passages"]))
        self.assertNotEqual(before["knowledge_sha256"], after["knowledge_sha256"])

    def test_core_search_preview_and_chat_use_postgres(self) -> None:
        app = create_app(Settings(fixture_root=self.root,
                                  lab_password="synthetic-test-passphrase",
                                  knowledge_manifest=self.manifest,
                                  knowledge_db=self.dsn), FakeModel())

        async def exercise() -> None:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://test") as client:
                engineer = await client.post("/api/login", json={
                    "user_id": "engineer", "password": "synthetic-test-passphrase"})
                deckhand = await client.post("/api/login", json={
                    "user_id": "deckhand", "password": "synthetic-test-passphrase"})
                self.assertEqual(engineer.status_code, 200)
                self.assertEqual(deckhand.status_code, 200)
                engineer_auth = {"Authorization": "Bearer " + engineer.json()["access_token"]}
                deckhand_auth = {"Authorization": "Bearer " + deckhand.json()["access_token"]}
                search = await client.post("/api/search", headers=engineer_auth,
                                           json={"query": "generator inspection"})
                self.assertEqual(search.status_code, 200)
                self.assertEqual(search.json()["results"][0]["document_id"], "ENG-001")
                denied = await client.post("/api/search", headers=deckhand_auth,
                                           json={"query": "generator inspection"})
                self.assertEqual(denied.json()["results"], [])
                preview = await client.get("/api/sources/ENG-001/preview", headers=engineer_auth)
                self.assertEqual(preview.status_code, 200)
                self.assertEqual(preview.json()["excerpt"], "generator inspection secret marker")
                self.assertEqual((await client.get("/api/sources/ENG-001/preview",
                                                   headers=deckhand_auth)).status_code, 404)
                chat = await client.post("/api/chat", headers=engineer_auth,
                                         json={"message": "generator inspection"})
                self.assertEqual(chat.status_code, 200)
                self.assertEqual(chat.json()["citations"][0]["document_id"], "ENG-001")

        asyncio.run(exercise())
