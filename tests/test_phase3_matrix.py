from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from apps.api.main import Settings, create_app
from services.knowledge.ingestion import sync_manifest


class FakeModel:
    async def complete(self, question: str, context: list[dict[str, object]], *, general: bool = False) -> str:
        return "Synthetic cited answer"


class Phase3RoleActionMatrix(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "sources").mkdir()
        self.rows = []
        for collection, prefix in (("management", "MAN"), ("engineering", "ENG"),
                                   ("interior", "INT"), ("deck", "DEC"), ("restricted", "RES")):
            payload = f"synthetic {collection} marker {prefix.lower()} unique".encode()
            (self.root / f"sources/{prefix}-001.txt").write_bytes(payload)
            self.rows.append({"document_id": f"{prefix}-001", "relative_path": f"sources/{prefix}-001.txt",
                              "collection": collection, "classification": f"C0_SYNTHETIC_{collection.upper()}",
                              "owner": "lab custodian", "version": "1", "sha256": hashlib.sha256(payload).hexdigest(),
                              "source_type": "synthetic-local"})
        self.policy = {
            "users": [{"id": role, "role": role, "status": "active"} for role in
                      ("captain", "chief_engineer", "chief_stewardess", "deckhand", "avit_admin")]
                     + [{"id": "removed", "role": "captain", "status": "revoked"}],
            "allow": {"captain": ["management", "engineering", "interior", "deck"],
                      "chief_engineer": ["engineering", "deck"],
                      "chief_stewardess": ["interior", "deck"],
                      "deckhand": ["deck"], "avit_admin": ["deck"]},
            "document_rules": {},
        }
        (self.root / "roles.json").write_text(json.dumps(self.policy))
        self.manifest = self.root / "approved.json"
        self.manifest.write_text(json.dumps({"schema": 1, "sources": self.rows}))
        self.database = self.root / "index.sqlite3"
        sync_manifest(self.root, self.manifest, self.database)
        self.app = create_app(Settings(fixture_root=self.root, lab_password="synthetic-test-passphrase",
                                       knowledge_manifest=self.manifest, knowledge_db=self.database), FakeModel())
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://matrix")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    async def login(self, user: str) -> dict[str, str]:
        reply = await self.client.post("/api/login", json={"user_id": user, "password": "synthetic-test-passphrase"})
        self.assertEqual(reply.status_code, 200)
        return {"Authorization": "Bearer " + reply.json()["access_token"]}

    async def test_five_roles_all_sources_and_actions(self) -> None:
        for role in ("captain", "chief_engineer", "chief_stewardess", "deckhand", "avit_admin"):
            headers = await self.login(role)
            allowed = set(self.policy["allow"][role])
            listed = await self.client.get("/api/sources", headers=headers)
            self.assertEqual({row["document_id"] for row in listed.json()["sources"]},
                             {row["document_id"] for row in self.rows if row["collection"] in allowed})
            for row in self.rows:
                document_id = row["document_id"]
                permitted = row["collection"] in allowed
                query = f"{row['collection']} marker {document_id[:3].lower()} unique"
                search = await self.client.post("/api/search", headers=headers,
                                                json={"query": query, "selected_documents": [document_id]})
                self.assertEqual(bool(search.json()["results"]), permitted, (role, document_id, "search"))
                preview = await self.client.get(f"/api/sources/{document_id}/preview", headers=headers)
                self.assertEqual(preview.status_code, 200 if permitted else 404, (role, document_id, "preview"))
                chat = await self.client.post("/api/chat", headers=headers,
                                              json={"message": query, "selected_documents": [document_id]})
                self.assertEqual(bool(chat.json()["citations"]), permitted, (role, document_id, "citation"))
                if not permitted:
                    self.assertNotIn(document_id, chat.json()["answer"])
                    self.assertNotIn("unique", search.text + preview.text)
                download = await self.client.get(f"/api/sources/{document_id}/download", headers=headers)
                self.assertEqual(download.status_code, 403)
            export = await self.client.get("/api/conversations/forged/export", headers=headers)
            self.assertEqual(export.status_code, 403)
        removed = await self.client.post("/api/login", json={"user_id": "removed", "password": "synthetic-test-passphrase"})
        self.assertEqual(removed.status_code, 401)


if __name__ == "__main__":
    unittest.main()
