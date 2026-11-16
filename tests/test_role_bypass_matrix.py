"""Direct API access matrix for synthetic roles, documents and output paths."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import httpx

from apps.api.main import Settings, create_app
from services.knowledge.ingestion import sync_manifest


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = {
    "management": ("MAN-001", "managementtoken"),
    "engineering": ("ENG-001", "engineeringtoken"),
    "interior": ("INT-001", "interiortoken"),
    "deck": ("DEC-001", "decktoken"),
    "restricted": ("OWN-001", "ownertoken"),
}
EXPECTED = {
    "captain": {"management", "engineering", "interior", "deck"},
    "chief_engineer": {"engineering", "deck"},
    "chief_stewardess": {"interior", "deck"},
    "deckhand": {"deck"},
    "avit_admin": {"deck"},
}


class RecordingModel:
    def __init__(self) -> None:
        self.contexts: list[list[dict[str, object]]] = []

    async def complete(self, question: str, context: list[dict[str, object]], *, general: bool = False) -> str:
        self.contexts.append(context)
        return "Synthetic answer from permitted source"


class RoleBypassMatrixTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "sources").mkdir()
        shutil.copy(ROOT / "fixtures/roles.json", self.root / "roles.json")
        rows = []
        for collection, (document_id, marker) in DOCUMENTS.items():
            relative = f"sources/{document_id}.txt"
            payload = f"Fictional {collection} procedure {marker}.".encode()
            (self.root / relative).write_bytes(payload)
            rows.append({"document_id": document_id, "relative_path": relative,
                         "collection": collection, "classification": f"C0_SYNTHETIC_{collection.upper()}",
                         "owner": "fictional custodian", "version": "1",
                         "sha256": hashlib.sha256(payload).hexdigest(), "source_type": "synthetic-local"})
        self.manifest = self.root / "approved.json"
        self.manifest.write_text(json.dumps({"schema": 1, "sources": rows}))
        self.database = self.root / "index.sqlite3"
        sync_manifest(self.root, self.manifest, self.database)
        self.model = RecordingModel()
        self.app = create_app(Settings(fixture_root=self.root, lab_password="synthetic-test-passphrase",
                                       knowledge_manifest=self.manifest, knowledge_db=self.database), self.model)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://test")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    async def login(self, role: str) -> dict[str, str]:
        reply = await self.client.post("/api/login", json={"user_id": f"lab-{role}-1",
                                                        "password": "synthetic-test-passphrase"})
        self.assertEqual(reply.status_code, 200)
        return {"Authorization": f"Bearer {reply.json()['access_token']}"}

    async def test_five_roles_five_collections_all_direct_read_paths(self) -> None:
        for role, permitted in EXPECTED.items():
            headers = await self.login(role)
            listed = await self.client.get("/api/sources", headers=headers)
            self.assertEqual(listed.status_code, 200)
            expected_ids = {DOCUMENTS[name][0] for name in permitted}
            self.assertEqual({item["document_id"] for item in listed.json()["sources"]}, expected_ids)
            for collection, (document_id, marker) in DOCUMENTS.items():
                with self.subTest(role=role, collection=collection):
                    allowed = collection in permitted
                    preview = await self.client.get(f"/api/sources/{document_id}/preview", headers=headers)
                    self.assertEqual(preview.status_code, 200 if allowed else 404)
                    search = await self.client.post("/api/search", headers=headers,
                                                    json={"query": marker, "selected_documents": [document_id]})
                    self.assertEqual(search.status_code, 200)
                    self.assertEqual([hit["document_id"] for hit in search.json()["results"]],
                                     [document_id] if allowed else [])
                    previous_calls = len(self.model.contexts)
                    chat = await self.client.post("/api/chat", headers=headers,
                                                  json={"message": marker, "selected_documents": [document_id]})
                    self.assertEqual(chat.status_code, 200)
                    self.assertEqual([citation["document_id"] for citation in chat.json()["citations"]],
                                     [document_id] if allowed else [])
                    if allowed:
                        self.assertEqual(len(self.model.contexts), previous_calls + 1)
                        self.assertEqual([item["document_id"] for item in self.model.contexts[-1]], [document_id])
                    else:
                        self.assertEqual(len(self.model.contexts), previous_calls)
                        self.assertNotIn(marker, chat.json()["answer"])
                    self.assertEqual((await self.client.get(f"/api/sources/{document_id}/download",
                                                            headers=headers)).status_code, 403)

    async def test_cross_user_history_export_and_security_scope(self) -> None:
        captain = await self.login("captain")
        engineer = await self.login("chief_engineer")
        avit = await self.login("avit_admin")
        created = await self.client.post("/api/chat", headers=captain,
                                         json={"message": "managementtoken", "selected_documents": ["MAN-001"]})
        conversation_id = created.json()["conversation_id"]
        self.assertEqual((await self.client.get(f"/api/conversations/{conversation_id}", headers=engineer)).status_code, 404)
        self.assertNotIn(conversation_id, (await self.client.get("/api/conversations", headers=engineer)).json()["conversation_ids"])
        self.assertEqual((await self.client.post("/api/chat", headers=engineer,
                         json={"message": "managementtoken", "conversation_id": conversation_id})).status_code, 404)
        for headers in (captain, engineer, avit):
            self.assertEqual((await self.client.get(f"/api/conversations/{conversation_id}/export",
                                                     headers=headers)).status_code, 403)
        self.assertEqual((await self.client.get("/api/admin/status", headers=engineer)).status_code, 403)
        self.assertEqual((await self.client.get("/api/security/incidents", headers=engineer)).status_code, 403)
        self.assertEqual((await self.client.get("/api/security/incidents", headers=avit)).status_code, 200)
        self.assertEqual((await self.client.get("/api/me", headers={"Authorization": "Bearer invalid"})).status_code, 401)
        self.assertEqual((await self.client.post("/api/chat", headers=engineer,
                         json={"message": "managementtoken", "role": "captain"})).status_code, 422)

    async def test_document_revocation_redacts_existing_history(self) -> None:
        captain = await self.login("captain")
        created = await self.client.post("/api/chat", headers=captain,
                                         json={"message": "managementtoken", "selected_documents": ["MAN-001"]})
        conversation_id = created.json()["conversation_id"]
        policy = json.loads((self.root / "roles.json").read_text())
        policy["document_rules"] = {"MAN-001": {"deny_users": ["lab-captain-1"]}}
        (self.root / "roles.json").write_text(json.dumps(policy))
        self.assertNotIn("MAN-001", [item["document_id"] for item in
                         (await self.client.get("/api/sources", headers=captain)).json()["sources"]])
        self.assertEqual((await self.client.get("/api/sources/MAN-001/preview", headers=captain)).status_code, 404)
        self.assertEqual((await self.client.post("/api/search", headers=captain,
                          json={"query": "managementtoken"})).json()["results"], [])
        history = await self.client.get(f"/api/conversations/{conversation_id}", headers=captain)
        self.assertEqual(history.json()["turns"][0]["mode"], "redacted")
        self.assertNotIn("Synthetic answer", history.text)
        before = len(self.model.contexts)
        response = await self.client.post("/api/chat", headers=captain,
                                          json={"message": "managementtoken", "selected_documents": ["MAN-001"]})
        self.assertEqual(response.json()["citations"], [])
        self.assertEqual(len(self.model.contexts), before)
