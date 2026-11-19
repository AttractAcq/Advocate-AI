from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

import httpx

from apps.api.main import Settings, create_app


ROOT = Path(__file__).resolve().parents[1]


class UploadStagingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        for name in ("roles.json", "manifest.csv"):
            shutil.copy(ROOT / "fixtures" / name, self.fixtures / name)
        shutil.copytree(ROOT / "fixtures/sources", self.fixtures / "sources")
        self.staging = self.root / "quarantine"
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(
            Settings(fixture_root=self.fixtures, lab_password="synthetic-test-passphrase",
                     upload_root=self.staging))), base_url="http://test")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    async def _login(self, user: str) -> dict[str, str]:
        reply = await self.client.post("/api/login", json={"user_id": user, "password": "synthetic-test-passphrase"})
        self.assertEqual(reply.status_code, 200)
        return {"Authorization": "Bearer " + reply.json()["access_token"]}

    async def test_submission_is_private_and_never_searchable(self) -> None:
        engineer = await self._login("lab-chief_engineer-1")
        deckhand = await self._login("lab-deckhand-1")
        payload = b"synthetic-private-upload-marker"
        response = await self.client.post("/api/documents/stage", headers={**engineer,
            "Content-Type": "application/octet-stream", "X-Filename": "engine-room.txt"}, content=payload)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["upload"]["status"], "pending")
        self.assertEqual((await self.client.get("/api/documents/staged", headers=deckhand)).json()["uploads"], [])
        self.assertEqual(len((await self.client.get("/api/documents/staged", headers=engineer)).json()["uploads"]), 1)
        self.assertEqual((await self.client.get("/api/sources", headers=engineer)).status_code, 200)
        self.assertNotIn("engine-room", (await self.client.get("/api/sources", headers=engineer)).text)
        self.assertEqual(list(self.staging.glob("*.blob"))[0].read_bytes(), payload)
        self.assertEqual(self.staging.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.staging.glob("*.blob"))[0].stat().st_mode & 0o777, 0o600)

    async def test_rejects_unauthenticated_oversize_and_bad_names(self) -> None:
        headers = {"Content-Type": "application/octet-stream", "X-Filename": "test.txt"}
        self.assertEqual((await self.client.post("/api/documents/stage", headers=headers, content=b"hi")).status_code, 401)
        actor = await self._login("lab-deckhand-1")
        for name in ("../secret.txt", "bad.exe", "a/b.pdf"):
            response = await self.client.post("/api/documents/stage", headers={**actor, **headers, "X-Filename": name}, content=b"hi")
            self.assertEqual(response.status_code, 422)
        too_large = await self.client.post("/api/documents/stage", headers={**actor, **headers}, content=b"x" * (8 * 1024 * 1024 + 1))
        self.assertEqual(too_large.status_code, 413)
        self.assertFalse(list(self.staging.glob("*.blob"))) if self.staging.exists() else None

    async def test_upload_root_cannot_overlap_approved_sources(self) -> None:
        with self.assertRaises(ValueError):
            create_app(Settings(fixture_root=self.fixtures, upload_root=self.fixtures / "uploads"))
