from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.api.main import Settings, create_app
from services.intelligence.threat_snapshot import (ThreatSnapshotError, ThreatSnapshotReader,
                                                   import_package, sign_payload, trusted_key)


class ThreatSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.store.mkdir(mode=0o700)
        key = Ed25519PrivateKey.generate()
        self.private = self.root / "signer.pem"
        self.private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.public = self.root / "trusted.pem"
        self.public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def payload(self, *, issued: datetime | None = None) -> dict[str, object]:
        issued = issued or self.now - timedelta(hours=1)
        return {"schema": 1, "feed_id": "synthetic-feed", "publisher": "synthetic-lab",
                "issued_at": issued.isoformat(),
                "expires_at": (issued + timedelta(days=14)).isoformat(),
                "indicators": [{"id": "fictional-1", "kind": "ipv4", "value": "203.0.113.7"},
                               {"id": "fictional-2", "kind": "domain", "value": "example.invalid"}]}

    def package(self, payload: dict[str, object], name: str) -> Path:
        source = self.root / f"{name}-payload.json"
        source.write_text(json.dumps(payload))
        package = self.root / f"{name}.json"
        sign_payload(source, self.private, package)
        return package

    def test_signed_import_age_and_rollback(self) -> None:
        first = self.package(self.payload(), "first")
        imported = import_package(first, self.store, trusted_key(self.public), now=self.now)
        self.assertEqual(imported["indicator_count"], 2)
        reader = ThreatSnapshotReader(self.store, self.public)
        current = reader.status(now=self.now)
        self.assertEqual(current["status"], "current")
        self.assertEqual(current["publisher"], "synthetic-lab")
        self.assertNotIn("indicators", current)
        self.assertEqual(reader.status(now=self.now + timedelta(days=8))["status"], "stale")
        damaged = self.root / "damaged.json"
        damaged.write_bytes(first.read_bytes().replace(b"synthetic-lab", b"forged-lab"))
        with self.assertRaisesRegex(ThreatSnapshotError, "signature mismatch"):
            import_package(damaged, self.store, trusted_key(self.public), now=self.now)
        self.assertEqual(reader.status(now=self.now)["sha256"], imported["sha256"])
        with self.assertRaisesRegex(ThreatSnapshotError, "rollback"):
            import_package(first, self.store, trusted_key(self.public), now=self.now)
        second = self.package(self.payload(issued=self.now), "second")
        import_package(second, self.store, trusted_key(self.public), now=self.now)
        self.assertEqual(reader.status(now=self.now)["status"], "current")

    def test_tamper_duplicate_invalid_and_linked_input_fail_closed(self) -> None:
        original = self.package(self.payload(), "original")
        import_package(original, self.store, trusted_key(self.public), now=self.now)
        saved = self.store / "snapshot.json"
        envelope = json.loads(saved.read_text())
        envelope["payload"]["publisher"] = "forged"
        saved.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(ThreatSnapshotError, "signature mismatch"):
            ThreatSnapshotReader(self.store, self.public).status(now=self.now)
        saved.unlink()
        saved.write_bytes(b'{"payload":{},"payload":{},"signature":"x"}')
        with self.assertRaisesRegex(ThreatSnapshotError, "duplicate"):
            ThreatSnapshotReader(self.store, self.public).status(now=self.now)
        saved.unlink()
        saved.symlink_to(original)
        with self.assertRaises(OSError):
            ThreatSnapshotReader(self.store, self.public).status(now=self.now)
        bad = self.payload()
        bad["indicators"] = [{"id": "bad", "kind": [], "value": "example.invalid"}]
        source = self.root / "bad-payload.json"
        source.write_text(json.dumps(bad))
        with self.assertRaises(ThreatSnapshotError):
            sign_payload(source, self.private, self.root / "bad-package.json")


class ThreatSnapshotApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_security_scope_and_tamper_denial(self) -> None:
        fixture = ThreatSnapshotTests()
        fixture.setUp()
        try:
            package = fixture.package(fixture.payload(), "api")
            import_package(package, fixture.store, trusted_key(fixture.public), now=fixture.now)
            app = create_app(Settings(lab_password="synthetic-test-passphrase",
                                      threat_snapshot_store=fixture.store,
                                      threat_snapshot_key=fixture.public))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://test") as client:
                async def token(user: str) -> str:
                    response = await client.post("/api/login", json={
                        "user_id": user, "password": "synthetic-test-passphrase"})
                    self.assertEqual(response.status_code, 200)
                    return response.json()["access_token"]
                admin = await token("lab-avit_admin-1")
                crew = await token("lab-deckhand-1")
                path = "/api/security/threat-intel"
                self.assertEqual((await client.get(path)).status_code, 401)
                self.assertEqual((await client.get(path, headers={"Authorization": f"Bearer {crew}"})).status_code, 403)
                response = await client.get(path, headers={"Authorization": f"Bearer {admin}"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "current")
                self.assertNotIn("indicators", response.json())
                saved = fixture.store / "snapshot.json"
                saved.write_bytes(saved.read_bytes() + b" ")
                response = await client.get(path, headers={"Authorization": f"Bearer {admin}"})
                self.assertEqual(response.status_code, 200)
                saved.write_bytes(saved.read_bytes().replace(b"synthetic-lab", b"forged-lab"))
                response = await client.get(path, headers={"Authorization": f"Bearer {admin}"})
                self.assertEqual(response.status_code, 503)
        finally:
            fixture.temp.cleanup()
