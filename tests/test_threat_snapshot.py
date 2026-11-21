from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

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

    def test_newer_package_cannot_silently_change_publisher(self) -> None:
        first = self.package(self.payload(issued=self.now - timedelta(hours=2)), "publisher-first")
        imported = import_package(first, self.store, trusted_key(self.public), now=self.now)
        changed = self.payload(issued=self.now - timedelta(hours=1))
        changed["publisher"] = "other-lab"
        second = self.package(changed, "publisher-changed")
        with self.assertRaisesRegex(ThreatSnapshotError, "provenance change"):
            import_package(second, self.store, trusted_key(self.public), now=self.now)
        self.assertEqual(ThreatSnapshotReader(self.store, self.public).status(now=self.now)["sha256"],
                         imported["sha256"])

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

    def test_concurrent_imports_cannot_install_older_snapshot_last(self) -> None:
        initial = self.package(self.payload(issued=self.now - timedelta(hours=3)), "initial")
        import_package(initial, self.store, trusted_key(self.public), now=self.now)
        older_payload = self.payload(issued=self.now - timedelta(hours=2))
        older_payload["indicators"][0]["id"] = "older"
        newer_payload = self.payload(issued=self.now - timedelta(hours=1))
        newer_payload["indicators"][0]["id"] = "newer"
        older = self.package(older_payload, "older")
        newer = self.package(newer_payload, "newer")
        entered = threading.Event()
        release = threading.Event()
        newer_done = threading.Event()
        failures: list[Exception] = []
        from services.intelligence import threat_snapshot
        actual_replace = threat_snapshot.os.replace

        def delayed_replace(source: str, destination: Path) -> None:
            if b'"id":"older"' in Path(source).read_bytes():
                entered.set()
                if not release.wait(5):
                    raise AssertionError("older import was not released")
            actual_replace(source, destination)

        def run(package: Path, *, signal: threading.Event | None = None) -> None:
            try:
                import_package(package, self.store, trusted_key(self.public), now=self.now)
            except Exception as exc:
                failures.append(exc)
            finally:
                if signal is not None:
                    signal.set()

        with patch.object(threat_snapshot.os, "replace", side_effect=delayed_replace):
            first = threading.Thread(target=run, args=(older,))
            second = threading.Thread(target=run, args=(newer,),
                                      kwargs={"signal": newer_done})
            first.start()
            try:
                self.assertTrue(entered.wait(5))
                second.start()
                self.assertFalse(newer_done.wait(0.5),
                                 "newer import bypassed the first import lock")
            finally:
                release.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(ThreatSnapshotReader(self.store, self.public).status(now=self.now)["issued_at"],
                         (self.now - timedelta(hours=1)).isoformat())

    def test_import_refuses_linked_lock_without_touching_target(self) -> None:
        target = self.root / "unrelated.txt"
        target.write_text("leave this alone")
        (self.store / ".snapshot-import.lock").symlink_to(target)
        package = self.package(self.payload(), "linked-lock")
        with self.assertRaises(OSError):
            import_package(package, self.store, trusted_key(self.public), now=self.now)
        self.assertEqual(target.read_text(), "leave this alone")
        self.assertFalse((self.store / "snapshot.json").exists())


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
