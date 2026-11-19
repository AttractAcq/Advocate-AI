"""Synthetic offline receipt issuer and Fleet importer interoperability."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.fleet.main import FleetSettings, create_app
from services.fleet.catalog import Customer, Deployment, FleetCatalog, Release
from services.fleet.offline_import import SignedDeploymentReceipt, verify_signed_receipt
from services.fleet.offline_issue import issue_receipt


class OfflineIssueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.record = self.root / "record.json"
        self.record.write_text(json.dumps({
            "code": "RCP-LAB01", "vessel_code": "VSL-LAB01",
            "release_code": "REL-LAB01", "source": "approved_offline_admin",
            "observed_on": "2026-11-19", "health": "healthy"}))
        self.record.chmod(0o600)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "issuer-private.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.output = self.root / "envelope.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signs_importable_envelope_without_overwrite(self) -> None:
        result = issue_receipt(self.record, self.key_path, self.output)
        envelope = SignedDeploymentReceipt.model_validate_json(
            self.output.read_bytes())
        self.assertEqual(result["key_id"], envelope.key_id)
        self.assertEqual(verify_signed_receipt(envelope, self.key.public_key()).code,
                         "RCP-LAB01")
        self.assertEqual(self.output.stat().st_mode & 0o077, 0)
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)

    def test_rejects_forbidden_and_duplicate_fields_before_signing(self) -> None:
        original = self.record.read_text()
        self.record.write_text(original[:-1] + ',"document":"private"}')
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.assertFalse(self.output.exists())
        self.record.write_text(original[:-1] + ',"health":"degraded"}')
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.assertFalse(self.output.exists())

    def test_rejects_weak_key_and_linked_record(self) -> None:
        self.key_path.chmod(0o644)
        with self.assertRaises(ValueError):
            issue_receipt(self.record, self.key_path, self.output)
        self.key_path.chmod(0o600)
        alias = self.root / "linked-record.json"
        alias.symlink_to(self.record)
        with self.assertRaises(OSError):
            issue_receipt(alias, self.key_path, self.output)
        self.assertFalse(self.output.exists())

    def test_cli_envelope_imports_through_authenticated_fleet_api(self) -> None:
        command = subprocess.run(
            [sys.executable, "-m", "services.fleet.offline_issue",
             "--record", str(self.record), "--signing-key", str(self.key_path),
             "--output", str(self.output)],
            capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(command.stdout)["code"], "RCP-LAB01")
        database = self.root / "fleet.db"
        catalog = FleetCatalog(database)
        catalog.add("release", Release(code="REL-LAB01", version="1.0.0",
                                       manifest_sha256="a" * 64,
                                       signing_key_id="b" * 64,
                                       status="approved"))
        catalog.add("customer", Customer(code="CUST-LAB01",
                                         category="owner_manager"))
        catalog.add("deployment", Deployment(
            code="VSL-LAB01", customer_code="CUST-LAB01",
            release_code="REL-LAB01", hardware_profile="pilot_gpu",
            status="pilot"))
        token = "synthetic-fleet-admin-token-0123456789"
        app = create_app(FleetSettings(database, token, self.key.public_key()))

        async def import_envelope():
            async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://fleet.invalid",
                    headers={"X-Fleet-Lab-Token": token}) as client:
                body = json.loads(self.output.read_text())
                response = await client.post(
                    "/api/fleet/import/deployment-receipts", json=body)
                self.assertEqual(response.status_code, 201, response.text)
                self.assertEqual(response.json()["code"], "RCP-LAB01")
                audit = (await client.get("/api/fleet/audit")).json()
                self.assertEqual(audit[-1]["action"],
                                 "import-signed:" + body["key_id"])
                replay = await client.post(
                    "/api/fleet/import/deployment-receipts", json=body)
                self.assertEqual(replay.status_code, 409)

        asyncio.run(import_envelope())


if __name__ == "__main__":
    unittest.main()
