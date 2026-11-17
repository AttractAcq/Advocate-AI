"""AT-24 synthetic Fleet metadata and forbidden-content import boundary."""

from __future__ import annotations

import json
import base64
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from apps.fleet.main import FleetSettings, create_app
from apps.fleet.body_limit import MAX_BODY_BYTES
from services.fleet.catalog import DeploymentReceipt, FleetCatalog, Release
from services.fleet.offline_import import key_id, load_import_key, receipt_bytes


class FleetMetadataTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db = Path(self.temporary.name) / "fleet.db"
        self.token = "synthetic-fleet-admin-token-0123456789"
        self.import_signer = Ed25519PrivateKey.generate()
        app = create_app(FleetSettings(self.db, self.token,
                                       self.import_signer.public_key()))
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url="http://fleet.invalid",
                                        headers={"X-Fleet-Lab-Token": self.token})

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    async def _seed(self) -> None:
        response = await self.client.post("/api/fleet/releases", json={
            "code": "REL-DEMO1", "version": "1.0.0", "manifest_sha256": "a" * 64,
            "signing_key_id": "b" * 64, "status": "approved"})
        self.assertEqual(response.status_code, 405)
        FleetCatalog(self.db).add("release", Release(
            code="REL-DEMO1", version="1.0.0", manifest_sha256="a" * 64,
            signing_key_id="b" * 64, status="approved"))
        for endpoint, payload in (
            ("customers", {"code": "CUST-ACME1", "category": "owner_manager"}),
            ("deployments", {"code": "VSL-TEST1", "customer_code": "CUST-ACME1",
                             "release_code": "REL-DEMO1", "hardware_profile": "pilot_gpu",
                             "status": "pilot"}),
        ):
            response = await self.client.post("/api/fleet/" + endpoint, json=payload)
            self.assertEqual(response.status_code, 201, response.text)

    def signed_receipt(self, payload: dict[str, object]) -> dict[str, object]:
        record = DeploymentReceipt.model_validate(payload)
        return {"schema_version": 1,
                "key_id": key_id(self.import_signer.public_key()),
                "receipt": payload,
                "signature": base64.b64encode(
                    self.import_signer.sign(receipt_bytes(record))).decode()}

    async def test_metadata_records_and_audit_without_vessel_content(self) -> None:
        await self._seed()
        for endpoint, payload in (
            ("licences", {"code": "LIC-DEMO1", "customer_code": "CUST-ACME1",
                          "vessel_code": "VSL-TEST1", "tier": "pilot",
                          "valid_from": "2026-11-01", "valid_until": "2027-11-01",
                          "status": "active"}),
            ("tickets", {"code": "TKT-DEMO1", "vessel_code": "VSL-TEST1",
                         "category": "recovery", "priority": "p2", "status": "open"}),
            ("maintenance", {"code": "MNT-DEMO1", "vessel_code": "VSL-TEST1",
                             "kind": "backup_rehearsal", "due_on": "2026-12-01",
                             "engineer_code": "ENGR-LAB1", "status": "planned"}),
            ("import/deployment-receipts", self.signed_receipt({
                "code": "RCP-DEMO1", "vessel_code": "VSL-TEST1",
                "release_code": "REL-DEMO1", "source": "approved_offline_admin",
                "observed_on": "2026-11-16", "health": "healthy"})),
        ):
            response = await self.client.post("/api/fleet/" + endpoint, json=payload)
            self.assertEqual(response.status_code, 201, response.text)
        audit = (await self.client.get("/api/fleet/audit")).json()
        self.assertEqual(len(audit), 7)
        self.assertEqual(audit[-1]["kind"], "receipt")
        self.assertEqual(audit[-1]["action"],
                         "import-signed:" + key_id(self.import_signer.public_key()))
        self.assertNotIn("payload", audit[-1])
        self.assertEqual(len((await self.client.get("/api/fleet/licences")).json()), 1)
        self.assertEqual(self.db.stat().st_mode & 0o077, 0)

    async def test_prompt_document_embedding_and_log_fields_are_rejected(self) -> None:
        await self._seed()
        receipt = {"code": "RCP-DEMO1", "vessel_code": "VSL-TEST1",
                   "release_code": "REL-DEMO1", "source": "approved_offline_admin",
                   "observed_on": "2026-11-16", "health": "healthy"}
        envelope = self.signed_receipt(receipt)
        for forbidden in ("prompt", "document", "embedding", "security_log"):
            with self.subTest(forbidden=forbidden):
                response = await self.client.post(
                    "/api/fleet/import/deployment-receipts",
                    json={**envelope, "receipt": {**receipt,
                          forbidden: "never-store-this-vessel-content"}})
                self.assertEqual(response.status_code, 422)
        self.assertEqual((await self.client.get(
            "/api/fleet/import/deployment-receipts")).json(), [])
        self.assertNotIn(b"never-store-this-vessel-content", self.db.read_bytes())

    async def test_oversized_json_and_streaming_body_reject_before_storage(self) -> None:
        marker = "oversized-vessel-content-marker"
        large = marker + "x" * MAX_BODY_BYTES
        response = await self.client.post("/api/fleet/customers", json={
            "code": "CUST-LAB1", "category": "owner_manager", "document": large})
        self.assertEqual(response.status_code, 413)

        async def chunks():
            yield b'{"code":"CUST-LAB1","category":"owner_manager","document":"'
            yield large.encode()
            yield b'"}'

        response = await self.client.post("/api/fleet/customers", content=chunks(),
                                          headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual((await self.client.get("/api/fleet/customers")).json(), [])
        self.assertNotIn(marker.encode(), self.db.read_bytes())

    async def test_signed_import_rejects_tamper_wrong_issuer_and_replay(self) -> None:
        await self._seed()
        receipt = {"code": "RCP-DEMO1", "vessel_code": "VSL-TEST1",
                   "release_code": "REL-DEMO1", "source": "approved_offline_admin",
                   "observed_on": "2026-11-16", "health": "healthy"}
        envelope = self.signed_receipt(receipt)
        for changed in (
            {**envelope, "receipt": {**receipt, "health": "degraded"}},
            {**envelope, "key_id": "a" * 64},
            {**envelope, "signature": "A" * 88},
        ):
            response = await self.client.post(
                "/api/fleet/import/deployment-receipts", json=changed)
            self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual((await self.client.get(
            "/api/fleet/import/deployment-receipts")).json(), [])
        response = await self.client.post(
            "/api/fleet/import/deployment-receipts", json=envelope)
        self.assertEqual(response.status_code, 201, response.text)
        response = await self.client.post(
            "/api/fleet/import/deployment-receipts", json=envelope)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(envelope["signature"].encode(), self.db.read_bytes())

    async def test_import_requires_configured_trust_key(self) -> None:
        await self._seed()
        app = create_app(FleetSettings(self.db, self.token))
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                   base_url="http://fleet.invalid",
                                   headers={"X-Fleet-Lab-Token": self.token})
        try:
            receipt = {"code": "RCP-DEMO1", "vessel_code": "VSL-TEST1",
                       "release_code": "REL-DEMO1", "source": "approved_offline_admin",
                       "observed_on": "2026-11-16", "health": "healthy"}
            response = await client.post("/api/fleet/import/deployment-receipts",
                                         json=self.signed_receipt(receipt))
            self.assertEqual(response.status_code, 503)
        finally:
            await client.aclose()

    async def test_import_trust_key_rejects_link_and_world_readable_file(self) -> None:
        key_path = Path(self.temporary.name) / "import-public.pem"
        key_path.write_bytes(self.import_signer.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        key_path.chmod(0o600)
        self.assertEqual(key_id(load_import_key(key_path)),
                         key_id(self.import_signer.public_key()))
        key_path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_import_key(key_path)
        key_path.chmod(0o600)
        alias = key_path.with_name("linked-import-public.pem")
        alias.symlink_to(key_path)
        with self.assertRaises(OSError):
            load_import_key(alias)

    async def test_record_and_audit_pages_have_stable_cursors(self) -> None:
        for code in ("CUST-LAB1", "CUST-LAB2", "CUST-LAB3"):
            response = await self.client.post("/api/fleet/customers", json={
                "code": code, "category": "owner_manager"})
            self.assertEqual(response.status_code, 201)
        first = (await self.client.get("/api/fleet/customers?limit=2")).json()
        self.assertEqual([row["code"] for row in first], ["CUST-LAB1", "CUST-LAB2"])
        second = (await self.client.get(
            "/api/fleet/customers?limit=2&after=CUST-LAB2")).json()
        self.assertEqual([row["code"] for row in second], ["CUST-LAB3"])
        audit_first = (await self.client.get("/api/fleet/audit?limit=2")).json()
        audit_second = (await self.client.get(
            f"/api/fleet/audit?limit=2&after={audit_first[-1]['seq']}")).json()
        self.assertEqual([row["seq"] for row in audit_first + audit_second], [1, 2, 3])
        self.assertEqual((await self.client.get(
            "/api/fleet/customers?limit=101")).status_code, 422)
        self.assertEqual((await self.client.get(
            "/api/fleet/audit?after=-1")).status_code, 422)

    async def test_auth_references_and_tamper_fail_closed(self) -> None:
        response = await self.client.get("/api/fleet/customers",
                                         headers={"X-Fleet-Lab-Token": "wrong"})
        self.assertEqual(response.status_code, 401)
        response = await self.client.post("/api/fleet/deployments", json={
            "code": "VSL-TEST1", "customer_code": "CUST-MISS1",
            "release_code": "REL-MISS1", "hardware_profile": "pilot_gpu",
            "status": "planned"})
        self.assertEqual(response.status_code, 409)
        await self._seed()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE records SET payload=? WHERE kind='customer'",
                               (json.dumps({"code": "CUST-ACME1", "prompt": "steal"}),))
        response = await self.client.get("/api/fleet/customers")
        self.assertEqual(response.status_code, 503)

    async def test_lifecycle_transitions_are_audited_and_reject_skips(self) -> None:
        await self._seed()
        records = (
            ("licences", "LIC-DEMO1", {"code": "LIC-DEMO1",
              "customer_code": "CUST-ACME1", "vessel_code": "VSL-TEST1",
              "tier": "pilot", "valid_from": "2026-11-01",
              "valid_until": "2027-11-01", "status": "pending"}),
            ("tickets", "TKT-DEMO1", {"code": "TKT-DEMO1",
              "vessel_code": "VSL-TEST1", "category": "recovery",
              "priority": "p2", "status": "open"}),
            ("maintenance", "MNT-DEMO1", {"code": "MNT-DEMO1",
              "vessel_code": "VSL-TEST1", "kind": "backup_rehearsal",
              "due_on": "2026-12-01", "engineer_code": "ENGR-LAB1",
              "status": "planned"}),
        )
        for endpoint, _, payload in records:
            self.assertEqual((await self.client.post(
                "/api/fleet/" + endpoint, json=payload)).status_code, 201)
        for endpoint, code in (("tickets", "TKT-DEMO1"),
                               ("maintenance", "MNT-DEMO1")):
            response = await self.client.patch(
                f"/api/fleet/{endpoint}/{code}/status", json={"status": "resolved"})
            self.assertIn(response.status_code, (409, 422))
        for endpoint, code, states in (
            ("licences", "LIC-DEMO1", ("active", "suspended", "expired")),
            ("tickets", "TKT-DEMO1", ("triaged", "waiting", "resolved")),
            ("maintenance", "MNT-DEMO1", ("deferred", "planned", "completed")),
        ):
            for state in states:
                response = await self.client.patch(
                    f"/api/fleet/{endpoint}/{code}/status", json={"status": state})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], state)
            self.assertEqual((await self.client.get("/api/fleet/" + endpoint)).json()[0]
                             ["status"], states[-1])
        events = (await self.client.get("/api/fleet/audit")).json()
        self.assertEqual(len(events), 15)
        self.assertEqual(events[-1]["action"], "status:planned:completed")
        self.assertNotIn("payload", events[-1])
        response = await self.client.patch(
            "/api/fleet/tickets/TKT-DEMO1/status",
            json={"status": "triaged", "prompt": "never-store-this-vessel-content"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(b"never-store-this-vessel-content", self.db.read_bytes())
        response = await self.client.patch(
            "/api/fleet/tickets/TKT-DEMO1/status",
            headers={"X-Fleet-Lab-Token": "wrong"}, json={"status": "triaged"})
        self.assertEqual(response.status_code, 401)

    async def test_lifecycle_audit_tamper_fails_closed(self) -> None:
        await self._seed()
        self.assertEqual((await self.client.post("/api/fleet/tickets", json={
            "code": "TKT-DEMO1", "vessel_code": "VSL-TEST1",
            "category": "recovery", "priority": "p2", "status": "open"})).status_code, 201)
        self.assertEqual((await self.client.patch(
            "/api/fleet/tickets/TKT-DEMO1/status",
            json={"status": "triaged"})).status_code, 200)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE audit SET action='status:open:resolved' "
                               "WHERE kind='ticket' AND action='status:open:triaged'")
        self.assertEqual((await self.client.get("/api/fleet/tickets")).status_code, 503)


if __name__ == "__main__":
    unittest.main()
