from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import httpx

from apps.api.main import Settings, create_app
from apps.api.model import ModelUnavailable
from services.connectors.wazuh import WazuhIndexerReader, WazuhUnavailable
from services.connectors.fortigate import parse_fortigate_syslog
from services.intelligence.assets import AssetRegistry
from services.intelligence.engine import load_fixture_incidents, normalize_alert

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "fixtures/phase-4/assets.json"
ALERTS = ROOT / "fixtures/phase-4/wazuh-alerts.json"


class FakeModel:
    def __init__(self) -> None:
        self.offline = False
        self.calls = []

    async def complete(self, question, context, *, general=False):
        if self.offline:
            raise ModelUnavailable("model offline")
        self.calls.append(question)
        return "Check the cited alert in Wazuh before investigation."


class IntelligenceTests(unittest.TestCase):
    def test_fortigate_syslog_adapter_drops_unapproved_fields(self):
        parsed = parse_fortigate_syslog((ROOT / "fixtures/phase-4/fortigate.log").read_text().strip())
        self.assertEqual(parsed["action"], "deny")
        self.assertEqual(parsed["srcip"], "10.40.1.20")
        self.assertNotIn("password", parsed)
        with self.assertRaises(ValueError):
            parse_fortigate_syslog("srcip=10.1.1.1 action=deny")
    def test_three_independent_alerts_have_evidence_and_explicit_assets(self):
        incidents = load_fixture_incidents(ALERTS, AssetRegistry(ASSETS))
        self.assertEqual({item["event"]["source"] for item in incidents}, {"FortiGate", "Switch", "Host"})
        for item in incidents:
            self.assertEqual(item["incident_id"], item["evidence"][0]["event_id"])
            self.assertTrue(item["evidence"][0]["timestamp"])
            self.assertTrue(item["event"]["read_only"])
            self.assertEqual(item["event"]["asset_status"], "known")

    def test_unmapped_and_malicious_fields_do_not_leak(self):
        hit = json.loads(ALERTS.read_text())["hits"]["hits"][0]
        hit["_source"]["agent"]["name"] = "unknown-device"
        hit["_source"]["full_log"] = "secret_password=never-show"
        incident = normalize_alert({"index_id": hit["_id"], "source": hit["_source"]}, AssetRegistry(ASSETS))
        self.assertEqual(incident["asset_status"], "unknown")
        self.assertNotIn("secret_password", json.dumps(incident))
        hit["_source"]["rule"]["description"] = "bad\nheader"
        with self.assertRaises(ValueError):
            normalize_alert({"index_id": hit["_id"], "source": hit["_source"]}, AssetRegistry(ASSETS))

    def test_indexer_reader_fixed_query_and_private_endpoint(self):
        observed = []

        def handler(request):
            observed.append(request)
            return httpx.Response(200, json=json.loads(ALERTS.read_text()))

        reader = WazuhIndexerReader("https://10.40.1.10:9200", "lab-read-token",
                                     transport=httpx.MockTransport(handler))
        self.assertEqual(len(reader.alerts(limit=3)), 3)
        self.assertEqual(observed[0].method, "POST")
        self.assertEqual(observed[0].url.path, "/wazuh-alerts*/_search")
        self.assertEqual(json.loads(observed[0].content)["size"], 3)
        self.assertNotIn("full_log", json.loads(observed[0].content)["_source"])
        for endpoint in ("http://10.40.1.10:9200", "https://8.8.8.8:9200",
                         "https://198.51.100.10:9200", "https://example.com:9200"):
            with self.assertRaises(ValueError):
                WazuhIndexerReader(endpoint, "token")
        with self.assertRaises(ValueError):
            reader.alerts(limit=101)
        broken = WazuhIndexerReader("https://10.40.1.10:9200", "token",
                                    transport=httpx.MockTransport(lambda _: httpx.Response(500)))
        with self.assertRaises(WazuhUnavailable):
            broken.alerts()


class SecurityApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.model = FakeModel()
        self.app = create_app(Settings(lab_password="synthetic-test-passphrase",
                                       audit_path=Path(self.temp.name) / "audit.jsonl"), self.model)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp.cleanup()

    async def login(self, user):
        response = await self.client.post("/api/login", json={"user_id": user,
                                                               "password": "synthetic-test-passphrase"})
        self.assertEqual(response.status_code, 200)
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    async def test_role_scope_evidence_and_model_outage(self):
        admin = await self.login("lab-avit_admin-1")
        crew = await self.login("lab-deckhand-1")
        self.assertEqual((await self.client.get("/api/security/incidents", headers=crew)).status_code, 403)
        self.assertEqual((await self.client.get("/api/security/incidents")).status_code, 401)
        listing = await self.client.get("/api/security/incidents", headers=admin)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()["incidents"]), 3)
        alert_id = listing.json()["incidents"][0]["incident_id"]
        detail = await self.client.get(f"/api/security/incidents/{alert_id}", headers=admin)
        self.assertEqual(detail.json()["evidence"][0]["event_id"], alert_id)
        explanation = await self.client.post(f"/api/security/incidents/{alert_id}/explain", headers=admin)
        self.assertEqual(explanation.status_code, 200, explanation.text)
        self.assertIn(alert_id, self.model.calls[0])
        self.model.offline = True
        self.assertEqual((await self.client.post(f"/api/security/incidents/{alert_id}/explain", headers=admin)).status_code, 503)
        self.assertEqual((await self.client.get("/api/security/incidents", headers=admin)).status_code, 200)
        self.assertEqual((await self.client.get(f"/api/security/incidents/{alert_id}", headers=admin)).status_code, 200)
