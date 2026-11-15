from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

import httpx

from apps.api.main import Settings, create_app
from apps.api.model import ModelUnavailable
from services.connectors.wazuh import SUPPORTED_DECODERS, WazuhIndexerReader, WazuhUnavailable
from services.connectors.fortigate import parse_fortigate_syslog
from services.intelligence.assets import AssetRegistry
from services.intelligence.engine import SOURCES, incident_view, load_fixture_incidents, normalize_alert, supported_incidents

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "fixtures/phase-4/assets.json"
ALERTS = ROOT / "fixtures/phase-4/wazuh-alerts.json"


def normalize_hit(hit, registry):
    return normalize_alert({"index_name": hit["_index"], "index_id": hit["_id"],
                            "source": hit["_source"]}, registry)


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
        parsed = parse_fortigate_syslog((ROOT / "fixtures/phase-4/fortigate-syslog.txt").read_text().strip())
        self.assertEqual(parsed["action"], "deny")
        self.assertEqual(parsed["srcip"], "10.40.1.20")
        self.assertNotIn("password", parsed)
        with self.assertRaises(ValueError):
            parse_fortigate_syslog("srcip=10.1.1.1 action=deny")

    def test_three_synthetic_alerts_have_evidence_and_explicit_assets(self):
        incidents = load_fixture_incidents(ALERTS, AssetRegistry(ASSETS))
        self.assertEqual({item["event"]["source"] for item in incidents}, {"FortiGate", "Switch", "Host"})
        for item in incidents:
            self.assertEqual(item["incident_id"],
                             f"{item['evidence'][0]['index_name']}:{item['evidence'][0]['index_id']}")
            self.assertEqual(item["event"]["event_id"], item["evidence"][0]["event_id"])
            self.assertTrue(item["evidence"][0]["timestamp"])
            self.assertTrue(item["event"]["read_only"])
            self.assertEqual(item["event"]["asset_status"], "known")

    def test_unmapped_and_malicious_fields_do_not_leak(self):
        hit = json.loads(ALERTS.read_text())["hits"]["hits"][0]
        hit["_source"]["data"].pop("devname")
        hit["_source"]["agent"]["name"] = "lab-forti-1"
        hit["_source"]["full_log"] = "secret_password=never-show"
        incident = normalize_hit(hit, AssetRegistry(ASSETS))
        self.assertEqual(incident["asset_status"], "unknown")
        self.assertNotIn("secret_password", json.dumps(incident))
        hit["_source"]["rule"]["description"] = "bad\nheader"
        with self.assertRaises(ValueError):
            normalize_hit(hit, AssetRegistry(ASSETS))
        hit["_source"]["rule"]["description"] = "password=fixture-canary-do-not-copy"
        with self.assertRaises(ValueError):
            normalize_hit(hit, AssetRegistry(ASSETS))

    def test_ambiguous_asset_mapping_is_reported_without_guessing(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = json.loads(ASSETS.read_text())
            payload["assets"].append({"asset_id": "lab-duplicate-ip", "hostname": "other-host",
                                      "owner": "Unknown", "equipment_class": "workstation",
                                      "addresses": [{"ip": "10.40.1.20", "vlan": 40}]})
            registry_path = Path(temporary) / "assets.json"
            registry_path.write_text(json.dumps(payload))
            registry = AssetRegistry(registry_path)
            self.assertEqual(registry.resolve(ip="10.40.1.20", vlan=40)["status"], "ambiguous")
            hit = json.loads(ALERTS.read_text())["hits"]["hits"][0]
            event = normalize_hit(hit, registry)
            self.assertIsNone(event["related_asset"])
            self.assertIn("ambiguous", incident_view(event)["confidence"])

    def test_unrelated_wazuh_decoders_are_skipped(self):
        hits = json.loads(ALERTS.read_text())["hits"]["hits"]
        unrelated = json.loads(json.dumps(hits[0]))
        unrelated["_source"]["decoder"]["name"] = "other-product"
        mapped = [{"index_name": hit["_index"], "index_id": hit["_id"], "source": hit["_source"]}
                  for hit in [unrelated, hits[1]]]
        incidents = supported_incidents(mapped, AssetRegistry(ASSETS))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event"]["source"], "Switch")

    def test_indexer_reader_fixed_query_and_private_endpoint(self):
        self.assertEqual(set(SUPPORTED_DECODERS), set(SOURCES))
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

    def test_indexer_queries_are_bounded_and_document_identity_is_exact(self):
        observed = []
        sample = json.loads(ALERTS.read_text())["hits"]["hits"][0]

        def handler(request):
            query = json.loads(request.content)
            observed.append(query)
            return httpx.Response(200, json={"hits": {"hits": [sample]}})

        reader = WazuhIndexerReader("https://10.40.1.10:9200", "lab-read-token",
                                     transport=httpx.MockTransport(handler))
        since = datetime(2026, 11, 15, 0, tzinfo=timezone.utc)
        until = datetime(2026, 11, 16, 0, tzinfo=timezone.utc)
        incident_id = f"{sample['_index']}:{sample['_id']}"
        self.assertEqual(reader.alerts(limit=1, since=since, until=until,
                                       incident_id=incident_id)[0]["index_id"], sample["_id"])
        filters = observed[0]["query"]["bool"]["filter"]
        self.assertEqual(set(filters[0]["terms"]["decoder.name"]), set(SUPPORTED_DECODERS))
        self.assertEqual(filters[1]["range"]["timestamp"]["gte"], since.isoformat())
        self.assertEqual(filters[2]["term"]["_index"], sample["_index"])
        self.assertEqual(filters[3]["ids"]["values"], [sample["_id"]])
        with self.assertRaises(ValueError):
            reader.alerts(incident_id="../_delete_by_query")
        with self.assertRaises(ValueError):
            reader.alerts(since=since, until=datetime(2026, 12, 1, tzinfo=timezone.utc))
        with self.assertRaises(WazuhUnavailable):
            reader.alerts(incident_id=f"{sample['_index']}:different-event")


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
        self.assertEqual(detail.json()["evidence"][0]["event_id"], "lab-wazuh-forti-001")
        self.assertEqual(alert_id, f"{detail.json()['evidence'][0]['index_name']}:{detail.json()['evidence'][0]['index_id']}")
        explanation = await self.client.post(f"/api/security/incidents/{alert_id}/explain", headers=admin)
        self.assertEqual(explanation.status_code, 200, explanation.text)
        self.assertIn(alert_id, self.model.calls[0])
        self.model.offline = True
        self.assertEqual((await self.client.post(f"/api/security/incidents/{alert_id}/explain", headers=admin)).status_code, 503)
        self.assertEqual((await self.client.get("/api/security/incidents", headers=admin)).status_code, 200)
        self.assertEqual((await self.client.get(f"/api/security/incidents/{alert_id}", headers=admin)).status_code, 200)

    async def test_time_filter_and_exact_incident_lookup(self):
        admin = await self.login("lab-avit_admin-1")
        response = await self.client.get("/api/security/incidents", headers=admin,
            params={"since": "2026-11-15T10:00:30Z", "until": "2026-11-15T10:01:30Z"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["incident_id"] for item in response.json()["incidents"]],
                         ["wazuh-alerts-4.x-2026.11.15:doc-switch-002"])
        self.assertEqual((await self.client.get("/api/security/incidents", headers=admin,
            params={"since": "2026-11-15T00:00:00Z", "until": "2026-12-15T00:00:00Z"})).status_code, 422)
        self.assertEqual((await self.client.get("/api/security/incidents/wazuh-alerts-4.x-2026.11.15:missing-event", headers=admin)).status_code, 404)

    async def test_ambiguous_mapping_never_reaches_model(self):
        payload = json.loads(ASSETS.read_text())
        payload["assets"].append({"asset_id": "lab-duplicate-ip", "hostname": "other-host",
                                  "owner": "Unknown", "equipment_class": "workstation",
                                  "addresses": [{"ip": "10.40.1.20", "vlan": 40}]})
        registry_path = Path(self.temp.name) / "assets.json"
        registry_path.write_text(json.dumps(payload))
        app = create_app(Settings(lab_password="synthetic-test-passphrase", asset_registry=registry_path), self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            login = await client.post("/api/login", json={"user_id": "lab-avit_admin-1",
                                                      "password": "synthetic-test-passphrase"})
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            response = await client.post("/api/security/incidents/wazuh-alerts-4.x-2026.11.15:doc-forti-001/explain", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["method"], "evidence-only")
        self.assertIn("ambiguous", response.json()["confidence"])
        self.assertEqual(self.model.calls, [])
