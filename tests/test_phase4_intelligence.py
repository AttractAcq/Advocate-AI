from __future__ import annotations

import json
import ipaddress
import os
import ssl
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apps.api.main import Settings, create_app
from apps.api.model import ModelUnavailable
from services.connectors.wazuh import MAX_ALERT_RESPONSE, SUPPORTED_DECODERS, WazuhIndexerReader, WazuhUnavailable
from services.connectors.fortigate import parse_fortigate_syslog
from services.intelligence.assets import AssetRegistry
from services.intelligence.engine import SOURCES, incident_view, load_fixture_incidents, normalize_alert, supported_incidents

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "fixtures/phase-4/assets.json"
ALERTS = ROOT / "fixtures/phase-4/wazuh-alerts.json"
ADVERSARIAL = json.loads((ROOT / "fixtures/phase-5/adversarial.json").read_text())


def normalize_hit(hit, registry):
    return normalize_alert({"index_name": hit["_index"], "index_id": hit["_id"],
                            "source": hit["_source"]}, registry)


class FakeModel:
    def __init__(self) -> None:
        self.offline = False
        self.calls = []
        self.answer = "The alert reported a synthetic event that requires verification."

    async def complete(self, question, context, *, general=False, system_instruction=None, max_tokens=320):
        if self.offline:
            raise ModelUnavailable("model offline")
        self.calls.append({"question": question, "system_instruction": system_instruction,
                           "max_tokens": max_tokens})
        return self.answer


class IntelligenceTests(unittest.TestCase):
    def test_wazuh_ca_snapshot_works_over_real_loopback_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                "Synthetic loopback indexer")])
            certificate = (x509.CertificateBuilder().subject_name(name)
                           .issuer_name(name).public_key(key.public_key())
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                           .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                           .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                          critical=True)
                           .add_extension(x509.SubjectAlternativeName([
                               x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                               critical=False).sign(key, hashes.SHA256()))
            ca = root / "indexer-ca.pem"
            ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            ca.chmod(0o600)
            private_key = root / "indexer-key.pem"
            private_key.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            private_key.chmod(0o600)

            class SyntheticIndexer(BaseHTTPRequestHandler):
                def do_POST(self):
                    self.rfile.read(int(self.headers["Content-Length"]))
                    response = ALERTS.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)

                def log_message(self, format, *args):
                    pass

            try:
                server = HTTPServer(("127.0.0.1", 0), SyntheticIndexer)
            except PermissionError:
                self.skipTest("loopback bind unavailable in the local sandbox")
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(ca, private_key)
            server.socket = server_tls.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                endpoint = f"https://127.0.0.1:{server.server_port}"
                reader = WazuhIndexerReader(endpoint, "synthetic-read-token", ca_bundle=ca)
                self.assertEqual(len(reader.alerts(limit=3)), 3)
                ca.unlink()
                ca.symlink_to(root / "missing-ca.pem")
                self.assertEqual(len(reader.alerts(limit=3)), 3)
                with self.assertRaises(ValueError):
                    WazuhIndexerReader(endpoint, "synthetic-read-token", ca_bundle=ca)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_wazuh_ca_is_private_and_snapshotted_before_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                "Synthetic Wazuh CA")])
            certificate = (x509.CertificateBuilder().subject_name(name)
                           .issuer_name(name).public_key(key.public_key())
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                           .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                           .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                          critical=True).sign(key, hashes.SHA256()))
            ca = root / "ca.pem"
            ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            ca.chmod(0o600)
            reader = WazuhIndexerReader(
                "https://10.40.1.10:9200", "synthetic-read-token", ca_bundle=ca,
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json=json.loads(ALERTS.read_text()))))
            self.assertIsInstance(reader._tls_context, ssl.SSLContext)
            trusted_certificates = reader._tls_context.get_ca_certs(binary_form=True)
            self.assertIn(certificate.public_bytes(serialization.Encoding.DER),
                          trusted_certificates)
            ca.unlink()
            ca.symlink_to(root / "other.pem")
            self.assertEqual(len(reader.alerts(limit=3)), 3)
            self.assertEqual(reader._tls_context.get_ca_certs(binary_form=True),
                             trusted_certificates)
            with self.assertRaises(ValueError):
                WazuhIndexerReader("https://10.40.1.10:9200", "token", ca_bundle=ca)
            ca.unlink()
            ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            ca.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "unsafe Wazuh CA"):
                WazuhIndexerReader("https://10.40.1.10:9200", "token", ca_bundle=ca)
            ca.chmod(0o600)
            os.link(ca, root / "alias.pem")
            with self.assertRaisesRegex(ValueError, "unsafe Wazuh CA"):
                WazuhIndexerReader("https://10.40.1.10:9200", "token", ca_bundle=ca)

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

    def test_indexer_rejects_oversized_response_and_external_redirect(self):
        large = WazuhIndexerReader("https://10.40.1.10:9200", "lab-read-token",
                                   transport=httpx.MockTransport(lambda _: httpx.Response(
                                       200, stream=httpx.ByteStream(b"x" * (MAX_ALERT_RESPONSE + 1)))))
        with self.assertRaises(WazuhUnavailable):
            large.alerts()
        requests = []

        def redirect(request):
            requests.append(request)
            return httpx.Response(302, headers={"Location": "https://example.invalid/collect"})

        redirected = WazuhIndexerReader("https://10.40.1.10:9200", "lab-read-token",
                                        transport=httpx.MockTransport(redirect))
        with self.assertRaises(WazuhUnavailable):
            redirected.alerts()
        self.assertEqual(len(requests), 1)


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
        crew_tools = (await self.client.get("/api/tools", headers=crew)).json()
        admin_tools = (await self.client.get("/api/tools", headers=admin)).json()
        self.assertNotIn("synthetic_alert_search", crew_tools["read_only"])
        self.assertIn("synthetic_alert_search", admin_tools["read_only"])
        self.assertEqual(crew_tools["write"], [])
        self.assertEqual(admin_tools["write"], [])
        for path in ("/api/security/firewall/rules", "/api/security/switch/config",
                     "/api/security/nas/files", "/api/security/safety/control"):
            self.assertEqual((await self.client.post(path, headers=admin)).status_code, 404)
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
        self.assertIn("lab-wazuh-forti-001", self.model.calls[0]["question"])
        self.assertEqual(self.model.calls[0]["max_tokens"], 96)
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

    async def test_unstructured_model_output_falls_back_to_evidence(self):
        admin = await self.login("lab-avit_admin-1")
        self.model.answer = "**Unsupported steps**\n1. Change firewall rules"
        response = await self.client.post(
            "/api/security/incidents/wazuh-alerts-4.x-2026.11.15:doc-forti-001/explain",
            headers=admin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["method"], "evidence-only")
        self.assertNotIn("Change firewall rules", response.text)

    async def test_actionable_one_sentence_model_output_falls_back_to_evidence(self):
        admin = await self.login("lab-avit_admin-1")
        self.model.answer = ADVERSARIAL["unsafe_model_responses"][0]
        response = await self.client.post(
            "/api/security/incidents/wazuh-alerts-4.x-2026.11.15:doc-forti-001/explain",
            headers=admin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["method"], "evidence-only")
        self.assertNotIn("disable the firewall", response.text)
        self.assertTrue(response.json()["evidence"])

    async def test_prompt_injected_alert_is_visible_but_withheld_from_model(self):
        fixture = json.loads(ALERTS.read_text())
        fixture["hits"]["hits"][0]["_source"]["rule"]["description"] = (
            ADVERSARIAL["injected_alert_description"])
        path = Path(self.temp.name) / "injected-alerts.json"
        path.write_text(json.dumps(fixture))
        app = create_app(Settings(lab_password="synthetic-test-passphrase",
                                  synthetic_alerts=path), self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            login = await client.post("/api/login", json={"user_id": "lab-avit_admin-1",
                                                      "password": "synthetic-test-passphrase"})
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            incident_id = "wazuh-alerts-4.x-2026.11.15:doc-forti-001"
            detail = await client.get(f"/api/security/incidents/{incident_id}", headers=headers)
            self.assertEqual(detail.status_code, 200)
            explanation = await client.post(f"/api/security/incidents/{incident_id}/explain",
                                            headers=headers)
        self.assertEqual(explanation.status_code, 422)
        self.assertEqual(self.model.calls, [])

    async def test_new_indexer_alerts_arrive_while_model_is_down(self):
        fixture_hits = json.loads(ALERTS.read_text())["hits"]["hits"]
        stored = [fixture_hits[0]]
        requests = []

        def indexer(request):
            requests.append(request)
            query = json.loads(request.content)
            filters = query["query"]["bool"]["filter"]
            ids = next((set(item["ids"]["values"]) for item in filters if "ids" in item), None)
            hits = [item for item in stored if ids is None or item["_id"] in ids]
            return httpx.Response(200, json={"hits": {"hits": hits[:query["size"]]}})

        reader = WazuhIndexerReader("https://10.40.1.10:9200", "synthetic-read-token",
                                     transport=httpx.MockTransport(indexer))
        with patch("apps.api.main.WazuhIndexerReader", return_value=reader):
            app = create_app(Settings(lab_password="synthetic-test-passphrase",
                                      wazuh_indexer_endpoint="https://10.40.1.10:9200",
                                      wazuh_read_token="synthetic-read-token"), self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            login = await client.post("/api/login", json={"user_id": "lab-avit_admin-1",
                                                      "password": "synthetic-test-passphrase"})
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            before = (await client.get("/api/security/incidents", headers=headers)).json()["incidents"]
            self.assertEqual(len(before), 1)
            self.model.offline = True
            stored.append(fixture_hits[1])  # Independent simulated indexer receives an event.
            during = (await client.get("/api/security/incidents", headers=headers)).json()["incidents"]
            self.assertEqual(len(during), 2)
            new_id = during[1]["incident_id"]
            self.assertEqual((await client.get(f"/api/security/incidents/{new_id}", headers=headers)).status_code, 200)
            self.assertEqual((await client.post(f"/api/security/incidents/{new_id}/explain", headers=headers)).status_code, 503)
            self.model.offline = False
            self.assertEqual((await client.post(f"/api/security/incidents/{new_id}/explain", headers=headers)).status_code, 200)
        self.assertTrue(requests)
        self.assertTrue(all(request.method == "POST" and request.url.path == "/wazuh-alerts*/_search"
                            for request in requests))
