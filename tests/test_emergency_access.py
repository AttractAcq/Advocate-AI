"""Synthetic emergency activation has separate credentials and restricted scope."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx

from apps.api.main import Settings, create_app
from services.policy.change import (PolicyChangeError, apply_change, create_proposal,
                                    sign_proposal)
from services.policy.policy_file import active_user

ROOT = Path(__file__).resolve().parents[1]


class FakeModel:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, question: str, context: list[dict[str, object]], *,
                       general: bool = False) -> str:
        self.calls += 1
        return "synthetic answer"


class EmergencyAccessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = self.root / "roles.json"
        self.policy.write_bytes((ROOT / "fixtures/roles.json").read_bytes())
        self.secret = self.root / "emergency-secret"
        self.emergency_value = secrets.token_urlsafe(24)
        self.rotated_value = secrets.token_urlsafe(24)
        self.secret.write_text(self.emergency_value + "\n", encoding="utf-8")
        self.secret.chmod(0o600)
        self.audit = self.root / "audit.jsonl"
        self.model = FakeModel()
        self.now = datetime.now(timezone.utc)

    async def asyncTearDown(self) -> None:
        self.temporary.cleanup()

    def activate(self, *, expiry_minutes: int = 5, incident: str | None = "INC-SYNTH-001",
                 collections: list[str] | None = None) -> None:
        candidate = json.loads(self.policy.read_text(encoding="utf-8"))
        emergency = next(user for user in candidate["users"]
                         if user["id"] == "lab-emergency-recovery-1")
        emergency["status"] = "active"
        emergency["expires_at"] = (self.now + timedelta(minutes=expiry_minutes)).isoformat()
        if incident is not None:
            emergency["emergency_incident"] = incident
        if collections is not None:
            candidate["allow"]["emergency_recovery"] = collections
        candidate_path = self.root / "candidate.json"
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        keys = {name: Ed25519PrivateKey.generate() for name in ("admin_a", "admin_b")}
        trust = self.root / "trust.json"
        trust.write_text(json.dumps({"schema": 1, "signers": {
            name: base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
            for name, key in keys.items()}}), encoding="utf-8")
        trust.chmod(0o600)
        proposal = self.root / "proposal.json"
        proposal.write_bytes(create_proposal(self.policy, candidate_path, "admin_a",
                                             "Activate fictional recovery incident", now=self.now))
        approvals = (self.root / "approval-a.json", self.root / "approval-b.json")
        for path, name in zip(approvals, ("admin_a", "admin_b")):
            path.write_bytes(sign_proposal(proposal.read_bytes(), name, keys[name], now=self.now))
        apply_change(self.policy, candidate_path, proposal, approvals, trust, self.audit, now=self.now)

    async def test_two_person_activation_restricts_core_and_secret_rotation(self) -> None:
        self.activate()
        app = create_app(Settings(fixture_root=self.root,
                                  lab_password="synthetic-test-passphrase",
                                  emergency_password_file=self.secret, audit_path=self.audit),
                         self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://emergency.invalid") as client:
            wrong = await client.post("/api/login", json={
                "user_id": "lab-emergency-recovery-1", "password": "synthetic-test-passphrase"})
            self.assertEqual(wrong.status_code, 401)
            login = await client.post("/api/login", json={
                "user_id": "lab-emergency-recovery-1",
                "password": self.emergency_value})
            self.assertEqual(login.status_code, 200)
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            self.assertEqual((await client.get("/api/me", headers=headers)).json()["role"],
                             "emergency_recovery")
            status = await client.get("/api/emergency/status", headers=headers)
            self.assertEqual(status.status_code, 200)
            self.assertEqual(status.json()["document_access"], "denied")
            ordinary = await client.post("/api/login", json={
                "user_id": "lab-avit_admin-1", "password": "synthetic-test-passphrase"})
            ordinary_headers = {"Authorization": "Bearer " + ordinary.json()["access_token"]}
            self.assertEqual((await client.get("/api/emergency/status",
                                               headers=ordinary_headers)).status_code, 403)
            for method, path, data in (
                    ("GET", "/api/sources", None),
                    ("POST", "/api/chat", {"message": "generator inspection"}),
                    ("GET", "/api/security/incidents", None),
                    ("GET", "/api/admin/status", None)):
                with self.subTest(path=path):
                    response = await client.request(method, path, headers=headers, json=data)
                    self.assertEqual(response.status_code, 403)
            self.assertEqual(self.model.calls, 0)
            self.secret.write_text(self.rotated_value + "\n", encoding="utf-8")
            self.assertEqual((await client.get("/api/emergency/status", headers=headers)).status_code, 401)
            renewed = await client.post("/api/login", json={
                "user_id": "lab-emergency-recovery-1",
                "password": self.rotated_value})
            self.assertEqual(renewed.status_code, 200)
            renewed_headers = {"Authorization": "Bearer " + renewed.json()["access_token"]}
            class FutureClock(datetime):
                @classmethod
                def now(cls, tz=None):
                    return self.now + timedelta(minutes=6)
            with patch("services.policy.policy_file.datetime", FutureClock):
                self.assertEqual((await client.get("/api/emergency/status",
                                                   headers=renewed_headers)).status_code, 401)
        audit_text = self.audit.read_text(encoding="utf-8")
        self.assertIn("policy-change-applied", audit_text)
        self.assertNotIn(self.rotated_value, audit_text)

    async def test_exposed_or_linked_emergency_secret_denies_login(self) -> None:
        self.activate()
        app = create_app(Settings(fixture_root=self.root,
                                  lab_password="synthetic-test-passphrase",
                                  emergency_password_file=self.secret, audit_path=self.audit),
                         self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://emergency.invalid") as client:
            credentials = {"user_id": "lab-emergency-recovery-1",
                           "password": self.emergency_value}
            self.secret.chmod(0o644)
            self.assertEqual((await client.post("/api/login", json=credentials)).status_code, 401)
            self.secret.chmod(0o600)
            saved = self.root / "saved-emergency-secret"
            self.secret.rename(saved)
            self.secret.symlink_to(saved)
            self.assertEqual((await client.post("/api/login", json=credentials)).status_code, 401)

    async def test_emergency_candidate_requires_incident_short_expiry_and_no_documents(self) -> None:
        for options in ({"expiry_minutes": 61}, {"incident": None},
                        {"collections": ["deck"]}):
            with self.subTest(options=options):
                with self.assertRaises(PolicyChangeError):
                    self.activate(**options)
        self.assertIsNone(active_user(json.loads(self.policy.read_text(encoding="utf-8")),
                                      "lab-emergency-recovery-1"))


if __name__ == "__main__":
    unittest.main()
