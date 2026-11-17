"""Company-side Fleet identity is separate from vessel Core identity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.api.oidc import OidcVerifier
from apps.fleet.main import FleetSettings, create_app
from services.fleet.catalog import FleetCatalog, Release


class FleetOidcTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db = Path(self.temporary.name) / "fleet.db"
        self.roles_path = Path(self.temporary.name) / "fleet-roles.json"
        self.policy = {"users": [
            {"id": "admin", "role": "fleet_admin", "status": "active"},
            {"id": "release", "role": "fleet_release_manager", "status": "active"},
            {"id": "support", "role": "fleet_support", "status": "active"},
            {"id": "viewer", "role": "fleet_viewer", "status": "active"},
        ]}
        self._write_policy()
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        key.update(kid="fleet-lab-key", alg="RS256", use="sig")
        self.issuer = "http://127.0.0.1:18086/realms/fleet-lab"
        verifier = OidcVerifier(
            self.issuer, self.roles_path, audience="sovereign-fleet",
            authorized_client="sovereign-fleet-portal",
            transport=httpx.MockTransport(lambda request: httpx.Response(
                200, json={"keys": [key]})))
        app = create_app(FleetSettings(self.db, None, oidc_verifier=verifier))
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url="http://fleet.invalid")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    def _write_policy(self) -> None:
        self.roles_path.write_text(json.dumps(self.policy))
        self.roles_path.chmod(0o600)

    def headers(self, user: str, role: str, **overrides: object) -> dict[str, str]:
        claims: dict[str, object] = {
            "iss": self.issuer, "aud": "sovereign-fleet",
            "azp": "sovereign-fleet-portal", "typ": "Bearer", "sub": f"fleet-{user}",
            "preferred_username": user, "realm_access": {"roles": [role]},
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }
        claims.update(overrides)
        token = jwt.encode(claims, self.private, algorithm="RS256",
                           headers={"kid": "fleet-lab-key"})
        return {"Authorization": "Bearer " + token}

    async def test_role_matrix_and_no_lab_token_fallback(self) -> None:
        catalog = FleetCatalog(self.db)
        catalog.add_verified_release(Release(
            code="REL-LAB1", version="1.0.0", manifest_sha256="a" * 64,
            signing_key_id="b" * 64, status="candidate"))
        viewer = self.headers("viewer", "fleet_viewer")
        support = self.headers("support", "fleet_support")
        release = self.headers("release", "fleet_release_manager")
        admin = self.headers("admin", "fleet_admin")

        self.assertEqual((await self.client.get("/api/fleet/me", headers=viewer)).json(),
                         {"id": "viewer", "role": "fleet_viewer"})
        self.assertEqual((await self.client.get("/api/fleet/releases",
                                                headers=viewer)).status_code, 200)
        self.assertEqual((await self.client.get("/api/fleet/audit",
                                                headers=viewer)).status_code, 403)
        self.assertEqual((await self.client.patch(
            "/api/fleet/releases/REL-LAB1/status", headers=viewer,
            json={"status": "approved"})).status_code, 403)
        self.assertEqual((await self.client.patch(
            "/api/fleet/releases/REL-LAB1/status", headers=release,
            json={"status": "approved"})).status_code, 200)
        self.assertEqual((await self.client.post("/api/fleet/customers", headers=support,
            json={"code": "CUST-LAB1", "category": "owner_manager"})).status_code, 403)
        self.assertEqual((await self.client.post("/api/fleet/customers", headers=admin,
            json={"code": "CUST-LAB1", "category": "owner_manager"})).status_code, 201)
        self.assertEqual((await self.client.post("/api/fleet/deployments", headers=admin,
            json={"code": "VSL-LAB1", "customer_code": "CUST-LAB1",
                  "release_code": "REL-LAB1", "hardware_profile": "pilot_gpu",
                  "status": "lab"})).status_code, 201)
        self.assertEqual((await self.client.post("/api/fleet/tickets", headers=support,
            json={"code": "TKT-LAB1", "vessel_code": "VSL-LAB1",
                  "category": "installation", "priority": "p3",
                  "status": "open"})).status_code, 201)
        self.assertEqual((await self.client.post("/api/fleet/tickets", headers=release,
            json={"code": "TKT-LAB2", "vessel_code": "VSL-LAB1",
                  "category": "installation", "priority": "p3",
                  "status": "open"})).status_code, 403)
        licence = {"code": "LIC-LAB1", "customer_code": "CUST-LAB1",
                   "vessel_code": "VSL-LAB1", "tier": "pilot",
                   "valid_from": "2026-11-17", "valid_until": "2027-11-17",
                   "status": "pending"}
        self.assertEqual((await self.client.post("/api/fleet/licences", headers=support,
                                                  json=licence)).status_code, 403)
        self.assertEqual((await self.client.post("/api/fleet/licences", headers=admin,
                                                  json=licence)).status_code, 201)
        self.assertEqual((await self.client.patch(
            "/api/fleet/licences/LIC-LAB1/status", headers=support,
            json={"status": "active"})).status_code, 403)
        self.assertEqual((await self.client.post("/api/fleet/maintenance", headers=support,
            json={"code": "MNT-LAB1", "vessel_code": "VSL-LAB1",
                  "kind": "backup_rehearsal", "due_on": "2026-12-01",
                  "engineer_code": "ENGR-LAB1", "status": "planned"})).status_code, 201)
        receipt = {"schema_version": 1, "key_id": "a" * 64,
                   "receipt": {"code": "RCP-LAB1", "vessel_code": "VSL-LAB1",
                               "release_code": "REL-LAB1",
                               "source": "approved_offline_admin",
                               "observed_on": "2026-11-17", "health": "healthy"},
                   "signature": "A" * 88}
        self.assertEqual((await self.client.post(
            "/api/fleet/import/deployment-receipts", headers=support,
            json=receipt)).status_code, 403)
        self.assertEqual((await self.client.post(
            "/api/fleet/import/deployment-receipts", headers=admin,
            json=receipt)).status_code, 503)
        self.assertEqual((await self.client.get("/api/fleet/audit",
                                                headers=release)).status_code, 200)
        self.assertEqual((await self.client.get(
            "/api/fleet/customers", headers={"X-Fleet-Lab-Token":
                                              "synthetic-fleet-admin-token-0123456789"}
        )).status_code, 401)

    async def test_claim_binding_and_revocation(self) -> None:
        for claims in ({"aud": "sovereign-core"},
                       {"azp": "sovereign-console"},
                       {"realm_access": {"roles": ["fleet_admin"]}},
                       {"exp": int(time.time()) - 1}):
            response = await self.client.get("/api/fleet/customers",
                headers=self.headers("viewer", "fleet_viewer", **claims))
            self.assertEqual(response.status_code, 401)
        viewer = self.headers("viewer", "fleet_viewer")
        self.assertEqual((await self.client.get("/api/fleet/customers",
                                                headers=viewer)).status_code, 200)
        self.policy["users"][-1]["status"] = "revoked"
        self._write_policy()
        self.assertEqual((await self.client.get("/api/fleet/customers",
                                                headers=viewer)).status_code, 401)

    async def test_identity_modes_are_mutually_exclusive(self) -> None:
        variables = {"SOVEREIGN_FLEET_DB": str(self.db),
                     "SOVEREIGN_FLEET_OIDC_ISSUER": self.issuer,
                     "SOVEREIGN_FLEET_ROLES_FILE": str(self.roles_path)}
        with patch.dict(os.environ, variables, clear=True):
            settings = FleetSettings.from_env()
            self.assertIsNone(settings.admin_token)
            self.assertIsNotNone(settings.oidc_verifier)
        with patch.dict(os.environ, {**variables,
            "SOVEREIGN_FLEET_TOKEN_FILE": str(self.roles_path)}, clear=True):
            with self.assertRaises(ValueError):
                FleetSettings.from_env()
        with self.assertRaises(ValueError):
            create_app(FleetSettings(self.db, None, oidc_verifier=OidcVerifier(
                self.issuer, self.roles_path, audience="sovereign-core")))


if __name__ == "__main__":
    unittest.main()
