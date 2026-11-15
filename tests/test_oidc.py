from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.api.oidc import OidcVerifier


class OidcTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.roles = Path(self.temporary.name) / "roles.json"
        self.policy = {"users": [{"id": "engineer", "role": "chief_engineer", "status": "active"}]}
        self.roles.write_text(json.dumps(self.policy))
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        key.update(kid="lab-key", alg="RS256", use="sig")
        self.issuer = "http://127.0.0.1:18086/realms/sovereign-lab"
        self.verifier = OidcVerifier(self.issuer, self.roles, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"keys": [key]})))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def token(self, **overrides: object) -> str:
        claims: dict[str, object] = {
            "iss": self.issuer, "aud": "sovereign-core", "azp": "sovereign-console", "typ": "Bearer",
            "sub": "synthetic-subject", "preferred_username": "engineer",
            "realm_access": {"roles": ["chief_engineer"]},
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private, algorithm="RS256", headers={"kid": "lab-key"})

    def test_signature_audience_role_expiry_and_policy_revocation(self) -> None:
        valid = self.token()
        self.assertEqual(self.verifier.user_for(valid)["id"], "engineer")
        self.assertIsNone(self.verifier.user_for(valid[:-1] + ("A" if valid[-1] != "A" else "B")))
        self.assertIsNone(self.verifier.user_for(self.token(aud="other-service")))
        self.assertIsNone(self.verifier.user_for(self.token(realm_access={"roles": ["deckhand"]})))
        self.assertIsNone(self.verifier.user_for(self.token(exp=int(time.time()) - 1)))
        self.policy["users"][0]["status"] = "revoked"
        self.roles.write_text(json.dumps(self.policy))
        self.assertIsNone(self.verifier.user_for(valid))

    def test_nonlocal_issuer_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OidcVerifier("https://example.com/realms/lab", self.roles)


if __name__ == "__main__":
    unittest.main()
