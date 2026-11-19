from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

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
        self.roles.write_text("[]")
        self.assertIsNone(self.verifier.user_for(valid))

    def test_nonlocal_issuer_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OidcVerifier("https://example.com/realms/lab", self.roles)

    def test_logout_revocation_survives_verifier_restart(self) -> None:
        path = Path(self.temporary.name) / "revoked.jsonl"
        original = self.verifier
        original.revocations_path = path
        token = self.token()
        self.assertIsNotNone(original.user_for(token))
        original.revoke(token)
        self.assertIsNone(original.user_for(token))
        restarted = OidcVerifier(self.issuer, self.roles, transport=original.transport,
                                 revocations_path=path)
        self.assertIsNone(restarted.user_for(token))
        self.assertIsNotNone(restarted.user_for(self.token(iat=int(time.time()) - 1)))
        path.write_text('{"sha256":')
        self.assertIsNone(restarted.user_for(self.token()))

    def test_unknown_kids_cannot_trigger_unbounded_jwks_refresh(self) -> None:
        calls = []
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        key.update(kid="lab-key", alg="RS256", use="sig")

        def respond(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={"keys": [key]})

        verifier = OidcVerifier(self.issuer, self.roles,
                                transport=httpx.MockTransport(respond))
        clock = [100.0]
        with patch("apps.api.oidc.time.monotonic", side_effect=lambda: clock[0]):
            self.assertIsNotNone(verifier._key("lab-key"))
            self.assertEqual(len(calls), 1)
            clock[0] = 100.1
            self.assertIsNone(verifier._key("unknown-1"))
            self.assertEqual(len(calls), 2)
            clock[0] = 100.2
            self.assertIsNone(verifier._key("unknown-2"))
            self.assertEqual(len(calls), 2)
            self.assertIsNone(verifier._key("x" * 257))
            self.assertEqual(len(calls), 2)
            clock[0] = 102.2
            self.assertIsNone(verifier._key("unknown-3"))
            self.assertEqual(len(calls), 3)

    def test_oversized_jwks_fails_closed(self) -> None:
        verifier = OidcVerifier(self.issuer, self.roles, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b" " * (256 * 1024 + 1))))
        self.assertIsNone(verifier.user_for(self.token()))


if __name__ == "__main__":
    unittest.main()
