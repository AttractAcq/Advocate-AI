from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apps.api.oidc import OidcVerifier
from apps.api.main import Settings, create_app


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

    def ca_file(self) -> Path:
        ca = Path(self.temporary.name) / "issuer-ca.pem"
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fictional Vessel CA")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(self.private.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                       .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(self.private, hashes.SHA256()))
        ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        ca.chmod(0o600)
        return ca

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

    def test_core_https_issuer_requires_private_ca(self) -> None:
        issuer = "https://identity.vessel.example/realms/sovereign"
        ca = self.ca_file()
        variables = {"SOVEREIGN_OIDC_ISSUER": issuer,
                     "SOVEREIGN_OIDC_CA_FILE": str(ca)}
        with patch.dict(os.environ, variables, clear=True):
            settings = Settings.from_env()
        with patch("apps.api.main.OidcVerifier") as verifier:
            create_app(settings)
        self.assertEqual(verifier.call_args.args[:2],
                         (issuer, settings.fixture_root / "roles.json"))
        self.assertTrue(verifier.call_args.kwargs["allow_https_issuer"])
        self.assertEqual(verifier.call_args.kwargs["ca_file"], ca)
        with self.assertRaises(ValueError):
            create_app(Settings(fixture_root=self.roles.parent, oidc_issuer=issuer))
        with self.assertRaises(ValueError):
            create_app(Settings(fixture_root=self.roles.parent, oidc_ca_file=ca))
        with self.assertRaises(ValueError):
            create_app(Settings(fixture_root=self.roles.parent, oidc_issuer=self.issuer,
                                oidc_ca_file=ca))

    def test_core_rejects_exposed_or_ambiguous_ca_file(self) -> None:
        ca = self.ca_file()
        variables = {"SOVEREIGN_OIDC_ISSUER":
                     "https://identity.vessel.example/realms/sovereign",
                     "SOVEREIGN_OIDC_CA_FILE": str(ca)}
        for mode in (0o644, 0o640):
            ca.chmod(mode)
            with patch.dict(os.environ, variables, clear=True), self.assertRaises(ValueError):
                Settings.from_env()
        ca.chmod(0o600)
        alias = ca.with_name("issuer-ca-alias.pem")
        os.link(ca, alias)
        with patch.dict(os.environ, variables, clear=True), self.assertRaises(ValueError):
            Settings.from_env()
        alias.unlink()
        alias.symlink_to(ca)
        with patch.dict(os.environ, {**variables, "SOVEREIGN_OIDC_CA_FILE": str(alias)},
                        clear=True), self.assertRaises(ValueError):
            Settings.from_env()
        ca.write_text("not a certificate")
        with patch.dict(os.environ, variables, clear=True), self.assertRaises(ValueError):
            Settings.from_env()

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
