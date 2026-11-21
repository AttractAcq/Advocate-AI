from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from infrastructure.deploy.vessel_identity import (
    VesselIdentityError, preflight_vessel_identity,
)


class VesselIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.config = self.root / "console.json"
        self.issuer = "https://identity.vessel.example/realms/sovereign"
        self.config.write_text(json.dumps({"schema": 1, "oidc_issuer": self.issuer}))
        self.ca = self.state / "oidc-ca.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Vessel CA")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                       .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(key, hashes.SHA256()))
        self.ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.ca.chmod(0o600)
        self.log = self.state / "oidc-revocations.jsonl"
        self.log.write_bytes(b"")
        self.log.chmod(0o600)

    @staticmethod
    def docker(*args: str) -> str:
        return {"{{.Id}}": "a" * 64, "{{.Internal}}": "true",
                '{{index .Labels "sovereign.vessel.identity"}}': "true"}[args[-1]]

    def test_private_material_and_labelled_internal_network_are_required(self) -> None:
        with patch("infrastructure.deploy.vessel_identity._docker", side_effect=self.docker):
            identity = preflight_vessel_identity(self.config, self.state, "vessel-identity")
        self.assertEqual(identity.issuer, self.issuer)
        self.assertEqual(identity.ca_file, self.ca)
        self.assertEqual(identity.revocations_file, self.log)
        self.assertEqual(identity.network_id, "a" * 64)

    def test_missing_or_tampered_identity_material_fails(self) -> None:
        with patch("infrastructure.deploy.vessel_identity._docker", side_effect=self.docker):
            self.log.unlink()
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")
            self.log.write_bytes(b'{"sha256":"' + b"a" * 64 + b'"}')
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")
            self.log.write_bytes(b"")
            self.log.chmod(0o644)
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")
            self.log.chmod(0o600)
            self.ca.unlink()
            self.ca.symlink_to(self.log)
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")

    def test_untrusted_network_and_lab_issuer_fail(self) -> None:
        with patch("infrastructure.deploy.vessel_identity._docker", return_value="false"):
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")
        self.config.write_text('{"schema":1,"oidc_issuer":null}')
        with patch("infrastructure.deploy.vessel_identity._docker", side_effect=self.docker):
            with self.assertRaises(VesselIdentityError):
                preflight_vessel_identity(self.config, self.state, "vessel-identity")
