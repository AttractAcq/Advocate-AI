"""Fixed-vector check for the synthetic Keycloak OTP rehearsal."""

from __future__ import annotations

import base64
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infrastructure.backup import BackupError, generate_key
from scripts.phase8_fleet_keycloak_rehearsal import (
    _ADMIN_ROTATE, _backup_realm, _checked_realm_restore, _lab_token_denied,
    _realm, _run_flow, _totp,
    _verify_base64_mitigation)


class FleetKeycloakMfaTests(unittest.TestCase):
    def test_live_jvm_mitigation_must_be_observed(self) -> None:
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   return_value="bool UseBASE64Intrinsics    = false    {product} {command line}") as command:
            _verify_base64_mitigation("synthetic-keycloak")
            command.assert_called_once_with(
                "docker", "exec", "synthetic-keycloak", "jcmd",
                "io.quarkus.bootstrap.runner.QuarkusEntryPoint", "VM.flags", "-all")
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   return_value="bool UseBASE64Intrinsics = true {product}"):
            with self.assertRaisesRegex(AssertionError, "Base64 intrinsics"):
                _verify_base64_mitigation("synthetic-keycloak")
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   return_value="bool UseBASE64Intrinsics = false {product} {default}"):
            with self.assertRaisesRegex(AssertionError, "Base64 intrinsics"):
                _verify_base64_mitigation("synthetic-keycloak")

    def test_rfc6238_sha1_vector_with_six_digits(self) -> None:
        # RFC 6238 uses 8 digits; the configured lab realm uses the last 6.
        encoded = base64.b32encode(b"12345678901234567890").decode()
        secret = " ".join(encoded[index:index + 4] for index in range(0, len(encoded), 4))
        self.assertEqual(_totp(secret, at=59), "287082")

    def test_mfa_realm_requires_otp_setup_only_when_selected(self) -> None:
        normal = _realm("synthetic-password")
        protected = _realm("synthetic-password", mfa=True)
        self.assertEqual(normal["users"][0]["requiredActions"], [])
        self.assertEqual(protected["users"][0]["requiredActions"], ["CONFIGURE_TOTP"])
        self.assertEqual(protected["otpPolicyType"], "totp")

    def test_keycloak_admin_rotation_probe_is_valid_python(self) -> None:
        script = _ADMIN_ROTATE
        for marker in ("__ISSUER__", "__PASSWORD__", "__ACTION__",
                       "__OLD_KID__", "__OLD_PROVIDER__", "__NEW_KID__"):
            script = script.replace(marker, repr("synthetic-value"))
        ast.parse(script)

    def test_realm_recovery_requires_fresh_authenticated_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "backup.key"
            generate_key(key)
            source = root / "fleet-realm.json"
            source.write_text(json.dumps(_realm("fictional-password")))
            old = root / "old.svbk"
            _backup_realm(source, root, old, key)
            source.write_text(json.dumps(_realm("new-fictional-password")))
            current = root / "current.svbk"
            expected = _backup_realm(source, root, current, key)
            with self.assertRaisesRegex(BackupError, "stale"):
                _checked_realm_restore(old, key, root / "rejected", expected)
            altered = root / "altered.svbk"
            payload = bytearray(current.read_bytes())
            payload[-20] ^= 1
            altered.write_bytes(payload)
            with self.assertRaises(BackupError):
                _checked_realm_restore(altered, key, root / "rejected",
                    hashlib.sha256(payload).hexdigest())
            _checked_realm_restore(current, key, root / "restored", expected)
            self.assertEqual(json.loads((root / "restored/fleet-realm.json").read_text())
                             ["users"][0]["credentials"][0]["value"],
                             "new-fictional-password")

    def test_pkce_flow_retries_only_transient_container_dns(self) -> None:
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   side_effect=[RuntimeError("httpx.ConnectError: [Errno -3] Try again")] * 14 +
                               ['{"fleet_role":"fleet_admin"}']) as command, \
             patch("scripts.phase8_fleet_keycloak_rehearsal.time.sleep") as pause:
            self.assertEqual(_run_flow("api", "flow"), {"fleet_role": "fleet_admin"})
            self.assertEqual(command.call_count, 15)
            self.assertEqual(pause.call_count, 14)
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   side_effect=RuntimeError("httpx.ConnectError: [Errno -3] Try again")) as command, \
             patch("scripts.phase8_fleet_keycloak_rehearsal.time.sleep") as pause:
            with self.assertRaises(RuntimeError):
                _run_flow("api", "flow")
            self.assertEqual(command.call_count, 15)
            self.assertEqual(pause.call_count, 14)
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   side_effect=RuntimeError("assert status_code == 200")) as command:
            with self.assertRaises(RuntimeError):
                _run_flow("api", "flow")
            command.assert_called_once()

    def test_lab_token_probe_retries_only_transient_container_dns(self) -> None:
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   side_effect=[RuntimeError("httpx.ConnectError: [Errno -3] Try again"), ""]) as command, \
             patch("scripts.phase8_fleet_keycloak_rehearsal.time.sleep") as pause:
            _lab_token_denied("api")
            self.assertEqual(command.call_count, 2)
            pause.assert_called_once_with(1)
        with patch("scripts.phase8_fleet_keycloak_rehearsal._run",
                   side_effect=RuntimeError("AssertionError: status_code was 200")) as command:
            with self.assertRaisesRegex(RuntimeError, "status_code was 200"):
                _lab_token_denied("api")
            command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
