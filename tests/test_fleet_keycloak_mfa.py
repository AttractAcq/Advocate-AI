"""Fixed-vector check for the synthetic Keycloak OTP rehearsal."""

from __future__ import annotations

import base64
import ast
import unittest

from scripts.phase8_fleet_keycloak_rehearsal import _ADMIN_ROTATE, _realm, _totp


class FleetKeycloakMfaTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
