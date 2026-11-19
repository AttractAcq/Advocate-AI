"""Fixed-vector check for the synthetic Keycloak OTP rehearsal."""

from __future__ import annotations

import base64
import unittest

from scripts.phase8_fleet_keycloak_rehearsal import _realm, _totp


class FleetKeycloakMfaTests(unittest.TestCase):
    def test_rfc6238_sha1_vector_with_six_digits(self) -> None:
        # RFC 6238 uses 8 digits; the configured lab realm uses the last 6.
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(_totp(secret, at=59), "287082")

    def test_mfa_realm_requires_otp_setup_only_when_selected(self) -> None:
        normal = _realm("synthetic-password")
        protected = _realm("synthetic-password", mfa=True)
        self.assertEqual(normal["users"][0]["requiredActions"], [])
        self.assertEqual(protected["users"][0]["requiredActions"], ["CONFIGURE_TOTP"])
        self.assertEqual(protected["otpPolicyType"], "totp")


if __name__ == "__main__":
    unittest.main()
