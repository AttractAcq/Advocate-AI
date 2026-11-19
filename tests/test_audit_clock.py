"""AT-25 synthetic audit behavior when the local wall clock moves backwards."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

from apps.fleet.main import FleetSettings, create_app
from services.fleet.catalog import Customer, FleetCatalog, FleetIntegrityError
from services.policy.audit import AuditLog, verify


class PastClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2020, 1, 1, tzinfo=tz or timezone.utc)


class AuditClockTests(unittest.TestCase):
    def test_core_audit_rejects_clock_rollback_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = AuditLog(path)
            audit.append(actor="fictional-user", action="read", resource="DOC-1",
                         decision="allow", policy_version="synthetic")
            with patch("services.policy.audit.datetime", PastClock):
                with self.assertRaisesRegex(ValueError, "local clock"):
                    verify(path, require_current_clock=True)
                with self.assertRaisesRegex(ValueError, "local clock"):
                    audit.append(actor="fictional-user", action="write", resource="DOC-1",
                                 decision="allow", policy_version="synthetic")
            self.assertEqual(verify(path)[0], 1)

    def test_fleet_catalog_rejects_clock_rollback_before_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = FleetCatalog(Path(directory) / "fleet.db")
            catalog.add("customer", Customer(code="CUST-LAB1", category="owner_manager"))
            with patch("services.fleet.catalog.datetime", PastClock):
                with self.assertRaisesRegex(FleetIntegrityError, "local clock"):
                    catalog.list("customer", after="", limit=10)
                with self.assertRaisesRegex(FleetIntegrityError, "local clock"):
                    catalog.add("customer", Customer(code="CUST-LAB2", category="owner_manager"))
            self.assertEqual(len(catalog.list("customer", after="", limit=10)), 1)


class FleetAuditClockApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_fleet_api_reports_clock_rollback_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fleet.db"
            token = "synthetic-clock-test-token-0123456789"
            app = create_app(FleetSettings(path, token))
            FleetCatalog(path).add("customer", Customer(
                code="CUST-LAB1", category="owner_manager"))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://fleet.invalid",
                                         headers={"X-Fleet-Lab-Token": token}) as client:
                with patch("services.fleet.catalog.datetime", PastClock):
                    response = await client.get("/api/fleet/customers")
                    unhealthy = await client.get("/health")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(unhealthy.status_code, 503)
                self.assertEqual((await client.get("/health")).status_code, 200)
                self.assertEqual(len((await client.get("/api/fleet/customers")).json()), 1)


if __name__ == "__main__":
    unittest.main()
