"""Guardrails for a site-rendered, boot-only signed vessel recovery unit."""

from pathlib import Path
import tempfile
import unittest

from infrastructure.deploy.boot_service import BootServiceError
from infrastructure.deploy.vessel_boot_service import (
    render_vessel_recovery_unit, write_vessel_recovery_unit,
)


class VesselBootServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = (Path("/var/lib/sovereign-vessel"),
                      Path("/var/lib/sovereign-core-state"),
                      Path("/etc/sovereign/vessel-trusted.pem"),
                      Path("/opt/sovereign/bin/crane"),
                      Path("/opt/sovereign/bin/python"),
                      Path("/opt/sovereign/app"), "sovereign-vessel", "sovereign-vessel")

    def test_checked_stop_recovery_and_health_are_ordered(self) -> None:
        unit = render_vessel_recovery_unit(*self.paths)
        self.assertIn("Requires=docker.service\nAfter=docker.service", unit)
        self.assertIn("ConditionPathExists=/var/lib/sovereign-vessel/vessel-state.json", unit)
        self.assertIn("User=sovereign-vessel\nGroup=sovereign-vessel", unit)
        self.assertIn("ReadWritePaths=/var/lib/sovereign-vessel /var/lib/sovereign-core-state", unit)
        self.assertLess(unit.index("vesselctl finish-stop"), unit.index("vesselctl recover"))
        self.assertLess(unit.index("vesselctl recover"), unit.index("vesselctl status"))
        output = self.root / "sovereign-vessel-recover.service"
        write_vessel_recovery_unit(output, *self.paths)
        self.assertEqual(output.read_text(), unit)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(BootServiceError):
            write_vessel_recovery_unit(output, *self.paths)

    def test_rejects_unsafe_paths_and_accounts(self) -> None:
        for bad in (Path("relative"), Path("/a path"), Path("/a%p"),
                    Path("/a\nExecStart=/bin/false"), Path("/a/../b")):
            with self.subTest(path=bad), self.assertRaises(BootServiceError):
                render_vessel_recovery_unit(bad, *self.paths[1:])
        with self.assertRaises(BootServiceError):
            render_vessel_recovery_unit(self.paths[0], self.paths[0] / "core",
                                        *self.paths[2:])
        for user, group in (("root", "sovereign-vessel"),
                            ("sovereign-vessel", "root"),
                            ("bad\nExecStart=/bin/false", "sovereign-vessel")):
            with self.subTest(user=user), self.assertRaises(BootServiceError):
                render_vessel_recovery_unit(*self.paths[:6], user, group)


if __name__ == "__main__":
    unittest.main()
