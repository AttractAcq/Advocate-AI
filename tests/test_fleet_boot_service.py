from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from infrastructure.deploy.boot_service import BootServiceError
from infrastructure.deploy.fleet_boot_service import (
    render_fleet_recovery_unit, write_fleet_recovery_unit,
)


class FleetBootServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.paths = (Path("/var/lib/sovereign-fleet"),
                      Path("/etc/sovereign/fleet-trusted.pem"),
                      Path("/opt/sovereign/bin/crane"),
                      Path("/opt/sovereign/bin/python"),
                      Path("/opt/sovereign/app"))

    def test_boot_recovery_requires_signed_state_then_health(self) -> None:
        unit = render_fleet_recovery_unit(*self.paths)
        self.assertIn("Requires=docker.service\nAfter=docker.service", unit)
        self.assertIn("ConditionPathExists=/var/lib/sovereign-fleet/fleet-state.json", unit)
        self.assertIn("User=sovereign-fleet", unit)
        self.assertIn("ReadWritePaths=/var/lib/sovereign-fleet", unit)
        self.assertLess(unit.index("fleet_installer recover"),
                        unit.index("fleet_installer status"))
        output = self.root / "sovereign-fleet-recover.service"
        write_fleet_recovery_unit(output, *self.paths)
        self.assertEqual(output.read_text(), unit)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(BootServiceError):
            write_fleet_recovery_unit(output, *self.paths)

    def test_rejects_injected_and_ambiguous_paths(self) -> None:
        for bad in (Path("relative"), Path("/a path"), Path("/a%p"),
                    Path("/a\nExecStart=/bin/false"), Path("/a/../b")):
            with self.subTest(path=bad), self.assertRaises(BootServiceError):
                render_fleet_recovery_unit(bad, *self.paths[1:])
        with self.assertRaises(BootServiceError):
            render_fleet_recovery_unit(self.paths[0], self.paths[0],
                                       *self.paths[2:])


if __name__ == "__main__":
    unittest.main()
