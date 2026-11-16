from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from infrastructure.deploy.boot_service import (
    BootServiceError, render_recovery_unit, write_recovery_unit,
)


class BootServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.paths = (Path("/var/lib/sovereign-lab"), Path("/etc/sovereign/trusted.pem"),
                      Path("/opt/sovereign/bin/crane"), Path("/opt/sovereign/bin/python"),
                      Path("/opt/sovereign/app"))

    def test_unit_orders_recovery_after_docker_and_restricts_install_write(self) -> None:
        unit = render_recovery_unit(*self.paths)
        self.assertIn("Requires=docker.service\nAfter=docker.service", unit)
        self.assertIn("ConditionPathExists=/var/lib/sovereign-lab/product-state.json", unit)
        self.assertIn("ReadWritePaths=/var/lib/sovereign-lab", unit)
        self.assertIn("ExecStart=/opt/sovereign/bin/python -m infrastructure.deploy.product_installer recover", unit)
        output = self.base / "sovereign-lab-recover.service"
        write_recovery_unit(output, *self.paths)
        self.assertEqual(output.read_text(), unit)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(BootServiceError):
            write_recovery_unit(output, *self.paths)

    def test_rejects_ambiguous_or_injected_paths(self) -> None:
        for bad in (Path("relative/root"), Path("/a path"), Path("/a%p"),
                    Path("/a\nExecStart=/bin/false"), Path("/a;rm")):
            with self.subTest(path=bad), self.assertRaises(BootServiceError):
                render_recovery_unit(bad, *self.paths[1:])


if __name__ == "__main__":
    unittest.main()
