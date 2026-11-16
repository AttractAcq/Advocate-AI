from __future__ import annotations

import copy
import json
import unittest

from scripts.phase3_identity import container_create_command
from scripts.security_config_scan import ROOT, scan


class SecurityConfigScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = json.loads((ROOT / "infrastructure/deploy/lab-config.json").read_text())
        self.topology = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())
        self.image = json.loads((ROOT / "infrastructure/lab/container-image.json").read_text())
        self.command = container_create_command()

    def test_current_lab_configuration_passes(self) -> None:
        self.assertEqual(scan(self.config, self.topology, self.image, self.command), [])

    def test_public_route_and_mismatched_port_fail(self) -> None:
        config = copy.deepcopy(self.config)
        config["public_egress"] = True
        self.assertTrue(scan(config, self.topology, self.image, self.command))
        topology = copy.deepcopy(self.topology)
        topology["dns"]["names"]["core.lab.sovereign.test"] = "8.8.8.8"
        topology["services"]["core"] = 28081
        issues = scan(self.config, topology, self.image, self.command)
        self.assertTrue(any("DNS" in issue for issue in issues))
        self.assertTrue(any("ports" in issue for issue in issues))

    def test_unpinned_or_privileged_container_fails(self) -> None:
        image = copy.deepcopy(self.image)
        image["digest"] = "latest"
        self.assertTrue(scan(self.config, self.topology, image, self.command))
        command = ["docker", "create", "--privileged", *self.command[2:]]
        self.assertTrue(any("privileged" in issue for issue in
                            scan(self.config, self.topology, self.image, command)))
        command = ["docker", "create", "--network=host", *self.command[2:]]
        self.assertTrue(any("privileged" in issue for issue in
                            scan(self.config, self.topology, self.image, command)))
        command = self.command.copy()
        command[command.index("127.0.0.1:18086:8080")] = "0.0.0.0:18086:8080"
        self.assertTrue(scan(self.config, self.topology, self.image, command))


if __name__ == "__main__":
    unittest.main()
