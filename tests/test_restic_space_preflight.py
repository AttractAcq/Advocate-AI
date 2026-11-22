from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infrastructure.restic_repository import (
    ResticError, _check_snapshot_space, create_snapshot,
)


class ResticSpacePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.source = self.root / "fictional.txt"
        self.source.write_bytes(b"fictional" * 512)
        self.spec = self.root / "spec.json"
        self.spec.write_text(json.dumps({"schema": 1, "files": [
            {"name": "fictional.txt", "kind": "file", "source": str(self.source)}]}))
        self.repository = self.root / "repository"

    def test_insufficient_same_volume_space_precedes_snapshot_copy(self) -> None:
        with patch("infrastructure.restic_repository._preflight"), \
             patch("infrastructure.restic_repository.shutil.disk_usage",
                   return_value=SimpleNamespace(free=0)), \
             patch("infrastructure.restic_repository._snapshot") as copied:
            with self.assertRaisesRegex(ResticError, "insufficient space"):
                create_snapshot(self.spec, self.repository, self.root / "password",
                                self.root / "restic", "0" * 64, self.stage)
        copied.assert_not_called()
        self.assertFalse(self.repository.exists())

    def test_sufficient_space_accepts_bounded_inventory(self) -> None:
        spec = json.loads(self.spec.read_text())
        with patch("infrastructure.restic_repository.shutil.disk_usage",
                   return_value=SimpleNamespace(free=1024 * 1024 * 1024)):
            _check_snapshot_space(spec, self.root, self.stage, self.repository,
                                  256 * 1024 * 1024)

    def test_separate_repository_volume_needs_its_own_capacity(self) -> None:
        spec = json.loads(self.spec.read_text())
        with patch("infrastructure.restic_repository._device", side_effect=[1, 2]), \
             patch("infrastructure.restic_repository.shutil.disk_usage",
                   side_effect=[SimpleNamespace(free=1024 * 1024 * 1024),
                                SimpleNamespace(free=0)]):
            with self.assertRaisesRegex(ResticError, "insufficient space"):
                _check_snapshot_space(spec, self.root, self.stage, self.repository,
                                      256 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
