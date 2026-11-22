from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.phase3_pgvector_recovery import _container, rehearse


class PgvectorRecoveryTests(unittest.TestCase):
    def test_rejects_unpinned_image_before_starting_containers(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                patch("scripts.phase3_pgvector_recovery._container") as container:
            with self.assertRaises(ValueError):
                rehearse("pgvector/pgvector:pg17-bookworm", Path(directory) / "restic", "0" * 64)
            container.assert_not_called()

    def test_failed_loopback_port_check_removes_started_container(self) -> None:
        with patch("scripts.phase3_pgvector_recovery._docker",
                   side_effect=["synthetic-id", "0.0.0.0:55439"]), \
                patch("scripts.phase3_pgvector_recovery._ready"), \
                patch("scripts.phase3_pgvector_recovery.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "loopback only"):
                _container("pgvector/pgvector@sha256:" + "0" * 64, "synthetic-name")
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["docker", "rm", "-f", "synthetic-id"])
