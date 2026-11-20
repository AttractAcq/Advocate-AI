from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from infrastructure.deploy.postgres_socket import ready


class PostgresSocketTests(unittest.TestCase):
    def test_ready_waits_past_temporary_initialization_server(self) -> None:
        shell = subprocess.CompletedProcess([], 0, stdout="sh\n")
        final = subprocess.CompletedProcess([], 0, stdout="postgres\n")
        listening = subprocess.CompletedProcess([], 0)
        with patch("infrastructure.deploy.postgres_socket.subprocess.run",
                   side_effect=[shell, listening, final, listening]) as run, \
             patch("infrastructure.deploy.postgres_socket.time.sleep") as sleep:
            ready("synthetic-container")
        self.assertEqual(run.call_count, 4)
        sleep.assert_called_once_with(1)

    def test_ready_requires_pg_isready_from_final_process(self) -> None:
        final = subprocess.CompletedProcess([], 0, stdout="postgres\n")
        unavailable = subprocess.CompletedProcess([], 1)
        listening = subprocess.CompletedProcess([], 0)
        with patch("infrastructure.deploy.postgres_socket.subprocess.run",
                   side_effect=[final, unavailable, final, listening]) as run, \
             patch("infrastructure.deploy.postgres_socket.time.sleep") as sleep:
            ready("synthetic-container")
        self.assertEqual(run.call_count, 4)
        sleep.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
