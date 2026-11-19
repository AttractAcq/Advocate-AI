from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.phase3_pgvector_core_socket import rehearse
from services.knowledge.postgres_index import _connect


class PgvectorCoreSocketTests(unittest.TestCase):
    def test_rejects_unpinned_database_image_before_docker(self) -> None:
        with patch("scripts.phase3_pgvector_core_socket._docker") as docker:
            with self.assertRaises(ValueError):
                rehearse("pgvector/pgvector:pg17-bookworm", "sovereign-core:synthetic")
            docker.assert_not_called()

    def test_rejects_unapproved_socket_uri(self) -> None:
        invalid = (
            "postgresql://sovereign@/postgres?host=/tmp/postgresql",
            "postgresql://sovereign@/postgres?host=/run/postgresql&sslmode=disable",
            "postgresql://sovereign:secret@/postgres?host=/run/postgresql",
            "postgresql://sovereign@postgres/knowledge",
        )
        with patch("services.knowledge.postgres_index.psycopg.connect") as connect:
            for dsn in invalid:
                with self.subTest(dsn=dsn), self.assertRaises(ValueError):
                    _connect(dsn)
            connect.assert_not_called()

    def test_accepts_only_approved_socket_mount(self) -> None:
        dsn = "postgresql://sovereign@/postgres?host=/run/postgresql"
        with patch("services.knowledge.postgres_index.psycopg.connect") as connect:
            _connect(dsn)
            self.assertEqual(connect.call_args.args[0], dsn)
            self.assertEqual(connect.call_args.kwargs["connect_timeout"], 3)
