"""Manifest polling must notice changes and retry failures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from services.knowledge.reconcile import ManifestReconciler


class ManifestReconcilerTests(unittest.TestCase):
    def test_oversized_manifest_does_not_reach_sync(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "approved.json"
            manifest.write_bytes(b"x" * 32)
            calls = []
            watcher = ManifestReconciler(root, manifest, root / "index.db",
                                         sync=lambda *_: calls.append(True) or {})
            with patch("services.knowledge.manifest_io.MAX_MANIFEST_BYTES", 16):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    watcher.poll(now=0)
            self.assertEqual(calls, [])
            self.assertIsNotNone(watcher.poll(now=1))

    def test_change_and_periodic_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "approved.json"
            manifest.write_text("first", encoding="utf-8")
            calls = []

            def sync(*_):
                calls.append(manifest.read_text(encoding="utf-8"))
                return {"indexed": [], "unchanged": [], "deleted": [], "quarantined": []}

            watcher = ManifestReconciler(root, manifest, root / "index.db",
                                         full_scan_seconds=60, sync=sync)
            self.assertIsNotNone(watcher.poll(now=0))
            self.assertIsNone(watcher.poll(now=5))
            manifest.write_text("second", encoding="utf-8")
            self.assertIsNotNone(watcher.poll(now=10))
            self.assertIsNone(watcher.poll(now=69))
            self.assertIsNotNone(watcher.poll(now=70))
            self.assertEqual(calls, ["first", "second", "second"])

    def test_failed_sync_retries_same_manifest_and_removal_reconciles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("Synthetic marker SAMPLE-1", encoding="utf-8")
            manifest = root / "approved.json"
            item = {"document_id": "LAB-001", "relative_path": "sample.txt",
                    "collection": "deck", "classification": "C0_SYNTHETIC_DECK",
                    "owner": "fictional", "version": "1", "source_type": "synthetic-local",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            manifest.write_text(json.dumps({"schema": 1, "sources": [item]}), encoding="utf-8")
            database = root / "index.db"
            watcher = ManifestReconciler(root, manifest, database)
            self.assertEqual(watcher.poll(now=0)["indexed"], ["LAB-001"])
            manifest.write_text("invalid", encoding="utf-8")
            with self.assertRaises(ValueError):
                watcher.poll(now=1)
            manifest.write_text(json.dumps({"schema": 1, "sources": []}), encoding="utf-8")
            self.assertEqual(watcher.poll(now=2)["deleted"], ["LAB-001"])

    def test_unchanged_manifest_gets_periodic_source_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.txt"
            source.write_text("Synthetic marker SAMPLE-1", encoding="utf-8")
            manifest = root / "approved.json"
            manifest.write_text(json.dumps({"schema": 1, "sources": [{
                "document_id": "LAB-001", "relative_path": "sample.txt",
                "collection": "deck", "classification": "C0_SYNTHETIC_DECK",
                "owner": "fictional", "version": "1", "source_type": "synthetic-local",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]}), encoding="utf-8")
            watcher = ManifestReconciler(root, manifest, root / "index.db",
                                         full_scan_seconds=60)
            self.assertEqual(watcher.poll(now=0)["indexed"], ["LAB-001"])
            source.write_text("Changed without manifest approval", encoding="utf-8")
            self.assertIsNone(watcher.poll(now=30))
            self.assertEqual(watcher.poll(now=60)["quarantined"], ["LAB-001"])


if __name__ == "__main__":
    unittest.main()
