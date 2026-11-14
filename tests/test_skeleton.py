from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from infrastructure.release.manifest import validate_files
from services.connectors.events import normalise_event
from services.knowledge.acl import source_access
from services.policy.decision import may_read

ROOT = Path(__file__).resolve().parents[1]


class PolicyFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads((ROOT / "fixtures/roles.json").read_text())
        with (ROOT / "fixtures/manifest.csv").open() as stream:
            cls.sources = list(csv.DictReader(stream))

    def test_allow_and_deny(self) -> None:
        self.assertTrue(may_read("lab-captain-1", "management", self.policy))
        self.assertFalse(may_read("lab-deckhand-1", "management", self.policy))
        self.assertFalse(may_read("lab-removed-1", "deck", self.policy))
        self.assertFalse(may_read("unknown", "deck", self.policy))
        self.assertFalse(may_read("lab-captain-1", "restricted", self.policy))
        malformed = dict(self.policy) | {"users": [{"id": "bad", "status": "active", "role": []}]}
        self.assertFalse(may_read("bad", "deck", malformed))

    def test_source_mapping_fails_closed(self) -> None:
        engineering = next(x for x in self.sources if x["collection"] == "engineering")
        self.assertTrue(source_access("lab-chief_engineer-1", engineering, self.policy))
        self.assertFalse(source_access("lab-deckhand-1", engineering, self.policy))
        self.assertFalse(source_access("lab-chief_engineer-1", {"collection": "engineering"}, self.policy))
        self.assertFalse(source_access("lab-chief_engineer-1",
                        engineering | {"sha256": "z" * 64}, self.policy))


class EventFixtureTests(unittest.TestCase):
    def test_normalise_and_reject(self) -> None:
        raw = json.loads((ROOT / "fixtures/phase-1/events.jsonl").read_text().splitlines()[0])
        event = normalise_event(raw)
        self.assertTrue(event["read_only"])
        self.assertEqual(event["event_id"], raw["event_id"])
        with self.assertRaises(ValueError):
            normalise_event(raw | {"source": "unapproved-device"})


class ReleaseManifestTests(unittest.TestCase):
    def test_valid_and_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bundle.txt").write_text("synthetic")
            digest = hashlib.sha256(b"synthetic").hexdigest()
            manifest = {"schema": 1, "files": [{"path": "bundle.txt", "sha256": digest}]}
            self.assertTrue(validate_files(root, manifest))
            (root / "bundle.txt").write_text("tampered")
            self.assertFalse(validate_files(root, manifest))
            self.assertFalse(validate_files(root, {"schema": 1, "files": [
                {"path": "../outside", "sha256": digest}
            ]}))
            self.assertFalse(validate_files(root, {"schema": 1, "files": []}))


if __name__ == "__main__":
    unittest.main()
