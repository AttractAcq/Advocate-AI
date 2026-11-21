from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.knowledge_volume import KnowledgeVolumeHandle
from infrastructure.deploy.vessel_installer import (
    _read_intent, _read_state, _state_payload, _write_intent, _write_state,
)
from infrastructure.deploy.vessel_runtime import ThreatFeedMount, VesselRuntimeError
from infrastructure.deploy.vessel_threat_feed import feed_from_record, feed_record


class VesselThreatFeedTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.parent.chmod(0o700)
        self.root = self.parent / "install"
        self.root.mkdir(mode=0o700)
        self.state = self.parent / "core"
        self.state.mkdir(mode=0o700)
        self.store = self.parent / "feed"
        self.store.mkdir(mode=0o700)
        self.key = self.parent / "feed-key.pem"
        self.key.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.key.chmod(0o600)
        self.feed = ThreatFeedMount(self.store, self.key)

    def test_intent_and_active_state_pin_separate_feed(self) -> None:
        record = feed_record(self.feed, self.state, self.root)
        self.assertEqual(feed_from_record(record, self.state, self.root),
                         ThreatFeedMount(self.store.resolve(), self.key.resolve()))
        installation = "f" * 32
        _write_intent(self.root, "a" * 24, installation, self.state,
                      self.parent / "lab-password", threat_feed=record)
        self.assertEqual(_read_intent(self.root)["threat_feed"], record)
        run = "sovereign-knowledge-" + "e" * 12
        payload = _state_payload("a" * 24, installation, self.state,
                                 self.parent / "lab-password",
                                 RuntimeHandle("a" * 64, "b" * 64, "c" * 64),
                                 KnowledgeVolumeHandle("d" * 64, run + "-socket",
                                                       f"sovereign-{installation}-knowledge-data",
                                                       run, installation),
                                 threat_feed=record)
        _write_state(self.root, payload)
        self.assertEqual(_read_state(self.root)["threat_feed"], record)
        self.key.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaisesRegex(VesselRuntimeError, "identity changed"):
            _read_state(self.root)
        with self.assertRaisesRegex(VesselRuntimeError, "identity changed"):
            _read_intent(self.root)

    def test_feed_cannot_overlap_install_or_core_state(self) -> None:
        with self.assertRaisesRegex(VesselRuntimeError, "separate"):
            feed_record(ThreatFeedMount(self.state, self.key), self.state, self.root)
        with self.assertRaisesRegex(VesselRuntimeError, "separate"):
            feed_record(ThreatFeedMount(self.root, self.key), self.state, self.root)


if __name__ == "__main__":
    unittest.main()
