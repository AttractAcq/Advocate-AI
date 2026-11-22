from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import json
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
from infrastructure.deploy.vessel_threat_feed import (
    feed_evidence, feed_from_record, feed_record, verify_feed_evidence,
)
from services.intelligence.threat_snapshot import import_package, sign_payload, trusted_key


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
        signing = Ed25519PrivateKey.generate()
        self.private = self.parent / "signing.pem"
        self.private.write_bytes(signing.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.private.chmod(0o600)
        self.key.write_bytes(signing.public_key().public_bytes(
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

    def test_signed_receipt_evidence_detects_snapshot_change(self) -> None:
        issued = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
        payload = {"schema": 1, "feed_id": "synthetic-feed",
                   "publisher": "synthetic-lab", "issued_at": issued.isoformat(),
                   "expires_at": (issued + timedelta(days=14)).isoformat(),
                   "indicators": [{"id": "fictional", "kind": "ipv4",
                                   "value": "203.0.113.7"}]}
        source = self.parent / "payload.json"
        source.write_text(json.dumps(payload))
        package = self.parent / "package.json"
        sign_payload(source, self.private, package)
        import_package(package, self.store, trusted_key(self.key))
        evidence = feed_evidence(self.feed, self.state, self.root)
        self.assertEqual(evidence["feed_id"], "synthetic-feed")
        verify_feed_evidence(evidence, self.feed, self.state, self.root)
        newer = {**payload, "issued_at": (issued + timedelta(minutes=1)).isoformat()}
        source.write_text(json.dumps(newer))
        second = self.parent / "second-package.json"
        sign_payload(source, self.private, second)
        import_package(second, self.store, trusted_key(self.key))
        with self.assertRaisesRegex(VesselRuntimeError, "signed feed binding differs"):
            verify_feed_evidence(evidence, self.feed, self.state, self.root)


if __name__ == "__main__":
    unittest.main()
