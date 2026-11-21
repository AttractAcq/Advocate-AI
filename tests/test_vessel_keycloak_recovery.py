"""Check the vessel realm archive boundary without Docker."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from infrastructure.backup import BackupError, generate_key
from scripts.phase3_vessel_keycloak_rehearsal import _backup_realm, _checked_restore


class VesselKeycloakArchiveTests(unittest.TestCase):
    def test_current_export_restores_and_stale_or_altered_export_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "backup.key"
            generate_key(key)
            source = root / "sovereign-realm.json"
            source.write_text(json.dumps({"realm": "sovereign", "users": [
                {"username": "synthetic-engineer"}]}))
            stale = root / "stale.svbk"
            _backup_realm(source, root, stale, key)
            source.write_text(json.dumps({"realm": "sovereign", "users": [
                {"username": "synthetic-engineer", "id": "current"}]}))
            current = root / "current.svbk"
            digest = _backup_realm(source, root, current, key)
            with self.assertRaises(BackupError):
                _checked_restore(stale, key, root / "stale-restore", digest)
            altered = root / "altered.svbk"
            payload = bytearray(current.read_bytes())
            payload[len(payload) // 2] ^= 1
            altered.write_bytes(payload)
            with self.assertRaises(BackupError):
                _checked_restore(altered, key, root / "altered-restore",
                                 hashlib.sha256(payload).hexdigest())
            restored = root / "restored"
            _checked_restore(current, key, restored, digest)
            self.assertEqual(json.loads((restored / "sovereign-realm.json").read_text()),
                             json.loads(source.read_text()))

    def test_wrong_realm_is_denied_after_authenticated_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "backup.key"
            generate_key(key)
            source = root / "sovereign-realm.json"
            source.write_text(json.dumps({"realm": "other", "users": [
                {"username": "synthetic-engineer"}]}))
            archive = root / "wrong-realm.svbk"
            digest = _backup_realm(source, root, archive, key)
            with self.assertRaises(BackupError):
                _checked_restore(archive, key, root / "wrong-realm-restore", digest)


if __name__ == "__main__":
    unittest.main()
