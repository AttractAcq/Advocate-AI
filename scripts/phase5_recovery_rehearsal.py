"""Rehearse encrypted backup and clean restore with fictional app state."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time

from apps.api.auth import LabSessions
from infrastructure.backup import BackupError, create_backup, generate_key, inspect_backup
from services.knowledge.ingestion import sync_manifest
from services.knowledge.indexed_retrieval import search_index

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
PASSPHRASE = "synthetic-test-passphrase"
USER = "lab-chief_engineer-1"


def rehearse() -> dict[str, object]:
    source = FIXTURES / "sources/ENG-001.txt"
    if not source.is_file():
        raise RuntimeError("run make fixtures first")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="sovereign-recovery-") as temporary:
        root = Path(temporary)
        live = root / "live"
        (live / "sources").mkdir(parents=True)
        shutil.copyfile(FIXTURES / "roles.json", live / "roles.json")
        shutil.copyfile(source, live / "sources/ENG-001.txt")
        all_sources = json.loads((FIXTURES / "phase-3/approved-sources.json").read_text())["sources"]
        document = next(row for row in all_sources if row["document_id"] == "ENG-001")
        (live / "approved.json").write_text(json.dumps({"schema": 1, "sources": [document]}))
        sync_manifest(live, live / "approved.json", live / "knowledge.db")
        before = search_index(live, live / "approved.json", live / "knowledge.db", USER,
                              "generator inspection")
        if not before or before[0]["document_id"] != "ENG-001":
            raise RuntimeError("synthetic source did not index")
        sessions = LabSessions(live / "roles.json", PASSPHRASE, live / "history.db")
        if not sessions.login(USER, PASSPHRASE):
            raise RuntimeError("synthetic sign-in failed")
        conversation_id, _ = sessions.create_conversation(USER)
        sessions.add_turn(conversation_id, USER, {"message": "fictional generator inspection"})
        spec = root / "backup-spec.json"
        spec.write_text(json.dumps({"schema": 1, "files": [
            {"name": "roles.json", "kind": "file", "source": "live/roles.json"},
            {"name": "approved.json", "kind": "file", "source": "live/approved.json"},
            {"name": "knowledge.db", "kind": "sqlite", "source": "live/knowledge.db"},
            {"name": "history.db", "kind": "sqlite", "source": "live/history.db"},
        ]}))
        key = root / "backup.key"
        generate_key(key)
        backup = root / "synthetic.svb"
        manifest = create_backup(spec, backup, key)
        inspect_backup(backup, key)
        tampered = root / "tampered.svb"
        changed = bytearray(backup.read_bytes())
        changed[40] ^= 1
        tampered.write_bytes(changed)
        tamper_rejected = False
        try:
            inspect_backup(tampered, key, root / "invalid-restore")
        except BackupError:
            tamper_rejected = not (root / "invalid-restore").exists()
        if not tamper_rejected:
            raise RuntimeError("tampered backup was accepted")
        shutil.rmtree(live)
        restored = root / "restored"
        inspect_backup(backup, key, restored)
        (restored / "sources").mkdir()
        shutil.copyfile(source, restored / "sources/ENG-001.txt")  # Simulated separate NAS source.
        reopened = LabSessions(restored / "roles.json", PASSPHRASE, restored / "history.db")
        history_recovered = (bool(reopened.login(USER, PASSPHRASE))
                             and len(reopened.conversation(conversation_id, USER).turns) == 1)
        role_isolation = reopened.conversation(conversation_id, "lab-deckhand-1") is None
        hits = search_index(restored, restored / "approved.json", restored / "knowledge.db", USER,
                            "generator inspection")
        denied = search_index(restored, restored / "approved.json", restored / "knowledge.db",
                              "lab-deckhand-1", "generator inspection")
        retrieval_recovered = bool(hits) and hits[0]["document_id"] == "ENG-001" and denied == []
        if not (history_recovered and role_isolation and retrieval_recovered):
            raise RuntimeError("restored application state failed verification")
        return {
            "schema": 1, "mode": "synthetic-local", "result": "pass",
            "files_restored": len(manifest["files"]), "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
            "tamper_rejected": tamper_rejected, "history_recovered": history_recovered,
            "retrieval_recovered": retrieval_recovered, "role_isolation": role_isolation,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "limitations": "Local synthetic state and separate fictional source; no clean host, model, Keycloak, Wazuh, offline network or backup-media test",
        }


if __name__ == "__main__":
    print(json.dumps(rehearse(), indent=2, sort_keys=True))
