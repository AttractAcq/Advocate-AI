"""Restore fictional Core state through restic and exercise an isolated container."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from apps.api.auth import LabSessions
from infrastructure.restic_repository import create_snapshot, restore_snapshot


ROOT = Path(__file__).resolve().parents[1]
USER = "lab-chief_engineer-1"
DENIED_USER = "lab-deckhand-1"
PASSPHRASE = "synthetic-restored-state-passphrase"
_PROBE = r'''
import json, sys, urllib.error, urllib.request
base = "http://127.0.0.1:18100"
conversation_id, phase = sys.argv[1:3]
password = open("/run/secrets/lab-password", encoding="utf-8").read().strip()
def login(user):
    body = json.dumps({"user_id": user, "password": password}).encode()
    request = urllib.request.Request(base + "/api/login", data=body,
                                     headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(request, timeout=5))["access_token"]
def get(path, token):
    request = urllib.request.Request(base + path,
                                     headers={"Authorization": "Bearer " + token})
    return json.load(urllib.request.urlopen(request, timeout=5))
chief = login("lab-chief_engineer-1")
deck = login("lab-deckhand-1")
sources = get("/api/sources", chief)["sources"]
history = get("/api/conversations/" + conversation_id, chief)["turns"]
deck_sources = get("/api/sources", deck)["sources"]
try:
    get("/api/conversations/" + conversation_id, deck)
except urllib.error.HTTPError as exc:
    assert exc.code == 404
else:
    raise AssertionError("cross-user history was disclosed")
assert deck_sources == []
assert len(history) == 1
if phase == "before":
    assert [item["document_id"] for item in sources] == ["ENG-001"]
    assert history[0]["answer"] == "Synthetic recovered answer"
    assert history[0]["citations"][0]["document_id"] == "ENG-001"
else:
    assert phase == "after" and sources == []
    assert history[0]["mode"] == "redacted" and history[0]["citations"] == []
print(json.dumps({"phase": phase, "sources": len(sources),
                  "history_turns": len(history), "cross_user_denied": True}))
'''


def _docker(*args: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(["docker", *args], check=True, capture_output=True,
                                text=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Core state Docker operation failed: {args[0]}") from exc
    return result.stdout.strip()


def _probe(container: str, conversation_id: str, phase: str) -> dict[str, object]:
    raw = _docker("exec", container, "python", "-c", _PROBE, conversation_id, phase)
    value = json.loads(raw)
    if value != {"phase": phase, "sources": 1 if phase == "before" else 0,
                  "history_turns": 1, "cross_user_denied": True}:
        raise RuntimeError("restored Core API result mismatch")
    return value


def prepare_synthetic_state(live: Path) -> str:
    """Create fictional policy, source and cited history for runtime rehearsals."""
    source = ROOT / "fixtures/sources/ENG-001.txt"
    if not source.is_file():
        raise RuntimeError("generate synthetic fixtures before Core restore rehearsal")
    (live / "sources").mkdir(parents=True)
    live.chmod(0o700)
    shutil.copyfile(ROOT / "fixtures/roles.json", live / "roles.json")
    shutil.copyfile(source, live / "sources/ENG-001.txt")
    with (ROOT / "fixtures/manifest.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    row = next(item for item in rows if item["document_id"] == "ENG-001")
    with (live / "manifest.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    if hashlib.sha256(source.read_bytes()).hexdigest() != row["sha256"]:
        raise RuntimeError("synthetic source manifest hash mismatch")
    sessions = LabSessions(live / "roles.json", PASSPHRASE, live / "history.db")
    conversation_id, _ = sessions.create_conversation(USER)
    sessions.add_turn(conversation_id, USER, {"message": "fictional generator inspection",
        "answer": "Synthetic recovered answer", "mode": "documents",
        "citations": [{"document_id": "ENG-001", "sha256": row["sha256"],
                       "version": row["version"], "ordinal": 0}]})
    return conversation_id


def restore_synthetic_state(root: Path, restic: Path,
                            restic_sha256: str) -> tuple[Path, str, str]:
    """Delete fictional live state and clean-restore its checked restic snapshot."""
    live = root / "live"
    conversation_id = prepare_synthetic_state(live)
    spec = root / "spec.json"
    spec.write_text(json.dumps({"schema": 1, "files": [
        {"name": "roles.json", "kind": "file", "source": "live/roles.json"},
        {"name": "manifest.csv", "kind": "file", "source": "live/manifest.csv"},
        {"name": "sources/ENG-001.txt", "kind": "file", "source": "live/sources/ENG-001.txt"},
        {"name": "history.db", "kind": "sqlite", "source": "live/history.db"}]}))
    password = root / "restic-password"
    password.write_text(os.urandom(32).hex())
    password.chmod(0o600)
    stage = root / "staging"
    stage.mkdir(mode=0o700)
    repository = root / "repository"
    saved = create_snapshot(spec, repository, password, restic, restic_sha256, stage)
    shutil.rmtree(live)
    restored = root / "restored"
    restore_snapshot(saved["snapshot_id"], repository, password, restic,
                     restic_sha256, restored)
    return restored, conversation_id, str(saved["snapshot_id"])


def rehearse(image: str, restic: Path, restic_sha256: str) -> dict[str, object]:
    if os.getuid() == 0:
        raise ValueError("synthetic Core restore must run as a non-root user")
    image_id = _docker("image", "inspect", image, "--format", "{{.Id}}")
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise RuntimeError("synthetic Core image ID is invalid")
    container = ""
    with tempfile.TemporaryDirectory(prefix="sovereign-core-restored-") as directory:
        root = Path(directory)
        restored, conversation_id, snapshot_id = restore_synthetic_state(
            root, restic, restic_sha256)
        credential = root / "lab-password"
        credential.write_text(PASSPHRASE + "\n")
        credential.chmod(0o600)
        try:
            container = _docker("run", "-d", "--pull", "never", "--network", "none",
                "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--mount", f"type=bind,source={restored},target=/var/lib/sovereign",
                "--mount", f"type=bind,source={credential},target=/run/secrets/lab-password,readonly",
                "-e", "SOVEREIGN_FIXTURE_ROOT=/var/lib/sovereign",
                "-e", "SOVEREIGN_HISTORY_DB=/var/lib/sovereign/history.db",
                "-e", "SOVEREIGN_LAB_PASSWORD_FILE=/run/secrets/lab-password",
                image_id)
            if (_docker("inspect", container, "--format", "{{.HostConfig.NetworkMode}}") != "none"
                    or _docker("inspect", container, "--format",
                               "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
                raise RuntimeError("restored Core container has a network route")
            for attempt in range(30):
                try:
                    _docker("exec", container, "python", "-c",
                            'import urllib.request; assert urllib.request.urlopen('
                            '"http://127.0.0.1:18100/health", timeout=2).status == 200')
                    break
                except RuntimeError:
                    if attempt == 29:
                        raise
                    time.sleep(1)
            before = _probe(container, conversation_id, "before")
            roles = json.loads((restored / "roles.json").read_text())
            roles["allow"]["chief_engineer"] = ["deck"]
            (restored / "roles.json").write_text(json.dumps(roles))
            after = _probe(container, conversation_id, "after")
            return {"status": "pass", "image_id": image_id,
                    "snapshot_id": snapshot_id, "restored_files": 4,
                    "network_mode": "none", "before": before, "after": after}
        finally:
            if container:
                subprocess.run(["docker", "rm", "-f", container], capture_output=True,
                               text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse restored Core state in Docker")
    parser.add_argument("--image", required=True)
    parser.add_argument("--restic", required=True, type=Path)
    parser.add_argument("--restic-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.image, args.restic, args.restic_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
