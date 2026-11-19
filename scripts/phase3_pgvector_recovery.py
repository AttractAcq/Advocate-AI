"""Encrypted clean restore of one synthetic pgvector knowledge recovery set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from infrastructure.restic_repository import create_snapshot, restore_snapshot
from scripts.phase5_postgres_rehearsal import _docker, _dump, _ready, _restore, _sql
from services.knowledge.embedding import build_vectors, vector_search
from services.knowledge.ingestion import sync_manifest
from services.knowledge.indexed_retrieval import search_index
from services.knowledge.manifest_io import load_manifest, read_manifest_bytes
from services.knowledge.paths import read_source_bytes
from services.knowledge.postgres_index import (_connect, initialize_schema,
                                               verify_knowledge_snapshot)
from services.policy.policy_file import policy_directory_lock, read_policy_bytes

_IMAGE = re.compile(r"(?:docker.io/)?pgvector/pgvector@sha256:[0-9a-f]{64}\Z")
_PORT = re.compile(r"127\.0\.0\.1:([0-9]{2,5})\Z")
_LOCK = 153352001


class SyntheticEmbedder:
    model = "synthetic-pgvector-recovery"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float("generator" in text.casefold()),
                 float("deck" in text.casefold())] for text in texts]


def _put(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


def _fixture(root: Path) -> Path:
    rows = []
    for identifier, collection, body in (
            ("ENG-001", "engineering", "generator inspection secret marker"),
            ("DEC-001", "deck", "deck line inspection marker")):
        relative = f"sources/{identifier}.txt"
        payload = body.encode()
        _put(root / relative, payload)
        rows.append({"document_id": identifier, "relative_path": relative,
                     "collection": collection,
                     "classification": f"C0_SYNTHETIC_{collection.upper()}",
                     "owner": "lab", "version": "1", "sha256": hashlib.sha256(payload).hexdigest(),
                     "source_type": "synthetic-local"})
    policy = {"users": [{"id": "engineer", "role": "chief_engineer", "status": "active"},
                        {"id": "deckhand", "role": "deckhand", "status": "active"}],
              "allow": {"chief_engineer": ["engineering", "deck"], "deckhand": ["deck"]},
              "document_rules": {}}
    _put(root / "roles.json", json.dumps(policy).encode())
    manifest = root / "approved.json"
    _put(manifest, json.dumps({"schema": 1, "sources": rows}).encode())
    return manifest


def _freeze(root: Path, destination: Path, manifest: Path) -> list[str]:
    """Copy only approved source bytes and the matching policy/manifest."""
    listed = load_manifest(manifest)["sources"]
    names = ["approved.json", "roles.json"]
    _put(destination / "approved.json", read_manifest_bytes(manifest))
    _put(destination / "roles.json", read_policy_bytes(root / "roles.json"))
    for item in listed:
        relative = item["relative_path"]
        payload = read_source_bytes(root, relative, 8 * 1024 * 1024)
        if hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise ValueError("approved source changed during freeze")
        _put(destination / relative, payload)
        names.append(relative)
    return names


def _container(image: str, name: str) -> tuple[str, str]:
    identifier = _docker("run", "-d", "--rm", "--pull", "never", "--name", name,
                         "--tmpfs", "/var/lib/postgresql/data",
                         "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                         "-p", "127.0.0.1::5432", image, timeout=120)
    try:
        _ready(identifier)
        binding = _docker("port", identifier, "5432/tcp")
        match = _PORT.fullmatch(binding)
        if match is None:
            raise RuntimeError("synthetic pgvector port must bind loopback only")
        return identifier, f"postgresql://postgres@127.0.0.1:{match.group(1)}/postgres"
    except Exception:
        subprocess.run(["docker", "rm", "-f", identifier], capture_output=True,
                       text=True, timeout=30)
        raise


def rehearse(image: str, restic: Path, restic_sha256: str) -> dict[str, object]:
    if not _IMAGE.fullmatch(image):
        raise ValueError("pgvector recovery requires an exact image digest")
    created: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="sovereign-pgvector-recovery-") as directory:
            root = Path(directory)
            source, source_dsn = _container(image, f"sovereign-knowledge-source-{uuid.uuid4().hex[:12]}")
            created.append(source)
            restored_db, restored_dsn = _container(image, f"sovereign-knowledge-restore-{uuid.uuid4().hex[:12]}")
            created.append(restored_db)
            live = root / "live"
            live.mkdir(mode=0o700)
            manifest = _fixture(live)
            _sql(source, "CREATE EXTENSION vector")
            initialize_schema(source_dsn)
            indexed = sync_manifest(live, manifest, source_dsn)
            if indexed["indexed"] != ["ENG-001", "DEC-001"]:
                raise RuntimeError("synthetic knowledge ingestion mismatch")
            if build_vectors(source_dsn, SyntheticEmbedder()) != 2:
                raise RuntimeError("synthetic pgvector embedding mismatch")
            before = verify_knowledge_snapshot(live, manifest, source_dsn,
                                               expected_model=SyntheticEmbedder.model)
            frozen = root / "frozen"
            frozen.mkdir(mode=0o700)
            with policy_directory_lock(live / "roles.json", exclusive=False):
                with _connect(source_dsn) as db:
                    db.execute("SELECT pg_advisory_lock(%s)", (_LOCK,))
                    try:
                        names = _freeze(live, frozen, manifest)
                        verify_knowledge_snapshot(frozen, frozen / "approved.json", source_dsn,
                                                  expected_model=SyntheticEmbedder.model)
                        _dump(source, frozen / "postgres.dump")
                        verify_knowledge_snapshot(frozen, frozen / "approved.json", source_dsn,
                                                  expected_model=SyntheticEmbedder.model)
                    finally:
                        db.execute("SELECT pg_advisory_unlock(%s)", (_LOCK,))
            if read_manifest_bytes(manifest) != (frozen / "approved.json").read_bytes():
                raise RuntimeError("approved manifest changed during capture")
            names.append("postgres.dump")
            spec = frozen / "snapshot-spec.json"
            spec.write_text(json.dumps({"schema": 1, "files": [
                {"name": name, "kind": "file", "source": name} for name in names]}))
            password = root / "restic-password"
            _put(password, os.urandom(48).hex().encode())
            repository = root / "repository"
            snapshot = create_snapshot(spec, repository, password, restic, restic_sha256, root)
            dump_digest = hashlib.sha256((frozen / "postgres.dump").read_bytes()).hexdigest()
            (frozen / "postgres.dump").unlink()
            recovered = root / "recovered"
            restore_snapshot(snapshot["snapshot_id"], repository, password,
                             restic, restic_sha256, recovered)
            archive = recovered / "postgres.dump"
            if hashlib.sha256(archive.read_bytes()).hexdigest() != dump_digest:
                raise RuntimeError("restored PostgreSQL dump changed")
            _restore(restored_db, archive)
            after = verify_knowledge_snapshot(recovered, recovered / "approved.json", restored_dsn,
                                              expected_model=SyntheticEmbedder.model)
            if before != after or before != {"sources": 2, "passages": 2}:
                raise RuntimeError("restored knowledge set mismatch")
            engineer = search_index(recovered, recovered / "approved.json", restored_dsn,
                                    "engineer", "generator inspection")
            deckhand = search_index(recovered, recovered / "approved.json", restored_dsn,
                                    "deckhand", "generator inspection")
            vector = vector_search(recovered, recovered / "approved.json", restored_dsn,
                                   "engineer", "generator", SyntheticEmbedder())
            if ([row["document_id"] for row in engineer] != ["ENG-001"] or deckhand
                    or [row["document_id"] for row in vector] != ["ENG-001"]):
                raise RuntimeError("restored permission or vector result mismatch")
            policy = json.loads((recovered / "roles.json").read_text())
            policy["document_rules"] = {"ENG-001": {"deny_users": ["engineer"]}}
            (recovered / "roles.json").write_text(json.dumps(policy))
            if search_index(recovered, recovered / "approved.json", restored_dsn,
                            "engineer", "generator inspection"):
                raise RuntimeError("restored policy revocation failed")
            return {"result": "pass", "image": image, "snapshot_id": snapshot["snapshot_id"],
                    "dump_sha256": dump_digest, "sources": after["sources"],
                    "passages": after["passages"], "revocation": "denied",
                    "host_binding": "loopback"}
    finally:
        for identifier in reversed(created):
            subprocess.run(["docker", "rm", "-f", identifier], capture_output=True,
                           text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--restic", required=True, type=Path)
    parser.add_argument("--restic-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.image, args.restic, args.restic_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
