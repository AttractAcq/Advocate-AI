"""Synthetic PostgreSQL custom dump, encrypted restic storage and clean restore."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from infrastructure.restic_repository import create_snapshot, restore_snapshot


_IMAGE = re.compile(r"(?:docker.io/library/)?postgres@sha256:[0-9a-f]{64}\Z")
_EXPECTED = "1|synthetic-alpha\n2|synthetic-beta"


def _docker(*args: str, timeout: int = 60) -> str:
    try:
        result = subprocess.run(["docker", *args], check=True, capture_output=True,
                                text=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"synthetic PostgreSQL Docker operation failed: {args[0]}") from exc
    return result.stdout.strip()


def _ready(identifier: str) -> None:
    for _ in range(40):
        result = subprocess.run(["docker", "exec", "-u", "postgres", identifier,
                                 "pg_isready", "-q", "-d", "postgres"],
                                capture_output=True, timeout=10)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("synthetic PostgreSQL server did not become ready")


def _sql(identifier: str, statement: str) -> str:
    return _docker("exec", "-u", "postgres", identifier, "psql", "-X",
                   "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-Atqc", statement)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dump(identifier: str, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("dump destination must be new")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            result = subprocess.run(["docker", "exec", "-u", "postgres", identifier,
                                     "pg_dump", "-Fc", "--no-owner", "--no-acl",
                                     "-d", "postgres"], stdout=stream,
                                    stderr=subprocess.PIPE, timeout=120)
        if result.returncode or not 5 <= output.stat().st_size <= 16 * 1024 * 1024:
            raise RuntimeError("synthetic PostgreSQL dump failed or exceeded size limit")
        with output.open("rb") as stream:
            header = stream.read(5)
        if header != b"PGDMP":
            raise RuntimeError("synthetic PostgreSQL custom archive header missing")
    except Exception:
        output.unlink(missing_ok=True)
        raise


def _restore(identifier: str, archive: Path) -> None:
    if archive.is_symlink() or not archive.is_file() or not 5 <= archive.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("invalid restored PostgreSQL archive")
    if _sql(identifier, "SELECT count(*) FROM pg_tables WHERE schemaname='public'") != "0":
        raise RuntimeError("restore target is not clean")
    try:
        result = subprocess.run(["docker", "exec", "-i", "-u", "postgres", identifier,
                                 "pg_restore", "--single-transaction", "--no-owner",
                                 "--no-privileges", "-d", "postgres"],
                                input=archive.read_bytes(), capture_output=True,
                                timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("synthetic PostgreSQL restore failed") from exc
    if result.returncode:
        raise RuntimeError("synthetic PostgreSQL restore failed")


def rehearse(image: str, restic: Path, restic_sha256: str) -> dict[str, object]:
    if not _IMAGE.fullmatch(image):
        raise ValueError("PostgreSQL rehearsal requires an exact image digest")
    names = [f"sovereign-pg-{uuid.uuid4().hex[:12]}-{role}" for role in ("source", "restore")]
    created: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="sovereign-postgres-") as directory:
            root = Path(directory)
            for name in names:
                identifier = _docker("run", "-d", "--pull", "never", "--network", "none",
                                     "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                                     image, timeout=120)
                created.append(identifier)
                if (_docker("inspect", identifier, "--format", "{{.HostConfig.NetworkMode}}") != "none"
                        or _docker("inspect", identifier, "--format",
                                   "{{json .HostConfig.PortBindings}}") not in ("null", "{}")):
                    raise RuntimeError("synthetic PostgreSQL container has a network route")
                _ready(identifier)
            _sql(created[0], "CREATE TABLE app_state (id integer PRIMARY KEY, payload text NOT NULL)")
            _sql(created[0], "INSERT INTO app_state VALUES (1, 'synthetic-alpha'), (2, 'synthetic-beta')")
            if _sql(created[0], "SELECT id, payload FROM app_state ORDER BY id") != _EXPECTED:
                raise RuntimeError("source synthetic PostgreSQL rows mismatch")
            dump = root / "postgres.dump"
            _dump(created[0], dump)
            digest = _sha256(dump)
            spec = root / "snapshot-spec.json"
            spec.write_text(json.dumps({"schema": 1, "files": [
                {"name": "postgres.dump", "kind": "file", "source": "postgres.dump"}]}))
            password = root / "restic-password"
            password.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
            password.chmod(0o600)
            repository = root / "repository"
            snapshot = create_snapshot(spec, repository, password, restic,
                                       restic_sha256, root)
            dump.unlink()
            restored = root / "restored"
            restore_snapshot(snapshot["snapshot_id"], repository, password,
                             restic, restic_sha256, restored)
            archive = restored / "postgres.dump"
            if _sha256(archive) != digest:
                raise RuntimeError("encrypted snapshot changed PostgreSQL archive")
            _restore(created[1], archive)
            if _sql(created[1], "SELECT id, payload FROM app_state ORDER BY id") != _EXPECTED:
                raise RuntimeError("restored synthetic PostgreSQL rows mismatch")
            return {"result": "pass", "source": "synthetic-postgresql",
                    "image": image, "dump_sha256": digest,
                    "restic_snapshot_id": snapshot["snapshot_id"],
                    "restored_rows": 2, "network_mode": "none"}
    finally:
        for identifier in reversed(created):
            subprocess.run(["docker", "rm", "-f", identifier], capture_output=True,
                           text=True, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse synthetic PostgreSQL recovery")
    parser.add_argument("--image", required=True)
    parser.add_argument("--restic", required=True, type=Path)
    parser.add_argument("--restic-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.image, args.restic, args.restic_sha256),
                     sort_keys=True))


if __name__ == "__main__":
    main()
