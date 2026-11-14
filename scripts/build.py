#!/usr/bin/env python3
"""Build a deterministic Phase 1 source bundle without external dependencies."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/sovereign-phase1-skeleton.tar.gz"
SKIP = {".git", "build", "__pycache__", ".venv", "node_modules", ".pytest_cache"}


def source_files() -> list[Path]:
    return sorted(
        p for p in ROOT.rglob("*")
        if p.is_file() and not p.is_symlink()
        and not any(part in SKIP for part in p.relative_to(ROOT).parts)
        and p.relative_to(ROOT).parts[:2] != ("fixtures", "sources")
        and p.relative_to(ROOT).parts[:3] != ("fixtures", "phase-1", "artifacts")
        and not p.name.endswith((".pyc", ".log", ".pem", ".key"))
    )


def build() -> str:
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for source in source_files():
                    info = archive.gettarinfo(str(source), arcname=str(source.relative_to(ROOT)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    with source.open("rb") as stream:
                        archive.addfile(info, stream)
    return hashlib.sha256(OUT.read_bytes()).hexdigest()


if __name__ == "__main__":
    print(f"{OUT.relative_to(ROOT)} sha256={build()}")
