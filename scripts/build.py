#!/usr/bin/env python3
"""Build a deterministic source bundle from committed application inputs."""

from __future__ import annotations

import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/sovereign-source.tar.gz"
SKIP = {".git", "build", "runtime", "dist", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
INCLUDE = {".github", ".gitignore", "Makefile", "pyproject.toml", "uv.lock", "requirements.lock",
           "apps", "services", "infrastructure", "scripts", "tests", "fixtures"}


def source_files() -> list[Path]:
    if (ROOT / ".git").exists():
        listed = subprocess.run(["git", "ls-files", "-z", "--cached"], cwd=ROOT,
                                check=True, stdout=subprocess.PIPE).stdout
        candidates = (ROOT / os.fsdecode(name) for name in listed.split(b"\0") if name)
    else:
        # A source bundle has no Git metadata; it contains only selected inputs.
        candidates = ROOT.rglob("*")
    return sorted(
        p for p in candidates
        if p.is_file() and not p.is_symlink()
        and p.relative_to(ROOT).parts[0] in INCLUDE
        and not any(part in SKIP for part in p.relative_to(ROOT).parts)
        and p.relative_to(ROOT).parts[:2] != ("fixtures", "sources")
        and p.relative_to(ROOT).parts[:3] != ("fixtures", "phase-1", "artifacts")
        and p.name != ".DS_Store"
        and not p.name.endswith((".pyc", ".log", ".pem", ".key"))
    )


def build() -> str:
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for source in source_files():
                    if os.environ.get("SOVEREIGN_BUILD_DEBUG") == "1":
                        print(f"packing {source.relative_to(ROOT)}", file=sys.stderr, flush=True)
                    info = archive.gettarinfo(str(source), arcname=str(source.relative_to(ROOT)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    with source.open("rb") as stream:
                        archive.addfile(info, stream)
    return hashlib.sha256(OUT.read_bytes()).hexdigest()


if __name__ == "__main__":
    print(f"{OUT.relative_to(ROOT)} sha256={build()}")
