"""Small provenance stamp for synthetic lab evidence records."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def stamp() -> dict[str, str | None]:
    source_bundle = ROOT / "build/sovereign-source.tar.gz"
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True, check=True).stdout.strip()
    return {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "source_bundle_sha256": hashlib.sha256(source_bundle.read_bytes()).hexdigest()
        if source_bundle.exists() else None,
        "fixture_manifest_sha256": hashlib.sha256((ROOT / "fixtures/manifest.csv").read_bytes()).hexdigest(),
    }
