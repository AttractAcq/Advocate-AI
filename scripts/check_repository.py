#!/usr/bin/env python3
"""Check Phase 1 repository invariants and synthetic fixture integrity."""

from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]


def check() -> None:
    required = [
        "apps/console", "apps/api", "services/knowledge", "services/policy",
        "services/intelligence", "services/connectors", "infrastructure/lab",
        "infrastructure/release", "tests", "docs", "fixtures",
    ]
    assert all((ROOT / path).is_dir() for path in required)
    topology = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())
    assert topology["bind"] == "127.0.0.1"
    assert len(set(topology["services"].values())) == len(topology["services"])
    assert all(1024 < port < 65536 for port in topology["services"].values())
    with (ROOT / "fixtures/manifest.csv").open() as stream:
        manifest = list(csv.DictReader(stream))
    assert len(manifest) >= 100
    def verify_source(item: dict[str, str]) -> bool:
        source = (ROOT / "fixtures" / item["relative_path"]).resolve()
        assert source.is_relative_to((ROOT / "fixtures").resolve())
        return hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert all(pool.map(verify_source, manifest))
    for doc in ROOT.rglob("*.md"):
        for raw in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            target = unquote(raw.strip("<>"))
            if target.startswith(("http:", "https:", "#", "mailto:")):
                continue
            assert (doc.parent / target.split("#", 1)[0]).exists(), (doc, target)
    print(f"Repository checks passed; {len(manifest)} synthetic sources verified")


if __name__ == "__main__":
    check()
