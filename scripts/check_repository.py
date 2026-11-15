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
from xml.etree import ElementTree
from zipfile import ZipFile

from services.connectors.events import normalise_event

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
    assert topology["dns"]["port"] not in topology["services"].values()
    assert all(name.endswith(".lab.sovereign.test") and address == "127.0.0.1"
               for name, address in topology["dns"]["names"].items())
    with (ROOT / "fixtures/manifest.csv").open() as stream:
        manifest = list(csv.DictReader(stream))
    assert len(manifest) >= 100
    def verify_source(item: dict[str, str]) -> bool:
        source = (ROOT / "fixtures" / item["relative_path"]).resolve()
        assert source.is_relative_to((ROOT / "fixtures").resolve())
        return hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert all(pool.map(verify_source, manifest))
    phase1 = ROOT / "fixtures/phase-1"
    artifact_manifest = json.loads((phase1 / "manifest.json").read_text())
    records = artifact_manifest["files"]
    assert artifact_manifest["schema"] == 1 and len(records) == 12
    assert {item["collection"] for item in records} >= {
        "management", "engineering", "interior", "deck", "restricted"
    }
    expected = {item["expected"] for item in records}
    assert expected >= {
        "accept-and-classify", "detect-duplicate", "quarantine",
        "ignore-instructions", "reject-by-declared-limit"
    }
    def verify_artifact(item: dict[str, str]) -> bool:
        artifact = (phase1 / item["path"]).resolve()
        assert artifact.is_relative_to(phase1.resolve())
        content = artifact.read_bytes()
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            return False
        if item["expected"] != "accept-and-classify":
            if item["expected"] == "quarantine":
                return not content.rstrip().endswith(b"%%EOF")
            return True
        if artifact.suffix == ".pdf":
            assert content.startswith(b"%PDF-") and content.rstrip().endswith(b"%%EOF")
            assert b"startxref" in content
        elif artifact.suffix in {".docx", ".xlsx"}:
            with ZipFile(artifact) as container:
                assert container.testzip() is None
                main_part = "word/document.xml" if artifact.suffix == ".docx" else "xl/workbook.xml"
                ElementTree.fromstring(container.read(main_part))
        return True
    with ThreadPoolExecutor(max_workers=12) as pool:
        assert all(pool.map(verify_artifact, records))
    hashes = {item["path"]: item["sha256"] for item in records}
    assert hashes["artifacts/ENG-P2.docx"] == hashes["artifacts/ENG-P2-duplicate.docx"]
    cases = json.loads((phase1 / "cases.json").read_text())
    assert cases["revoked_user"]["expected"] == "deny"
    assert cases["acl_reversal"]["expected"] == "deny-after-change"
    events = [normalise_event(json.loads(line))
              for line in (phase1 / "events.jsonl").read_text().splitlines()]
    assert len(events) >= 4 and len({item["event_id"] for item in events}) == len(events)
    assert any(item["asset_id"] is None for item in events)
    assert any(item["asset_id"] == "AMBIGUOUS-LAB-IP" for item in events)
    def verify_links(doc: Path) -> bool:
        for raw in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            target = unquote(raw.strip("<>"))
            if target.startswith(("http:", "https:", "#", "mailto:")):
                continue
            assert (doc.parent / target.split("#", 1)[0]).exists(), (doc, target)
        return True
    docs = (doc for doc in ROOT.rglob("*.md")
            if not any(part in {".venv", "node_modules", "build", "dist", ".git"}
                       for part in doc.relative_to(ROOT).parts))
    with ThreadPoolExecutor(max_workers=12) as pool:
        assert all(pool.map(verify_links, docs))
    print(f"Repository checks passed; {len(manifest)} sources, "
          f"{len(records)} mixed-format cases and {len(events)} events verified")


if __name__ == "__main__":
    check()
