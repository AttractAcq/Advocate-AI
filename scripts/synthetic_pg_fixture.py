"""Private two-source fixture for disposable PostgreSQL knowledge rehearsals."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def put(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


def fixture(root: Path) -> Path:
    rows = []
    for identifier, collection, body in (
            ("ENG-001", "engineering", "generator inspection secret marker"),
            ("DEC-001", "deck", "deck line inspection marker")):
        relative = f"sources/{identifier}.txt"
        payload = body.encode()
        put(root / relative, payload)
        rows.append({"document_id": identifier, "relative_path": relative,
                     "collection": collection,
                     "classification": f"C0_SYNTHETIC_{collection.upper()}",
                     "owner": "lab", "version": "1", "sha256": hashlib.sha256(payload).hexdigest(),
                     "source_type": "synthetic-local"})
    policy = {"users": [{"id": "engineer", "role": "chief_engineer", "status": "active"},
                        {"id": "deckhand", "role": "deckhand", "status": "active"},
                        {"id": "avit", "role": "avit_admin", "status": "active"}],
              "allow": {"chief_engineer": ["engineering", "deck"], "deckhand": ["deck"],
                        "avit_admin": []},
              "document_rules": {}}
    put(root / "roles.json", json.dumps(policy).encode())
    manifest = root / "approved.json"
    put(manifest, json.dumps({"schema": 1, "sources": rows}).encode())
    return manifest
