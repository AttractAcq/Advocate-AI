"""Provision and fill the synthetic local PostgreSQL/pgvector knowledge index."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from services.knowledge.embedding import LocalEmbedder, build_vectors
from services.knowledge.ingestion import sync_manifest
from services.knowledge.postgres_index import initialize_schema, migrate_unversioned_schema

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "sync", "vectors", "migrate-legacy"))
    args = parser.parse_args()
    dsn = os.environ.get("SOVEREIGN_KNOWLEDGE_DB", "")
    if not dsn.startswith("postgresql://"):
        parser.error("SOVEREIGN_KNOWLEDGE_DB must be a local PostgreSQL URI")
    if args.action == "init":
        initialize_schema(dsn)
        print(json.dumps({"status": "schema-ready"}))
    elif args.action == "migrate-legacy":
        result = migrate_unversioned_schema(
            ROOT / "fixtures", ROOT / "fixtures/phase-3/approved-sources.json", dsn)
        print(json.dumps({"status": "legacy-schema-ledgered", **result}))
    elif args.action == "sync":
        result = sync_manifest(ROOT / "fixtures", ROOT / "fixtures/phase-3/approved-sources.json", dsn)
        print(json.dumps({"status": "reconciled", **{key: len(value) for key, value in result.items()}}))
    else:
        count = build_vectors(dsn, LocalEmbedder())
        print(json.dumps({"status": "embedded", "count": count}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
