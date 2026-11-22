"""Poll the approved synthetic manifest and reconcile its local index."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import time

from services.knowledge.reconcile import ManifestReconciler

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--full-scan-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 5 <= args.poll_seconds <= 300:
        parser.error("poll interval must be 5–300 seconds")
    location = os.environ.get("SOVEREIGN_KNOWLEDGE_DB")
    database = location if location and location.startswith("postgresql://") else (
        Path(location) if location else ROOT / "infrastructure/lab/runtime/phase3-knowledge/index.sqlite3")
    reconciler = ManifestReconciler(
        ROOT / "fixtures", ROOT / "fixtures/phase-3/approved-sources.json",
        database,
        full_scan_seconds=args.full_scan_seconds)
    while True:
        try:
            result = reconciler.poll()
        except (OSError, ValueError, RuntimeError, ImportError, UnicodeError,
                sqlite3.Error) as exc:
            print(json.dumps({"status": "error", "error_type": type(exc).__name__}), flush=True)
            if args.once:
                return 1
        else:
            if result is not None:
                print(json.dumps({"status": "reconciled", **{
                    key: len(value) for key, value in result.items() if isinstance(value, list)}}), flush=True)
            if args.once:
                return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
