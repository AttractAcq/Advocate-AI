"""Create a pinned offline ClamAV profile from an approved signature database."""

from __future__ import annotations

import argparse
from pathlib import Path

from scripts.phase3_policy_admin import _write_new
from services.knowledge.inspection import create_profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--database-as-of", required=True,
                        help="UTC timestamp from the approved database import record")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    _write_new(args.out, create_profile(args.scanner, args.database, args.database_as_of))


if __name__ == "__main__":
    main()
