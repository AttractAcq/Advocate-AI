"""Local-only signed threat snapshot preparation and import."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from services.intelligence.threat_snapshot import (ThreatSnapshotError, ThreatSnapshotReader,
                                                   import_package, sign_payload, trusted_key)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare or inspect an offline threat snapshot")
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--payload", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    load = commands.add_parser("import")
    load.add_argument("--package", type=Path, required=True)
    load.add_argument("--store", type=Path, required=True)
    load.add_argument("--trusted-key", type=Path, required=True)
    inspect = commands.add_parser("status")
    inspect.add_argument("--store", type=Path, required=True)
    inspect.add_argument("--trusted-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "sign":
            sign_payload(args.payload, args.private_key, args.output)
            result: dict[str, object] = {"status": "signed", "output": str(args.output)}
        elif args.command == "import":
            result = import_package(args.package, args.store, trusted_key(args.trusted_key))
        else:
            result = ThreatSnapshotReader(args.store, args.trusted_key).status()
    except (OSError, ThreatSnapshotError) as exc:
        parser.exit(1, f"threat snapshot: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
