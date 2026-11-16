"""Run bounded local health checks without printing endpoints or payloads."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from infrastructure.diagnostics import DiagnosticConfigError, diagnose
from infrastructure.lab.pki import CA

ROOT = Path(__file__).resolve().parents[1]


def lab_config() -> dict[str, object]:
    topology = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())
    if topology["bind"] != "127.0.0.1":
        raise DiagnosticConfigError("lab must bind to loopback")
    return {
        "schema": 1, "mode": "synthetic-loopback", "allowed_cidrs": ["127.0.0.0/8"],
        "checks": [
            {"name": name.replace("-", "_"), "kind": "https",
             "url": f"https://127.0.0.1:{port}/health", "ca_file": str(CA),
             "expected_service": name}
            for name, port in topology["services"].items()
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Metadata-only local health report")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--lab", action="store_true", help="probe the synthetic loopback services")
    source.add_argument("--config", type=Path, help="JSON configuration for local endpoints")
    args = parser.parse_args()
    try:
        config = lab_config() if args.lab else json.loads(args.config.read_text())
        base = ROOT if args.lab else args.config.parent.resolve()
        result = diagnose(config, base)
    except (DiagnosticConfigError, OSError, ValueError, KeyError) as exc:
        print(f"diagnostics: invalid configuration ({type(exc).__name__})", file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["all_ok"] else 1)


if __name__ == "__main__":
    main()
