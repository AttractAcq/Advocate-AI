"""Import a verified product bundle into the company-side Fleet catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from infrastructure.release.bundle import MANIFEST, BundleError, verify_bundle
from services.fleet.catalog import FleetCatalog, FleetError, Release
from services.fleet.offline_import import key_id, load_import_key


def import_product_release(catalog: FleetCatalog, code: str, bundle: Path,
                           trusted_key: Path) -> dict[str, object]:
    """Record only schema-4 Core+Console bundles verified under the trust key."""
    trusted_id = key_id(load_import_key(trusted_key))
    before = (bundle / MANIFEST).read_bytes()
    manifest = verify_bundle(bundle, trusted_key)
    after = (bundle / MANIFEST).read_bytes()
    if before != after:
        raise FleetError("release manifest changed during import")
    if manifest.get("schema") != 4 or manifest.get("key_id") != trusted_id:
        raise FleetError("Fleet requires a trusted signed Core and Console product bundle")
    record = Release(code=code, version=manifest["version"],
                     manifest_sha256=hashlib.sha256(after).hexdigest(),
                     signing_key_id=trusted_id, status="candidate")
    return catalog.add_verified_release(record)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a signed product release into Fleet")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--code", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trusted-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = import_product_release(FleetCatalog(args.db), args.code,
                                        args.bundle, args.trusted_key)
    except (BundleError, FleetError, OSError, ValueError) as exc:
        parser.exit(1, f"release import rejected: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
