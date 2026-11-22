"""Recheck downloaded synthetic release evidence against a recorded result hash.

This checks artifact consistency and reported outcomes. The downloaded folder
contains no signed bundle or image archives, so it cannot prove their identity
or approve deployment independently of the CI run and release procedure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from infrastructure.release.intake import IntakeError, verify_intake

HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_RESULT_BYTES = 1024 * 1024


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate release result key")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise ValueError("non-finite release result value")


def read_result(path: Path, expected_sha256: str) -> dict[str, object]:
    if not HASH.fullmatch(expected_sha256):
        raise ValueError("invalid expected result hash")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                not 0 < info.st_size <= MAX_RESULT_BYTES):
            raise ValueError("unsafe release result file")
        raw = stream.read(MAX_RESULT_BYTES + 1)
    if len(raw) > MAX_RESULT_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("release result hash mismatch")
    result = json.loads(raw, object_pairs_hook=_unique_object,
                        parse_constant=_invalid_constant)
    if not isinstance(result, dict):
        raise ValueError("release result must be an object")
    return result


def verify(directory: Path, expected_sha256: str) -> dict[str, object]:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("release evidence directory is unavailable")
    result = read_result(directory / "result.json", expected_sha256)
    if (result.get("source") != "locally-built-synthetic-vessel-images" or
            result.get("three_image_bundle") != "signed-and-verified"):
        raise ValueError("release result does not report a verified synthetic bundle")
    required_passes = ("signed_vessel_first_install", "signed_vessel_clean_restore",
                       "signed_vessel_updated_restore", "signed_vessel_oidc",
                       "signed_vessel_keycloak_pair", "feed_bound_clean_restore")
    for name in required_passes:
        row = result.get(name)
        if not isinstance(row, dict) or row.get("result") != "pass":
            raise ValueError(f"release result lacks passing {name}")
    feed = result["feed_bound_clean_restore"]
    if (feed.get("feed_status") != "stale" or
            feed.get("indicator_values") != "withheld" or
            feed.get("restore") != "signed-and-healthy"):
        raise ValueError("feed-bound clean restore evidence is incomplete")
    images = result.get("images")
    if not isinstance(images, dict) or set(images) != {"core", "console", "knowledge"}:
        raise ValueError("release result has an incomplete image set")
    checked = {}
    for name in ("core", "console", "knowledge", "updated-core"):
        entry = (result.get("updated_core_image") if name == "updated-core"
                 else images[name])
        if not isinstance(entry, dict) or entry.get("intake") != "preflight-pass" or \
                type(entry.get("unresolved_findings")) is not int or \
                entry["unresolved_findings"] != 0:
            raise ValueError(f"{name} image intake is incomplete")
        folder = directory / "updated-core" if name == "updated-core" else directory
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError(f"{name} evidence directory is unavailable")
        prefix = "core" if name == "updated-core" else name
        intake = verify_intake(folder / f"{prefix}-scan.json",
                               folder / f"{prefix}-sbom.json", entry.get("image_ref"),
                               entry.get("scan_sha256"), entry.get("sbom_sha256"))
        if (intake.get("components") != entry.get("components") or
                intake.get("archive_sha256") != entry.get("archive_sha256")):
            raise ValueError(f"{name} image inventory disagrees with result")
        checked[name] = {"image_ref": entry["image_ref"],
                         "scan_sha256": entry["scan_sha256"],
                         "sbom_sha256": entry["sbom_sha256"]}
    return {"status": "artifact-consistency-pass", "result_sha256": expected_sha256,
            "reported_bundle": result["three_image_bundle"],
            "reported_recovery_checks": list(required_passes), "images": checked,
            "scope": "downloaded synthetic evidence only; no bundle signature or archive recheck"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--result-sha256", required=True)
    args = parser.parse_args()
    try:
        report = verify(args.directory, args.result_sha256)
    except (OSError, ValueError, IntakeError, TypeError) as exc:
        parser.exit(1, f"release artifact evidence: {exc}\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
