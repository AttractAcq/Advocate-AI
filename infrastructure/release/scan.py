"""Bind a pinned Trivy scan of a local image archive to its validated digest."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

from infrastructure.release.upstream import _binary, _run, _sha256, validate_image_archive

TRIVY_VERSION = "0.76.2"
MAX_DATABASE_AGE = timedelta(days=7)


class ScanError(ValueError):
    """The local scanner, database or scan report failed validation."""


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ScanError("missing scanner database timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScanError("invalid scanner database timestamp") from exc
    if result.tzinfo is None:
        raise ScanError("scanner database timestamp has no timezone")
    return result


def generate_archive_scan(archive: Path, image_ref: str, output: Path,
                          crane: Path, crane_sha256: str, trivy: Path,
                          trivy_sha256: str, cache: Path) -> dict[str, str]:
    """Scan the same verified tar with an existing offline vulnerability DB."""
    identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
    _binary(trivy, trivy_sha256)
    if not re.fullmatch(r"Version: " + re.escape(TRIVY_VERSION) + r"\s*",
                        _run([str(trivy), "--version"])):
        raise ScanError("unapproved Trivy version")
    if not cache.is_dir() or cache.is_symlink():
        raise ScanError("scanner cache is missing or linked")
    database = cache / "db" / "trivy.db"
    metadata_file = cache / "db" / "metadata.json"
    if ((cache / "db").is_symlink() or database.is_symlink() or not database.is_file() or
            metadata_file.is_symlink() or not metadata_file.is_file()):
        raise ScanError("offline vulnerability database is missing or linked")
    database_sha256 = _sha256(database)
    metadata_bytes = metadata_file.read_bytes()
    try:
        db_metadata = json.loads(metadata_bytes)
    except (OSError, ValueError) as exc:
        raise ScanError("invalid scanner database metadata") from exc
    if not isinstance(db_metadata, dict) or db_metadata.get("Version") != 2:
        raise ScanError("unsupported scanner database schema")
    now = datetime.now(timezone.utc)
    updated = _timestamp(db_metadata.get("UpdatedAt"))
    next_update = _timestamp(db_metadata.get("NextUpdate"))
    if (updated > now + timedelta(minutes=5) or now - updated > MAX_DATABASE_AGE or
            next_update <= now):
        raise ScanError("offline vulnerability database is stale")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ScanError("scan output must be a new file in an existing directory")
    raw_path = output.parent / (output.name + ".raw.tmp")
    if raw_path.exists() or raw_path.is_symlink():
        raise ScanError("temporary scan path already exists")
    try:
        _run([str(trivy), "image", "--input", str(archive), "--scanners", "vuln",
              "--format", "json", "--output", str(raw_path), "--cache-dir", str(cache),
              "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
              "--offline-scan", "--quiet"], timeout=600)
        try:
            report = json.loads(raw_path.read_text())
        except (OSError, ValueError) as exc:
            raise ScanError("invalid Trivy report") from exc
    finally:
        raw_path.unlink(missing_ok=True)
    if (not isinstance(report, dict) or report.get("SchemaVersion") != 2 or
            report.get("ArtifactType") != "container_image" or
            report.get("ArtifactName") != str(archive) or
            not isinstance(report.get("Trivy"), dict) or
            report["Trivy"].get("Version") != TRIVY_VERSION or
            not isinstance(report.get("Metadata"), dict) or
            not isinstance(report.get("Results"), list) or not report["Results"]):
        raise ScanError("Trivy did not scan the expected local image archive")
    if (_sha256(archive) != identity["archive_sha256"] or
            _sha256(database) != database_sha256 or
            metadata_file.read_bytes() != metadata_bytes):
        raise ScanError("image archive or vulnerability database changed during scan")
    scanned_at = _timestamp(report.get("CreatedAt"))
    if scanned_at < updated or scanned_at > next_update:
        raise ScanError("scanner database does not cover scan time")
    report["ArtifactName"] = image_ref
    report["Metadata"]["RepoDigests"] = [image_ref]
    report["Sovereign"] = {
        "Source": "offline-local-docker-archive", "ArchiveSHA256": identity["archive_sha256"],
        "ManifestDigest": identity["manifest_digest"],
        "ScannerBinarySHA256": trivy_sha256, "DatabaseSHA256": database_sha256,
        "DatabaseUpdatedAt": db_metadata["UpdatedAt"],
        "DatabaseNextUpdate": db_metadata["NextUpdate"],
    }
    output.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return {"image_ref": image_ref, "archive_sha256": identity["archive_sha256"],
            "scan_sha256": _sha256(output), "database_sha256": report["Sovereign"]["DatabaseSHA256"],
            "trivy_version": TRIVY_VERSION}


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a validated local image archive offline")
    for name in ("archive", "image-ref", "output", "crane", "crane-sha256",
                 "trivy", "trivy-sha256", "cache"):
        parser.add_argument("--" + name, required=True,
                            type=Path if name in {"archive", "output", "crane", "trivy", "cache"} else str)
    args = parser.parse_args()
    try:
        result = generate_archive_scan(args.archive, args.image_ref, args.output,
                                       args.crane, args.crane_sha256, args.trivy,
                                       args.trivy_sha256, args.cache)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"archive scan: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
