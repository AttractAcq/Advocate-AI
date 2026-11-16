"""Fail-closed, offline preflight for a proposed container release.

This validates reviewer-supplied evidence files. It does not establish their
provenance or approve a vessel deployment.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

MAX_EVIDENCE_BYTES = 20 * 1024 * 1024
MAX_AGE = timedelta(days=30)
MIN_SCANNER_VERSION = (0, 76, 2)
APPROVED_SYFT_VERSION = "1.57.1"
APPROVED_CRANE_VERSION = "0.22.1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9./_:-]*@sha256:([0-9a-f]{64})\Z")


class IntakeError(ValueError):
    """Release evidence is missing, stale or does not meet the preflight policy."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError("duplicate evidence key")
        result[key] = value
    return result


def _read(path: Path, expected_digest: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or not _DIGEST.fullmatch(expected_digest):
        raise IntakeError("invalid evidence file or expected digest")
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise IntakeError("evidence file exceeds size limit")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise IntakeError("evidence hash mismatch")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntakeError("invalid evidence JSON") from exc
    if not isinstance(data, dict):
        raise IntakeError("evidence must be an object")
    return data


def _recent(value: object, now: datetime) -> None:
    if not isinstance(value, str):
        raise IntakeError("missing evidence timestamp")
    try:
        stamped = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntakeError("invalid evidence timestamp") from exc
    if stamped.tzinfo is None or stamped > now + timedelta(minutes=5) or now - stamped > MAX_AGE:
        raise IntakeError("evidence timestamp is stale or in the future")


def _archive_scan_provenance(scan: dict[str, object], archive_sha256: str,
                             image_digest: str) -> None:
    provenance = scan.get("Sovereign")
    required = {"Source", "ArchiveSHA256", "ManifestDigest", "ScannerBinarySHA256",
                "DatabaseSHA256", "DatabaseUpdatedAt", "DatabaseNextUpdate"}
    if (not isinstance(provenance, dict) or set(provenance) != required or
            provenance["Source"] != "offline-local-docker-archive" or
            provenance["ArchiveSHA256"] != archive_sha256 or
            provenance["ManifestDigest"] != f"sha256:{image_digest}" or
            any(not isinstance(provenance[name], str) or
                    not _DIGEST.fullmatch(provenance[name])
                    for name in ("ScannerBinarySHA256", "DatabaseSHA256"))):
        raise IntakeError("scan lacks matching local archive provenance")
    try:
        scanned = datetime.fromisoformat(scan["CreatedAt"].replace("Z", "+00:00"))
        updated = datetime.fromisoformat(provenance["DatabaseUpdatedAt"].replace("Z", "+00:00"))
        next_update = datetime.fromisoformat(provenance["DatabaseNextUpdate"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise IntakeError("invalid vulnerability database date") from exc
    if (scanned.tzinfo is None or updated.tzinfo is None or next_update.tzinfo is None or
            updated > scanned or scanned > next_update or
            scanned - updated > timedelta(days=7)):
        raise IntakeError("vulnerability database does not cover the scan")


def _sha256_hashes(component: object) -> set[str]:
    if not isinstance(component, dict) or not isinstance(component.get("hashes"), list):
        return set()
    return {entry["content"] for entry in component["hashes"]
            if isinstance(entry, dict) and entry.get("alg") == "SHA-256" and
            isinstance(entry.get("content"), str) and _DIGEST.fullmatch(entry["content"])}


def verify_intake(scan_path: Path, sbom_path: Path, image_ref: str,
                  scan_sha256: str, sbom_sha256: str,
                  *, now: datetime | None = None) -> dict[str, object]:
    """Reject a release candidate with incomplete evidence or high findings."""
    match = _IMAGE.fullmatch(image_ref) if isinstance(image_ref, str) else None
    if match is None or ".." in image_ref or "//" in image_ref:
        raise IntakeError("image must use a digest-pinned repository reference")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise IntakeError("current time must have a timezone")
    scan = _read(scan_path, scan_sha256)
    sbom = _read(sbom_path, sbom_sha256)
    digests = scan.get("Metadata", {}).get("RepoDigests") if isinstance(scan.get("Metadata"), dict) else None
    if (scan.get("SchemaVersion") != 2 or scan.get("ArtifactType") != "container_image" or
            scan.get("ArtifactName") != image_ref or not isinstance(digests, list) or
            image_ref not in digests or
            not isinstance(scan.get("Trivy"), dict)):
        raise IntakeError("scan does not match the pinned image")
    version = scan["Trivy"].get("Version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version) or \
            tuple(map(int, version.split("."))) < MIN_SCANNER_VERSION:
        raise IntakeError("scanner version is missing or too old")
    _recent(scan.get("CreatedAt"), now)
    results = scan.get("Results")
    if not isinstance(results, list) or not results:
        raise IntakeError("scan has no result sections")
    findings: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise IntakeError("invalid scan result")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise IntakeError("invalid vulnerability list")
        for item in vulnerabilities:
            if not isinstance(item, dict) or not isinstance(item.get("VulnerabilityID"), str):
                raise IntakeError("invalid vulnerability record")
            severity = item.get("Severity")
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
                raise IntakeError("unknown vulnerability severity")
            if severity in {"HIGH", "CRITICAL", "UNKNOWN"}:
                findings.append(item["VulnerabilityID"])
    if findings:
        raise IntakeError(f"unresolved high, critical or unknown findings: {len(findings)}")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        raise IntakeError("unsupported SBOM format")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        raise IntakeError("missing SBOM metadata")
    _recent(metadata.get("timestamp"), now)
    properties = metadata.get("properties")
    if not isinstance(properties, list):
        raise IntakeError("candidate-only or unresolved SBOM")
    values: dict[str, object] = {}
    for item in properties:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            name = item["name"]
            if name.startswith("sovereign-ai:") and name in values:
                raise IntakeError("duplicate release provenance property")
            values[name] = item.get("value")
    status = values.get("sovereign-ai:inventory-status")
    if status not in {"resolved-release-candidate", "generated-from-validated-archive"}:
        raise IntakeError("candidate-only or unresolved SBOM")
    if status == "generated-from-validated-archive":
        tools = metadata.get("tools")
        generated_by = tools.get("components") if isinstance(tools, dict) else None
        if (not isinstance(generated_by, list) or
                not any(isinstance(item, dict) and item.get("name") == "syft" and
                        item.get("version") == APPROVED_SYFT_VERSION for item in generated_by) or
                values.get("sovereign-ai:crane-version") != APPROVED_CRANE_VERSION or
                not isinstance(values.get("sovereign-ai:archive-sha256"), str) or
                not _DIGEST.fullmatch(values["sovereign-ai:archive-sha256"])):
            raise IntakeError("missing approved image inventory provenance")
        _archive_scan_provenance(scan, values["sovereign-ai:archive-sha256"], match.group(1))
    image_component = metadata.get("component")
    repository = image_ref.split("@", 1)[0]
    if (not isinstance(image_component, dict) or image_component.get("name") != repository or
            match.group(1) not in _sha256_hashes(image_component)):
        raise IntakeError("SBOM does not bind the scanned image digest")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        raise IntakeError("empty SBOM inventory")
    references: set[str] = set()
    for component in components:
        if (not isinstance(component, dict) or not isinstance(component.get("bom-ref"), str) or
                not component["bom-ref"] or not isinstance(component.get("name"), str) or
                not component["name"] or component["bom-ref"] in references):
            raise IntakeError("unresolved or duplicate SBOM component")
        if status == "generated-from-validated-archive":
            kind = component.get("type")
            if kind == "file":
                resolved = bool(_sha256_hashes(component))
            elif kind in {"library", "application"}:
                resolved = (isinstance(component.get("version"), str) and
                            bool(component["version"]) and
                            isinstance(component.get("purl"), str) and
                            component["purl"].startswith("pkg:"))
            elif kind == "operating-system":
                resolved = isinstance(component.get("version"), str) and bool(component["version"])
            else:
                resolved = (isinstance(component.get("version"), str) and
                            bool(component["version"]) and bool(_sha256_hashes(component)))
            if not resolved:
                raise IntakeError("unresolved SBOM component")
        elif (not isinstance(component.get("version"), str) or not component["version"] or
              not _sha256_hashes(component)):
            raise IntakeError("unresolved SBOM component")
        references.add(component["bom-ref"])
    result = {"status": "preflight-pass", "image": image_ref, "components": len(components),
              "scan_sha256": scan_sha256, "sbom_sha256": sbom_sha256}
    if status == "generated-from-validated-archive":
        result["archive_sha256"] = values["sovereign-ai:archive-sha256"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline release evidence preflight")
    parser.add_argument("--scan", required=True, type=Path)
    parser.add_argument("--scan-sha256", required=True)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--sbom-sha256", required=True)
    parser.add_argument("--image-ref", required=True)
    args = parser.parse_args()
    try:
        result = verify_intake(args.scan, args.sbom, args.image_ref,
                               args.scan_sha256, args.sbom_sha256)
    except (IntakeError, OSError, ValueError) as exc:
        parser.exit(1, f"release intake: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
