"""Recheck downloaded synthetic release evidence against a recorded result hash.

This checks artifact consistency, reported outcomes and the retained detached
manifest signatures. Image archives are not retained, so this cannot recheck
their bytes or approve deployment independently of the CI run.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from infrastructure.release.intake import IntakeError, verify_intake

HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_RESULT_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 256
MAX_PUBLIC_KEY_BYTES = 4096


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


def _read_control(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                not 0 < info.st_size <= limit):
            raise ValueError("unsafe retained signature control")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("oversized retained signature control")
    return raw


def _verify_manifest_proof(directory: Path, result: dict[str, object],
                           images: dict[str, object], label: str) -> None:
    proof = directory / "signed-manifests"
    source = proof / label
    if proof.is_symlink() or source.is_symlink() or not source.is_dir():
        raise ValueError("retained signed manifest is unavailable")
    public_bytes = _read_control(proof / "synthetic-trusted.pem", MAX_PUBLIC_KEY_BYTES)
    if hashlib.sha256(public_bytes).hexdigest() != result.get("synthetic_public_key_sha256"):
        raise ValueError("retained synthetic public key hash mismatch")
    key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("retained key is not Ed25519")
    raw = _read_control(source / "release-manifest.json", MAX_RESULT_BYTES)
    field = ("bundle_manifest_sha256" if label == "initial"
             else "updated_bundle_manifest_sha256")
    if hashlib.sha256(raw).hexdigest() != result.get(field):
        raise ValueError("retained manifest hash mismatch")
    signature = base64.b64decode(
        _read_control(source / "release-manifest.sig", MAX_SIGNATURE_BYTES),
        validate=True)
    try:
        key.verify(signature, raw)
    except InvalidSignature as exc:
        raise ValueError("retained manifest signature mismatch") from exc
    manifest = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    if (not isinstance(manifest, dict) or manifest.get("schema") != 8 or
            manifest.get("target") != "vessel" or
            manifest.get("key_id") != hashlib.sha256(key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest() or
            set(manifest.get("images", {})) != {"core", "console", "knowledge"} or
            manifest.get("compatibility") != result.get("vessel_compatibility")):
        raise ValueError("retained manifest has wrong vessel identity")
    rows = manifest.get("files")
    if not isinstance(rows, list) or any(not isinstance(row, dict) or
                                          set(row) != {"path", "sha256", "size"}
                                          for row in rows):
        raise ValueError("retained manifest has invalid inventory")
    inventory = {row["path"]: row for row in rows if isinstance(row["path"], str)}
    if len(inventory) != len(rows):
        raise ValueError("retained manifest has duplicate inventory path")
    for role in ("core", "console", "knowledge"):
        descriptor = manifest["images"][role]
        entry = images[role]
        if not isinstance(descriptor, dict) or not isinstance(entry, dict):
            raise ValueError("retained image descriptor is invalid")
        for field_name in ("image_ref", "archive_sha256", "scan_sha256", "sbom_sha256"):
            if descriptor.get(field_name) != entry.get(field_name):
                raise ValueError(f"retained {role} image evidence differs from result")
        for kind, path in (("archive", f"images/{role}.tar"),
                           ("scan", f"evidence/{role}-scan.json"),
                           ("sbom", f"evidence/{role}-sbom.json")):
            if (descriptor.get(f"{kind}_path") != path or
                    inventory.get(path, {}).get("sha256") != entry.get(f"{kind}_sha256")):
                raise ValueError(f"retained {role} signed inventory differs from result")


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
    _verify_manifest_proof(directory, result, images, "initial")
    _verify_manifest_proof(directory, result,
                           {**images, "core": result["updated_core_image"]}, "updated")
    return {"status": "artifact-consistency-pass", "result_sha256": expected_sha256,
            "reported_bundle": result["three_image_bundle"],
            "reported_recovery_checks": list(required_passes), "images": checked,
            "signed_manifests": "initial-and-updated-verified",
            "scope": "synthetic signatures and inventory; no image archive bytes or external key trust"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--result-sha256", required=True)
    args = parser.parse_args()
    try:
        report = verify(args.directory, args.result_sha256)
    except (OSError, ValueError, IntakeError, TypeError, binascii.Error) as exc:
        parser.exit(1, f"release artifact evidence: {exc}\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
