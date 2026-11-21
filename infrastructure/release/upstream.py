"""Offline image identity and SBOM preparation using pinned upstream CLIs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

CRANE_VERSION = "0.22.1"
SYFT_VERSION = "1.57.1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9./_:-]*@sha256:([0-9a-f]{64})\Z")


class UpstreamError(ValueError):
    """The local image or an approved upstream tool failed verification."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new_json(path: Path, value: dict[str, object]) -> str:
    """Create one private evidence file without following a replaced path."""
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def _binary(path: Path, expected_hash: str) -> None:
    if (path.is_symlink() or not path.is_file() or not _DIGEST.fullmatch(expected_hash) or
            _sha256(path) != expected_hash):
        raise UpstreamError("upstream binary is missing, linked or has an unapproved hash")


def _run(argv: list[str], *, timeout: int = 120) -> str:
    env = os.environ.copy()
    env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    try:
        completed = subprocess.run(argv, check=True, capture_output=True, text=True,
                                   timeout=timeout, env=env)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise UpstreamError(f"upstream tool failed: {Path(argv[0]).name} {argv[1]}") from exc
    return completed.stdout.strip()


def validate_image_archive(archive: Path, image_ref: str, crane: Path,
                           crane_sha256: str) -> dict[str, str]:
    """Check all saved-image layers and compare the local manifest digest."""
    match = _IMAGE.fullmatch(image_ref) if isinstance(image_ref, str) else None
    if match is None or ".." in image_ref or "//" in image_ref:
        raise UpstreamError("image reference must be digest-pinned")
    if archive.is_symlink() or not archive.is_file():
        raise UpstreamError("image archive is missing or linked")
    _binary(crane, crane_sha256)
    if _run([str(crane), "version"]) != CRANE_VERSION:
        raise UpstreamError("unapproved crane version")
    archive_sha256 = _sha256(archive)
    _run([str(crane), "validate", "--tarball", str(archive)], timeout=300)
    digest = _run([str(crane), "digest", "--tarball", str(archive)], timeout=300)
    if digest != f"sha256:{match.group(1)}":
        raise UpstreamError("saved image manifest does not match scanned digest")
    if _sha256(archive) != archive_sha256:
        raise UpstreamError("image archive changed during validation")
    return {"image_ref": image_ref, "archive_sha256": archive_sha256,
            "manifest_digest": digest, "crane_version": CRANE_VERSION}


def image_labels_from_archive(archive: Path, role: str) -> dict[str, str]:
    """Read the hash-bound config labels from one validated Docker save."""
    if archive.is_symlink() or not archive.is_file() or not re.fullmatch(r"[a-z-]+", role):
        raise UpstreamError("invalid image archive or role")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise UpstreamError("duplicate image configuration key")
            value[key] = item
        return value

    try:
        with tarfile.open(archive, "r") as stream:
            members: dict[str, list[tarfile.TarInfo]] = {}
            for member in stream.getmembers():
                members.setdefault(member.name, []).append(member)

            def small_file(name: str) -> bytes:
                matches = members.get(name, [])
                if (len(matches) != 1 or not matches[0].isfile() or
                        not 0 < matches[0].size <= 1024 * 1024):
                    raise UpstreamError("invalid image configuration file")
                source = stream.extractfile(matches[0])
                if source is None:
                    raise UpstreamError("missing image configuration file")
                return source.read()

            manifest = json.loads(small_file("manifest.json"), object_pairs_hook=unique_object)
            if (not isinstance(manifest, list) or len(manifest) != 1 or
                    not isinstance(manifest[0], dict) or
                    manifest[0].get("RepoTags") != [f"sovereign-{role}:synthetic"]):
                raise UpstreamError("archive has unexpected image tags")
            config_path = manifest[0].get("Config")
            if isinstance(config_path, str) and re.fullmatch(r"[0-9a-f]{64}\.json", config_path):
                expected = config_path[:-5]
            elif isinstance(config_path, str) and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", config_path):
                expected = config_path.rsplit("/", 1)[-1]
            else:
                raise UpstreamError("invalid image configuration path")
            raw = small_file(config_path)
            if hashlib.sha256(raw).hexdigest() != expected:
                raise UpstreamError("image configuration digest mismatch")
            configuration = json.loads(raw, object_pairs_hook=unique_object)
            labels = configuration.get("config", {}).get("Labels") if isinstance(configuration, dict) else None
            if (not isinstance(labels, dict) or
                    any(not isinstance(key, str) or not isinstance(value, str)
                        for key, value in labels.items())):
                raise UpstreamError("image labels are unavailable")
            return labels
    except (OSError, tarfile.TarError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        raise UpstreamError("invalid image configuration archive") from exc


def generate_resolved_sbom(archive: Path, image_ref: str, output: Path,
                           crane: Path, crane_sha256: str, syft: Path,
                           syft_sha256: str) -> dict[str, object]:
    """Catalog the validated local archive and annotate its provenance."""
    identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
    _binary(syft, syft_sha256)
    try:
        version = json.loads(_run([str(syft), "version", "-o", "json"]))
    except json.JSONDecodeError as exc:
        raise UpstreamError("invalid syft version output") from exc
    if not isinstance(version, dict) or version.get("version") != SYFT_VERSION:
        raise UpstreamError("unapproved syft version")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise UpstreamError("SBOM output must be a new file in an existing directory")
    with tempfile.TemporaryDirectory() as directory:
        raw_path = Path(directory) / "raw.json"
        _run([str(syft), str(archive), "--from", "docker-archive", "-o",
              f"cyclonedx-json@1.6={raw_path}", "-q"], timeout=300)
        try:
            sbom = json.loads(raw_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise UpstreamError("invalid generated SBOM") from exc
    if _sha256(archive) != identity["archive_sha256"]:
        raise UpstreamError("image archive changed during inventory generation")
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or
            sbom.get("specVersion") != "1.6" or
            not isinstance(sbom.get("metadata"), dict) or
            not isinstance(sbom.get("components"), list) or not sbom["components"]):
        raise UpstreamError("Syft produced an empty or unsupported inventory")
    metadata_tools = sbom["metadata"].get("tools")
    tools = metadata_tools.get("components") if isinstance(metadata_tools, dict) else None
    if not isinstance(tools, list):
        raise UpstreamError("SBOM does not identify the approved generator")
    if not any(isinstance(item, dict) and item.get("name") == "syft" and
               item.get("version") == SYFT_VERSION for item in tools):
        raise UpstreamError("SBOM does not identify the approved generator")
    repository, digest = image_ref.split("@sha256:", 1)
    sbom["metadata"]["component"] = {
        "type": "container", "name": repository, "version": f"sha256:{digest}",
        "hashes": [{"alg": "SHA-256", "content": digest}],
    }
    properties = sbom["metadata"].setdefault("properties", [])
    if not isinstance(properties, list):
        raise UpstreamError("invalid SBOM metadata properties")
    properties.extend([
        {"name": "sovereign-ai:inventory-status", "value": "generated-from-validated-archive"},
        {"name": "sovereign-ai:archive-sha256", "value": identity["archive_sha256"]},
        {"name": "sovereign-ai:crane-version", "value": CRANE_VERSION},
    ])
    sbom_sha256 = _write_new_json(output, sbom)
    return {"image_ref": image_ref, "archive_sha256": identity["archive_sha256"],
            "sbom_sha256": sbom_sha256, "components": len(sbom["components"]),
            "crane_version": CRANE_VERSION, "syft_version": SYFT_VERSION}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare an offline SBOM from a local Docker archive")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--crane-sha256", required=True)
    parser.add_argument("--syft", required=True, type=Path)
    parser.add_argument("--syft-sha256", required=True)
    args = parser.parse_args()
    try:
        result = generate_resolved_sbom(args.archive, args.image_ref, args.output,
                                        args.crane, args.crane_sha256, args.syft,
                                        args.syft_sha256)
    except (UpstreamError, OSError) as exc:
        parser.exit(1, f"upstream evidence: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
