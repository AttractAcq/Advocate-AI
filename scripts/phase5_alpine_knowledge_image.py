"""Scan a locally built, source-pinned Alpine PostgreSQL/pgvector image."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive

IMAGE = "sovereign-knowledge:synthetic"
BASE_DIGEST = "sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8"
SOURCE_SHA256 = "cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85"


def _run(*argv: str) -> str:
    completed = subprocess.run(argv, check=True, capture_output=True,
                               text=True, timeout=300)
    return completed.stdout.strip()


def rehearse(output: Path, crane: Path, crane_sha256: str, syft: Path,
             syft_sha256: str, trivy: Path, trivy_sha256: str,
             trivy_cache: Path) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise ValueError("Knowledge evidence output must be new")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="sovereign-alpine-knowledge-") as directory:
        archive = Path(directory) / "knowledge.tar"
        image_id = _run("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("invalid built Knowledge image ID")
        _run("docker", "save", "-o", str(archive), IMAGE)
        digest = _run(str(crane), "digest", "--tarball", str(archive))
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid built Knowledge archive digest")
        image_ref = f"registry.example.invalid/sovereign/knowledge@{digest}"
        identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
        sbom = output / "knowledge-sbom.json"
        scan = output / "knowledge-scan.json"
        inventory = generate_resolved_sbom(archive, image_ref, sbom,
                                           crane, crane_sha256, syft, syft_sha256)
        generated = generate_archive_scan(archive, image_ref, scan, crane,
                                          crane_sha256, trivy, trivy_sha256,
                                          trivy_cache)
        findings = [item for section in json.loads(scan.read_text())["Results"]
                    for item in section.get("Vulnerabilities", [])
                    if item.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
        result: dict[str, object] = {
            "source": "locally-built-pinned-alpine-pgvector",
            "base_image_digest": BASE_DIGEST,
            "pgvector_version": "0.8.7",
            "pgvector_source_sha256": SOURCE_SHA256,
            "image_id": image_id,
            "local_archive_ref": image_ref,
            "archive_sha256": identity["archive_sha256"],
            "sbom_sha256": inventory["sbom_sha256"],
            "scan_sha256": generated["scan_sha256"],
            "components": inventory["components"],
            "unresolved_findings": len(findings),
        }
        try:
            verify_intake(scan, sbom, image_ref, generated["scan_sha256"],
                          inventory["sbom_sha256"])
        except IntakeError as exc:
            if not findings or "unresolved high, critical or unknown findings" not in str(exc):
                raise
            result["intake"] = "denied-findings"
        else:
            result["intake"] = "preflight-pass"
        (output / "result.json").write_text(json.dumps(result, sort_keys=True) + "\n")
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--crane", required=True, type=Path)
    parser.add_argument("--crane-sha256", required=True)
    parser.add_argument("--syft", required=True, type=Path)
    parser.add_argument("--syft-sha256", required=True)
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--trivy-sha256", required=True)
    parser.add_argument("--trivy-cache", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.output, args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256, args.trivy,
                             args.trivy_sha256, args.trivy_cache), sort_keys=True))


if __name__ == "__main__":
    main()
