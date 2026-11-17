"""Bind locally built company-side Fleet images to signed offline evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import create_fleet_bundle, verify_bundle
from infrastructure.deploy.fleet_installer import (
    fleet_status, install_fleet, restore_install_fleet,
    rollback_fleet,
)
from infrastructure.deploy.fleet_runtime import FleetRuntime, stop_runtime
from infrastructure.deploy.fleet_backup import backup_fleet
from infrastructure.backup import generate_key
from services.fleet.catalog import Customer, FleetCatalog
from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive
from scripts.phase8_fleet_oidc_rehearsal import rehearse_oidc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rehearse(output: Path, crane: Path, crane_sha256: str, syft: Path,
             syft_sha256: str, trivy: Path, trivy_sha256: str,
             trivy_cache: Path) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise ValueError("Fleet evidence output must be new")
    output.mkdir(parents=True)
    result: dict[str, object] = {"source": "locally-built-synthetic-fleet-images",
                                 "images": {}}
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            (payload / "images").mkdir(parents=True)
            (payload / "evidence").mkdir()
            descriptors: dict[str, dict[str, str]] = {}
            for role in ("fleet-api", "fleet-portal"):
                archive = payload / "images" / f"{role}.tar"
                subprocess.run(["docker", "save", "-o", str(archive),
                                f"sovereign-{role}:synthetic"], check=True, timeout=300)
                digest = subprocess.run([str(crane), "digest", "--tarball", str(archive)],
                                        check=True, capture_output=True, text=True,
                                        timeout=300).stdout.strip()
                if not digest.startswith("sha256:") or len(digest) != 71:
                    raise ValueError("invalid Fleet image manifest digest")
                image_ref = f"registry.example.invalid/sovereign/{role}@{digest}"
                identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
                scan = payload / "evidence" / f"{role}-scan.json"
                sbom = payload / "evidence" / f"{role}-sbom.json"
                inventory = generate_resolved_sbom(archive, image_ref, sbom,
                                                   crane, crane_sha256, syft, syft_sha256)
                generated = generate_archive_scan(archive, image_ref, scan, crane,
                                                  crane_sha256, trivy, trivy_sha256, trivy_cache)
                shutil.copyfile(scan, output / scan.name)
                shutil.copyfile(sbom, output / sbom.name)
                findings = [item for section in json.loads(scan.read_text())["Results"]
                            for item in section.get("Vulnerabilities", [])
                            if item.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
                entry = {"image_ref": image_ref,
                         "archive_sha256": identity["archive_sha256"],
                         "scan_sha256": generated["scan_sha256"],
                         "sbom_sha256": inventory["sbom_sha256"],
                         "components": inventory["components"],
                         "unresolved_findings": len(findings)}
                try:
                    verify_intake(scan, sbom, image_ref, generated["scan_sha256"],
                                  inventory["sbom_sha256"])
                except IntakeError as exc:
                    if not findings or "unresolved high, critical or unknown findings" not in str(exc):
                        raise
                    entry["intake"] = "denied-findings"
                else:
                    entry["intake"] = "preflight-pass"
                result["images"][role] = entry
                descriptors[role] = {
                    "image_ref": image_ref,
                    "archive_path": f"images/{role}.tar",
                    "archive_sha256": identity["archive_sha256"],
                    "crane_sha256": crane_sha256,
                    "scan_path": f"evidence/{role}-scan.json",
                    "scan_sha256": generated["scan_sha256"],
                    "sbom_path": f"evidence/{role}-sbom.json",
                    "sbom_sha256": inventory["sbom_sha256"],
                }
            if any(result["images"][role]["intake"] != "preflight-pass"
                   for role in ("fleet-api", "fleet-portal")):
                result["fleet_bundle"] = "denied-findings"
            else:
                key = Ed25519PrivateKey.generate()
                private = root / "synthetic-fleet-signing.pem"
                trusted = root / "synthetic-fleet-trust.pem"
                private.write_bytes(key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
                trusted.write_bytes(key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
                bundle = root / "signed-fleet"
                created = create_fleet_bundle(payload, bundle, private,
                                              "synthetic-fleet-trial", descriptors,
                                              crane=crane)
                if verify_bundle(bundle, trusted) != created:
                    raise AssertionError("signed Fleet bundle did not verify")
                result["fleet_bundle"] = "verified"
                second_bundle = root / "signed-fleet-2"
                create_fleet_bundle(payload, second_bundle, private,
                                    "synthetic-fleet-trial-2", descriptors, crane=crane)
                config = root / "fleet-config.json"
                config.write_text('{"schema":1,"oidc_issuer":null}\n')
                config.chmod(0o644)
                token = root / "fleet-token"
                token.write_text("synthetic-fleet-admin-token-0123456789\n")
                token.chmod(0o600)
                install_root = root / "fleet-install"
                active_runtime: FleetRuntime | None = None
                try:
                    first = install_fleet(bundle, trusted, crane, config,
                                          install_root, token)
                    if fleet_status(install_root, trusted)["active"] != first["active"]:
                        raise AssertionError("Fleet first install is not healthy")
                    try:
                        install_fleet(root / "missing-bundle", trusted, crane,
                                      config, install_root)
                    except (OSError, ValueError):
                        if fleet_status(install_root, trusted)["active"] != first["active"]:
                            raise AssertionError("failed Fleet candidate changed active state")
                        result["failed_candidate"] = "previous-runtime-preserved"
                    else:
                        raise AssertionError("missing Fleet bundle unexpectedly installed")
                    second = install_fleet(second_bundle, trusted, crane,
                                           config, install_root)
                    if second["previous"] != first["active"] or \
                            fleet_status(install_root, trusted)["active"] != second["active"]:
                        raise AssertionError("Fleet update did not activate cleanly")
                    result["update"] = "healthy-candidate-activated"
                    restored = rollback_fleet(install_root, trusted, crane)
                    if restored["active"] != first["active"] or \
                            fleet_status(install_root, trusted)["active"] != first["active"]:
                        raise AssertionError("Fleet rollback did not restore first release")
                    result["rollback"] = "previous-release-restored"
                    state = json.loads((install_root / "fleet-state.json").read_text())
                    active_runtime = FleetRuntime(**state["runtime"])
                    subprocess.run(["docker", "stop", active_runtime.portal_id],
                                   check=True, capture_output=True, timeout=60)
                    command = [sys.executable, "-m", "infrastructure.deploy.fleet_installer"]
                    base_args = ["--root", str(install_root), "--trusted-key", str(trusted)]
                    recovery = json.loads(subprocess.run(
                        command + ["recover", *base_args, "--crane", str(crane)],
                        check=True, capture_output=True, text=True, timeout=300).stdout)
                    status = json.loads(subprocess.run(
                        command + ["status", *base_args], check=True,
                        capture_output=True, text=True, timeout=60).stdout)
                    if (recovery["result"] != "recovered" or
                            status["result"] != "healthy" or
                            status["active"] != first["active"]):
                        raise AssertionError("Fleet stopped portal did not recover")
                    result["recovery"] = "signed-release-restarted"
                    catalog = FleetCatalog(install_root / "state" / "fleet.db")
                    catalog.add("customer", Customer(code="CUST-LAB1",
                                                     category="owner_manager"))
                    backup_key = root / "fleet-backup.key"
                    generate_key(backup_key)
                    archive = root / "fleet-backup.svb"
                    backup_fleet(install_root / "state" / "fleet.db", archive,
                                 backup_key)
                    restored_root = root / "fleet-restored-install"
                    try:
                        restored = restore_install_fleet(
                            bundle, trusted, crane, config, restored_root,
                            token, archive, backup_key)
                        rows = FleetCatalog(restored_root / "state" / "fleet.db").list(
                            "customer")
                        if (restored["restored_files"] != 1 or
                                [row["code"] for row in rows] != ["CUST-LAB1"] or
                                fleet_status(restored_root, trusted)["result"] != "healthy"):
                            raise AssertionError("Fleet restored catalog is not healthy")
                        result["encrypted_recovery"] = "fictional-customer-restored"
                    finally:
                        restored_state = restored_root / "fleet-state.json"
                        if restored_state.exists():
                            value = json.loads(restored_state.read_text())
                            stop_runtime(FleetRuntime(**value["runtime"]))
                finally:
                    state_file = install_root / "fleet-state.json"
                    if state_file.exists():
                        current = json.loads(state_file.read_text())
                        stop_runtime(FleetRuntime(**current["runtime"]))
                result.update(rehearse_oidc(bundle, trusted, crane, root))
        (output / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return result
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse actual Fleet image release evidence")
    for name in ("output", "crane", "crane-sha256", "syft", "syft-sha256",
                 "trivy", "trivy-sha256", "trivy-cache"):
        parser.add_argument("--" + name, required=True,
                            type=Path if name in {"output", "crane", "syft", "trivy", "trivy-cache"}
                            else str)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.output, args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256, args.trivy,
                             args.trivy_sha256, args.trivy_cache), sort_keys=True))


if __name__ == "__main__":
    main()
