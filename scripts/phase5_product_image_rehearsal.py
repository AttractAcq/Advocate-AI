"""Exercise release intake on the actual synthetic Core and Console OCI images."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from infrastructure.release.bundle import create_candidate_bundle, create_product_bundle, verify_bundle
from infrastructure.deploy.container_runtime import (
    RuntimeError as ContainerRuntimeError, RuntimeHandle, start_verified_bundle,
    stop_runtime,
)
from infrastructure.deploy.product_installer import (
    cleanup_product_orphans, install_product, product_status, recover_product,
    refresh_emergency_product, restore_install_product, rollback_product,
)
from infrastructure.deploy.boot_service import write_recovery_unit
from infrastructure.release.intake import IntakeError, verify_intake
from infrastructure.release.scan import generate_archive_scan
from infrastructure.release.upstream import generate_resolved_sbom, validate_image_archive
from scripts.phase5_core_state_restore import PASSPHRASE, _probe, snapshot_synthetic_state

_UPLOAD_PROBE = r'''
import hashlib, json, sys, urllib.request
phase, expected_id = sys.argv[1:3]
base = "http://127.0.0.1:18100"
password = open("/run/secrets/lab-password", encoding="utf-8").read().strip()
body = json.dumps({"user_id":"lab-chief_engineer-1", "password":password}).encode()
login = urllib.request.Request(base + "/api/login", data=body,
                               headers={"Content-Type":"application/json"})
token = json.load(urllib.request.urlopen(login, timeout=5))["access_token"]
headers = {"Authorization":"Bearer " + token}
if phase == "stage":
    payload = b"synthetic product upload boundary"
    request = urllib.request.Request(base + "/api/documents/stage", data=payload,
                                     headers={**headers, "Content-Type":"application/octet-stream",
                                              "X-Filename":"synthetic-note.txt"})
    item = json.load(urllib.request.urlopen(request, timeout=5))["upload"]
    expected_id = item["id"]
    assert item["sha256"] == hashlib.sha256(payload).hexdigest()
uploads = json.load(urllib.request.urlopen(
    urllib.request.Request(base + "/api/documents/staged", headers=headers), timeout=5))["uploads"]
assert len(uploads) == 1 and uploads[0]["id"] == expected_id and uploads[0]["status"] == "pending"
sources = json.load(urllib.request.urlopen(
    urllib.request.Request(base + "/api/sources", headers=headers), timeout=5))["sources"]
assert all(item["document_id"] != "synthetic-note" for item in sources)
assert len(sources) == (0 if phase == "late" else 1)
print(json.dumps({"upload_id":expected_id, "status":"pending", "source_count":len(sources)}))
'''


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _docker(*arguments: str) -> str:
    completed = subprocess.run(["docker", *arguments], check=True, capture_output=True,
                               text=True, timeout=300)
    return completed.stdout.strip()


def _mounted_emergency_digest(core_id: str) -> str:
    code = ("import hashlib; from pathlib import Path; "
            "print(hashlib.sha256(Path('/run/secrets/emergency-password').read_bytes()).hexdigest())")
    return _docker("exec", core_id, "python", "-c", code)


def _signed_trial(root: Path, archive: Path, scan: Path, sbom: Path,
                  image_ref: str, crane: Path, crane_sha256: str) -> None:
    payload = root / "payload"
    (payload / "images").mkdir(parents=True)
    (payload / "evidence").mkdir()
    shutil.copyfile(archive, payload / "images" / "core.tar")
    shutil.copyfile(scan, payload / "evidence" / "scan.json")
    shutil.copyfile(sbom, payload / "evidence" / "sbom.json")
    key = Ed25519PrivateKey.generate()
    private = root / "synthetic-signing-key.pem"
    trusted = root / "synthetic-trusted-key.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    trusted.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    evidence = {"image_ref": image_ref, "archive_path": "images/core.tar",
                "archive_sha256": _sha256(archive), "crane_sha256": crane_sha256,
                "scan_path": "evidence/scan.json", "scan_sha256": _sha256(scan),
                "sbom_path": "evidence/sbom.json", "sbom_sha256": _sha256(sbom)}
    bundle = root / "signed-core-trial"
    created = create_candidate_bundle(payload, bundle, private, "synthetic-core-trial",
                                      evidence, crane=crane)
    verified = verify_bundle(bundle, trusted)
    if verified != created or verified["evidence"] != evidence:
        raise AssertionError("signed Core trial did not verify")


def rehearse(output: Path, crane: Path, crane_sha256: str,
             syft: Path, syft_sha256: str, trivy: Path,
             trivy_sha256: str, trivy_cache: Path,
             restic: Path, restic_sha256: str) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    output.mkdir(parents=True)
    result: dict[str, object] = {"source": "locally-built-synthetic-product-images",
                                 "images": {}}
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("core", "console"):
                tag = f"sovereign-{name}:synthetic"
                image_id = _docker("image", "inspect", tag, "--format", "{{.Id}}")
                if not image_id.startswith("sha256:") or len(image_id) != 71:
                    raise ValueError("invalid local image ID")
                archive = root / f"{name}.tar"
                _docker("save", "-o", str(archive), tag)
                digest = subprocess.run([str(crane), "digest", "--tarball", str(archive)],
                                        check=True, capture_output=True, text=True,
                                        timeout=300).stdout.strip()
                if not digest.startswith("sha256:") or len(digest) != 71:
                    raise ValueError("invalid local image manifest digest")
                image_ref = f"registry.example.invalid/sovereign/{name}@{digest}"
                identity = validate_image_archive(archive, image_ref, crane, crane_sha256)
                sbom = output / f"{name}-sbom.json"
                scan = output / f"{name}-scan.json"
                inventory = generate_resolved_sbom(archive, image_ref, sbom,
                                                   crane, crane_sha256, syft, syft_sha256)
                generated = generate_archive_scan(archive, image_ref, scan, crane,
                                                  crane_sha256, trivy, trivy_sha256, trivy_cache)
                findings = [item for section in json.loads(scan.read_text())["Results"]
                            for item in section.get("Vulnerabilities", [])
                            if item.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
                entry = {"image_id": image_id, "image_ref": image_ref,
                         "archive_sha256": identity["archive_sha256"],
                         "sbom_sha256": inventory["sbom_sha256"],
                         "scan_sha256": generated["scan_sha256"],
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
                    if name == "core":
                        _signed_trial(root, archive, scan, sbom, image_ref,
                                      crane, crane_sha256)
                        entry["signed_trial"] = "verified"
                result["images"][name] = entry
            payload = root / "product-payload"
            (payload / "images").mkdir(parents=True)
            (payload / "evidence").mkdir()
            descriptors: dict[str, dict[str, str]] = {}
            for name in ("core", "console"):
                entry = result["images"][name]
                os.link(root / f"{name}.tar", payload / "images" / f"{name}.tar")
                shutil.copyfile(output / f"{name}-scan.json",
                                payload / "evidence" / f"{name}-scan.json")
                shutil.copyfile(output / f"{name}-sbom.json",
                                payload / "evidence" / f"{name}-sbom.json")
                descriptors[name] = {
                    "image_ref": entry["image_ref"],
                    "archive_path": f"images/{name}.tar",
                    "archive_sha256": entry["archive_sha256"],
                    "crane_sha256": crane_sha256,
                    "scan_path": f"evidence/{name}-scan.json",
                    "scan_sha256": entry["scan_sha256"],
                    "sbom_path": f"evidence/{name}-sbom.json",
                    "sbom_sha256": entry["sbom_sha256"],
                }
            private = root / "synthetic-signing-key.pem"
            trusted = root / "synthetic-trusted-key.pem"
            product_bundle = root / "signed-product-trial"
            try:
                created = create_product_bundle(payload, product_bundle, private,
                                                "synthetic-product-trial", descriptors,
                                                crane=crane)
            except IntakeError as exc:
                if (not any(result["images"][name]["unresolved_findings"]
                            for name in ("core", "console")) or
                        "unresolved high, critical or unknown findings" not in str(exc)):
                    raise
                result["product_bundle"] = "denied-findings"
            else:
                if verify_bundle(product_bundle, trusted) != created:
                    raise AssertionError("signed product trial did not verify")
                result["product_bundle"] = "verified"
                state_root = root / "core-restore"
                state_root.mkdir(mode=0o700)
                repository, backup_password, snapshot_id, conversation_id = snapshot_synthetic_state(
                    state_root, restic, restic_sha256)
                lab_credential = root / "lab-password"
                lab_credential.write_text(PASSPHRASE + "\n")
                lab_credential.chmod(0o600)
                emergency_credential = root / "emergency-password"
                emergency_credential.write_text(secrets.token_urlsafe(24) + "\n")
                emergency_credential.chmod(0o600)
                second_bundle = root / "signed-product-trial-2"
                create_product_bundle(payload, second_bundle, private,
                                      "synthetic-product-trial-2", descriptors,
                                      crane=crane)
                descriptor, config_name = tempfile.mkstemp(prefix=".sovereign-console-config-",
                                                           dir=Path.home())
                config = Path(config_name)
                install_root = root / "product-install"
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(b'{"schema":1,"oidc_issuer":null}\n')
                    config.chmod(0o644)
                    first = restore_install_product(
                        product_bundle, trusted, crane, config, install_root,
                        snapshot_id, repository, backup_password, restic,
                        restic_sha256, lab_credential, emergency_credential,
                        enable_uploads=True)
                    state = install_root / "core-state"
                    try:
                        def active_core() -> str:
                            active = json.loads((install_root / "product-state.json").read_text())
                            return str(active["runtime"]["core_id"])

                        before = _probe(active_core(), conversation_id, "before")
                        staged = json.loads(_docker("exec", active_core(), "python", "-c",
                                                    _UPLOAD_PROBE, "stage", "-"))
                        staged_id = staged["upload_id"]
                        if (not isinstance(staged_id, str) or len(staged_id) != 32 or
                                not (install_root / "product-uploads" / f"{staged_id}.blob").is_file() or
                                staged["source_count"] != 1):
                            raise AssertionError("signed Core upload quarantine failed")
                        result["upload_quarantine"] = "staged-and-not-indexed"
                        old_core = active_core()
                        initial_digest = _sha256(emergency_credential)
                        if _mounted_emergency_digest(old_core) != initial_digest:
                            raise AssertionError("initial emergency mount content mismatch")
                        replacement = root / "replacement-emergency-password"
                        replacement.write_text(secrets.token_urlsafe(24) + "\n")
                        replacement.chmod(0o600)
                        replacement.replace(emergency_credential)
                        rotated_digest = _sha256(emergency_credential)
                        if rotated_digest == initial_digest or \
                                _mounted_emergency_digest(old_core) != initial_digest:
                            raise AssertionError("old Core did not retain the prior file bind")
                        try:
                            product_status(install_root, trusted)
                        except ContainerRuntimeError as exc:
                            if "stale" not in str(exc):
                                raise
                        else:
                            raise AssertionError("stale emergency mount passed product status")
                        refreshed = refresh_emergency_product(install_root, trusted, crane)
                        if (refreshed["active"] != first["active"] or
                                active_core() == old_core or
                                _mounted_emergency_digest(active_core()) != rotated_digest or
                                product_status(install_root, trusted)["active"] != first["active"]):
                            raise AssertionError("emergency credential did not rebind")
                        try:
                            _docker("inspect", old_core)
                        except subprocess.CalledProcessError:
                            pass
                        else:
                            raise AssertionError("old Core survived emergency refresh")
                        result["emergency_rotation"] = "atomic-file-rebound"
                        retained = json.loads(_docker("exec", active_core(), "python", "-c",
                                                      _UPLOAD_PROBE, "verify", staged_id))
                        if retained["upload_id"] != staged_id:
                            raise AssertionError("upload quarantine did not survive runtime refresh")
                        roles = json.loads((state / "roles.json").read_text())
                        roles["allow"]["chief_engineer"] = ["deck"]
                        (state / "roles.json").write_text(json.dumps(roles))
                        after = _probe(active_core(), conversation_id, "after")
                        result["signed_state_runtime"] = {"snapshot_id": snapshot_id,
                                                          "before": before, "after": after}
                        unit = root / "sovereign-synthetic-recover.service"
                        write_recovery_unit(unit, install_root, trusted, crane,
                                            Path(sys.executable), Path.cwd())
                        checked = subprocess.run(["systemd-analyze", "verify", str(unit)],
                                                 capture_output=True, text=True, timeout=30)
                        if checked.returncode:
                            raise AssertionError("boot recovery unit failed systemd verification: "
                                                 + checked.stderr[-2000:])
                        result["boot_unit"] = "syntax-verified"
                        if product_status(install_root, trusted)["active"] != first["active"]:
                            raise AssertionError("installed product status mismatch")
                        result["runtime"] = "healthy-isolated"
                        installation_id = (install_root / "installation-id").read_text().strip()
                        orphan = start_verified_bundle(product_bundle, trusted, crane,
                                                       config, installation_id=installation_id)
                        try:
                            cleaned = cleanup_product_orphans(install_root, trusted)
                            if (cleaned["containers"], cleaned["networks"]) != (2, 1):
                                raise AssertionError("orphan cleanup did not remove exactly one runtime")
                            if product_status(install_root, trusted)["active"] != first["active"]:
                                raise AssertionError("orphan cleanup changed the active runtime")
                            try:
                                _docker("inspect", orphan.core_id)
                            except subprocess.CalledProcessError:
                                pass
                            else:
                                raise AssertionError("orphan Core container survived cleanup")
                            result["orphan_cleanup"] = "scoped-runtime-retired"
                        finally:
                            stop_runtime(orphan)
                        try:
                            install_product(root / "missing-candidate", trusted,
                                            crane, config, install_root)
                        except (OSError, ValueError):
                            if product_status(install_root, trusted)["active"] != first["active"]:
                                raise AssertionError("rejected candidate changed active release")
                            result["failed_candidate"] = "previous-runtime-preserved"
                        else:
                            raise AssertionError("missing candidate unexpectedly activated")
                        second = install_product(second_bundle, trusted, crane,
                                                 config, install_root)
                        if second["previous"] != first["active"]:
                            raise AssertionError("previous product release was not retained")
                        if product_status(install_root, trusted)["active"] != second["active"]:
                            raise AssertionError("replacement product status mismatch")
                        _probe(active_core(), conversation_id, "after")
                        result["switchover"] = "healthy-candidate-activated"
                        restored = rollback_product(install_root, trusted, crane)
                        if restored["active"] != first["active"]:
                            raise AssertionError("product rollback did not restore prior release")
                        if product_status(install_root, trusted)["active"] != first["active"]:
                            raise AssertionError("rolled back product is unhealthy")
                        _probe(active_core(), conversation_id, "after")
                        result["rollback"] = "previous-release-restored"
                        stopped_state = json.loads((install_root / "product-state.json").read_text())
                        stopped_runtime = RuntimeHandle(**stopped_state["runtime"])
                        _docker("stop", stopped_runtime.console_id)
                        try:
                            product_status(install_root, trusted)
                        except ContainerRuntimeError:
                            pass
                        else:
                            raise AssertionError("stopped Console unexpectedly passed health")
                        recovery = recover_product(install_root, trusted, crane)
                        if recovery["result"] != "recovered" or \
                                product_status(install_root, trusted)["active"] != first["active"]:
                            raise AssertionError("stopped runtime did not recover from staged bundle")
                        _probe(active_core(), conversation_id, "after")
                        late_upload = json.loads(_docker("exec", active_core(), "python", "-c",
                                                        _UPLOAD_PROBE, "late", staged_id))
                        if late_upload["upload_id"] != staged_id:
                            raise AssertionError("upload quarantine did not survive release recovery")
                        try:
                            _docker("inspect", stopped_runtime.core_id)
                        except subprocess.CalledProcessError:
                            pass
                        else:
                            raise AssertionError("recovered old runtime was not retired")
                        result["recovery"] = "staged-release-restarted"
                        result["installer_state_continuity"] = "install-upgrade-rollback-recover"
                    finally:
                        active_state = json.loads((install_root / "product-state.json").read_text())
                        stop_runtime(RuntimeHandle(**active_state["runtime"]))
                finally:
                    config.unlink(missing_ok=True)
        (output / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return result
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Rehearse exact product-image release evidence")
    for name in ("output", "crane", "crane-sha256", "syft", "syft-sha256",
                 "trivy", "trivy-sha256", "trivy-cache", "restic", "restic-sha256"):
        parser.add_argument("--" + name, required=True,
                            type=Path if name in {"output", "crane", "syft", "trivy", "trivy-cache", "restic"} else str)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.output, args.crane, args.crane_sha256,
                             args.syft, args.syft_sha256, args.trivy,
                             args.trivy_sha256, args.trivy_cache,
                             args.restic, args.restic_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
