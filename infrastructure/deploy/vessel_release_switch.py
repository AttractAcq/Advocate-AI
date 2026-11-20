"""Signed, stopped-only vessel release switch on an existing Knowledge volume."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile

from infrastructure.deploy.knowledge_volume import (
    KnowledgeVolumeHandle, start_signed_knowledge,
)
from infrastructure.deploy.container_runtime import RuntimeHandle
from infrastructure.deploy.history_migration import _fingerprint
from infrastructure.deploy.vessel_installer import (
    VesselInstallError, _candidate_release_id, _cleanup_failed_install,
    _operation_lock, _owner_directory,
    _read_state, _recovery_inventory, _release_id, _stage, _state_payload,
    _verify_knowledge_schema, _verify_stage, _write_state,
)
from infrastructure.deploy.vessel_recovery_set import (
    _sha256, _stage_core, _verify_database, restore_vessel_recovery_files,
    verify_vessel_recovery_receipt,
)
from infrastructure.deploy.vessel_runtime import _state_options, start_signed_vessel_services
from infrastructure.restic_repository import MANIFEST
from services.policy.policy_file import policy_directory_lock


def _discardable_stage(stage: Path) -> None:
    _owner_directory(stage)
    device = stage.stat().st_dev
    for item in stage.rglob("*"):
        details = item.lstat()
        if (details.st_uid != os.getuid() or details.st_dev != device or
                not (stat.S_ISREG(details.st_mode) or
                     stat.S_ISDIR(details.st_mode)) or
                stat.S_IMODE(details.st_mode) & 0o022):
            raise VesselInstallError("staged candidate contains unsafe entry")


def _core_hashes(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in root.rglob("*"):
        if not item.is_file():
            continue
        name = item.relative_to(root).as_posix()
        if name in ("postgres.dump", MANIFEST):
            continue
        if name == "history.db":
            digest, count = _fingerprint(item, 1)
            result[name] = f"{digest}:{count}"
        else:
            result[name] = _sha256(item)
    return result


def _verify_preupdate_recovery(current: dict[str, object],
                               receipt: Path, receipt_key: Path,
                               password_file: Path, restic: Path,
                               restic_sha256: str,
                               staging_parent: Path,
                               root: Path) -> dict[str, object]:
    """Prove a signed, clean-restorable set matches the stopped live Core."""
    payload = verify_vessel_recovery_receipt(receipt, receipt_key)
    if (payload["installation_id"] != current["installation_id"] or
            payload["release"] != current["active"] or
            payload["data_volume"] != current["runtime"]["data_volume"]):
        raise VesselInstallError("pre-update recovery receipt names another installation")
    if payload["schema"] != 2:
        raise VesselInstallError("pre-update recovery receipt lacks Knowledge row digest")
    state = Path(current["core_state"])
    repository = Path(payload["repository"])
    _owner_directory(staging_parent)
    _owner_directory(receipt.parent)
    for path in (staging_parent, repository, receipt.parent):
        if (path.resolve().is_relative_to(root.resolve()) or
                root.resolve().is_relative_to(path.resolve()) or
                path.resolve().is_relative_to(state.resolve()) or
                state.resolve().is_relative_to(path.resolve())):
            raise VesselInstallError("pre-update recovery paths overlap vessel state")
    if (staging_parent.resolve().is_relative_to(repository.resolve()) or
            repository.resolve().is_relative_to(staging_parent.resolve())):
        raise VesselInstallError("pre-update staging overlaps repository")
    with tempfile.TemporaryDirectory(prefix=".vessel-preupdate-",
                                     dir=staging_parent) as temporary:
        workspace = Path(temporary)
        restored = workspace / "restored"
        restore_vessel_recovery_files(receipt, receipt_key, password_file,
                                      restic, restic_sha256, restored)
        with policy_directory_lock(state / "roles.json", exclusive=True):
            sources, checkpoint, manifest_sha256 = _stage_core(
                state, workspace / "live")
        if (sources != payload["sources"] or
                checkpoint != (payload["audit_count"], payload["audit_tail_hash"]) or
                manifest_sha256 != payload["manifest_sha256"] or
                _core_hashes(workspace / "live") != _core_hashes(restored)):
            raise VesselInstallError("live Core differs from pre-update recovery set")
    return payload


def discard_stopped_vessel_stage(root: Path, trusted_key: Path, bundle: Path,
                                 console_config: Path,
                                 *, discard_stage: bool = False) -> dict[str, str]:
    """Remove one non-active stage after a clean stop and signed identity check."""
    if not discard_stage:
        raise VesselInstallError("explicit staged-candidate discard required")
    with _operation_lock(root):
        current = _read_state(root)
        active = current["active"]
        _verify_stage(root / "vessel-releases" / active, trusted_key, active)
        state = Path(current["core_state"])
        password = Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        identifier = _candidate_release_id(bundle, trusted_key, console_config)
        if identifier in (active, current.get("previous")):
            raise VesselInstallError("cannot discard active or rollback vessel release")
        releases = root / "vessel-releases"
        _owner_directory(releases)
        stage = releases / identifier
        _discardable_stage(stage)
        shutil.rmtree(stage)
        return {"result": "staged-candidate-discarded", "release": identifier}


def _activate_stopped(root: Path, trusted_key: Path, crane: Path,
                      current: dict[str, object], identifier: str,
                      stage: Path, result_name: str,
                      recovery: dict[str, object] | None = None) -> dict[str, object]:
    state = Path(current["core_state"])
    password = Path(current["lab_password_file"])
    installation_id = current["installation_id"]
    data_volume = current["runtime"]["data_volume"]
    knowledge: KnowledgeVolumeHandle | None = None
    services: RuntimeHandle | None = None
    payload: dict[str, object] | None = None
    try:
        with policy_directory_lock(state / "roles.json"):
            knowledge = start_signed_knowledge(
                stage / "bundle", trusted_key, crane, root,
                installation_id, initialize=False)
            _verify_knowledge_schema(knowledge)
            inventory = _verify_database(stage / "bundle", trusted_key, crane,
                                         knowledge, state, root)
            if recovery is not None and (inventory["sources"] != recovery["sources"]
                                         or inventory["passages"] != recovery["passages"]
                                         or inventory["knowledge_sha256"] !=
                                         recovery["knowledge_sha256"]):
                raise VesselInstallError("live Knowledge differs from pre-update recovery set")
            services = start_signed_vessel_services(
                stage / "bundle", trusted_key, crane,
                stage / "console-config.json", state, password,
                root, knowledge, installation_id)
            payload = _state_payload(
                identifier, installation_id, state, password, services,
                knowledge, previous=current["active"])
            _write_state(root, payload)
        return {"result": result_name, "active": identifier,
                "previous": current["active"],
                "sources": inventory["sources"],
                "passages": inventory["passages"]}
    except Exception as exc:
        try:
            recorded = _read_state(root)
        except Exception:
            recorded = None
        if payload is not None and recorded != current:
            raise VesselInstallError(
                "release switch state may have changed; retain candidate for reconciliation"
            ) from exc
        if not _cleanup_failed_install(installation_id, services, knowledge,
                                       data_volume, retain_data=True):
            raise VesselInstallError(
                "release switch cleanup incomplete; prior state and data retained"
            ) from exc
        raise


def switch_stopped_vessel_release(root: Path, trusted_key: Path, crane: Path,
                                  bundle: Path,
                                  console_config: Path,
                                  receipt: Path, receipt_key: Path,
                                  password_file: Path, restic: Path,
                                  restic_sha256: str,
                                  staging_parent: Path) -> dict[str, object]:
    """Activate a new signed release only after a clean vessel stop and health."""
    with _operation_lock(root):
        current = _read_state(root)
        old = current["active"]
        _verify_stage(root / "vessel-releases" / old, trusted_key, old)
        state, password = Path(current["core_state"]), Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        recovery = _verify_preupdate_recovery(
            current, receipt, receipt_key, password_file, restic,
            restic_sha256, staging_parent, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        identifier = _release_id(bundle, console_config)
        if identifier == old:
            raise VesselInstallError("new vessel release equals active release")
        identifier, stage = _stage(root, bundle, trusted_key, console_config)
        return _activate_stopped(root, trusted_key, crane, current, identifier,
                                 stage, "upgraded", recovery)


def rollback_stopped_vessel_release(root: Path, trusted_key: Path,
                                    crane: Path, receipt: Path,
                                    receipt_key: Path, password_file: Path,
                                    restic: Path, restic_sha256: str,
                                    staging_parent: Path) -> dict[str, object]:
    """Re-activate the previous signed release after proving current recovery."""
    with _operation_lock(root):
        current = _read_state(root)
        previous = current.get("previous")
        if previous is None:
            raise VesselInstallError("no previous vessel release")
        _verify_stage(root / "vessel-releases" / current["active"],
                      trusted_key, current["active"])
        stage = root / "vessel-releases" / previous
        _verify_stage(stage, trusted_key, previous)
        state, password = Path(current["core_state"]), Path(current["lab_password_file"])
        _state_options(state, password, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        recovery = _verify_preupdate_recovery(
            current, receipt, receipt_key, password_file, restic,
            restic_sha256, staging_parent, root)
        _recovery_inventory(current["installation_id"], current["runtime"])
        return _activate_stopped(root, trusted_key, crane, current, previous,
                                 stage, "rolled-back", recovery)
