"""Explicit, reviewable retention for encrypted synthetic Fleet archives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from infrastructure.backup import BackupError
from infrastructure.deploy.fleet_backup import (
    FleetBackupError, _owner_directory, _owner_file, restore_fleet,
)
from infrastructure.deploy.fleet_backup_service import _archives, _backup_lock
from services.fleet.catalog import FleetError


class FleetRetentionError(ValueError):
    """The retention policy, preview or archive set failed validation."""


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _policy(path: Path) -> tuple[dict[str, int], str]:
    _owner_file(path)
    if path.stat().st_size > 4096:
        raise FleetRetentionError("retention policy is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (type(value) is not dict or set(value) !=
            {"schema", "keep_last", "max_age_hours"} or
            type(value["schema"]) is not int or value["schema"] != 1 or
            type(value["keep_last"]) is not int or
            not 2 <= value["keep_last"] <= 10000 or
            type(value["max_age_hours"]) is not int or
            not 1 <= value["max_age_hours"] <= 720):
        raise FleetRetentionError("invalid Fleet retention policy")
    return value, _digest(path)


def _inventory(directory: Path) -> list[dict[str, object]]:
    return [{"name": path.name, "bytes": path.stat().st_size,
             "sha256": _digest(path)} for path in _archives(directory, 10000)]


def plan_retention(directory: Path, policy_file: Path, output: Path) -> dict[str, object]:
    """Write an owner-only preview outside the archive directory; delete nothing."""
    _owner_directory(directory)
    _owner_directory(output.parent)
    if (output.is_relative_to(directory) or output.exists() or output.is_symlink() or
            policy_file.is_relative_to(directory)):
        raise FleetRetentionError("policy and new plan must be outside archive directory")
    policy, policy_hash = _policy(policy_file)
    with _backup_lock(directory, exclusive=False):
        inventory = _inventory(directory)
        if len(inventory) < policy["keep_last"]:
            raise FleetRetentionError("fewer archives than required keep count")
        retain = inventory[-policy["keep_last"]:]
        remove = inventory[:-policy["keep_last"]]
        details = directory.stat()
        preview = {"schema": 1, "directory": str(directory),
                   "directory_device": details.st_dev, "directory_inode": details.st_ino,
                   "policy": policy, "policy_sha256": policy_hash,
                   "created_utc": datetime.now(timezone.utc).isoformat(),
                   "inventory": inventory,
                   "retain": [item["name"] for item in retain],
                   "remove": [item["name"] for item in remove]}
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(preview, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            output.unlink(missing_ok=True)
            raise
        return {"plan": str(output), "plan_sha256": _digest(output),
                "retain": preview["retain"], "remove": preview["remove"]}


def apply_retention(directory: Path, policy_file: Path, plan_file: Path,
                    expected_sha256: str, key: Path) -> dict[str, object]:
    """Recheck exact inventory and clean restores before unlinking planned archives."""
    _owner_directory(directory)
    _owner_file(key)
    _owner_file(plan_file)
    if (plan_file.is_relative_to(directory) or policy_file.is_relative_to(directory) or
            len(expected_sha256) != 64 or
            any(ch not in "0123456789abcdef" for ch in expected_sha256) or
            _digest(plan_file) != expected_sha256 or plan_file.stat().st_size > 2_000_000):
        raise FleetRetentionError("Fleet retention plan mismatch or unsafe location")
    preview = json.loads(plan_file.read_text(encoding="utf-8"))
    if type(preview) is not dict or set(preview) != {
            "schema", "directory", "directory_device", "directory_inode", "policy",
            "policy_sha256", "created_utc", "inventory", "retain", "remove"}:
        raise FleetRetentionError("invalid Fleet retention plan")
    created = datetime.fromisoformat(preview["created_utc"])
    if created.tzinfo is None:
        raise FleetRetentionError("Fleet retention plan has no timezone")
    age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
    if age < -300 or age > 86400:
        raise FleetRetentionError("Fleet retention plan expired")
    policy, policy_hash = _policy(policy_file)
    if preview["schema"] != 1 or preview["directory"] != str(directory) or \
            preview["policy"] != policy or preview["policy_sha256"] != policy_hash:
        raise FleetRetentionError("Fleet retention policy or directory changed")
    with _backup_lock(directory, exclusive=True):
        details = directory.stat()
        inventory = _inventory(directory)
        if (preview["directory_device"] != details.st_dev or
                preview["directory_inode"] != details.st_ino or
                preview["inventory"] != inventory or
                preview["retain"] != [item["name"] for item in
                                      inventory[-policy["keep_last"]:]] or
                preview["remove"] != [item["name"] for item in
                                      inventory[:-policy["keep_last"]]]):
            raise FleetRetentionError("Fleet archive inventory changed; create a new plan")
        retained = inventory[-policy["keep_last"]:]
        if not retained:
            raise FleetRetentionError("no Fleet archives to retain")
        for item in retained:
            stage = Path(tempfile.mkdtemp(prefix=".fleet-retain-", dir=directory))
            try:
                restored = restore_fleet(directory / str(item["name"]), key,
                                         stage / "restored")
                if item is retained[-1]:
                    timestamp = datetime.fromisoformat(str(restored["created_utc"]))
                    if timestamp.tzinfo is None:
                        raise FleetRetentionError("backup timestamp has no timezone")
                    backup_age = (datetime.now(timezone.utc) - timestamp).total_seconds()
                    if backup_age < -300 or backup_age > policy["max_age_hours"] * 3600:
                        raise FleetRetentionError("latest Fleet backup is outside freshness limit")
            finally:
                shutil.rmtree(stage)
        removed = []
        for item in inventory[:-policy["keep_last"]]:
            archive = directory / str(item["name"])
            _owner_file(archive)
            if archive.stat().st_size != item["bytes"] or _digest(archive) != item["sha256"]:
                raise FleetRetentionError("Fleet archive changed during retention")
            archive.unlink()
            removed.append(item["name"])
        if [item["name"] for item in _inventory(directory)] != preview["retain"]:
            raise FleetRetentionError("Fleet archive inventory changed after retention")
        return {"removed": removed, "retained": preview["retain"],
                "clean_restore": "verified", "plan_sha256": expected_sha256}


def main() -> None:
    parser = argparse.ArgumentParser(description="Review and apply synthetic Fleet retention")
    actions = parser.add_subparsers(dest="action", required=True)
    plan = actions.add_parser("plan")
    plan.add_argument("--directory", required=True, type=Path)
    plan.add_argument("--policy", required=True, type=Path)
    plan.add_argument("--output", required=True, type=Path)
    apply = actions.add_parser("apply")
    apply.add_argument("--directory", required=True, type=Path)
    apply.add_argument("--policy", required=True, type=Path)
    apply.add_argument("--plan", required=True, type=Path)
    apply.add_argument("--plan-sha256", required=True)
    apply.add_argument("--key", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = (plan_retention(args.directory, args.policy, args.output)
                  if args.action == "plan" else
                  apply_retention(args.directory, args.policy, args.plan,
                                  args.plan_sha256, args.key))
    except (BackupError, FleetBackupError, FleetError, FleetRetentionError,
            OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"fleet-retention: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
