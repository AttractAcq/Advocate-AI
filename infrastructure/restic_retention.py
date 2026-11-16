"""Reviewable retention for Sovereign-tagged local restic snapshots."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re

from infrastructure.restic_repository import (
    RESTIC_VERSION, SNAPSHOT_HOST, SNAPSHOT_TAG, ResticError, _preflight, _run,
)
from infrastructure.backup import _unique_object

_ID = re.compile(r"[0-9a-f]{64}\Z")
MAX_PLAN_BYTES = 64 * 1024
MAX_REMOVAL = 100


def _read_policy(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ResticError("retention policy is missing, linked or too large")
    try:
        policy = json.loads(path.read_bytes(), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as exc:
        raise ResticError("invalid retention policy JSON") from exc
    if (not isinstance(policy, dict) or set(policy) != {"schema", "keep_last", "keep_within_days"}
            or type(policy["schema"]) is not int or policy["schema"] != 1
            or type(policy["keep_last"]) is not int or not 2 <= policy["keep_last"] <= 1000
            or (policy["keep_within_days"] is not None and
                (type(policy["keep_within_days"]) is not int or
                 not 1 <= policy["keep_within_days"] <= 3650))):
        raise ResticError("invalid retention policy fields")
    return policy


def _json_command(restic: Path, repository: Path, password_file: Path,
                  *arguments: str) -> object:
    try:
        return json.loads(_run(restic, repository, password_file, *arguments))
    except (ValueError, UnicodeError) as exc:
        raise ResticError(f"invalid restic {arguments[0]} JSON") from exc


def _repository_id(restic: Path, repository: Path, password_file: Path) -> str:
    config = _json_command(restic, repository, password_file, "cat", "config")
    identifier = config.get("id") if isinstance(config, dict) else None
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ResticError("invalid repository identity")
    return identifier


def _ids(rows: object) -> list[str]:
    if not isinstance(rows, list):
        raise ResticError("invalid restic snapshot list")
    result: list[str] = []
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                or not _ID.fullmatch(row["id"]) or row.get("hostname") != SNAPSHOT_HOST
                or not isinstance(row.get("tags"), list) or SNAPSHOT_TAG not in row["tags"]):
            raise ResticError("snapshot is outside the Sovereign retention scope")
        result.append(row["id"])
    if len(result) != len(set(result)):
        raise ResticError("duplicate snapshot ID")
    return sorted(result)


def _plan(restic: Path, repository: Path, password_file: Path,
          policy: dict[str, object]) -> dict[str, object]:
    repo_id = _repository_id(restic, repository, password_file)
    all_ids = _ids(_json_command(restic, repository, password_file, "snapshots", "--json",
                                 "--tag", SNAPSHOT_TAG, "--host", SNAPSHOT_HOST))
    args = ["forget", "--tag", SNAPSHOT_TAG, "--host", SNAPSHOT_HOST,
            "--group-by", "", "--keep-last", str(policy["keep_last"])]
    if policy["keep_within_days"] is not None:
        args.extend(["--keep-within", f"{policy['keep_within_days']}d"])
    groups = _json_command(restic, repository, password_file, *args, "--dry-run", "--json")
    if not isinstance(groups, list) or len(groups) > 1 or (all_ids and len(groups) != 1):
        raise ResticError("unexpected retention groups")
    group = groups[0] if groups else {"keep": [], "remove": []}
    if not isinstance(group, dict):
        raise ResticError("invalid retention group")
    keep = _ids(group.get("keep"))
    remove = _ids(group.get("remove"))
    if (set(keep) & set(remove) or sorted(keep + remove) != all_ids or
            len(keep) < min(2, len(all_ids)) or len(remove) > MAX_REMOVAL):
        raise ResticError("unsafe retention preview")
    return {"schema": 1, "repository_id": repo_id, "scope": {"tag": SNAPSHOT_TAG,
            "host": SNAPSHOT_HOST}, "policy": policy, "snapshot_ids": all_ids,
            "keep_ids": keep, "remove_ids": remove, "restic_version": RESTIC_VERSION}


def create_plan(policy_path: Path, repository: Path, password_file: Path,
                restic: Path, restic_sha256: str, output: Path) -> dict[str, object]:
    """Write an owner-only dry-run plan; do not remove snapshots."""
    _preflight(restic, restic_sha256, repository, password_file)
    policy = _read_policy(policy_path)
    if (output.exists() or output.is_symlink() or not output.parent.is_dir() or
            output.absolute().is_relative_to(repository.resolve())):
        raise ResticError("retention plan must be new and outside the repository")
    plan = _plan(restic, repository, password_file, policy)
    plan["created_utc"] = datetime.now(timezone.utc).isoformat()
    raw = (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > MAX_PLAN_BYTES:
        raise ResticError("retention plan exceeds size limit")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return {"status": "planned", "plan_sha256": hashlib.sha256(raw).hexdigest(),
            "keep": len(plan["keep_ids"]), "remove": len(plan["remove_ids"])}


def apply_plan(plan_path: Path, plan_sha256: str, repository: Path, password_file: Path,
               restic: Path, restic_sha256: str) -> dict[str, object]:
    """Recheck the exact preview, then forget only its listed snapshot IDs."""
    _preflight(restic, restic_sha256, repository, password_file)
    if (plan_path.is_symlink() or not plan_path.is_file() or
            plan_path.stat().st_size > MAX_PLAN_BYTES or
            plan_path.absolute().is_relative_to(repository.resolve())):
        raise ResticError("retention plan is missing, linked or unsafe")
    raw = plan_path.read_bytes()
    if (not _ID.fullmatch(plan_sha256) or hashlib.sha256(raw).hexdigest() != plan_sha256):
        raise ResticError("retention plan hash mismatch")
    try:
        saved = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as exc:
        raise ResticError("invalid retention plan JSON") from exc
    if not isinstance(saved, dict) or set(saved) != {
            "schema", "repository_id", "scope", "policy", "snapshot_ids",
            "keep_ids", "remove_ids", "restic_version", "created_utc"}:
        raise ResticError("invalid retention plan fields")
    policy = saved["policy"]
    if (not isinstance(policy, dict) or set(policy) != {"schema", "keep_last", "keep_within_days"}
            or type(policy["schema"]) is not int or policy["schema"] != 1
            or type(policy["keep_last"]) is not int or not 2 <= policy["keep_last"] <= 1000
            or (policy["keep_within_days"] is not None and
                (type(policy["keep_within_days"]) is not int or
                 not 1 <= policy["keep_within_days"] <= 3650))):
        raise ResticError("invalid saved retention policy")
    try:
        created = datetime.fromisoformat(saved["created_utc"])
    except (TypeError, ValueError) as exc:
        raise ResticError("invalid retention plan timestamp") from exc
    now = datetime.now(timezone.utc)
    if created.tzinfo is None or created > now or now - created > timedelta(hours=24):
        raise ResticError("retention plan is stale")
    current = _plan(restic, repository, password_file, policy)
    if any(saved[key] != current[key] for key in current):
        raise ResticError("repository changed since retention preview")
    remove = current["remove_ids"]
    if not remove:
        return {"status": "unchanged", "removed": 0, "kept": len(current["keep_ids"])}
    _run(restic, repository, password_file, "check", "--read-data")
    _run(restic, repository, password_file, "forget", *remove, "--prune")
    _run(restic, repository, password_file, "check", "--read-data")
    remaining = _ids(_json_command(restic, repository, password_file, "snapshots", "--json",
                                   "--tag", SNAPSHOT_TAG, "--host", SNAPSHOT_HOST))
    if remaining != current["keep_ids"]:
        raise ResticError("unexpected snapshot inventory after retention")
    return {"status": "applied", "removed": len(remove), "kept": len(remaining)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Reviewable local restic snapshot retention")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "apply"):
        command = commands.add_parser(name)
        command.add_argument("--repository", required=True, type=Path)
        command.add_argument("--password-file", required=True, type=Path)
        command.add_argument("--restic", required=True, type=Path)
        command.add_argument("--restic-sha256", required=True)
        if name == "plan":
            command.add_argument("--policy", required=True, type=Path)
            command.add_argument("--output", required=True, type=Path)
        else:
            command.add_argument("--plan", required=True, type=Path)
            command.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            result = create_plan(args.policy, args.repository, args.password_file,
                                 args.restic, args.restic_sha256, args.output)
        else:
            result = apply_plan(args.plan, args.plan_sha256, args.repository,
                                args.password_file, args.restic, args.restic_sha256)
    except (ResticError, OSError, ValueError) as exc:
        parser.exit(1, f"restic retention: {exc}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
