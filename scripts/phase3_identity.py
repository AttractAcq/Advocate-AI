"""Prepare and start a loopback-only Keycloak realm with synthetic users."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "infrastructure/lab/runtime/phase3-identity"
IMAGE_MANIFEST = ROOT / "infrastructure/lab/container-image.json"
_IMAGE = json.loads(IMAGE_MANIFEST.read_text(encoding="utf-8"))
IMAGE = f"{_IMAGE['name']}@{_IMAGE['digest']}"
NAME = "sovereign-keycloak-lab"
KEYCLOAK_BASE64_FLAG = "JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics"


def container_create_command() -> list[str]:
    """Describe the synthetic lab container without starting Docker."""
    return ["docker", "create", "--name", NAME, "--memory", "1g", "--pids-limit", "256",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "-p", "127.0.0.1:18086:8080", "--env-file", str(RUNTIME / "keycloak.env"),
            "-e", KEYCLOAK_BASE64_FLAG,
            IMAGE, "start-dev", "--import-realm", "--hostname=http://127.0.0.1:18086"]


def prepare() -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    realm_path = RUNTIME / "sovereign-lab-realm.json"
    env_path = RUNTIME / "keycloak.env"
    secret_path = RUNTIME / "test-credentials.json"
    if any(path.exists() for path in (realm_path, env_path, secret_path)):
        if not all(path.exists() for path in (realm_path, env_path, secret_path)):
            raise RuntimeError("partial identity state; inspect before retry")
        print("Synthetic realm already prepared")
        return
    realm = json.loads((ROOT / "infrastructure/lab/keycloak-realm.template.json").read_text())
    policy = json.loads((ROOT / "fixtures/roles.json").read_text())
    test_password = secrets.token_urlsafe(24)
    admin_password = secrets.token_urlsafe(32)
    realm["users"] = [
        {"username": user["id"], "enabled": user["status"] == "active",
         "firstName": "Synthetic", "lastName": user["role"],
         "email": f"{user['id']}@lab.invalid", "emailVerified": True,
         "requiredActions": [], "realmRoles": [user["role"]],
         "credentials": [{"type": "password", "value": test_password, "temporary": False}]}
        for user in policy["users"]
    ]
    for path, content in (
        (realm_path, json.dumps(realm, indent=2) + "\n"),
        (env_path, f"KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}\n"),
        (secret_path, json.dumps({"synthetic_user_password": test_password}, indent=2) + "\n"),
    ):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
    print(f"Prepared {len(realm['users'])} synthetic users; credentials remain in ignored runtime files")


def start() -> None:
    prepare()
    subprocess.run(container_create_command(), check=True)
    import_dir = RUNTIME / "import"
    import_dir.mkdir(exist_ok=True)
    shutil.copy2(RUNTIME / "sovereign-lab-realm.json", import_dir / "sovereign-lab-realm.json")
    # Docker copies this as root; Keycloak's non-root process must read the
    # generated synthetic-only import. The protected source remains 0600.
    (import_dir / "sovereign-lab-realm.json").chmod(0o644)
    subprocess.run(["docker", "cp", str(import_dir), f"{NAME}:/opt/keycloak/data/import"], check=True)
    subprocess.run(["docker", "start", NAME], check=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "start"}:
        raise SystemExit("usage: python -m scripts.phase3_identity prepare|start")
    (prepare if sys.argv[1] == "prepare" else start)()
