"""Static guardrails for the synthetic loopback lab configuration."""

from __future__ import annotations

import json
from pathlib import Path
import re

from infrastructure.deploy.installer import InstallError, validate_config
from scripts.phase3_identity import container_create_command

ROOT = Path(__file__).resolve().parents[1]
_IMAGE_NAME = "quay.io/keycloak/keycloak"
_SERVICES = {"console", "core", "knowledge", "policy", "intelligence", "wazuh-simulator"}


def scan(config: object, topology: object, image: object, command: list[str]) -> list[str]:
    issues: list[str] = []
    try:
        valid_config = validate_config(config)
    except InstallError:
        issues.append("installer configuration violates the synthetic loopback schema")
        valid_config = None
    if not isinstance(topology, dict) or (topology.get("schema") != 1 or
        topology.get("mode") != "loopback-simulation" or topology.get("bind") != "127.0.0.1" or
        topology.get("no_wan_egress_required") is not True):
        issues.append("lab topology boundary is invalid")
    else:
        names = topology.get("dns", {}).get("names") if isinstance(topology.get("dns"), dict) else None
        if not isinstance(names, dict) or not names or any(ip != "127.0.0.1" for ip in names.values()):
            issues.append("lab DNS points outside loopback")
        services = topology.get("services")
        if (not isinstance(services, dict) or set(services) != _SERVICES or
                valid_config is None or services != valid_config["services"]):
            issues.append("lab service ports disagree with installer configuration")
    if (not isinstance(image, dict) or set(image) != {"schema", "purpose", "name", "version", "digest"} or
            image.get("schema") != 1 or image.get("purpose") != "synthetic Keycloak lab only" or
            image.get("name") != _IMAGE_NAME or image.get("version") != "26.8.2" or
            not isinstance(image.get("digest"), str) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", image["digest"])):
        issues.append("lab container image is not an approved digest reference")
        image_ref = None
    else:
        image_ref = f"{image['name']}@{image['digest']}"
    command_shape = (isinstance(command, list) and command[:2] == ["docker", "create"] and
                     image_ref is not None and command.count(image_ref) == 1 and
                     command.count("-p") == 1 and "127.0.0.1:18086:8080" in command and
                     command.count("--cap-drop") == 1 and
                     command.index("--cap-drop") + 1 < len(command) and
                     command[command.index("--cap-drop") + 1] == "ALL")
    if not command_shape:
        issues.append("lab container command has an unsafe identity or network shape")
    if isinstance(command, list):
        required = {"--memory": "1g", "--pids-limit": "256",
                    "--security-opt": "no-new-privileges:true"}
        for flag, value in required.items():
            if command.count(flag) != 1 or command.index(flag) + 1 >= len(command) or command[command.index(flag) + 1] != value:
                issues.append(f"lab container is missing {flag} limit")
        forbidden = ("--privileged", "--cap-add", "--network", "--pid", "--mount",
                     "--publish", "--volume", "--user")
        if any(token in {"-v", "-P"} or
               any(token == flag or token.startswith(flag + "=") for flag in forbidden)
               for token in command):
            issues.append("lab container requests a privileged or host resource")
        if any(token.startswith("0.0.0.0:") or token.startswith("[::]:") for token in command):
            issues.append("lab container publishes a public port")
    return issues


def main() -> None:
    try:
        config = json.loads((ROOT / "infrastructure/deploy/lab-config.json").read_text(encoding="utf-8"))
        topology = json.loads((ROOT / "infrastructure/lab/topology.json").read_text(encoding="utf-8"))
        image = json.loads((ROOT / "infrastructure/lab/container-image.json").read_text(encoding="utf-8"))
        issues = scan(config, topology, image, container_create_command())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issues = [f"configuration scan could not read or validate inputs: {type(exc).__name__}"]
    print(json.dumps({"status": "pass" if not issues else "fail", "checks": 4,
                      "issues": issues}, sort_keys=True))
    if issues:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
