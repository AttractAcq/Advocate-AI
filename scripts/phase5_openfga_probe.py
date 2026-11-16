"""Compare a loopback OpenFGA prototype with Sovereign's synthetic role matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

VERSION = "v1.22.1"
COLLECTIONS = ("management", "engineering", "interior", "deck", "restricted")
ROOT = Path(__file__).resolve().parents[1]


def _port() -> int:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def _post(base: str, path: str, body: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
    if not isinstance(result, dict):
        raise RuntimeError("invalid OpenFGA response")
    return result


def probe(binary: Path, expected_sha256: str) -> dict[str, object]:
    if (binary.is_symlink() or not binary.is_file() or
            hashlib.sha256(binary.read_bytes()).hexdigest() != expected_sha256):
        raise RuntimeError("OpenFGA binary hash mismatch")
    version = subprocess.run([str(binary), "version"], check=True,
                             capture_output=True, text=True, timeout=10)
    if VERSION not in version.stdout + version.stderr:
        raise RuntimeError("unapproved OpenFGA version")
    http_port, grpc_port = _port(), _port()
    while grpc_port == http_port:
        grpc_port = _port()
    process = subprocess.Popen([
        str(binary), "run", "--datastore-engine", "memory",
        "--http-addr", f"127.0.0.1:{http_port}",
        "--grpc-addr", f"127.0.0.1:{grpc_port}",
        "--metrics-enabled=false", "--playground-enabled=false",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{http_port}"
    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen(base + "/stores", timeout=1):
                    break
            except (urllib.error.URLError, TimeoutError):
                if process.poll() is not None:
                    raise RuntimeError("OpenFGA server exited during startup")
                time.sleep(0.1)
        else:
            raise RuntimeError("OpenFGA server did not start")
        store = _post(base, "/stores", {"name": "sovereign-synthetic-probe"})["id"]
        model = {"schema_version": "1.1", "type_definitions": [
            {"type": "user"},
            {"type": "department", "relations": {"member": {"this": {}}},
             "metadata": {"relations": {"member": {
                 "directly_related_user_types": [{"type": "user"}]}}}},
            {"type": "document", "relations": {"viewer": {"this": {}}},
             "metadata": {"relations": {"viewer": {
                 "directly_related_user_types": [
                     {"type": "department", "relation": "member"}]}}}},
        ]}
        model_id = _post(base, f"/stores/{store}/authorization-models", model)[
            "authorization_model_id"]
        policy = json.loads((ROOT / "fixtures/roles.json").read_text())
        grants = policy["allow"]
        tuples = []
        for role, allowed in grants.items():
            tuples.append({"user": f"user:{role}", "relation": "member",
                           "object": f"department:{role}"})
            for collection in allowed:
                tuples.append({"user": f"department:{role}#member", "relation": "viewer",
                               "object": f"document:{collection}"})
        _post(base, f"/stores/{store}/write",
              {"writes": {"tuple_keys": tuples}, "authorization_model_id": model_id})

        def check(role: str, collection: str) -> bool:
            response = _post(base, f"/stores/{store}/check", {
                "tuple_key": {"user": f"user:{role}", "relation": "viewer",
                              "object": f"document:{collection}"},
                "authorization_model_id": model_id,
                "consistency": "HIGHER_CONSISTENCY",
            })
            return response.get("allowed") is True

        checks = 0
        for role, allowed in grants.items():
            for collection in COLLECTIONS:
                if check(role, collection) != (collection in allowed):
                    raise AssertionError(f"OpenFGA disagrees for {role}/{collection}")
                checks += 1
        engineer = {"user": "user:chief_engineer", "relation": "member",
                    "object": "department:chief_engineer"}
        _post(base, f"/stores/{store}/write",
              {"deletes": {"tuple_keys": [engineer]}, "authorization_model_id": model_id})
        if check("chief_engineer", "engineering"):
            raise AssertionError("revoked engineering membership still permits retrieval")
        return {"status": "pass", "mode": "synthetic-memory-loopback",
                "role_collection_checks": checks, "revocation_denied": True,
                "version": VERSION}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic OpenFGA policy comparison")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.binary, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
