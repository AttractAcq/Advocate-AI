"""Compare a loopback OpenFGA prototype with synthetic collection and source policy."""

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

from services.policy.decision import may_read, may_read_document

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
            {"type": "source", "relations": {
                "parent": {"this": {}},
                "permitted": {"this": {}},
                "blocked": {"this": {}},
                "can_view": {"difference": {
                    "base": {"intersection": {"child": [
                        {"tupleToUserset": {
                            "tupleset": {"object": "", "relation": "parent"},
                            "computedUserset": {"object": "", "relation": "viewer"}}},
                        {"computedUserset": {"object": "", "relation": "permitted"}},
                    ]}},
                    "subtract": {"computedUserset": {
                        "object": "", "relation": "blocked"}},
                }},
            }, "metadata": {"relations": {
                "parent": {"directly_related_user_types": [{"type": "document"}]},
                "permitted": {"directly_related_user_types": [
                    {"type": "department", "relation": "member"}]},
                "blocked": {"directly_related_user_types": [{"type": "user"}]},
            }}},
        ]}
        model_id = _post(base, f"/stores/{store}/authorization-models", model)[
            "authorization_model_id"]
        policy = json.loads((ROOT / "fixtures/roles.json").read_text())
        grants = policy["allow"]
        policy["document_rules"] = {
            "MAN-001": {"allow_roles": ["captain"],
                        "deny_users": ["lab-captain-1"]},
            "ENG-001": {"allow_roles": ["chief_engineer"],
                        "deny_users": ["lab-chief_engineer-1"]},
        }
        sources = [
            {"document_id": "MAN-001", "collection": "management",
             "classification": "C0_SYNTHETIC_MANAGEMENT"},
            {"document_id": "ENG-001", "collection": "engineering",
             "classification": "C0_SYNTHETIC_ENGINEERING"},
            {"document_id": "DEC-001", "collection": "deck",
             "classification": "C0_SYNTHETIC_DECK"},
            {"document_id": "BAD-001", "collection": "deck",
             "classification": "UNKNOWN"},
        ]
        tuples = []
        for role, allowed in grants.items():
            tuples.append({"user": f"user:{role}", "relation": "member",
                           "object": f"department:{role}"})
            for collection in allowed:
                tuples.append({"user": f"department:{role}#member", "relation": "viewer",
                               "object": f"document:{collection}"})
        for user in policy["users"]:
            if user["status"] == "active":
                tuples.append({"user": f"user:{user['id']}", "relation": "member",
                               "object": f"department:{user['role']}"})
        for source in sources:
            identifier = source["document_id"]
            collection = source["collection"]
            if source["classification"] == f"C0_SYNTHETIC_{collection.upper()}":
                tuples.append({"user": f"document:{collection}", "relation": "parent",
                               "object": f"source:{identifier}"})
            rule = policy["document_rules"].get(identifier, {})
            for role in rule.get("allow_roles", grants):
                tuples.append({"user": f"department:{role}#member",
                               "relation": "permitted", "object": f"source:{identifier}"})
            for user_id in rule.get("deny_users", []):
                tuples.append({"user": f"user:{user_id}", "relation": "blocked",
                               "object": f"source:{identifier}"})
        _post(base, f"/stores/{store}/write",
              {"writes": {"tuple_keys": tuples}, "authorization_model_id": model_id})

        def check(user: str, relation: str, object_id: str) -> bool:
            response = _post(base, f"/stores/{store}/check", {
                "tuple_key": {"user": f"user:{user}", "relation": relation,
                              "object": object_id},
                "authorization_model_id": model_id,
                "consistency": "HIGHER_CONSISTENCY",
            })
            return response.get("allowed") is True

        def listed_sources(user: str) -> set[str]:
            response = _post(base, f"/stores/{store}/list-objects", {
                "user": f"user:{user}", "relation": "can_view",
                "type": "source", "authorization_model_id": model_id,
                "consistency": "HIGHER_CONSISTENCY",
            })
            objects = response.get("objects")
            if (not isinstance(objects, list) or
                    any(not isinstance(item, str) or not item.startswith("source:")
                        for item in objects) or len(objects) != len(set(objects))):
                raise RuntimeError("invalid OpenFGA source listing")
            return set(objects)

        checks = 0
        for role, allowed in grants.items():
            for collection in COLLECTIONS:
                if check(role, "viewer", f"document:{collection}") != (collection in allowed):
                    raise AssertionError(f"OpenFGA disagrees for {role}/{collection}")
                checks += 1
        source_checks = 0
        for user in policy["users"]:
            expected_sources: set[str] = set()
            for source in sources:
                expected = (may_read(user["id"], source["collection"], policy) and
                            may_read_document(user["id"], source, policy))
                if expected:
                    expected_sources.add(f"source:{source['document_id']}")
                if check(user["id"], "can_view",
                         f"source:{source['document_id']}") != expected:
                    raise AssertionError(
                        f"OpenFGA disagrees for {user['id']}/{source['document_id']}")
                source_checks += 1
            if listed_sources(user["id"]) != expected_sources:
                raise AssertionError(f"OpenFGA source listing differs for {user['id']}")
        def change(*, writes: list[dict[str, str]] | None = None,
                   deletes: list[dict[str, str]] | None = None) -> None:
            body: dict[str, object] = {"authorization_model_id": model_id}
            if writes:
                body["writes"] = {"tuple_keys": writes}
            if deletes:
                body["deletes"] = {"tuple_keys": deletes}
            _post(base, f"/stores/{store}/write", body)

        def require_denied_after_delete(tuple_key: dict[str, str],
                                        user_id: str, source_id: str) -> None:
            if not check(user_id, "can_view", f"source:{source_id}"):
                raise AssertionError("expected source grant is absent before revocation")
            change(deletes=[tuple_key])
            if check(user_id, "can_view", f"source:{source_id}"):
                raise AssertionError("revoked source grant still permits retrieval")
            if f"source:{source_id}" in listed_sources(user_id):
                raise AssertionError("revoked source remains in document listing")
            change(writes=[tuple_key])

        require_denied_after_delete(
            {"user": "user:lab-captain-2", "relation": "member",
             "object": "department:captain"}, "lab-captain-2", "MAN-001")
        require_denied_after_delete(
            {"user": "department:chief_engineer#member", "relation": "permitted",
             "object": "source:ENG-001"}, "lab-chief_engineer-2", "ENG-001")
        require_denied_after_delete(
            {"user": "department:chief_engineer#member", "relation": "viewer",
             "object": "document:engineering"}, "lab-chief_engineer-2", "ENG-001")
        denied = {"user": "user:lab-captain-1", "relation": "blocked",
                  "object": "source:MAN-001"}
        if check("lab-captain-1", "can_view", "source:MAN-001"):
            raise AssertionError("document-level deny lost precedence")
        change(deletes=[denied])
        if not check("lab-captain-1", "can_view", "source:MAN-001"):
            raise AssertionError("removed document deny did not restore access")
        change(writes=[denied])
        if check("lab-captain-1", "can_view", "source:MAN-001"):
            raise AssertionError("restored document deny did not take effect")
        engineer = {"user": "user:chief_engineer", "relation": "member",
                    "object": "department:chief_engineer"}
        change(deletes=[engineer])
        if check("chief_engineer", "viewer", "document:engineering"):
            raise AssertionError("revoked engineering membership still permits retrieval")
        return {"status": "pass", "mode": "synthetic-memory-loopback",
                "role_collection_checks": checks, "revocation_denied": True,
                "source_checks": source_checks,
                "source_listing_checks": len(policy["users"]) + 3,
                "document_deny_precedence": True,
                "membership_collection_and_source_revocation": True,
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
