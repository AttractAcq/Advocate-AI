#!/usr/bin/env python3
"""Exercise the synthetic Console proxy, Core, retrieval and local model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

import httpx

from scripts.evidence import stamp


def run(base_url: str, password: str) -> dict[str, object]:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("demo target must be a numeric loopback HTTP service")
    if len(password) < 12:
        raise ValueError("set a synthetic lab passphrase of at least 12 characters")
    roles = ("captain", "chief_engineer", "chief_stewardess", "deckhand", "avit_admin")
    with httpx.Client(base_url=base_url, timeout=100, trust_env=False) as client:
        page = client.get("/")
        assert page.status_code == 200 and b"/src/main.tsx" in page.content

        headers: dict[str, dict[str, str]] = {}
        for role in roles:
            user_id = f"lab-{role}-1"
            reply = client.post("/api/login", json={"user_id": user_id, "password": password})
            assert reply.status_code == 200, (role, reply.status_code)
            headers[role] = {"Authorization": f"Bearer {reply.json()['access_token']}"}
            assert client.get("/api/me", headers=headers[role]).json()["role"] == role
        for user_id in ("lab-removed-1", "unknown"):
            reply = client.post("/api/login", json={"user_id": user_id, "password": password})
            assert reply.status_code == 401

        question = "What is the verification marker in the Generator inspection procedure?"
        started = time.monotonic()
        reply = client.post("/api/chat", headers=headers["chief_engineer"],
                            json={"message": question, "mode": "documents", "workspace": "engineering"})
        elapsed = round(time.monotonic() - started, 3)
        assert reply.status_code == 200, (reply.status_code, reply.text[:300])
        answer = reply.json()
        assert "SYN-ENGINEERING-001-ALPHA" in answer["answer"]
        assert [item["document_id"] for item in answer["citations"]] == ["ENG-001"]
        history = client.get(f"/api/conversations/{answer['conversation_id']}",
                             headers=headers["chief_engineer"])
        assert history.status_code == 200 and len(history.json()["turns"]) == 1
        assert client.get(f"/api/conversations/{answer['conversation_id']}",
                          headers=headers["deckhand"]).status_code == 404

        denied = client.post("/api/chat", headers=headers["deckhand"],
                             json={"message": "Private itinerary", "mode": "documents"})
        assert denied.status_code == 200 and denied.json()["citations"] == []
        assert "No matching permitted source" in denied.json()["answer"]
        assert client.get("/api/admin/status", headers=headers["avit_admin"]).status_code == 200
        assert client.get("/api/admin/status", headers=headers["chief_engineer"]).status_code == 403

        return {
            "schema": 1,
            **stamp(),
            "target": base_url,
            "accounts_checked": list(roles),
            "removed_and_unknown_denied": True,
            "question_id": "Q-ENG-001",
            "model": answer["model"],
            "citation_ids": [item["document_id"] for item in answer["citations"]],
            "answer_contains_expected_marker": True,
            "answer_sha256": hashlib.sha256(answer["answer"].encode()).hexdigest(),
            "answer_excerpt": answer["answer"][:250],
            "chat_seconds": elapsed,
            "history_and_cross_user_checks": True,
            "restricted_document_denied": True,
            "admin_scope_checked": True,
            "wan_disconnected": False,
            "packet_capture_recorded": False,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18101")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.base_url, os.environ.get("SOVEREIGN_LAB_PASSWORD", ""))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
