from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import httpx

from apps.api.main import Settings, create_app, search_fixture_documents
from apps.api.model import LocalModel, ModelTimeout, ModelUnavailable, validate_local_endpoint

ROOT = Path(__file__).resolve().parents[1]


class FakeModel:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.fail = False
        self.timeout = False
        self.ready = True

    async def check_ready(self) -> None:
        if not self.ready:
            raise ModelUnavailable("local model route unavailable")

    async def complete(self, question: str, context: list[dict[str, object]], *, general: bool = False) -> str:
        if self.timeout:
            raise ModelTimeout("local inference timed out")
        if self.fail:
            raise ModelUnavailable("local inference unavailable")
        self.calls.append({"question": question, "context": context, "general": general})
        return "Synthetic answer [ENG-001 v1]" if context else "Synthetic general answer"


class CoreApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixtures = Path(self.temporary.name)
        shutil.copy(ROOT / "fixtures/roles.json", self.fixtures / "roles.json")
        shutil.copy(ROOT / "fixtures/manifest.csv", self.fixtures / "manifest.csv")
        shutil.copytree(ROOT / "fixtures/sources", self.fixtures / "sources")
        self.model = FakeModel()
        self.app = create_app(Settings(fixture_root=self.fixtures, lab_password="synthetic-test-passphrase"), self.model)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://test")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.temporary.cleanup()

    async def login(self, user_id: str) -> dict[str, str]:
        reply = await self.client.post("/api/login", json={"user_id": user_id, "password": "synthetic-test-passphrase"})
        self.assertEqual(reply.status_code, 200)
        return {"Authorization": f"Bearer {reply.json()['access_token']}"}

    async def test_five_roles_login_and_removed_denied(self) -> None:
        for role in ("captain", "chief_engineer", "chief_stewardess", "deckhand", "avit_admin"):
            headers = await self.login(f"lab-{role}-1")
            reply = await self.client.get("/api/me", headers=headers)
            self.assertEqual(reply.json()["role"], role)
        for user in ("lab-removed-1", "unknown"):
            reply = await self.client.post("/api/login", json={"user_id": user, "password": "synthetic-test-passphrase"})
            self.assertEqual(reply.status_code, 401)
        self.assertEqual((await self.client.get("/api/models")).status_code, 401)

    async def test_chat_citations_history_and_cross_user_denial(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        deckhand = await self.login("lab-deckhand-1")
        reply = await self.client.post("/api/chat", headers=engineer,
                                       json={"message": "generator inspection", "mode": "documents"})
        self.assertEqual(reply.status_code, 200, reply.text)
        data = reply.json()
        self.assertEqual(data["citations"][0]["document_id"], "ENG-001")
        self.assertEqual(self.model.calls[0]["context"][0]["document_id"], "ENG-001")
        history = await self.client.get(f"/api/conversations/{data['conversation_id']}", headers=engineer)
        self.assertEqual(len(history.json()["turns"]), 1)
        denied = await self.client.get(f"/api/conversations/{data['conversation_id']}", headers=deckhand)
        self.assertEqual(denied.status_code, 404)

        before = len(self.model.calls)
        reply = await self.client.post("/api/chat", headers=deckhand,
                                       json={"message": "generator inspection", "mode": "documents"})
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()["citations"], [])
        self.assertEqual(len(self.model.calls), before)

    async def test_revocation_redacts_history_and_token(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        reply = await self.client.post("/api/chat", headers=engineer, json={"message": "generator inspection"})
        conversation_id = reply.json()["conversation_id"]
        policy = json.loads((self.fixtures / "roles.json").read_text())
        policy["allow"]["chief_engineer"] = ["deck"]
        (self.fixtures / "roles.json").write_text(json.dumps(policy))
        history = await self.client.get(f"/api/conversations/{conversation_id}", headers=engineer)
        self.assertEqual(history.json()["turns"][0]["mode"], "redacted")
        self.assertNotIn("Synthetic answer", history.text)
        policy["users"] = [user | {"status": "revoked"} if user["id"] == "lab-chief_engineer-1" else user
                           for user in policy["users"]]
        (self.fixtures / "roles.json").write_text(json.dumps(policy))
        self.assertEqual((await self.client.get("/api/me", headers=engineer)).status_code, 401)

    async def test_revocation_during_model_call_discards_chat_and_incident_answer(self) -> None:
        policy_path = self.fixtures / "roles.json"
        initial = policy_path.read_bytes()
        calls = 0

        async def revoke_during_model(question, context, **kwargs):
            nonlocal calls
            calls += 1
            policy = json.loads(policy_path.read_text())
            policy["users"] = [user | {"status": "revoked"}
                               if user["id"] == actor else user
                               for user in policy["users"]]
            policy_path.write_text(json.dumps(policy))
            return "Synthetic answer that must be discarded"

        self.model.complete = revoke_during_model
        for mode in ("documents", "general"):
            policy_path.write_bytes(initial)
            actor = "lab-chief_engineer-1"
            engineer = await self.login(actor)
            response = await self.client.post("/api/chat", headers=engineer,
                                              json={"message": "generator inspection",
                                                    "mode": mode})
            self.assertEqual(response.status_code, 403, response.text)
            self.assertNotIn("Synthetic answer", response.text)
            for conversation_id in self.app.state.sessions.list_conversations(actor):
                self.assertEqual(self.app.state.sessions.conversation(
                    conversation_id, actor).turns, [])

        policy_path.write_bytes(initial)
        actor = "lab-avit_admin-1"
        admin = await self.login(actor)
        listing = await self.client.get("/api/security/incidents", headers=admin)
        self.assertEqual(listing.status_code, 200)
        incident_id = listing.json()["incidents"][0]["incident_id"]
        response = await self.client.post(
            f"/api/security/incidents/{incident_id}/explain", headers=admin)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn("Synthetic answer", response.text)
        self.assertEqual(calls, 3)

    async def test_revocation_after_retrieval_blocks_model_context(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        policy_path = self.fixtures / "roles.json"

        def retrieve_then_revoke(*args, **kwargs):
            hits = search_fixture_documents(*args, **kwargs)
            self.assertTrue(hits)
            policy = json.loads(policy_path.read_text())
            policy["users"] = [user | {"status": "revoked"}
                               if user["id"] == "lab-chief_engineer-1" else user
                               for user in policy["users"]]
            policy_path.write_text(json.dumps(policy))
            return hits

        with patch("apps.api.main.search_fixture_documents", side_effect=retrieve_then_revoke):
            response = await self.client.post("/api/chat", headers=engineer,
                                              json={"message": "generator inspection"})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(self.model.calls, [])

    async def test_pending_policy_change_blocks_new_api_and_health_requests(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        marker = self.fixtures / "roles.json.pending"
        marker.write_text("synthetic pending change")
        try:
            self.assertEqual((await self.client.get("/api/me", headers=engineer)).status_code,
                             503)
            self.assertEqual((await self.client.get("/health")).status_code, 503)
        finally:
            marker.unlink()
        self.assertEqual((await self.client.get("/api/me", headers=engineer)).status_code,
                         200)

    async def test_optional_history_survives_restart_and_rechecks_scope(self) -> None:
        settings = Settings(fixture_root=self.fixtures, lab_password="synthetic-test-passphrase",
                            history_db=self.fixtures / "runtime/history.sqlite3")
        first = create_app(settings, self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=first), base_url="http://history") as client:
            login = await client.post("/api/login", json={"user_id": "lab-chief_engineer-1",
                                                      "password": "synthetic-test-passphrase"})
            engineer = {"Authorization": "Bearer " + login.json()["access_token"]}
            reply = await client.post("/api/chat", headers=engineer, json={"message": "generator inspection"})
            conversation_id = reply.json()["conversation_id"]
        restarted = create_app(settings, self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url="http://history") as client:
            login = await client.post("/api/login", json={"user_id": "lab-chief_engineer-1",
                                                      "password": "synthetic-test-passphrase"})
            engineer = {"Authorization": "Bearer " + login.json()["access_token"]}
            self.assertIn(conversation_id, (await client.get("/api/conversations", headers=engineer)).json()["conversation_ids"])
            history = await client.get(f"/api/conversations/{conversation_id}", headers=engineer)
            self.assertEqual(history.json()["turns"][0]["citations"][0]["document_id"], "ENG-001")
            login = await client.post("/api/login", json={"user_id": "lab-deckhand-1",
                                                      "password": "synthetic-test-passphrase"})
            deckhand = {"Authorization": "Bearer " + login.json()["access_token"]}
            self.assertEqual((await client.get(f"/api/conversations/{conversation_id}", headers=deckhand)).status_code, 404)
            policy = json.loads((self.fixtures / "roles.json").read_text())
            policy["allow"]["chief_engineer"] = ["deck"]
            (self.fixtures / "roles.json").write_text(json.dumps(policy))
            redacted = await client.get(f"/api/conversations/{conversation_id}", headers=engineer)
            self.assertEqual(redacted.json()["turns"][0]["mode"], "redacted")
            self.assertNotIn("Synthetic answer", redacted.text)

    async def test_source_tamper_redacts_history_and_hides_source_list(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        reply = await self.client.post("/api/chat", headers=engineer, json={"message": "generator inspection"})
        conversation_id = reply.json()["conversation_id"]
        (self.fixtures / "sources/ENG-001.txt").write_text("changed")
        listed = await self.client.get("/api/sources", headers=engineer)
        self.assertNotIn("ENG-001", [item["document_id"] for item in listed.json()["sources"]])
        history = await self.client.get(f"/api/conversations/{conversation_id}", headers=engineer)
        self.assertEqual(history.json()["turns"][0]["mode"], "redacted")

    async def test_model_selection_errors_and_source_filter(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        self.assertEqual((await self.client.post("/api/chat", headers=engineer,
                         json={"message": "hello", "model": "remote-model"})).status_code, 400)
        self.assertEqual((await self.client.post("/api/chat", headers=engineer,
                         json={"message": "hello", "unknown": "x"})).status_code, 422)
        sources = (await self.client.get("/api/sources", headers=engineer)).json()["sources"]
        self.assertNotIn("MAN-001", [item["document_id"] for item in sources])
        reply = await self.client.post("/api/chat", headers=engineer,
                                       json={"message": "generator inspection", "selected_documents": ["DEC-001"]})
        self.assertEqual(reply.json()["citations"], [])
        self.model.fail = True
        reply = await self.client.post("/api/chat", headers=engineer,
                                       json={"message": "generator inspection"})
        self.assertEqual(reply.status_code, 503)
        self.assertNotIn("generator inspection", reply.text)

    async def test_replaced_fixture_source_symlink_is_not_listed(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        listed = await self.client.get("/api/sources", headers=engineer)
        self.assertIn("ENG-001", [item["document_id"] for item in listed.json()["sources"]])
        source = self.fixtures / "sources/ENG-001.txt"
        payload = source.read_bytes()
        with tempfile.TemporaryDirectory() as outside:
            replacement = Path(outside) / "ENG-001.txt"
            replacement.write_bytes(payload)
            source.unlink()
            source.symlink_to(replacement)
            listed = await self.client.get("/api/sources", headers=engineer)
            self.assertNotIn("ENG-001", [item["document_id"] for item in listed.json()["sources"]])
            reply = await self.client.post("/api/chat", headers=engineer,
                                           json={"message": "generator inspection"})
            self.assertEqual(reply.json()["citations"], [])
            self.assertEqual(self.model.calls, [])

    async def test_logout(self) -> None:
        headers = await self.login("lab-deckhand-1")
        self.assertEqual((await self.client.post("/api/logout", headers=headers)).status_code, 200)
        self.assertEqual((await self.client.get("/api/me", headers=headers)).status_code, 401)

    async def test_body_rate_and_timeout_limits(self) -> None:
        oversize = await self.client.post("/api/login", content=b"x" * 17000,
                                          headers={"Content-Type": "application/json"})
        self.assertEqual(oversize.status_code, 413)
        engineer = await self.login("lab-chief_engineer-1")
        self.model.timeout = True
        reply = await self.client.post("/api/chat", headers=engineer, json={"message": "generator inspection"})
        self.assertEqual(reply.status_code, 504)
        self.model.timeout = False
        for _ in range(29):
            reply = await self.client.post("/api/chat", headers=engineer, json={"message": "zzznomatch"})
            self.assertEqual(reply.status_code, 200)
        self.assertEqual((await self.client.post("/api/chat", headers=engineer,
                          json={"message": "zzznomatch"})).status_code, 429)

    async def test_admin_and_workspace_scope(self) -> None:
        avit = await self.login("lab-avit_admin-1")
        engineer = await self.login("lab-chief_engineer-1")
        self.assertEqual((await self.client.get("/api/admin/status", headers=avit)).status_code, 200)
        self.assertEqual((await self.client.get("/api/admin/status", headers=engineer)).status_code, 403)
        self.assertEqual((await self.client.get("/api/admin/model-readiness", headers=engineer)).status_code, 403)
        self.assertEqual((await self.client.get("/api/admin/model-readiness", headers=avit)).json()["route"],
                         "advertised")
        self.model.ready = False
        self.assertEqual((await self.client.get("/api/admin/model-readiness", headers=avit)).status_code, 503)
        reply = await self.client.post("/api/chat", headers=engineer,
                                       json={"message": "generator inspection", "workspace": "deck"})
        self.assertEqual(reply.json()["citations"], [])
        self.assertEqual(self.model.calls, [])

    async def test_failed_local_model_does_not_create_empty_history(self) -> None:
        engineer = await self.login("lab-chief_engineer-1")
        before = (await self.client.get("/api/conversations", headers=engineer)).json()["conversation_ids"]
        self.model.fail = True
        reply = await self.client.post("/api/chat", headers=engineer,
                                       json={"mode": "general", "message": "synthetic outage"})
        self.assertEqual(reply.status_code, 503)
        after = (await self.client.get("/api/conversations", headers=engineer)).json()["conversation_ids"]
        self.assertEqual(after, before)
        persistent = create_app(Settings(fixture_root=self.fixtures,
                                         lab_password="synthetic-test-passphrase",
                                         history_db=self.fixtures / "persistent/history.db"),
                                self.model)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=persistent),
                                     base_url="http://persistent") as client:
            login = await client.post("/api/login", json={"user_id": "lab-chief_engineer-1",
                                                      "password": "synthetic-test-passphrase"})
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}
            self.assertEqual((await client.post("/api/chat", headers=headers,
                                                json={"mode": "general",
                                                      "message": "synthetic outage"})).status_code, 503)
            self.assertEqual((await client.get("/api/conversations", headers=headers)).json(),
                             {"conversation_ids": []})


class ModelBoundaryTests(unittest.TestCase):
    def test_only_loopback_model_endpoint(self) -> None:
        self.assertEqual(validate_local_endpoint("http://127.0.0.1:11434/v1"), "http://127.0.0.1:11434/v1")
        for endpoint in ("https://example.com/v1", "http://192.168.1.10:8000/v1",
                         "http://127.0.0.1:11434/admin", "http://user:pass@127.0.0.1:11434/v1",
                         "http://127.0.0.1:11434/v1?x=1"):
            with self.assertRaises(ValueError):
                validate_local_endpoint(endpoint)


class LocalModelAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_readiness_requires_matching_advertised_model(self) -> None:
        observed: list[str] = []

        def response(request: httpx.Request) -> httpx.Response:
            observed.append(str(request.url))
            return httpx.Response(200, json={"data": [{"id": "signed-model"}]})

        model = LocalModel("http://127.0.0.1:11434/v1", "signed-model",
                           transport=httpx.MockTransport(response))
        await model.check_ready()
        self.assertEqual(observed, ["http://127.0.0.1:11434/v1/models"])
        for payload in ({"data": [{"id": "other-model"}]}, {"data": "signed-model"}, {}):
            model = LocalModel("http://127.0.0.1:11434/v1", "signed-model",
                               transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload)))
            with self.assertRaises(ModelUnavailable):
                await model.check_ready()
        model = LocalModel("http://127.0.0.1:11434/v1", "signed-model",
                           transport=httpx.MockTransport(lambda _: httpx.Response(503)))
        with self.assertRaises(ModelUnavailable):
            await model.check_ready()
        model = LocalModel("http://127.0.0.1:11434/v1", "signed-model",
                           transport=httpx.MockTransport(lambda _: httpx.Response(
                               200, content=b" " * (64 * 1024 + 1))))
        with self.assertRaises(ModelUnavailable):
            await model.check_ready()

    async def test_incident_prompt_is_bounded_and_has_no_tools(self) -> None:
        requests: list[httpx.Request] = []

        def answer(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": "An alert was reported."}}]})

        model = LocalModel("http://127.0.0.1:11434/v1", "qwen3.5:2b",
                           transport=httpx.MockTransport(answer))
        await model.complete("synthetic alert facts", [], general=True,
                             system_instruction="One evidence-bound sentence.", max_tokens=96)
        payload = json.loads(requests[0].content)
        self.assertEqual(payload["messages"][0]["content"], "One evidence-bound sentence.")
        self.assertEqual(payload["max_tokens"], 96)
        self.assertNotIn("tools", payload)

    async def test_request_is_local_and_has_no_tools(self) -> None:
        requests: list[httpx.Request] = []

        def answer(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": "A cited answer"}}]})

        model = LocalModel("http://127.0.0.1:11434/v1", "qwen3.5:2b",
                           transport=httpx.MockTransport(answer))
        result = await model.complete("generator inspection", [{"document_id": "ENG-001", "version": "1",
                                                                 "excerpt": "Synthetic generator inspection."}])
        self.assertEqual(result, "A cited answer")
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:11434/v1/chat/completions")
        payload = json.loads(requests[0].content)
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertNotIn("tools", payload)
        self.assertIn("ENG-001", payload["messages"][1]["content"])

    async def test_timeout_is_distinct(self) -> None:
        def timeout(_: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("synthetic timeout")

        model = LocalModel("http://127.0.0.1:11434/v1", "qwen3.5:2b",
                           transport=httpx.MockTransport(timeout))
        with self.assertRaises(ModelTimeout):
            await model.complete("hello", [], general=True)
