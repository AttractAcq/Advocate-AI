# Phase 3 local synthetic runbook

Run from the repository root. Use generated fixtures only. No vessel document
or credential should be placed in this lab.

1. Install the pinned Python environment and regenerate fixtures:

   ```sh
   uv sync --locked --extra phase3
   make fixtures
   make check
   ```

2. Prepare the local embedding model once on the connected development Mac:

   ```sh
   ollama pull embeddinggemma:300m
   ollama list
   ```

   The running application only calls the loopback `/api/embed` endpoint. It
   never pulls a model at request time. The [model card](https://ollama.com/library/embeddinggemma%3A300m)
   describes the 300M test model. Package the exact model digest for a future
   disconnected lab run.

3. Build the local index and run the fixed retrieval evaluation:

   ```sh
   .venv/bin/python -m scripts.phase3_evaluate
   ```

   This writes the SQLite index under ignored `infrastructure/lab/runtime/`
   and the per-case report to [evaluation.json](evaluation.json). The index is
   a Mac simulation; the target PostgreSQL/pgvector service is not deployed.

4. Prepare and start synthetic Keycloak on loopback. The script creates random
   test passwords in ignored runtime files; it does not print them:

   ```sh
   .venv/bin/python -m scripts.phase3_identity prepare
   .venv/bin/python -m scripts.phase3_identity start
   ```

   The pinned container is `quay.io/keycloak/keycloak:26.8.2`, exposed only on
   `127.0.0.1:18086`. Its realm import has named synthetic users, five roles,
   a public Console client with PKCE and a Core audience. Keycloak's
   [container guide](https://www.keycloak.org/server/containers) documents
   the import mechanism. The `start-dev` mode and direct password grant in
   this lab realm are test-only. Production identity needs TLS, persistent
   storage, MFA, service identities and a reviewed admin process.

5. Start Core and Console with the Phase 3 index and local identity:

   ```sh
   SOVEREIGN_KNOWLEDGE_MANIFEST=fixtures/phase-3/approved-sources.json \
   SOVEREIGN_KNOWLEDGE_DB=infrastructure/lab/runtime/phase3-knowledge/index.sqlite3 \
   SOVEREIGN_AUDIT_PATH=infrastructure/lab/runtime/phase3-audit/events.jsonl \
   SOVEREIGN_HISTORY_DB=infrastructure/lab/runtime/phase3-history/conversations.sqlite3 \
   SOVEREIGN_OIDC_ISSUER=http://127.0.0.1:18086/realms/sovereign-lab \
   .venv/bin/uvicorn apps.api.main:app --host 127.0.0.1 --port 18100
   ```

   ```sh
   cd apps/console/web
   VITE_OIDC_ISSUER=http://127.0.0.1:18086/realms/sovereign-lab \
   npm run dev -- --host 127.0.0.1 --port 18101
   ```

   Open `http://127.0.0.1:18101/`. The browser uses Keycloak's authorization
   code flow with PKCE. The local container's generated credentials are in
   ignored `infrastructure/lab/runtime/phase3-identity/test-credentials.json`.

6. Run source access and audit tests with `make test`. The indexed search API
   accepts `POST /api/search` with `query`, `mode` (`lexical` or `vector`),
   optional selected documents and workspace. The preview path is
   `GET /api/sources/{document_id}/preview`. All paths recheck the current
   manifest, source hash and role policy. The audit log contains actor, action,
   resource, decision, policy hash, timestamp and correlation ID, without the
   prompt or passage body. Its hash-chain verifier is
   `services.policy.audit.verify`.

   `SOVEREIGN_HISTORY_DB` enables optional restart-persistent **synthetic**
   conversations. The local SQLite file is restricted to the process account
   and each read rechecks current source permissions. It contains prompt and
   answer text and is not encrypted; do not place vessel data in it. Vessel
   retention, encryption and backup key custody require separate approval.

## Boundaries

The local demo uses generated documents and Keycloak development mode. It
does not validate NAS service-account permissions, production TLS, MFA,
emergency access, PostgreSQL/pgvector, a disconnected target host or an
independent security review. These remain open in [gate.md](gate.md).

