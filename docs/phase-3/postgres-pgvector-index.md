# Synthetic PostgreSQL and pgvector knowledge index

The Phase 3 index can now use a local PostgreSQL database with pgvector. Core
selects it when `SOVEREIGN_KNOWLEDGE_DB` is a `postgresql://` URI. The existing
SQLite path remains the default synthetic lab path. The PostgreSQL adapter
reuses the approved manifest, bounded parser, policy and live source-byte
checks before search, preview, chat citation or vector ranking. Source and
passage replacement, quarantine and deletion occur in one database transaction.
Ingestion and embedding writers share a database advisory transaction lock.

The adapter requires a numeric loopback URI with a named user and database. It
rejects a password in the URI; use a separately protected local PostgreSQL
credential mechanism when authentication is introduced. It never silently
falls back to SQLite after a PostgreSQL error. The `init` action requires a
database where the `vector` extension was installed separately by a migration
role. The application role should have only the table privileges it needs;
roles and network policy still require target design and review.

## Disposable lab rehearsal

The [CI job](../../.github/workflows/ci.yml) uses the official pgvector image
at digest `sha256:b513c48566e4777cd3370451400000c78eda6a08131d68f4c31d4a76f27bd8fd`.
It binds PostgreSQL to loopback, uses a disposable database and runs the Core
API, source permission, revocation, deletion, manifest failure and vector
ranking tests. A local reproduction after starting a temporary container is:

```sh
uv sync --locked --extra phase3
export SOVEREIGN_KNOWLEDGE_DB=postgresql://postgres@127.0.0.1:55439/sovereign_pgvector_test
.venv/bin/python -m scripts.phase3_postgres_index init
.venv/bin/python -m scripts.phase3_postgres_index sync
.venv/bin/python -m scripts.phase3_postgres_index vectors
SOVEREIGN_TEST_PG_DSN="$SOVEREIGN_KNOWLEDGE_DB" \
  .venv/bin/python -m unittest tests.test_phase3_postgres_index -v
```

The synthetic Core API can use the same URI together with
`SOVEREIGN_KNOWLEDGE_MANIFEST=fixtures/phase-3/approved-sources.json`.
`scripts.phase3_reconcile` also accepts that URI from the environment. The
`vectors` action calls the numeric loopback embedding service; it cannot run
until the approved model is present locally. The tests use a deterministic
synthetic embedder and do not require a model download.

An [encrypted knowledge recovery rehearsal](../phase-5/pgvector-knowledge-recovery.md)
now captures the database with its manifest, policy and source bytes and
checks a clean restore. This is a software candidate, not the Phase 3 target
gate. PostgreSQL is not yet included in the signed vessel runtime or
coordinated full-stack recovery set. Index ownership, database credentials,
extension migration, target backup and restore, failure handling, target network isolation, NAS access propagation,
semantic quality and independent security review remain open. The current
vector query uses exact pgvector cosine ranking on policy-filtered candidate
documents; the exact-term guard still limits semantic recall.
