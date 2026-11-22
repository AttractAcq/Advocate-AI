# Explicit migration of the pre-version synthetic Knowledge schema

The first pgvector prototype created four Knowledge tables without a version
ledger. Current Core startup and vessel commands refuse that unversioned state.
The `migrate-legacy` action is an explicit lab path for that exact prior shape;
normal `init` and startup still refuse it. It adds only the schema-1 ledger and
leaves the existing passages and vectors in place.

Use a disposable synthetic database. Stop Core and ingestion writers, preserve
a tested database and source backup, and keep the approved manifest and source
tree frozen before running:

```sh
SOVEREIGN_KNOWLEDGE_DB=postgresql://postgres@127.0.0.1:55439/sovereign_pgvector_test \
  .venv/bin/python -m scripts.phase3_postgres_index migrate-legacy
```

The command uses the repository's fictional Phase 3 fixture and manifest. It
locks the four tables, requires the expected legacy columns and named validated
primary and foreign-key constraints, verifies the indexed source set and every passage
against the approved source bytes, then creates the version ledger in the same
database transaction. Missing sources, quarantine, altered passages, unknown
table shape and already-versioned databases refuse the migration. A failed
transaction does not leave a ledger behind. `verify_schema_version` must report
1 afterward; the ordinary Core and ingestion paths can then use the database.

This is not a production vessel migration command. It does not provision new
database grants, verify vector model quality, prove cross-version application
compatibility, or replace the coordinated encrypted recovery and target-host
rehearsal. An operator path for real vessel data needs a release-specific
migration plan, protected backup, rollback proof and independent review.
