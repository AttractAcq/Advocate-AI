# Synthetic pgvector knowledge recovery set

The [Phase 3 PostgreSQL index](../phase-3/postgres-pgvector-index.md) now has a
clean restore rehearsal. Two synthetic sources, their approved manifest and
role policy, the PostgreSQL database dump and its pgvector embeddings are
captured in one encrypted restic snapshot. The source index writer and vector
writer use the same PostgreSQL advisory lock held during the dump; the policy
directory lock is also held while the source set is frozen. The script checks
that the frozen source bytes and manifest match the database before and after
the dump.

The rehearsal restores the snapshot into a new private directory and the dump
into a fresh pgvector database. It re-parses every approved source and compares
every stored passage, metadata row and vector inventory. It then checks
permission-filtered lexical and vector results and proves a restored policy
revocation denies access. A forged passage or missing vector fails the
verifier in separate integration tests.

CI uses the digest-pinned official pgvector image, a loopback host binding,
disposable trust authentication and the [pinned restic adapter](restic-repository.md).
The local run passed with two sources and two passages. The command is:

```sh
.venv/bin/python -m scripts.phase3_pgvector_recovery \
  --image docker.io/pgvector/pgvector@sha256:b513c48566e4777cd3370451400000c78eda6a08131d68f4c31d4a76f27bd8fd \
  --restic /path/to/verified/restic \
  --restic-sha256 <sha256-of-extracted-restic-binary>
```

The snapshot is still a synthetic candidate. It does not replace the current
signed Core recovery set, which contains SQLite knowledge state. A production
design must bind PostgreSQL to the installed Core runtime, provision separate
database and migration identities, establish protected authentication and
network controls, include history, audit, identity and other services in a
coordinated recovery window, and qualify retention, media, capacity, timing
and clean-host restore on target hardware. The rehearsal's 16 MiB dump cap
and temporary plaintext staging are lab constraints. Independent security
and recovery review remains open.
