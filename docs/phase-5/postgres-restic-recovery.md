# Synthetic PostgreSQL encrypted recovery rehearsal

The CI recovery job starts two disposable PostgreSQL containers with Docker
network mode `none` and no host ports. It writes two fictional application
rows to the first, captures a custom-format `pg_dump` archive, stores that
archive in the pinned restic encrypted repository, deletes the plaintext
copy, restores the exact snapshot to a new private directory, and streams the
archive into the second clean database with `pg_restore --single-transaction`.
The exporter enforces a 16 MiB limit while streaming and removes partial dumps
on failure. The job checks the archive hash and compares the restored rows. CI pulls the
synthetic PostgreSQL image by the exact digest recorded during the first
passing runner rehearsal; production image provenance remains open.

The official [pg_dump documentation](https://www.postgresql.org/docs/current/app-pgdump.html)
describes consistent exports during concurrent database use and custom
archives. [pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html)
documents the single-transaction restore used here. The test containers use
synthetic trust authentication only because their Docker network is disabled;
no real password or vessel data is involved.

This proves a small PostgreSQL dump can pass through the same encrypted restic
repository and be restored into a fresh database. It does not back up global
roles, tablespaces, Keycloak, model files, production configuration or the
full application; it does not test disk failure, restore on clean target
hardware, recovery time objectives, protected media or release key custody.
PostgreSQL notes that `pg_dump` covers one database and is not generally the
right sole method for regular production backup. Those choices and the
site-specific restore plan remain [open](../blockers-and-build-queue.md).

The later [pgvector knowledge recovery rehearsal](pgvector-knowledge-recovery.md)
adds the actual Phase 3 index schema, approved manifest, policy and source
bytes to one encrypted synthetic recovery set.
