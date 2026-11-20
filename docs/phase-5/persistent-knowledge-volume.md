# Persistent signed Knowledge runtime candidate

The [three-image release rehearsal](actual-three-image-release.md) now stages
the exact signed Knowledge archive on a dedicated Docker data volume and a
separate per-run Unix socket volume. The data volume is labelled with one
installation ID and survives a graceful container stop. The socket volume is
discarded after each run. Both volumes and the container have scoped labels;
the runtime checks those identities before stopping a running instance.

Private administrator, ingestion writer and Core reader credentials are created
outside the signed image under an owner-only installation directory. The
PostgreSQL container has no network attachment or published host ports. On a
new volume, setup installs pgvector, distinct non-privileged roles and the
local `peer`/SCRAM authentication file. On restart, it checks the persisted
authentication rules, role attributes and credentials before returning a
healthy handle. The login probes send secrets through standard input, not
Docker command arguments.

CI writes a fictional marker into the first run, stops the container, starts
the same signed image and data volume with a new socket, and confirms the
marker and vector extension remain. It then removes the disposable data
volume. The metadata-only result records `persistent_knowledge_restart=pass`.

This is a lab building block. The product installer still needs to record the
Knowledge container and data volume, attach the socket and reader passfile to
Core, run migrations and ingestion with a separate authority, and coordinate
database snapshots and clean restore with the existing recovery receipt.
Credential rotation, volume encryption, host boot recovery, target-host
capacity and independent review remain open.
