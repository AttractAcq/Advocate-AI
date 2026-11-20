# Networkless Core and pgvector socket rehearsal

The built Core image can read the Phase 3 PostgreSQL/pgvector knowledge index
through a shared Unix socket. Both disposable containers run with Docker
network mode `none`, no published host ports, and a private Docker socket
volume. Core mounts that volume read-only and mounts a private synthetic
source tree and lab credential from outside its image. The PostgreSQL URI
allows only a numeric loopback host or the exact `/run/postgresql` socket path;
credentials cannot be embedded in the URI.

The rehearsal starts PostgreSQL with a private file-backed administrator
password, replaces its bootstrap authentication with `peer` for the database
administrator and SCRAM-SHA-256 for other local socket users, and rejects TCP
clients. A temporary ingestion container uses an owner-only writer passfile
to create the schema, index two fictional text sources and build synthetic
vectors. The installed-style Core container receives a different, owner-only
reader passfile. It can SELECT from the four knowledge tables but cannot
insert rows, create tables or authenticate as the ingestion writer. Both
passfiles are read-only mounts; no database password appears in the URI or
Docker command arguments.

Core then
exercises Core's HTTP login, search and preview routes from inside its own
network namespace. A deckhand cannot retrieve the engineering source. A role
policy change immediately revokes the engineer's search access. Local output
records `network_mode=none` and `database_transport=unix-socket`. The
[CI container job](../../.github/workflows/ci.yml) repeats this with the built
Core image and the digest-pinned official pgvector image.

```sh
python3 -m scripts.phase3_pgvector_core_socket \
  --pgvector-image docker.io/pgvector/pgvector@sha256:b513c48566e4777cd3370451400000c78eda6a08131d68f4c31d4a76f27bd8fd \
  --core-image sovereign-core:synthetic
```

This is an actual-image lab rehearsal, not an installed release. The signed
two-image installer still assumes a SQLite knowledge file
and does not provision, sign, start, identify, update or recover PostgreSQL.
The next installation slice must move these roles and credentials into the
signed three-image deployment, separate schema migration from ingestion,
and add a coordinated recovery receipt before the target topology can be
qualified. Release key custody, credential rotation, model, NAS,
identity and vessel hardware checks also remain open.
