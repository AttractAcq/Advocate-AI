# Networkless Core and pgvector socket rehearsal

The built Core image can read the Phase 3 PostgreSQL/pgvector knowledge index
through a shared Unix socket. Both disposable containers run with Docker
network mode `none`, no published host ports, and a private Docker socket
volume. Core mounts that volume read-only and mounts a private synthetic
source tree and lab credential from outside its image. The PostgreSQL URI
allows only a numeric loopback host or the exact `/run/postgresql` socket path;
credentials cannot be embedded in the URI.

The rehearsal enables pgvector in the database, indexes two fictional text
sources from within the actual Core image, builds synthetic vectors, then
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

This is an actual-image lab rehearsal, not an installed release. Its temporary
database uses trust authentication and a role that can create the synthetic
schema. The signed two-image installer still assumes a SQLite knowledge file
and does not provision, sign, start, identify, update or recover PostgreSQL.
The next installation slice must introduce separate migration and runtime
roles, protected credentials, a signed database image and a coordinated
recovery receipt before the target topology can be qualified. Model, NAS,
identity and vessel hardware checks also remain open.
