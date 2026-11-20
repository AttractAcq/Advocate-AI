# Locally built Alpine Knowledge image candidate

The [Knowledge Dockerfile](../../infrastructure/containers/Knowledge.Dockerfile)
uses the official PostgreSQL 17.12 Alpine 3.24 amd64 image at a fixed manifest
digest. A separate build stage downloads the pgvector v0.8.7 source archive
with Docker's SHA-256 check, compiles the extension with PostgreSQL's own
headers and copies only the installed extension and licence into the runtime
base. Compiler tools and source files stay out of the runtime image. The
runtime stage uses Alpine's pinned `su-exec` package under the entrypoint's
`gosu` command name, replacing the base image's Go binary while preserving its
user-switch call. The actual PostgreSQL start and role rehearsal tests that
replacement. A final stage copies the assembled filesystem into a new layer
and explicitly sets PostgreSQL's entrypoint, data volume and shutdown signal.
This keeps the removed Go binary out of the distributed archive, which the
offline scanner must inspect again. The official [PostgreSQL Alpine image](https://hub.docker.com/_/postgres) requires
custom compilation for extensions, and [pgvector](https://github.com/pgvector/pgvector)
documents source builds for PostgreSQL 13 and newer.

The CI synthetic container job runs this built image through the same
networkless Core-to-pgvector socket rehearsal used for the official images.
That check includes SCRAM authentication, separate writer and read-only Core
roles, indexing, role-restricted search and live revocation. The release job
saves the built image into a temporary archive, validates its local manifest
and layers with pinned crane, generates a CycloneDX inventory with pinned Syft,
and scans the exact archive with pinned Trivy and the dated offline database.
It retains the report and records `preflight-pass` or `denied-findings` under
the same release rules. The temporary archive and synthetic image are not a
distributed or signed vessel release.

The build currently pins only the amd64 base manifest used by the Ubuntu CI
runner. An arm64 image requires a separately pinned base, build and functional
evidence. Source licence and commercial distribution, signing-key custody,
installer activation, coordinated recovery, target hardware and independent
security review remain open.

The first [actual-image CI scan](https://github.com/AttractAcq/Advocate-AI/actions/runs/44649074950)
found 28 unresolved HIGH, CRITICAL or UNKNOWN advisories, all in the inherited
`gosu` Go binary; Alpine OS packages had none at those severities. That intake
correctly returned `denied-findings`. The `su-exec` replacement requires a
fresh build, functional rehearsal and scan before its result can be used.
The second scan still reported those 28 Go findings from `gosu` in an
inherited layer, despite the working `su-exec` replacement. The final
filesystem stage is the next candidate; its scan has not yet passed.
