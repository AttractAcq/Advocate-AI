# Actual-image signed vessel bundle rehearsal

The CI upstream release job builds synthetic Core, Console and the
[Alpine Knowledge candidate](alpine-knowledge-image.md) as three separate
images. It saves each exact local image into a temporary archive, validates
the archive layers and manifest digest with pinned crane, produces a CycloneDX
inventory with pinned Syft, and scans the same archive with pinned Trivy and
the dated offline vulnerability database. Each role must pass the release
intake before [schema 6](signed-knowledge-bundle.md) can sign the exact three
archives, their evidence files and `target=vessel` under one detached Ed25519
signature. The verifier checks the resulting copy with a separate public key.
It then loads Core, Console and Knowledge only from those verified archives,
binds the loaded image IDs back to each archive, and runs all three signed
images together. Core and Console use an internal Docker network with no host
ports; Knowledge has no network attachment and uses a private Unix socket.
The live check
requires distinct SCRAM writer and read-only Core roles, denies Core writes and
writer authentication, checks authorised retrieval and revocation, and uses
no published ports. It checks Console configuration, its proxy to Core and
denial of unauthenticated API access.

CI retains the three scan reports, inventories and a metadata-only result as
`synthetic-three-image-bundle-evidence`. The trial's signing key and full image
archives remain temporary and are discarded; no package is published or
trusted for a vessel. If any image has unresolved HIGH, CRITICAL or UNKNOWN
findings, the result must be `denied-findings` and no bundle is signed. Other
evidence or signature errors fail the CI job.

This proves actual image evidence can satisfy the three-image release
contract and that the three signed image archives can run together in
the synthetic socket topology. The [vessel first installer](signed-vessel-first-install.md)
now accepts this signed three-image bundle and checks the persistent database,
runtime identities and schema version before recording activation. The
[stopped release switch](vessel-release-switch.md) and
[encrypted recovery set](vessel-recovery-set.md) have separate synthetic
rehearsals. Real software-version migrations and rollback compatibility,
credential custody, signed production keys, commercial distribution approval,
target hardware and independent security review remain open.
