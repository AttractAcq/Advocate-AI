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

CI retains the three scan reports, inventories and a metadata-only result as
`synthetic-three-image-bundle-evidence`. The trial's signing key and full image
archives remain temporary and are discarded; no package is published or
trusted for a vessel. If any image has unresolved HIGH, CRITICAL or UNKNOWN
findings, the result must be `denied-findings` and no bundle is signed. Other
evidence or signature errors fail the CI job.

This proves actual image evidence can satisfy the three-image release
contract. The current installer accepts only the two-image bundle. Database
state, migration and runtime identities, credential custody, coordinated
recovery, signed production keys, commercial distribution approval, target
hardware and independent security review remain open.
