# Pinned Knowledge image intake rehearsal

The CI upstream release job pulls the digest-pinned official pgvector image
used by the synthetic lab and confirms its image ID survives a local tag. It
saves that exact image into a temporary Docker archive, validates the archive
layers and local manifest digest with pinned crane, creates a CycloneDX 1.6
inventory with pinned Syft, and scans the same archive with pinned Trivy and
its dated offline database. The release intake preflight must reject unresolved
HIGH, CRITICAL or UNKNOWN findings. CI retains the scan, inventory and result
as `synthetic-knowledge-image-release-evidence`; a finding is reported as a
denied candidate, while malformed or mismatched evidence fails the job.

Docker's saved archive manifest digest may differ from the registry manifest
digest. The result records the original pinned registry reference, the pulled
image ID and the local archive digest. Its `registry.example.invalid` reference
is an evidence label, not a published image. The temporary archive is discarded
after the rehearsal. This step does not approve a vessel release or sign a
three-image bundle. It gives the [schema 6 release contract](signed-knowledge-bundle.md)
real Knowledge image evidence for later integration. Licence review, findings
triage, installer activation and coordinated recovery remain open.
