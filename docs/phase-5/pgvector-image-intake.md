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

The [first PR #132 CI run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44642494637)
completed the Knowledge image intake step and retained the evidence artifact.
Its pinned image has 161 unresolved findings: 140 HIGH, 4 CRITICAL and 17
UNKNOWN. Trivy attributed 133 package findings to Debian 12.15 and 28 to the
`gosu` Go binary. The intake result is `denied-findings`. Some advisories have
no fixed version in this report; no finding has been accepted or waived.
Release owners must choose and qualify a fixed image or review each exception
before a signed Knowledge bundle can be a release candidate.

The next CI comparison scans the official `pg17-trixie` amd64 image pinned to
`sha256:494f5c1091d49ad96d6070f07ce3c08d92912d6edce1e1595028eb6bbd1db71d`.
This digest came from the [publisher's Docker Hub tag metadata](https://hub.docker.com/v2/repositories/pgvector/pgvector/tags/pg17-trixie)
on 20 November 2026. The comparison uses the identical archive, SBOM, scanner
and intake rules, and retains a separate artifact. It does not replace the
current lab pin or approve a new image until its scan and functional checks
have been reviewed.
The synthetic container CI job also runs the existing private Unix socket
Core-to-pgvector rehearsal against this exact Trixie digest. It checks startup,
indexing, authorised and denied API search, source preview and live revocation.
