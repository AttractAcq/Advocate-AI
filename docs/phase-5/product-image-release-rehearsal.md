# Product image release evidence rehearsal

The CI `upstream-release-rehearsal` job now builds the actual synthetic Core
and Console images and saves each as a Docker archive. For each archive it:

1. Resolves and validates the local manifest digest and layers with pinned crane.
2. Generates a CycloneDX 1.6 inventory from that same archive with pinned Syft.
3. Scans that archive in offline mode with pinned Trivy and a dated local database.
4. Runs the release intake preflight against the matching digest, SBOM and scan.

When Core passes preflight, CI creates and verifies a candidate bundle with an
ephemeral synthetic signing key. A Console finding produces a documented denial;
other evidence errors fail the job. The `synthetic-product-image-release-evidence`
artifact retains the scan, inventory and result for both images. The temporary
archives and key are discarded after the rehearsal; CI does not publish a
release or create a trusted signing identity.

The job also attempts the [schema-4 product bundle](multi-image-release.md)
containing both exact archives. A finding in either image must deny that
bundle before any product package is signed.

The signed-image installer leg opts into a separate private upload quarantine.
It also restores a one-source Phase 3 manifest and SQLite passage index into
Core's external state, so the signed runtime exercises permission-aware indexed
retrieval rather than the earlier CSV fallback. The later recovery set captures
and restores that index with the audit trail.
It submits a fictional document through Core, verifies that the file is staged
but absent from approved sources, and checks that the staged record survives a
runtime refresh. This tests the mounted upload path in the actual container;
it does not exercise vessel content. After stopping the first product runtime,
the rehearsal [captures a signed recovery set](product-recovery-set.md) under
the policy and upload locks. The receipt binds the fresh Core and upload restic
snapshot IDs and capture window. A second clean installation uses exactly that
pair before starting the signed images. It checks the restored pending record
through Core and confirms it is still absent from approved sources.
Before capture, the rehearsal expands the synthetic source manifest to all 100
fictional fixture files. The signed recovery path copies them through real
restic, then verifies every restored source against the manifest and expects
the corresponding 106-file Core snapshot. The Phase 3 passage index remains
the one-source test index; full multi-source retrieval quality remains separate
work.

This proves the evidence pipeline can process the product images rather than
only the small fictional test archive. It does not yet produce an approved
multi-image appliance package, authenticate base-image publishers, resolve the
[open findings](product-image-scan.md), or qualify target hardware and site
deployment. These remain in the [blocker tracker](../blockers-and-build-queue.md).
