# Local configuration scan and parser corpus

**Status:** synthetic lab security regression only. T-026, AT-04/19 and G2 remain open.

## Configuration and container evidence

Run `make security-config-scan` from the repository root. The scanner exits nonzero if the synthetic installer and topology disagree, a DNS name leaves loopback, the lab advertises public egress, the Keycloak image loses its digest pin, or its Docker create command exposes a public port or requests privileged/host resources. The launch command also applies a memory limit, PID limit, capability drop and no-new-privileges. `make check` runs the same scan in CI. This is a static check of committed settings, **not** a host firewall or live no-egress test.

The only container currently declared by this repository is the **synthetic Keycloak lab** image. Its OCI index digest is in [container-image.json](../../infrastructure/lab/container-image.json); the manifest was read from the public Quay registry on 16 November 2026. The `container-scan` PR job uses the pinned [Trivy action](https://github.com/aquasecurity/trivy-action) and Trivy v0.76.2 to scan that digest for high and critical package advisories. It validates and retains the JSON report as a CI artifact for 30 days, and writes the finding count to the job summary. Findings do not currently fail the job: the image is lab-only and findings require human triage against a release candidate. A scanner failure or missing report **does** fail the job. Capture the CI run, exact image digest, scanner/database versions, finding IDs, fix availability and disposition in the controlled review record. This scan does not cover a production Core/Console/model image, because none has been approved or built.

The lab still uses Keycloak `start-dev` and a Docker bridge that may have egress. The added flags do not qualify production identity, network isolation, image provenance or container runtime hardening. Those are [B-03, B-06, B-08 and B-11](../blockers-and-build-queue.md).

The first [CI scan](https://github.com/AttractAcq/Advocate-AI/actions/runs/43850286761)
found **six HIGH and zero CRITICAL** advisories in the lab image. The
[summary record](keycloak-lab-image-scan.json) lists the IDs, package names,
scanner status and the retained report hash. One finding has a listed fixed
Guava version; four SQLite findings had no fixed version in this report, and
one Java finding was marked `will_not_fix`. No finding has been accepted for a
release. The raw `keycloak-lab-trivy` artifact in that CI run is the evidence
source; the committed summary contains no vessel data.

## Parser regression corpus

The [fictional corpus](../../fixtures/phase-5/parser-cases.json) now checks malformed PDF envelopes; recognizable active, encrypted or compressed-object PDF names, including a `#hh` encoded name; duplicate and case-folded Office ZIP members; ZIP symlink/traversal entries; and compression ratio and expanded-size limits. Each malicious case must be quarantined **before** the Docling parser stub is called. A simple non-active PDF envelope must still reach the parser. Existing generated PDF/DOCX/XLSX acceptance tests continue to run through Docling.

This PDF preflight scans raw names and rejects compressed object streams. It cannot prove that all active content is absent from every PDF encoding or detect every parser exploit. Office preflight likewise does not replace process isolation or a specialist malicious-document assessment. The parser worker still has a timeout and output limit, but no OS-level memory/CPU sandbox. Qualified target execution and independent review remain open.
