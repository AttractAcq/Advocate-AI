# Offline release evidence preflight

**Status:** local synthetic software slice. This is a negative release check,
not a release approval or a completed G2/G3 gate.

Run the preflight on a digest-pinned container candidate with a Trivy JSON
report and a resolved CycloneDX 1.6 inventory. The expected SHA-256 values
must be taken from a separately controlled CI or reviewer record, not from
the same untrusted transfer as the JSON files.

```sh
.venv/bin/python -m infrastructure.release.intake \
  --image-ref 'registry.example.invalid/example/image@sha256:<64-hex-digest>' \
  --scan /path/to/trivy.json --scan-sha256 '<64-hex-report-hash>' \
  --sbom /path/to/resolved-sbom.json --sbom-sha256 '<64-hex-sbom-hash>'
```

The command exits nonzero for missing, oversized, linked, altered or stale
evidence; a mismatched image digest; an unsupported/old scanner report; an
empty scan; malformed findings; any HIGH, CRITICAL or UNKNOWN vulnerability;
an unresolved or candidate-only SBOM; or a component without a SHA-256 hash.
A pass prints the image and evidence hashes so the reviewer can attach them to
the controlled release record. The local synthetic tests exercise both the
pass and denial paths.

This check reads supplied files. It does not authenticate the scanner, prove
that the scan covered every package, establish image or dependency provenance,
verify licence rights, triage findings, or bind the evidence to a signed
release bundle. A `sovereign-ai:inventory-status` property is a release process
assertion that must be independently checked. The existing `bundle pack`
command remains a synthetic signing exercise and does not invoke this
preflight. Release owners must verify those controls and the final artifact
set before signing. The [first lab Keycloak scan](keycloak-lab-image-scan.json)
contains six HIGH findings and cannot pass this preflight.
