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
or an unresolved or candidate-only SBOM. For a [Syft-generated inventory](upstream-release-tools.md),
file entries require SHA-256 hashes and library entries require a package URL
and version. The earlier fictional test format requires a version and SHA-256
for each component. A generated archive candidate also requires a scan that
binds the matching archive hash and manifest digest, scanner binary hash,
vulnerability database hash and dates, and offline archive mode. The database
must cover the scan time and have been updated within seven days. The
[archive scan adapter](../../infrastructure/release/scan.py) produces these fields.
A pass prints the image and evidence hashes so the reviewer can attach them to
the controlled release record. The local synthetic tests exercise both the
pass and denial paths. The [candidate bundle command](offline-release.md)
runs this preflight again and includes the evidence files in its signed
inventory. The bundle verifier reruns it against the signed creation time;
the signed timestamp is an assertion by the release signer, not a trusted
external timestamp.

This check reads supplied files. It does not authenticate the scanner or its
vulnerability database publisher, prove
that the scan covered every package, establish image or dependency provenance,
verify licence rights or triage findings. A `sovereign-ai:inventory-status`
property is a release process assertion that must be independently checked.
The standalone preflight does not itself prove a particular image archive
contains the named digest. The candidate pack command does this for a
Syft-generated inventory with pinned crane and signs the archive hash. The legacy
`bundle pack` command remains a synthetic signing exercise without evidence
preflight. Release owners must verify provenance, scan coverage and the final
artifact set before signing. The [first lab Keycloak scan](keycloak-lab-image-scan.json)
contains six HIGH findings and cannot pass this preflight.
