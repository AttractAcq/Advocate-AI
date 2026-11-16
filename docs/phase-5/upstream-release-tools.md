# Pinned upstream image and SBOM tools

**Status:** synthetic local and CI rehearsal. This qualifies the integration
path, not a production image or release.

The release preparation adapter uses [crane v0.22.1](https://github.com/google/go-containerregistry/releases/tag/v0.22.1)
to validate every layer in a local Docker archive and calculate its image
manifest digest. It requires the digest to equal the reference used by the
Trivy scan. It uses [Syft v1.57.1](https://github.com/anchore/syft/releases/tag/v1.57.1)
with `--from docker-archive` and CycloneDX 1.6 output to catalog that same
archive. Both binaries must match approved SHA-256 values supplied from a
controlled release record. The adapter disables Syft's update check and gives
neither tool a registry source.

For an already saved, approved local image archive:

```sh
.venv/bin/python -m infrastructure.release.upstream \
  --archive /path/to/payload/images/image.tar \
  --image-ref 'registry.example.invalid/example/image@sha256:<archive-manifest-digest>' \
  --output /path/to/payload/evidence/sbom.json \
  --crane /path/to/approved/crane --crane-sha256 '<approved-binary-sha256>' \
  --syft /path/to/approved/syft --syft-sha256 '<approved-binary-sha256>'
```

The output is the real Syft inventory, with only the top-level component and
three Sovereign provenance properties added: the validated image digest,
archive SHA-256 and approved crane version. Syft library records commonly
have package URLs and versions, while file records have content hashes but no
version. The intake check treats those types accordingly. It rejects an empty
inventory or an unknown generator version.

Place the archive, generated SBOM and scan report inside the candidate
payload. `pack-candidate` requires the archive path and SHA-256 plus the
approved crane binary when using this generated SBOM. The signed descriptor
binds all three files. The bundle verifier checks their hashes, image
reference and cross-file provenance again without requiring an executable
from the bundle.

The [upstream CI rehearsal](../../.github/workflows/ci.yml) downloads pinned
Linux release archives, checks their published hashes, builds a fictional
scratch image with network disabled, then runs crane, Syft, candidate signing,
verification and tamper checks. The local Mac rehearsal used the official
Darwin arm64 assets and the same workflow. The Trivy report in this rehearsal
is **synthetic**; it demonstrates the interface, not a vulnerability scan.

An OCI index digest can differ from the single-platform manifest digest in a
Docker save archive. The release record must use and scan the exact artifact
digest that crane validates; a mismatch fails. A tool's ability to parse an
archive does not authenticate its publisher, prove every package was found,
verify licences, or approve vulnerabilities. The [six HIGH findings in the
lab Keycloak image](keycloak-lab-image-scan.json) remain open. A production
image, independent review, and target-host rehearsal remain B-07/B-08/B-11.
