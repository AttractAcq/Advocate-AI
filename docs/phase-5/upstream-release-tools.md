# Pinned upstream image and SBOM tools

**Status:** synthetic local and CI rehearsal. This qualifies the integration
path, not a production image or release.

The release preparation adapter uses [crane v0.22.1](https://github.com/google/go-containerregistry/releases/tag/v0.22.1)
to validate every layer in a local Docker archive and calculate its image
manifest digest. It requires the digest to equal the reference used by the
[Trivy v0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2)
scan. It uses [Syft v1.57.1](https://github.com/anchore/syft/releases/tag/v1.57.1)
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

With a separately prepared, approved Trivy vulnerability database cache,
scan the exact same archive. The adapter checks the pinned Trivy binary and
database age, runs `trivy image --input` with update and network dependency
lookups disabled, and checks that the archive and database did not change
during the scan:

```sh
.venv/bin/python -m infrastructure.release.scan \
  --archive /path/to/payload/images/image.tar \
  --image-ref 'registry.example.invalid/example/image@sha256:<archive-manifest-digest>' \
  --output /path/to/payload/evidence/scan.json \
  --crane /path/to/approved/crane --crane-sha256 '<approved-binary-sha256>' \
  --trivy /path/to/approved/trivy --trivy-sha256 '<approved-binary-sha256>' \
  --cache /path/to/approved/trivy-cache
```

Trivy names the input tar path in its raw report. The adapter verifies that
field, then writes the digest-pinned image reference and records the archive,
scanner and vulnerability database hashes and database dates. The generated
archive preflight requires these fields to match the Syft inventory. The
release owner must separately approve the database source and hash; a local
hash alone does not authenticate its publisher. The cache may be prepared
online before the offline release build and must not be updated while scanning.

Place the archive, generated SBOM and scan report inside the candidate
payload. `pack-candidate` requires the archive path and SHA-256 plus the
approved crane binary when using this generated SBOM. The signed descriptor
binds all three files. The bundle verifier checks their hashes, image
reference and cross-file provenance again without requiring an executable
from the bundle.

The [upstream CI rehearsal](../../.github/workflows/ci.yml) downloads pinned
Linux release archives, checks their published hashes, downloads a fresh
Trivy database into a temporary cache, and builds a fictional scratch image
with network disabled. It then runs crane, Syft, a real offline Trivy scan,
candidate signing, verification and tamper checks. The local Mac rehearsal
used the official Darwin arm64 assets and the same workflow. The fictional
image contains a package lock, not production software.

An OCI index digest can differ from the single-platform manifest digest in a
Docker save archive. The release record must use and scan the exact artifact
digest that crane validates; a mismatch fails. A tool's ability to parse an
archive does not authenticate its publisher, prove every package was found,
verify licences, or approve vulnerabilities. The [six HIGH findings in the
lab Keycloak image](keycloak-lab-image-scan.json) remain open. A production
image, independent review, and target-host rehearsal remain B-07/B-08/B-11.
