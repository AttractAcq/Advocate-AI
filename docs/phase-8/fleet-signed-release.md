# Separate signed Fleet release candidate

Fleet is a company-side service and does not ship in the strict vessel image.
Its offline release bundle uses schema 5 with `target: fleet` and exactly two
image descriptors, `fleet-api` and `fleet-portal`. Each descriptor binds an
`images/<role>.tar` archive, digest-pinned image reference, generated Syft
inventory and Trivy scan. The existing release intake rejects missing or stale
evidence and unresolved HIGH, CRITICAL or UNKNOWN findings. The signer checks
both archives with the pinned crane binary before signing. The verifier checks
the detached Ed25519 signature, exact file inventory and signed evidence.

The descriptor JSON has exactly `fleet-api` and `fleet-portal` keys, each
using the same fields as the schema-4 product descriptor. After preparing the
approved archives and evidence:

```sh
.venv/bin/python -m infrastructure.release.bundle pack-fleet \
  /path/to/payload /path/to/new-fleet-bundle \
  --signing-key /protected/fleet-release-key.pem --version VERSION \
  --images-json /path/to/fleet-images.json --crane /path/to/pinned/crane
.venv/bin/python -m infrastructure.release.bundle verify \
  /path/to/new-fleet-bundle --trusted-key /protected/fleet-trust-key.pem
```

This is a local software candidate. The Fleet release signing authority,
production vulnerability policy, company deployment topology and independent
review remain under B-12. A schema-5 Fleet bundle cannot be imported as a
schema-4 vessel release or passed to the vessel product installer.

The CI Fleet image rehearsal builds the actual API and portal images, saves
their archives, obtains manifest digests with crane, generates Syft inventory
and an offline-database Trivy scan, then attempts the schema-5 signature. If
either image has unresolved HIGH, CRITICAL or UNKNOWN findings, the expected
result is `denied-findings` and no signed bundle. Its metadata-only result,
scan and inventory files are retained as CI artifacts; temporary signing keys
and image archives are not published by the rehearsal. This is evidence of
the software path, not approval to distribute an image.
