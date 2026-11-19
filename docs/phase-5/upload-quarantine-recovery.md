# Synthetic upload quarantine recovery

The installed Core mounts a private `product-uploads` directory outside its
approved source tree. Its existing Core-state restic snapshot does not include
pending uploads. This adapter makes a separate encrypted restic snapshot of
that directory and restores it only into a new owner-only location.

Stop Core or put it in a reviewed write-frozen maintenance state before
creating a snapshot. The adapter checks the exact `.json` and `.blob` file
inventory, owner-only modes, pending metadata, sizes and SHA-256 digests.
Approved records may retain metadata but no upload bytes. It rejects orphaned,
linked or unexpected files. The bounded synthetic profile accepts at most 100
pending uploads, 1,024 records and 240 MiB of payload. If the upload area
exceeds that bound, the backup fails; no partial snapshot is accepted. The
private plaintext staging parent must be separate from the upload area and
protected by an encrypted filesystem before vessel use.

```sh
.venv/bin/python -m infrastructure.upload_quarantine_backup create \
  --upload-root /path/to/product-uploads \
  --repository /path/to/separate-encrypted-restic-repository \
  --password-file /path/to/owner-only-restic-password \
  --restic /path/to/pinned-restic --restic-sha256 exact-binary-sha256 \
  --staging-parent /path/to/private-encrypted-staging
.venv/bin/python -m infrastructure.upload_quarantine_backup restore \
  --snapshot-id exact-64-hex-snapshot-id \
  --repository /path/to/separate-encrypted-restic-repository \
  --password-file /path/to/owner-only-restic-password \
  --restic /path/to/pinned-restic --restic-sha256 exact-binary-sha256 \
  --destination /path/to/new-owner-only-parent/restored-uploads
```

The adapter packages the checked inventory as one bounded archive, then uses
the existing pinned restic adapter to encrypt, check and restore it. Restore
checks the restic manifest, archive inventory and every upload digest, and
refuses an existing destination. The test suite covers archive tampering,
orphaned bytes, missing bytes, unsafe modes, clean restore, and a pinned-restic
round trip in CI. A restored upload is still quarantined; it is never made an
approved knowledge source by this procedure.

For a complete recovery, restore the Core state and upload quarantine from a
coordinated maintenance point, then inspect both before activating the
installer. Scheduling, coordination with an active Core, approved retention,
protected off-host media, key custody, target-host recovery timing and an
independent security review remain open gates.
