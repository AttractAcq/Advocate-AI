# Synthetic upload quarantine recovery

The installed Core mounts a private `product-uploads` directory outside its
approved source tree. Its existing Core-state restic snapshot does not include
pending uploads. This adapter makes a separate encrypted restic snapshot of
that directory and restores it only into a new owner-only location.

The adapter takes a shared directory lock while checking and copying the
quarantine. Core upload writers and the offline promotion tool take the
exclusive form of the same lock, so a cooperative writer cannot change files
during that copy. A production snapshot procedure still needs a reviewed
maintenance state that coordinates Core, policy and source changes. The adapter
checks the exact `.json` and `.blob` file
inventory, owner-only modes, pending metadata, sizes and SHA-256 digests.
Approved records may retain metadata but no upload bytes. It rejects orphaned,
linked or unexpected files. The bounded synthetic profile accepts at most 100
pending uploads, 1,024 records and 900 MiB of payload, covering the full
100-by-8-MiB pending queue. The scanner, archive writer and restore extractor
process blobs in bounded chunks. If the upload area exceeds the limit, the
backup fails; no partial snapshot is accepted. The
private plaintext staging parent must be separate from the upload area and
protected by an encrypted filesystem before vessel use.

Before copying, the adapter checks available space on the staging and restic
repository volumes. It reserves room for the plaintext archive, the restic
staging copy, the encrypted pack and a 128 MiB margin. A shared volume must
have room for all three copies. Insufficient space fails before creating a
repository snapshot. This estimate is deliberately conservative; target-host
capacity, filesystem quotas and sustained restore space still need validation.

Restore first reads the exact snapshot's JSON file listing through the pinned
restic binary. It requires one archive and one Sovereign manifest, then checks
space for the encrypted restore's plaintext archive and extracted quarantine
plus the same reserve. The checked listing is only a capacity estimate; the
normal repository integrity, manifest, archive and upload-digest checks still
run before the new destination appears. Filesystem quotas and measured
clean-host restore capacity remain target gates.
The listing parser follows the [restic v0.19.1 JSON `ls` format](https://github.com/restic/restic/blob/v0.19.1/doc/075_scripting.rst#ls).

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
coordinated maintenance point. The product installer's `restore-install` command
can now verify both snapshots into a new private root before launching the
signed release. It refuses a partial upload restore, a shared repository or an
existing root. Scheduling, coordination with an active Core, approved retention,
protected off-host media, key custody, target-host recovery timing and an
independent security review remain open gates.
