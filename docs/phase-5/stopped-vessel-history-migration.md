# Stopped synthetic vessel history migration

`vesselctl migrate-history-stopped` extends the [encrypted legacy history
rehearsal](encrypted-legacy-history-migration.md) to a recorded synthetic vessel
installation. It takes the existing vessel operation lock, verifies the active
signed release and Core archive identity, and requires the scoped Docker
inventory to contain only the persistent Knowledge data volume. It checks the
legacy Core state and policy,
then creates and clean-restores an encrypted restic snapshot before changing
SQLite `user_version` from 0 to 1. The normal Core state check must pass after
the change. It checks the stopped inventory again and signs a receipt binding
the installation ID, active release manifest hash, snapshot ID, repository,
conversation count and content hash. The raw migration evidence is separate
from the signed receipt.

Stop the vessel runtime first and retain its signed release and key. Use new,
owner-only evidence and receipt paths outside the installation and Core state.
The restic repository and staging paths must also be separate from Core state.
The staging path temporarily holds plaintext during the clean restore. Protect
that storage and the backup password. The command refuses an existing receipt,
existing migration evidence, a current or future history version, and a
running or unrecorded Docker resource.

```sh
python -m scripts.vesselctl migrate-history-stopped \
  --root /private/lab/install --trusted-key /private/lab/keys/release.pub \
  --crane /private/lab/tools/crane \
  --repository /private/lab/backup/repository \
  --password-file /private/lab/keys/restic-password \
  --restic /private/lab/tools/restic \
  --restic-sha256 APPROVED_RESTIC_SHA256 \
  --staging-parent /private/lab/staging \
  --evidence /private/lab/evidence/history-migration.json \
  --receipt-signing-key /private/lab/keys/recovery-signing.pem \
  --receipt /private/lab/evidence/history-migration-receipt.json

python -m scripts.vesselctl verify-history-migration-receipt \
  --receipt /private/lab/evidence/history-migration-receipt.json \
  --receipt-key /private/lab/keys/recovery-signing.pub

python -m scripts.vesselctl verify-history-migration-backup \
  --receipt /private/lab/evidence/history-migration-receipt.json \
  --receipt-key /private/lab/keys/recovery-signing.pub \
  --password-file /private/lab/keys/restic-password \
  --restic /private/lab/tools/restic \
  --restic-sha256 APPROVED_RESTIC_SHA256 \
  --staging-parent /private/lab/staging
```

Verify the signed receipt and its encrypted clean restore, then capture a
complete vessel recovery set before switching software releases. The signed
migration receipt attests the completed history transformation; the separate
backup verifier checks that its pre-migration snapshot remains recoverable.
Neither attests the other Core files or Knowledge database. If the command
fails after the backup or database change, inspect the private evidence and
live database version before any retry. Preserve the recorded snapshot and
restore into a separate clean directory for investigation. There is no
automatic rollback of the database or release.

This remains synthetic. The operation lock and stopped inventory do not stop
an unrelated process writing the Core state. Production use still requires
reviewed process isolation, a full recoverable pre-update set, cross-version
rollback proof, protected media and key custody, target hardware testing and
independent security assessment.
