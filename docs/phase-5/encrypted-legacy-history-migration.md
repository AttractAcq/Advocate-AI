# Encrypted synthetic Core history migration

An older synthetic Core installation can contain a valid, unversioned
`history.db`. The versioned Core refuses that file. This lab command snapshots
it to the pinned encrypted restic repository, checks the repository, restores
to a clean directory, compares the recovered conversations, and only then sets
SQLite `user_version=1`. It writes a private JSON evidence record before the
version change and updates it after verification. The evidence includes the
snapshot ID, repository path, row count and canonical content hash.

Stop every Core process and any other writer before running it. Use absolute,
owner-only paths for the Core state, staging and evidence directories. Keep the
restic password outside Core state. The staging directory holds a temporary
plaintext copy during verification, so use protected local storage and remove
it under the normal recovery procedure. Retain the encrypted repository,
password and evidence together for recovery. The command refuses an existing
evidence file or a database that is already versioned.

```sh
python -m infrastructure.deploy.history_migration --synthetic-lab \
  --history-db /private/lab/core/history.db \
  --repository /private/lab/backup/repository \
  --password-file /private/lab/keys/restic-password \
  --restic /private/lab/tools/restic \
  --restic-sha256 APPROVED_RESTIC_SHA256 \
  --staging-parent /private/lab/staging \
  --evidence /private/lab/evidence/history-migration.json
```

If the command fails after creating the encrypted snapshot, inspect the
evidence and live database version before retrying. A `backup-verified` record
means the version update may have happened but its completion record was not
written. The command does not roll back or retry automatically. Restore the
recorded snapshot into a separate clean directory to recover the old database.

This rehearsal does not stop Core, acquire a vessel deployment lock, update a
signed vessel release receipt or implement a production rollback. A production
upgrade still requires a signed migration plan for all Core state, a tested
recoverable pre-update set, protected staging and key custody, vessel hardware
validation, and independent review.
