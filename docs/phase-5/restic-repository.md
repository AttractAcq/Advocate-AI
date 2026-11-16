# Local restic repository adapter

**Status:** synthetic recovery software slice. AT-16, G2 and the clean-host
recovery gate remain open.

The adapter uses [restic v0.19.1](https://github.com/restic/restic/releases/tag/v0.19.1)
for an encrypted local repository. It reuses Sovereign's allowlisted file and
SQLite backup API snapshot logic, writes a manifest with per-file hashes, then
backs up the private staging directory. It checks all repository data after
backup and before restore. Restore only accepts a new destination, verifies
the restored manifest and exact file inventory, and moves the checked files
into place. The restic binary must match an approved SHA-256 value. The
passphrase is read from an owner-only file outside the repository and never
passed as a command argument. The adapter disables restic's local cache and
accepts only local absolute repository paths.

```sh
.venv/bin/python -m infrastructure.restic_repository create \
  --spec /path/to/allowlist-spec.json --repository /path/to/encrypted-repository \
  --password-file /secure/password-file --restic /path/to/approved/restic \
  --restic-sha256 '<approved-binary-sha256>' \
  --staging-parent /path/to/private-encrypted-staging
.venv/bin/python -m infrastructure.restic_repository restore \
  --snapshot-id '<64-hex-id>' --repository /path/to/encrypted-repository \
  --password-file /secure/password-file --restic /path/to/approved/restic \
  --restic-sha256 '<approved-binary-sha256>' --destination /path/to/new-restore
```

The spec format is the one in [backup and recovery](backup-recovery.md).
The local test uses fictional configuration and a WAL-mode SQLite database.
It proves a committed database row and configuration survive a clean restore;
wrong password and unapproved binary hashes leave no restore directory. CI
downloads the pinned Linux binary and checks its official release SHA-256
before rerunning the tests.

Snapshot preparation and restored files are plaintext in a private temporary
directory. Production requires a protected encrypted staging filesystem,
approved key custody, PostgreSQL/Keycloak/model/Wazuh procedures, retention
and media handling, a clean-host restoration rehearsal, and independent
review. This adapter does not replace the existing synthetic `.svb` archive
until those gates are passed.
