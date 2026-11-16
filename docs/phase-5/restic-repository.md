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
.venv/bin/python -m infrastructure.restic_repository verify \
  --repository /path/to/encrypted-repository \
  --password-file /secure/password-file --restic /path/to/approved/restic \
  --restic-sha256 '<approved-binary-sha256>' --max-age-hours 24
```

The spec format is the one in [backup and recovery](backup-recovery.md).
The local test uses fictional configuration and a WAL-mode SQLite database.
It proves a committed database row and configuration survive a clean restore;
wrong password and unapproved binary hashes leave no restore directory. CI
downloads the pinned Linux binary and checks its official release SHA-256
before rerunning the tests.

The `verify` command checks every encrypted pack and requires a recent
snapshot bearing the exact Sovereign tag and host. A healthy but empty or
stale repository fails. It returns snapshot metadata only; it does not restore
files or establish a recovery time objective. The age threshold is supplied
by the operator and is not an approved vessel backup policy. A
[daily service and timer renderer](scheduled-backup-verification.md) can run a
synthetic backup followed by this check.

## Retention rehearsal

New Sovereign snapshots carry the stable `sovereign-ai` tag and host so restic
can apply a policy across the adapter's changing private staging paths.
Existing untagged snapshots are excluded and need a reviewed migration plan.
An owner-approved policy is supplied as JSON; this **synthetic example** keeps
the newest two snapshots and all snapshots within 30 days of the newest:

```json
{"schema":1,"keep_last":2,"keep_within_days":30}
```

Set `keep_within_days` to `null` to apply only `keep_last`. The preview runs
`restic forget --dry-run` scoped to the Sovereign tag and host. It writes an
owner-only plan naming the exact snapshot IDs to keep and remove, the
repository ID and policy. Review the plan and its reported SHA-256 before
applying it:

```sh
.venv/bin/python -m infrastructure.restic_retention plan \
  --policy /path/to/approved-policy.json --output /path/to/new-plan.json \
  --repository /path/to/encrypted-repository \
  --password-file /secure/password-file --restic /path/to/approved/restic \
  --restic-sha256 '<approved-binary-sha256>'
.venv/bin/python -m infrastructure.restic_retention apply \
  --plan /path/to/new-plan.json --plan-sha256 '<printed-plan-sha256>' \
  --repository /path/to/encrypted-repository \
  --password-file /secure/password-file --restic /path/to/approved/restic \
  --restic-sha256 '<approved-binary-sha256>'
```

Apply accepts a plan less than 24 hours old, rechecks the full scoped snapshot
set and policy result, and forgets **only the listed IDs** with prune. It then
checks repository data and the remaining inventory. It keeps at least two
snapshots where two exist and refuses to remove more than 100 in one run. A
failed prune or check needs operator investigation; some snapshots may already
have been forgotten. The local test covers three Sovereign snapshots plus an
unrelated repository snapshot. Restic's [retention documentation](https://restic.readthedocs.io/en/stable/060_forget.html)
explains dry runs, grouping and the risks of policy deletion in an append-only
repository.

Snapshot preparation and restored files are plaintext in a private temporary
directory. Production requires a protected encrypted staging filesystem,
approved key custody, PostgreSQL/Keycloak/model/Wazuh procedures, an
owner-approved retention schedule and protected separate copy, media handling,
a clean-host restoration rehearsal, and independent
review. This adapter does not replace the existing synthetic `.svb` archive
until those gates are passed.
