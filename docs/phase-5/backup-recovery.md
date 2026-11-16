# Encrypted backup and local recovery rehearsal

The synthetic backup tool snapshots explicitly listed files and SQLite
databases. SQLite is copied through its backup API so committed WAL data is
included consistently. The archive is encrypted and authenticated with
AES-256-GCM using a new random nonce per backup. The key is a separate
32-byte file. Restore authenticates the entire archive and checks its file
inventory before placing anything in a new destination directory. Wrong keys,
changed bytes, unsafe paths and duplicate entries fail closed.

This format has a **synthetic 1 GiB total / 256 MiB per-file limit**. It does
not yet back up PostgreSQL, Keycloak, model files, Wazuh or vessel NAS data.
Only the named application state is included; backup key material must have
separate custody. Plaintext snapshots and the authenticated restore staging
file use private temporary directories on the local filesystem. Real data
requires an approved encrypted staging volume and protected backup media.

## Synthetic procedure

Create a key **outside the repository**, then prepare an allowlist spec with
paths relative to the spec file or absolute paths. The destination for restore
must not exist.

```json
{
  "schema": 1,
  "files": [
    {"name": "knowledge.db", "kind": "sqlite", "source": "lab/knowledge.db"},
    {"name": "config.json", "kind": "file", "source": "lab/config.json"}
  ]
}
```

```sh
.venv/bin/python -m infrastructure.backup keygen /private/backup-test.key
.venv/bin/python -m infrastructure.backup create --spec /path/to/spec.json --output /path/to/new-backup.svb --key /private/backup-test.key
.venv/bin/python -m infrastructure.backup verify --backup /path/to/new-backup.svb --key /private/backup-test.key
.venv/bin/python -m infrastructure.backup restore --backup /path/to/new-backup.svb --key /private/backup-test.key --destination /path/to/new-restore-directory
```

Keep the key on separately protected media. A lost key makes the backup
unrecoverable. The tool does not manage key rotation, offsite copies,
retention, scheduling or media scanning. Those require approved owners and
target-host evidence before production.

## Local rehearsal, 16 November 2026

Run `make recovery-rehearsal`. The script creates a fictional Knowledge index,
synthetic role policy and persistent conversation history. It encrypts four
state files, verifies the archive, rejects a one-byte alteration, removes the
live state, restores into a clean directory, and checks sign-in, history,
permission-filtered retrieval and cross-user isolation. The fictional source
document is supplied again as a separate NAS stand-in. The recorded
[result](recovery-rehearsal.json) passed locally.

This is a software rehearsal. **AT-16 and G2 remain open** until restoration
on wiped lab equipment verifies the complete stack, model, identity provider,
Wazuh separation and offline operation within the proposed RTO/RPO, with key
custody, independent review and protected media. See the
[blocker tracker](../blockers-and-build-queue.md).
