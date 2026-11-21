# Offline maintenance and recovery SOP — synthetic lab

**Owner:** release/recovery engineer. **Second person:** release or recovery witness. The commands in the first sections below exercise the earlier synthetic software-pointer installer and small encrypted file archive. They do not update running containers or restore PostgreSQL, Keycloak, model files or Wazuh. The current signed vessel image path has separate [stopped release](../phase-5/vessel-release-switch.md), [recovery-set](../phase-5/vessel-recovery-set.md) and [paired identity](../phase-5/vessel-identity-recovery-pair.md) procedures. Keep software signing keys, trusted public keys and backup decryption keys in separate custody.

## Before an offline update

1. Record the approved change, current version, proposed version, release manifest hash, trusted public-key fingerprint, backup ID, rollback owner and maintenance window. Check the [release provenance and media requirements](../phase-5/offline-release.md). Stop if any are missing.
2. Verify the existing staged state, then verify the incoming bundle. Use only an authenticated, separately pinned public key; a valid signature alone does not approve the payload.

```sh
.venv/bin/python -m infrastructure.deploy.installer status --root /path/to/synthetic-install --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.release.bundle verify /path/to/new-bundle --trusted-key /path/to/pinned-public-key.pem
```

3. Create and verify a fresh backup of the explicitly listed **synthetic** files. The backup spec names each file and SQLite database; see the [format and limits](../phase-5/backup-recovery.md). The backup key and archive must be held separately from the release media.

```sh
.venv/bin/python -m infrastructure.backup create --spec /path/to/spec.json --output /path/to/new-backup.svb --key /private/backup-test.key
.venv/bin/python -m infrastructure.backup verify --backup /path/to/new-backup.svb --key /private/backup-test.key
```

## Stage, check and decide

```sh
.venv/bin/python -m infrastructure.deploy.installer install --bundle /path/to/new-bundle --trusted-key /path/to/pinned-public-key.pem --config infrastructure/deploy/lab-config.json --root /path/to/synthetic-install
.venv/bin/python -m infrastructure.deploy.installer status --root /path/to/synthetic-install --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.deploy.installer postcheck --root /path/to/synthetic-install --trusted-key /path/to/pinned-public-key.pem --health-config /path/to/local-health.json
```

The services must be running before `postcheck`. Record each exit code and the metadata-only report. A failed verify, status or postcheck means **stop and investigate**. Do not announce the release as healthy based on the pointer alone. The [diagnostic procedure](../phase-5/diagnostics.md) explains the bounded local checks and their limits.

## Rollback or restore

For the synthetic staged software pointer, if a previous verified release exists:

```sh
.venv/bin/python -m infrastructure.deploy.installer rollback --root /path/to/synthetic-install --trusted-key /path/to/pinned-public-key.pem
.venv/bin/python -m infrastructure.deploy.installer status --root /path/to/synthetic-install --trusted-key /path/to/pinned-public-key.pem
```

This pointer rollback does not restart a production stack or reverse a data migration. If application state needs recovery, first verify the encrypted archive and then restore into a **new, absent** destination; never overwrite the live directory with this tool.

```sh
.venv/bin/python -m infrastructure.backup verify --backup /path/to/new-backup.svb --key /private/backup-test.key
.venv/bin/python -m infrastructure.backup restore --backup /path/to/new-backup.svb --key /private/backup-test.key --destination /path/to/new-restore-directory
```

Inspect restored file inventory and rerun identity, history, permission-filtered retrieval and local service checks before an operator accepts the result. `make recovery-rehearsal` reproduces this on fictional data. If the key is unavailable, the archive cannot be recovered. Escalate key loss, restore failure or uncertain data integrity to the recovery owner; preserve the prior state and evidence.

## Current signed vessel image path

For a synthetic signed Core, Console and Knowledge installation, use
`python -m scripts.vesselctl --help` and the linked vessel procedures above.
Stop and finish-stop the source installation before capturing a new encrypted
Core/Knowledge recovery set. Verify its signed receipt and restic repository,
then restore into new owner-only installation and Core-state directories.
The clean activation command checks the signed bundle, image identities,
Knowledge row digest and Core source bytes before recording an active vessel.
It does not overwrite a live installation.

For OIDC mode, also stop the local Keycloak writer before capture, export its
realm from the stopped synthetic volume, encrypt it, and sign the exact
Keycloak/Core artifact pair. Import only the checked export into a fresh local
Keycloak before activating the signed vessel recovery set. Pass the pair,
verification key, archive and archive key to activation, interrupted finish
or abandoned retry. Those commands recheck the pair against the same signed
Core receipt; retry also requires the pair recorded by the abandoned attempt.
The [real Keycloak rehearsal](../phase-5/vessel-keycloak-paired-recovery.md)
tests this stopped synthetic sequence. It does not prove a production
database-consistent capture or that an operator imported the exact realm into
a live identity service.

## Records and limits

Record who authorised and witnessed the action, versions/hashes, backup and key-custodian references, start/end times, observed results, defects and reviewer decision in the controlled evidence store. A production schedule, retention policy, protected media, key rotation, production-consistent PostgreSQL/Keycloak/model/Wazuh backups and measured RTO/RPO remain open under [B-07](../blockers-and-build-queue.md). Do not export prompts, documents, raw logs or backup contents to the company portal; use authorised metadata only and no standing strict-mode vessel connection.
