# Signed vessel first-install candidate

The new first-install entry point takes a verified schema-6 vessel bundle,
trusted public key, pinned crane binary, synthetic Console configuration,
owner-only Core state and a separate lab credential. It requires a new private
installation root beneath a private parent. It copies and re-verifies the
complete signed bundle and Console configuration into a release directory.

Installation creates a labelled persistent PostgreSQL volume and private
administrator, migration, ingestion and reader credentials outside the signed images.
A disposable signed Core container uses the migration role to create the
Knowledge tables and grant table-level DML to ingestion and SELECT to the
reader. A separate container uses the ingestion role to reconcile the approved
manifest. The ingestion and reader roles cannot create schema objects.
Quarantined sources deny activation. The installer starts the signed Core
and Console images against the running Knowledge container, and checks their
network, mount, role, image and health boundaries. It writes `vessel-state.json`
atomically only after those checks pass. `status_vessel` verifies the staged
signature and compares the running images with the exact signed archives.

The CI release rehearsal performs a clean synthetic installation from the
temporary signed bundle, checks that the active release reports healthy, then
removes the disposable services and data volume. A failed candidate has no
active record. The installer removes its private root only after scoped Docker
inventory confirms that the candidate's containers, network and volumes are
gone. If cleanup cannot be confirmed, it retains the private root and its
database credentials and reports an incomplete cleanup for manual recovery.

The first-install path covers initial activation. Release updates, rollback,
versioned schema migrations, database encryption, coordinated restic
capture and clean restore, key custody, real vessel identity/model/NAS
integration, target hardware checks and independent review remain open.

## Knowledge schema version boundary

The migration role now creates a single-row `knowledge_schema_version` table
with version `1` in the same transaction as the four Knowledge tables. A
repeated setup accepts exactly that version and all four tables. It refuses an
unversioned existing schema, a missing table, an empty or extra version row,
and a future version. The Core reader can inspect the version but cannot
change it. Vessel status and stopped-runtime recovery check the version before
accepting the Knowledge runtime; a clean recovery snapshot checks it too.
The signed-image rehearsal changes the synthetic version to `2`, verifies that
status denies it, and restores `1` before continuing. This is a compatibility
guard, not a migration from an older schema. A real upgrade path and rollback
compatibility remain open.

## Clean stopped-runtime recovery candidate

`stop_vessel` checks the healthy signed installation, removes the Core and
Console containers and their private network, then stops Knowledge and removes
its disposable socket volume. It retains the database volume and active
release record. `recover_vessel` re-verifies the signed stage, Core state and
credentials, and requires Docker to show only the installation's checked
persistent data volume. It also confirms that the old container, network and
socket IDs are absent. It starts a new signed Knowledge container against the
existing data, then new Core and Console containers, and records their IDs only
after health checks pass. A failed recovery keeps the old state and data; if
cleanup or state reconciliation is uncertain, it retains the private root for
investigation. The actual-image CI rehearsal stops and recovers the synthetic
installation and rechecks signed image identity and health.

Interrupted-process reconciliation, automated rollback, versioned schema migration,
coordinated encrypted recovery, target hardware and independent review remain
open.

## Operator command

`python -m scripts.vesselctl` exposes `install`, `status`, `stop`,
`finish-stop`, `reconcile`, `recover`, `reconcile-install`, `resume-install`
and `reset-bootstrap`
for the synthetic candidate. Every command requires explicit absolute paths
for `--root`, `--trusted-key` and the pinned `--crane` binary. `install` also
requires `--bundle`, `--console-config`, `--core-state` and
`--lab-password-file`. It prints a small JSON result after success; errors
exit nonzero. Stop and recover take an exclusive owner-only installation lock
and reject a competing operator command. `recover` requires a clean stop and
refuses residual old Docker resources. The command is not yet a vessel service
unit or a production commissioning workflow.

`reconcile` addresses an interruption after a clean stop when new signed
services started but their IDs were never committed to the active record. It
first proves the old recorded resource IDs are absent. It then inventories
installation-scoped containers, networks and volumes, checking their labels,
names, roles, network isolation and Knowledge volume mounts. Only after every
resource passes does it remove the orphan containers, networks and disposable
socket volumes. The persistent Knowledge data volume and credentials remain.
The signed-image rehearsal creates a full orphan Core, Console and Knowledge
runtime, reconciles it and recovers the same installation. An interruption
during the initial installation and a crash after active-state replacement
still require separate handling.

`finish-stop` handles an interrupted or incomplete stop. It requires every
remaining container, network and socket volume to be one of the recorded
resources, verifies their signed image and installation identity, and removes
them in service, network, Knowledge order. It preserves the persistent
database volume. A foreign or unrecorded resource causes a refusal before
deletion. The actual-image rehearsal leaves Knowledge running after Core,
Console and their network are removed, then uses `finish-stop` before
reconciliation and recovery.

## First-install intent

Before creating the first Knowledge volume, the installer writes an owner-only,
fsynced `vessel-intent.json` containing the installation ID, signed release ID,
external Core state path and credential path. A failed install with incomplete
Docker cleanup retains this record alongside the private credentials. A
successful activation writes the active state and removes the intent; the
actual-image rehearsal checks its absence. The intent is strictly parsed with
duplicate-key and field checks.

`reconcile-install` uses that intent to validate the signed stage and the
installation's scoped Docker inventory. If the data volume exists, it checks
all orphan containers, networks and socket volumes before removing them, while
retaining the data and credentials. If no data volume or scoped runtime exists,
it verifies the volume is truly absent and clears only private bootstrap
credentials so initialization can safely start again. It refuses an active
record or any unexpected resource.

`resume-install` requires the same signed stage and a clean scoped inventory.
It initializes a new Knowledge volume only if none exists, or reattaches the
checked persistent volume with its external credentials. It reruns idempotent
approved-source ingestion, starts signed Core and Console, and writes the
active record only after health. The intent is then removed. The actual-image
CI rehearsal creates an unrecorded three-service first install, reconciles it,
resumes it against the same database volume and checks the final healthy state.
If the active record was already committed but the intent remains, `resume-install`
checks the complete running signed installation and requires the active release,
installation ID, external paths and data volume to match the intent. It then
clears only the stale intent and reports `already-activated`.
Interrupted PostgreSQL bootstrap with an existing but not yet secured data
volume still requires explicit operator investigation.

`reset-bootstrap --discard-data` is an explicit synthetic recovery option when
a first-install data volume cannot be safely resumed. It requires a signed
intent, no active record, no containers, no network, exactly one labelled data
volume and valid private bootstrap credential files. Only then does it remove
the volume and those credentials, retaining the signed stage and intent for
`resume-install` to initialize afresh. The actual-image rehearsal creates a
labelled incomplete bootstrap volume, resets it and verifies a fresh signed
activation. This command discards any data in that volume; it never runs
automatically during resume or reconciliation.
