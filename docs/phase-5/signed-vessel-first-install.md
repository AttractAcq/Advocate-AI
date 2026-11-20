# Signed vessel first-install candidate

The new first-install entry point takes a verified schema-6 vessel bundle,
trusted public key, pinned crane binary, synthetic Console configuration,
owner-only Core state and a separate lab credential. It requires a new private
installation root beneath a private parent. It copies and re-verifies the
complete signed bundle and Console configuration into a release directory.

Installation creates a labelled persistent PostgreSQL volume and private
administrator, ingestion and reader credentials outside the signed images.
A disposable signed Core container uses the ingestion role to reconcile the
approved manifest. Quarantined sources deny activation. The installer grants
the Core reader role SELECT on the knowledge tables, starts the signed Core
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
separate schema-migration authority, database encryption, coordinated restic
capture and clean restore, key custody, real vessel identity/model/NAS
integration, target hardware checks and independent review remain open.

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

Interrupted-process reconciliation, automated rollback, schema migration,
coordinated encrypted recovery, target hardware and independent review remain
open.

## Operator command

`python -m scripts.vesselctl` exposes `install`, `status`, `stop` and `recover`
for the synthetic candidate. Every command requires explicit absolute paths
for `--root`, `--trusted-key` and the pinned `--crane` binary. `install` also
requires `--bundle`, `--console-config`, `--core-state` and
`--lab-password-file`. It prints a small JSON result after success; errors
exit nonzero. `recover` requires a clean stop and refuses residual old Docker
resources. The command is not yet a vessel service unit or a production
commissioning workflow.
