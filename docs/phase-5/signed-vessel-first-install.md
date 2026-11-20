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

This only covers first activation. Release updates, rollback, stopped-runtime
recovery, separate schema-migration authority, database encryption, coordinated
restic capture and clean restore, key custody, real vessel identity/model/NAS
integration, target hardware checks and independent review remain open.
