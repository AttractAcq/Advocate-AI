# Signed Core image with external synthetic state

The product-image CI rehearsal builds Core and Console, checks each image
archive against its digest, generates an SBOM and vulnerability scan, and
creates a signed two-image bundle only when release intake passes. It takes
an application-consistent restic snapshot of fictional Core policy, one source,
manifest and SQLite history, removes the original state, verifies the encrypted
repository and restores into a clean directory. The synthetic installer then
launches the exact verified bundle with that restored state mounted outside the
image and records its paths for update, rollback and recovery. The lab
passphrase is a separate owner-only read-only mount and is absent from the
snapshot and signed bundle.

The Core container uses the host test user's UID to read and update the
mounted state. It and Console run on an internal Docker network without a
published port. The rehearsal checks the signed Core's APIs: a chief engineer
can see the approved source and cited history, a deckhand cannot, and a role
change immediately hides the source and redacts the old citation. The same
restored state remains mounted after update, rollback and recovery. The
separate restic CI job also exercises a network-isolated Core image and a
PostgreSQL restore. A candidate with unresolved
HIGH, CRITICAL or UNKNOWN image findings is denied before bundle creation,
so this runtime check is conditional on a releasable synthetic candidate.

This closes the local test gap between signed images, a clean restic Core
restore and installer-managed state mounts. The installer still does not
perform the restore itself or prove
Keycloak, PostgreSQL, model, NAS, Wazuh, protected media, target timing or
vessel recovery. Those remain in the [blocker tracker](../blockers-and-build-queue.md).
