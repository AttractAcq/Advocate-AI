# Signed Core image with external synthetic state

The product-image CI rehearsal builds Core and Console, checks each image
archive against its digest, generates an SBOM and vulnerability scan, and
creates a signed two-image bundle only when release intake passes. It now
launches that exact verified bundle with fictional Core policy, one source,
manifest and history mounted outside the image. The lab passphrase is a
separate owner-only read-only mount and is absent from the signed bundle.

The Core container uses the host test user's UID to read and update the
mounted state. It and Console run on an internal Docker network without a
published port. The rehearsal checks the signed Core's APIs: a chief engineer
can see the approved source and cited history, a deckhand cannot, and a role
change immediately hides the source and redacts the old citation. The
existing restic CI job independently proves that the same fictional state
can be backed up and restored before Core starts. A candidate with unresolved
HIGH, CRITICAL or UNKNOWN image findings is denied before bundle creation,
so this runtime check is conditional on a releasable synthetic candidate.

This closes the local test gap between signed images and external Core state.
It does not coordinate a restic restore with the signed installer or prove
Keycloak, PostgreSQL, model, NAS, Wazuh, protected media, target timing or
vessel recovery. Those remain in the [blocker tracker](../blockers-and-build-queue.md).
