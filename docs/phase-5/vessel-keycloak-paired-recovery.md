# Signed vessel and Keycloak paired recovery rehearsal

**Status: synthetic Linux CI candidate, not a production recovery procedure.**

The three-image release rehearsal now starts the signed Core, Console and
Knowledge bundle with the pinned synthetic Keycloak image on an internal
identity network. Fictional engineer and deckhand users obtain real PKCE
tokens. Core checks the approved source boundary and persists an engineer
logout revocation.

The rehearsal stops the signed vessel runtime and Keycloak before capture.
It creates the encrypted Core/Knowledge restic snapshot and Ed25519 receipt,
exports the stopped Keycloak realm from its disposable data volume, encrypts
that export, and signs an [identity artifact pair](vessel-identity-recovery-pair.md)
binding both exact artifacts. It then removes the old Keycloak and Knowledge
volumes, verifies and restores the paired realm into a clean import directory,
starts a fresh Keycloak instance, and activates the signed vessel bundle with
clean Core and Knowledge state. An old **unrevoked**, unexpired deckhand token
must still work against the fresh Core and restored Keycloak keys; the old
**revoked**, unexpired engineer token must remain denied. Fresh engineer and
deckhand logins must regain only their permitted source scope. The lab
Keycloak image is pulled by digest before the rehearsal; all rehearsal
`docker run` calls use locally present images.

The result is retained in the `signed_vessel_keycloak_pair` section of the
three-image release evidence. It proves a **stopped synthetic sequence** on
the CI runner. Keycloak's development database and realm export omit some
persistent production state, including sessions and events. A production
Keycloak database topology, a capture lock spanning all live writers,
approved keys and media, live identity import attestation, target-host timing,
site PKI and independent review remain [open](../blockers-and-build-queue.md).
