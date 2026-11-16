# Restored Core state in an isolated container

The CI recovery job uses the pinned restic binary to back up fictional role
policy, a one-source manifest, that source file and SQLite conversation
history. It removes the original directory, restores those four files into a
new directory, and starts a freshly built Core image with that state mounted.
The container runs as a non-root user, with a read-only image filesystem,
Docker network mode `none` and no published host port. A separate owner-only
synthetic passphrase file is mounted read-only; the passphrase is absent from
the Docker command line and restored snapshot.

From inside the container, the rehearsal logs in as a chief engineer, reads
the restored source and cited conversation, and confirms that a deckhand
cannot see either. It then removes engineering permission in the mounted
fictional policy and confirms that Core immediately hides the source and
redacts the old cited answer. The image is identified by its local Docker
content ID after being built from the digest-pinned base and locked Python
dependencies. This test does not use a model server or a signed product
bundle.

The optional `SOVEREIGN_FIXTURE_ROOT` and
`SOVEREIGN_LAB_PASSWORD_FILE` settings exist for this synthetic recovery
exercise. The credential file must be an unlinked, owner-only regular file;
the environment carries only its path. These lab settings are not the vessel
identity or document storage design.

This demonstrates that restored application state can be consumed by a new
Core process and that permissions are rechecked after recovery. It does not
restore Console, Keycloak, PostgreSQL, model files, Wazuh, NAS data or the
signed installer as a coordinated stack. Protected media, target timing,
offline model operation and [AT-16](../05-acceptance-tests.md) remain open.
