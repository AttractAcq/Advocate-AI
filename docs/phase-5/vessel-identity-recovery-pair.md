# Synthetic vessel identity recovery pair

**Status: artifact binding candidate, not coordinated production recovery.**

The signed Core/Knowledge recovery receipt (schema 3) captures the Core CA and
revocation log. The separate encrypted Keycloak export contains the fictional
realm. `pair-identity-recovery` verifies both artifacts and signs their exact
hashes, the Core snapshot ID, installation ID, issuer and realm content hash.
This prevents an operator from silently substituting an older valid export or
another valid Core receipt at clean realm import.

Use a separately retained, trusted SHA-256 checkpoint for the current Keycloak
archive. The archive key, Core receipt verification key and pair signing key
remain separate. With owner-controlled paths, the synthetic commands are:

```sh
python -m scripts.vesselctl pair-identity-recovery \
  --core-receipt /private/core-receipt.json \
  --core-receipt-key /private/core-receipt-public.pem \
  --archive /private/keycloak.svbk \
  --archive-key /private/keycloak-backup.key \
  --archive-checkpoint <trusted-64-character-sha256> \
  --signing-key /private/pair-signing.pem \
  --output /private/identity-pair.json

python -m scripts.vesselctl restore-paired-identity \
  --pair /private/identity-pair.json \
  --pair-key /private/pair-public.pem \
  --core-receipt /private/core-receipt.json \
  --core-receipt-key /private/core-receipt-public.pem \
  --archive /private/keycloak.svbk \
  --archive-key /private/keycloak-backup.key \
  --destination /private/new-realm-import
```

The restore command requires a new directory, verifies both signatures and
exact archive bytes, authenticates the encrypted export and admits only one
realm file matching the Core issuer. The synthetic realm JSON is capped at
32 MiB before parsing. It removes only output that it created on failure.
The realm must then be imported through an approved Keycloak recovery process.
The pair itself does **not** prove a shared capture point, Keycloak database
consistency, live imported account state or a successful Core/Knowledge
activation. The current production identity topology, signing-key custody,
protected checkpoint media, clean-host timing, site PKI and independent review
remain open in [B-03/B-07/B-08/B-10](../blockers-and-build-queue.md).
