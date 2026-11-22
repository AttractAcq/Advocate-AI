# Synthetic direct API role-bypass matrix

**Status:** local regression evidence only. This is not independent AT-05/06/07/08 acceptance, T-026 completion or G2 approval.

The new `tests/test_role_bypass_matrix.py` creates five fictional indexed sources with distinct markers: management, engineering, interior, deck and restricted owner. It logs in as one user from each synthetic role and checks all 25 role/source pairs. Expected access is specified in the test independently of the policy file:

| Role | Management | Engineering | Interior | Deck | Restricted owner |
|---|---:|---:|---:|---:|---:|
| Captain | Allow | Allow | Allow | Allow | Deny |
| Chief engineer | Deny | Allow | Deny | Allow | Deny |
| Chief stewardess | Deny | Deny | Allow | Allow | Deny |
| Deckhand | Deny | Deny | Deny | Allow | Deny |
| AV/IT administrator | Deny | Deny | Deny | Allow | Deny |

For each pair, the test directly calls source listing, passage preview, lexical search with an explicit document ID, document chat with that ID, and the disabled download route. It checks citations, returned answers and the model's received context; denied content must not reach the model. Separate cases verify cross-user conversation IDs, export denial, administrator and security route scope, invalid bearer tokens, rejected client-supplied role claims, and immediate redaction after a per-document deny rule. These exercise the server paths rather than Console visibility.

The matrix also found a fixture-path inconsistency: source listing in Core used `Path.resolve()` and could still list a source replaced by a same-content symlink, although retrieval rejected it. The initial fix used a shared path check, and a regression test replaces the source after startup before listing and chatting. W-56 now reads each component through directory descriptors, so listing and retrieval reject symlink replacements without a separate path check; ingestion parses the verified byte snapshot. Target NAS concurrency remains to be tested.

**Limits:** The test uses local lab bearer sessions, SQLite indexing, fictional documents and a fake model. It does not exercise deployed Keycloak/OIDC, NAS ACLs, vector API results, source downloads/exports (both disabled), concurrent policy changes, real vessel classifications or independent assessor attempts. The owner-approved vessel matrix and full role/action trace set remain [B-03 and B-08](../blockers-and-build-queue.md). Target host and no-egress proof remain B-06.
