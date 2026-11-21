# Phase 3 knowledge and permission gate

**Status: open.** The synthetic Mac flow now runs, but the technical Phase 3
gate requires a reviewable role, revocation, citation and injection result for
the intended local architecture. The target identity, database and NAS
boundaries have not yet been qualified.

| Plan item | Implemented and run | Remaining |
|---|---|---|
| T-014 ingestion | Allowlisted SHA-256 manifest, local Docling conversion of PDF/DOCX/XLSX, UTF-8 text, chunking, quarantine and deletion reconciliation; 109/112 synthetic sources index. Office ZIP preflight, time-bounded offline parser worker, Linux address-space/CPU limits, polling reconciliation and bounded regular-file manifest intake were added. Repeated JSON keys and non-finite constants are rejected by both ingestion and retrieval. The parser receives a private snapshot of the exact bytes checked against the source digest | Read-only service identity and approved local share mount; scanned PDF/OCR, target Linux parser/cgroup qualification and NAS ACL/polling behavior |
| T-015 index/retrieval | Local passage and embedding index, permission filter before lexical/vector ranking, source recheck before citation and preview; 50/50 fixed selection cases for both guarded modes. Citation metadata carries the passage ordinal, with an API regression for later-passage preview. A fresh [Core API run](core-answer-evaluation.json) captures citation objects and exact preview text: 40/40 expected synthetic markers and matching citations, 10/10 no-answer denials. A [local PostgreSQL/pgvector candidate](postgres-pgvector-index.md) supports Core search, preview and chat plus transactional ingestion and exact vector ranking. A [synthetic encrypted recovery rehearsal](../phase-5/pgvector-knowledge-recovery.md) restores the index with approved sources and policy and rechecks access; six disposable-database integration tests pass. An [actual Core image and pgvector socket rehearsal](../phase-5/pgvector-core-socket-runtime.md) runs without container network routes and checks live API permission revocation | Signed PostgreSQL runtime deployment and full-stack recovery, semantic quality beyond exact-term guard, independent claim-support assessment and broader adversarial corpus |
| T-016 identity/policy | Pinned local Keycloak lab realm, PKCE Console path, signed JWT validation, active-role and expiry checks, source-level deny rules, persistent hash-only logout revocations and hash-chained audit. The synthetic role file has bounded intake; duplicate/expired identities deny access, and role changes invalidate old lab tokens. The [audit file boundary](audit-file-boundary.md) rejects symlink/inode replacement. A [two-person offline change rehearsal](policy-change-rehearsal.md) binds approvals to exact policy bytes, blocks Core during a pending change and supports rollback. The [emergency drill](emergency-access-rehearsal.md) uses a disabled fixture identity, a separate secret, short expiry and restricted diagnostics | Enforce MFA, durable identity store, service accounts, owner-approved signer and role maps, production admin and emergency recovery actions; protect audit parent/retention and test deployment network controls |
| T-017 non-disclosure | Automated five-role/collection matrix covering list, search, preview, chat citation, disabled download/export and removed users; revocation, deletion, history, token-signature and audit tamper tests; live engineer/deckhand Keycloak checks and restart-persistent logout check. Local API ACL change denies search, preview, chat context/citation and prior history within 60 seconds. Corrupt manifests, duplicate IDs or keys, and non-finite JSON fail closed across source, preview, search and chat APIs; malformed role policy denies authentication. Source reads are anchored to directory descriptors and reject symlink components; live retrieval rechecks bytes against the manifest | Repeat propagation and cache probing in target topology, independent QA/security execution and wider adversarial corpus |

Core revalidates the requesting identity after source listing, preview, search,
staged-document listing and conversation reads, before returning their content.
A synthetic mid-request token revocation test covers the source, preview,
search and conversation paths. This checks the local API behavior; the target
identity and policy-change propagation still require independent testing.
For document staging, Core revalidates after the quarantine write and audit
decision and removes the new upload if the identity changed during the request.
A synthetic test revokes the token inside the write and checks that no blob or
metadata remains.

The injection fixture initially reached the local model and produced an
unsupported description of its hex text. Core now withholds instruction-like
passages from inference and returns an authorised citation with a review
message. This is a conservative local safeguard; it is not proof against all
indirect prompt injection. See the [runbook](runbook.md),
[format register](supported-formats.md) and [evaluation](evaluation.json).
The [answer evaluation](answer-evaluation.json) contains all 50 generated
answers and proxy scores. Source labels in model prose are not a substitute
for verifying API citation metadata and support for each claim.
An [internal answer-by-answer review](claim-support-review.md) found six
wording or support exceptions among the 40 allowed responses. The historical
report does not retain structured citation objects or exact passages. The
19 November Core API run records both and has five preliminary prose
exceptions. A [21 November concise-answer candidate](core-answer-evaluation.json)
again records 40/40 expected markers and matching citations, plus 10/10
no-answer denials; an internal reading found no unsupported additions in those
40 marker answers. This narrow synthetic result does not close AT-09 or replace
independent assessment of broader vessel questions.

A [five-case procedure-action run](procedure-answer-evaluation.json) adds four
non-marker action questions and one cross-role denial. It cites the intended
source in all four permitted cases and denies the engineering source to a
deckhand. One answer expands “use” to “retrieve” for a checklist; the
[internal review](claim-support-review.md) records that wording for the
independent assessor. The 50 marker cases also passed unchanged after the
query normalization. This improves local retrieval coverage without closing
the target identity, NAS or claim-support gates.

Phase 3 does not authorise vessel data. The G1 hardware/offline items from
[Phase 2](../phase-2/gate.md) also remain open.
