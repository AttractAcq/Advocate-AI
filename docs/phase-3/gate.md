# Phase 3 knowledge and permission gate

**Status: open.** The synthetic Mac flow now runs, but the technical Phase 3
gate requires a reviewable role, revocation, citation and injection result for
the intended local architecture. The target identity, database and NAS
boundaries have not yet been qualified.

| Plan item | Implemented and run | Remaining |
|---|---|---|
| T-014 ingestion | Allowlisted SHA-256 manifest, local Docling conversion of PDF/DOCX/XLSX, UTF-8 text, chunking, quarantine and deletion reconciliation; 109/112 synthetic sources index. Office ZIP preflight and a time-bounded offline parser worker were added | Read-only service identity and approved local share mount; scanned PDF/OCR, OS-level parser resource limits, NAS ACL mapping and incremental watcher |
| T-015 index/retrieval | Local passage and embedding index, permission filter before lexical/vector ranking, source recheck before citation and preview; 50/50 fixed selection cases for both guarded modes. Generated-answer run: 40/40 expected synthetic markers, 10/10 no-answer denials, 32/40 source labels in answer text | PostgreSQL/pgvector target topology, semantic quality beyond exact-term guard, independent claim-support assessment and broader adversarial corpus |
| T-016 identity/policy | Pinned local Keycloak lab realm, PKCE Console path, signed JWT validation, active-role check, source-level deny rules, persistent hash-only logout revocations and hash-chained audit | MFA enforcement, durable identity store, service accounts, admin workflow, emergency access and deployment network controls |
| T-017 non-disclosure | Automated five-role/collection matrix covering list, search, preview, chat citation, disabled download/export and removed users; revocation, deletion, history, token-signature and audit tamper tests; live engineer/deckhand Keycloak checks and restart-persistent logout check | Cache/context probing and 60-second propagation proof in target topology, independent QA/security execution and wider adversarial corpus |

The injection fixture initially reached the local model and produced an
unsupported description of its hex text. Core now withholds instruction-like
passages from inference and returns an authorised citation with a review
message. This is a conservative local safeguard; it is not proof against all
indirect prompt injection. See the [runbook](runbook.md),
[format register](supported-formats.md) and [evaluation](evaluation.json).
The [answer evaluation](answer-evaluation.json) contains all 50 generated
answers and proxy scores. Source labels in model prose are not a substitute
for verifying API citation metadata and support for each claim.

Phase 3 does not authorise vessel data. The G1 hardware/offline items from
[Phase 2](../phase-2/gate.md) also remain open.
