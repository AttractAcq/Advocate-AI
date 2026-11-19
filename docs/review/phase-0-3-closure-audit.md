# Phase 0–3 closure audit for the synthetic baseline

**Status: not closed.** This audit maps the technical plan's T-001–T-017 and
gate requirements to current evidence. “Local evidence” means synthetic
macOS or CI behavior; it does not certify the intended vessel appliance.
Hardware, site access and owner decisions remain deferred by the requester.
An external security/QA reviewer was selected in principle but has not been
named or completed a review. No independent sign-off is claimed here.
The requester directed a [one-time PR #9 review exception](../approval/2026-11-15-pr9-review-exception.md)
to merge the synthetic work without a second GitHub account's approval. This
does not close the external security/QA review task.
The requester separately [approved Phase 0 and reviewed/approved Phase 1](../approval/2026-11-15-phase0-phase1.md)
on 15 November 2026. That decision closes requester acceptance of their
synthetic deliverables; it does not replace the target G0A test or an
independent PR/security review.

| Plan item | Local evidence now | What prevents closure |
|---|---|---|
| T-001 V1 operating model | [Scope](../01-scope-and-requirements.md) defines strict local operation, users, workflows and exclusions; [G0 approval](../approval/2026-11-14-g0.md) accepts D-01–D-07 for synthetic work | Vessel-specific scope and role approvals are separate |
| T-002 architecture and trust boundaries | [Architecture](../02-architecture.md) maps services, stores, zones and preliminary ports | Physical addresses, final local DNS/NTP/PKI and deployment port verification need target site |
| T-003 threats and data classes | [Threat model](../03-threat-model-and-data-policy.md) covers intrusion, crew device, injection, insider, theft and supply chain | External specialist review; owner retention and key-custody decisions before real data |
| T-004 reference stack and licensing | [Stack/provenance](../04-stack-and-provenance.md) and [candidate SBOM](../candidate-sbom.json) describe candidates and acquisition checks | GPU/inference compatibility requires hardware; commercial redistribution review is due before G3 |
| T-005 measurable tests | [Acceptance matrix](../05-acceptance-tests.md), deterministic corpus and named lab roles exist | Product and QA have not signed proposed AT-09/AT-18 thresholds; target measurements remain open |
| **G0** signed baseline | Requester [approved](../approval/2026-11-14-g0.md) and [reconfirmed pass](../approval/2026-11-15-phase0-phase1.md) for the synthetic Phase 0 baseline | Later independent security review and any organisation-required formal signature remain separate; no vessel approval |
| T-006 repository and secure CI | Public repo, protected `main`, PR checks for quality, full-history secrets and dependency audits; [controls](../phase-1/repo-controls.md) | External reviewer account/approval and release-tag controls when releases begin |
| T-007 isolated lab | [Loopback topology and inventory](../phase-1/as-built-inventory.json), disposable PKI/DNS and synthetic events | Ubuntu GPU host, segmented network, test NAS, firewall and Wazuh VM need hardware |
| T-008 safe fixtures | 100 fictional documents, 12 mixed/negative files, four events; [fixture guide](../fixtures.md) and hash checks | Independent fixture-safety review |
| T-009 observability | Local health, metrics, dashboard, structured logs, [runbook](../phase-1/lab-runbook.md) and smoke result | Target CPU/GPU/storage metrics and network observability need deployment |
| **G0A** reproducibility | [Fresh-clone record](../phase-1/gate.md) has a 33-test run at commit `151e014`, Console build, smoke probes and matching source archive; the later history change passes 34 tests locally. Requester [reviewed and approved](../approval/2026-11-15-phase0-phase1.md) local Phase 1 work | Repeat latest commit in target Ubuntu/segmented lab and obtain independent QA record |
| T-010 local inference | [Mac model card](../phase-2/model-card.md) and [benchmark](../phase-2/benchmark-mac.json) show loopback Ollama simulation | Pinned vLLM/NIM, planned model and GPU capacity/offline cold start need target hardware |
| T-011 Sovereign Core | FastAPI chat, history, model routing, request limits, local model boundary, optional restart-persistent synthetic history and API tests | Encrypted/retained history and target network isolation need approved deployment design |
| T-012 Sovereign Console | React sign-in, chat, document selection, inspectable passage citations, scope, history, read-only admin; build and [source review](../phase-2/console-accessibility.md) | Rendered keyboard, screen-reader and zoom QA was unavailable in the current browser service; target TLS/proxy deployment remains |
| T-013 end-to-end demo | [Synthetic demo](../phase-2/demo-result.json) and [runbook](../phase-2/runbook.md) show local role and cited-answer flow | G1 requires a disconnected-WAN run, egress capture and target-host evidence |
| **G1** offline cited chat | Local synthetic model and citations work | Disconnected target-host proof is absent; gate remains open |
| T-014 ingestion | [Format register](../phase-3/supported-formats.md): Docling PDF/DOCX/XLSX, UTF-8, SHA-256 allowlist, quarantine, bounded worker, Linux address-space/CPU limits, deletion reconciliation, polling manifest watcher, bounded manifest intake with strict duplicate-key rejection, and parsing from the verified byte snapshot | Read-only NAS identity/mount, ACL mapping, OCR qualification and target Linux parser/polling validation |
| T-015 authorised retrieval | Passage/embedding index, pre-ranking permission filter, source recheck, passage-ordinal citations and [fixed evaluation](../phase-3/evaluation.json); [generated answers](../phase-3/answer-evaluation.json) | Semantic/claim-support assessment by an independent reviewer; target database topology |
| T-016 identity and policy | Local Keycloak lab, Console PKCE, signed JWTs, bounded role-file intake, role/source policy, logout revocation, audit, [operations design](../phase-3/identity-operations.md) | MFA enforcement, service identities, approved policy administration and emergency access are designed but not implemented or reviewed for deployment |
| T-017 role non-disclosure | Automated five-role/action matrix, revocation, deletion, injection, audit tamper, corrupt-manifest and history-redaction tests | Independent adversarial QA/security execution; target NAS/identity/cache propagation checks |
| **Phase 3 gate** role, revocation, citation and injection tests | Local regression suite and historical 50-question evidence exist; an [internal reading](../phase-3/claim-support-review.md) finds six wording/support exceptions. A fresh [Core API run](../phase-3/core-answer-evaluation.json) captures 40/40 matching marker and structured citation passages, 10/10 denials and five preliminary prose exceptions | Independent claim review, agreed AT-09 threshold and security sign-off are missing; target boundaries unqualified |

## Actionable nonhardware work still open

1. Appoint an external reviewer, request PR approval and obtain an
   attributable Phase 0–3 report using the [review brief](phase-0-3-external-review.md).
2. Have an independent reviewer assess both 50-answer runs, their recorded
   wording exceptions and the fresh Core citation passages; then agree AT-09
   quality thresholds.
3. Complete a rendered Console keyboard/screen-reader/zoom run when a browser
   automation surface or human tester is available.
4. Implement and test the synthetic administrative identity/emergency workflow
   or obtain the authorised vessel policy needed to scope it; the current
   [design](../phase-3/identity-operations.md) is not an operational control.

The requested move to Phase 4 can be planned with synthetic fixtures, but
this audit does not change the original G0A, G1 or Phase 3 exit criteria.
