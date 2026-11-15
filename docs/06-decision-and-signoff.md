# Phase 0 decision log and G0 sign-off

**Status:** **G0 approved for synthetic lab development** by the requesting user at 12:41 UTC on 14 November 2026. The [original electronic approval record](approval/2026-11-14-g0.md) captures the question and response. On 15 November the requester reconfirmed “0 - passes and approved” in a [Phase 0/1 review record](approval/2026-11-15-phase0-phase1.md). These are requester approvals, not an invented specialist certification or vessel permission.

## Baseline decisions proposed for approval

| ID | Decision | Rationale | Change trigger |
|---|---|---|---|
| D-01 | Strict Sovereign Mode is V1 default; all AI processing and security telemetry remain onboard. | Central product claim and data-sovereignty boundary | Any remote support, cloud processing or telemetry exception |
| D-02 | Crew enters through Console/Core HTTPS; Policy makes server-side resource/action decisions before retrieval and output. | Prevent cross-role disclosure and client bypass | New source, action, cache or tool path |
| D-03 | Wazuh runs independently; Intelligence has read-only approved findings access. | Security collection survives AI failure and model cannot administer equipment | New monitoring topology or write-capable integration |
| D-04 | Development lab uses synthetic data; Legacy 4 is only a compatibility reference until written approval. | Prevent informal production access | Specific export or live test request |
| D-05 | Initial stack is the candidate versions in `04-stack-and-provenance.md`; exact hashes are pinned at acquisition. | Reproducible lab path with supply-chain control | Version/licence/hardware incompatibility |
| D-06 | G1 basic retrieval may be simple; full ACL synchronisation and security testing belong to Phases 3–6. | Separates demonstrator from security-tested MVP | Attempt to use G1 with confidential data |
| D-07 | Sovereign Fleet is separate, with no standing strict-mode vessel connection. | Supports multi-vessel operations without contradicting no-egress claim | Request for automated Fleet telemetry |

## Open decisions requiring named owners

| ID | Decision needed | Proposed default / decision criterion | Owner | Due gate |
|---|---|---|---|---|
| O-01 | Confirm product scope, first user workflows and hard exclusions | **Resolved for synthetic lab baseline:** requester approved D-01 through D-07 on 14 November 2026 | Requesting user | G0 |
| O-02 | Confirm acceptable performance and quality thresholds | Review AT-09 and AT-18 proposals against target corpus/concurrency; sign before G2 run | Product + QA | Before Phase 2 benchmark/G2 |
| O-03 | Confirm source types, OCR and QNAP ACL semantics | Start PDF/DOCX/text/spreadsheet; add OCR only with staged models and parser test | Knowledge + security leads | Before source connector build |
| O-04 | Confirm operating OS, GPU/CUDA/vLLM and model compatibility | Benchmark exact artifacts on selected hardware; change stack if incompatible | AI + infrastructure leads | Before G1 |
| O-05 | Confirm redistribution and commercial terms | Obtain counsel/qualified licence review for all shipped binaries, weights and notices | Product/legal + DevSecOps | Before G3 distribution |
| O-06 | Confirm RPO/RTO and patch response | Lab proposal 24 h/4 h; vessel values based on owner needs and measured restore | Vessel owner + infrastructure | Before G3/G4 |
| O-07 | Confirm retention and key custody | Approve class-specific retention, backup and break-glass custodians | Vessel owner + security | Before real data |
| O-08 | Confirm vessel source/ACL matrix and Legacy 4 test scope | Separate written authorisation naming systems, datasets, method and expiry | Vessel authorised representative | Before any real data/access |
| O-09 | Confirm logs-only vs passive sensor for V1 | Logs first; passive packet sensor adds collection and privacy scope | Security + vessel AV/IT | Before Phase 4 |
| O-10 | Confirm local DNS/NTP/PKI and network port manifest | Use site-approved local services, exact IP/port matrix and cert custody | Vessel network lead | Before G3/G4 |
| O-11 | Confirm offline CTI snapshot cadence | Show age and coverage limits; set update frequency by operational capacity | Security operations | Before G3 |
| O-12 | Confirm Fleet metadata and licence workflow | No raw vessel logs/prompts/files; administrative/offline import only | Product + security | Before Fleet build |

## G0 review checklist and deferred reviews

- [x] T-001: `01-scope-and-requirements.md` approved for synthetic lab work.
- [x] T-002: `02-architecture.md` logical diagrams, data stores, flows and preliminary port matrix supplied as the lab baseline.
- [x] T-003: `03-threat-model-and-data-policy.md` records threats, risk owners and class rules. Specialist review is required before pilot.
- [x] T-004: `04-stack-and-provenance.md` candidate stack and artifact acquisition/licence process accepted for Phase 1 lab work.
- [x] T-005: `05-acceptance-tests.md` specifies pass/fail evidence and the synthetic corpus. Proposed benchmark thresholds have assigned owners and later due gates.
- [x] O-01 resolved by the requesting user; O-02 through O-05 have owners and due gates.
- [x] Electronic requester approval recorded for the G0 synthetic lab baseline. Separate vessel approval remains required for any real access or data.

## Approval and later reviewer record

| Role | Name | Decision (approve / changes required) | Date | Signature or approved record reference |
|---|---|---|---|---|
| Requesting user | Name not exposed in this workspace | Approved Phase 0 baseline for synthetic lab development | 14 Nov 2026, 12:41 UTC | Conversation response; see `approval/2026-11-14-g0.md` |
| Security architect |  | Review required before pilot; no sign-off claimed |  |  |
| Infrastructure lead |  | Site compatibility review required before installation |  |  |
| QA/test lead |  | Confirm numeric thresholds before G2 test run |  |  |

**Meaning of approval:** approval of a technical design and test baseline for synthetic lab development. It does not authorise deployment, connection to Legacy 4, collection of real vessel data, procurement, or a claim of achieved security. The original plan calls for a signed G0 baseline; the conversation response is the available electronic approval record. If a named formal signature is required by the organisation, attach it here before treating the gate as formally signed outside this workspace.
