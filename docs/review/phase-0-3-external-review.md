# External security and QA review package: Phases 0–3

**Purpose.** Independently assess the synthetic development baseline and the
software controls that can be tested before target hardware or vessel access.
The requester selected an external reviewer on 15 November 2026. The reviewer
has not been appointed or signed off. No vessel documents, credentials or logs
are included in this package.

## Review scope

| Area | Primary evidence | Reviewer decision needed |
|---|---|---|
| Phase 0 design | [Scope](../01-scope-and-requirements.md), [architecture](../02-architecture.md), [threat model](../03-threat-model-and-data-policy.md), [stack](../04-stack-and-provenance.md), [acceptance matrix](../05-acceptance-tests.md), [G0 approval](../approval/2026-11-14-g0.md) | Confirm threat coverage, data classes, exclusion boundaries and proposed AT-09/AT-18 thresholds; record changes |
| Phase 1 repo and fixtures | [G0A record](../phase-1/gate.md), [runbook](../phase-1/lab-runbook.md), `.github/workflows/ci.yml`, `fixtures/` | Review fixture safety, source integrity, public-repository exposure and active branch protection |
| Phase 2 Core and Console | [G1 record](../phase-2/gate.md), [runbook](../phase-2/runbook.md), `apps/api/`, `apps/console/web/` | Review API auth, model boundary, citations, error handling and browser accessibility; separate hardware/offline items remain deferred |
| Phase 3 Knowledge and Policy | [gate record](../phase-3/gate.md), [ingestion register](../phase-3/supported-formats.md), [identity operations design](../phase-3/identity-operations.md), [retrieval evaluation](../phase-3/evaluation.json), [generated answers](../phase-3/answer-evaluation.json), `services/knowledge/`, `services/policy/`, `tests/` | Attempt cross-role access, stale ACL, deletion, injection, source spoofing, audit tamper and token replay; judge identity controls, answer claim support, parser limits and residual risk |

## Reproduction commands

From a fresh clone on a connected preparation workstation:

```sh
uv sync --locked --extra phase3
make fixtures
make check
make lab-smoke
cd apps/console/web && npm ci --ignore-scripts && npm run build
```

For local model and identity checks, use the Phase 2 and Phase 3 runbooks. The
reviewer should record the commit, host OS, model digest, fixture manifest hash,
exact commands, observed outputs, defects and retest results. They should
inspect application behavior as well as green CI. Do not copy local test
passwords or model cache into the review report.

## Required reviewer record

The reviewer should return a signed or otherwise attributable report with:

1. Reviewer name, organisation, qualifications and independence statement.
2. Commit SHA, scope, environment, test dates and tool versions.
3. Each test case and observed result, including prohibited-access attempts.
4. Findings with severity, exploit path, evidence and remediation or accepted risk.
5. Explicit decisions for software-only Phase 0–3 work and clearly deferred
   hardware/vessel checks. A synthetic pass must not be described as a vessel
   permission review or G1/G0A hardware gate pass.
6. Retest evidence for all critical and high findings before pilot use.

The automated answer run found 40/40 expected markers and 10/10 no-answer
denials, but only 32/40 permitted answers named their source and version in
prose. The API returns structured citations separately. The reviewer should
assess citation integrity and whether generated claims actually follow from
source text; neither proxy score is a human citation-support pass.

## Decision register

| Decision | Owner | Current state |
|---|---|---|
| Appoint independent security/QA reviewer | Requester | External reviewer selected; name and engagement pending |
| Adopt AT-09 answer/citation/no-answer thresholds | Product + QA | Proposed in acceptance matrix; not signed |
| Adopt AT-18 latency/concurrency thresholds | Product + QA | Proposed; target GPU measurement pending |
| Approve source formats, OCR and NAS ACL mapping | Knowledge + security leads | Text-layer PDF, DOCX, XLSX and UTF-8 synthetic formats tested; real NAS semantics pending |
| Approve vessel data/roles/retention/key custody | Vessel owner/management | Not requested or approved; requires site-specific process |
| Review commercial redistribution terms | Qualified legal/product owner | Open before G3 distribution |

## Review outcome

**Pending external execution.** This page is the review brief, not a sign-off.
Attach the attributable report and defect register under `docs/review/` when
received. Until then, reviewer-dependent gates remain open.
