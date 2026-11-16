# Sovereign AI

Sovereign AI is a private vessel assistant and read-only cybersecurity intelligence product. The [technical development and implementation plan](docs/Sovereign_AI_Technical_Development_and_Implementation_Plan.docx) is the detailed build plan for this repository. Its task IDs and gates govern delivery. The [build-plan overview](<docs/Soverign AI build plan 14_11_2026.txt>) describes the five product milestones and seven proprietary modules.

**Current state:** Phase 0 G0 was approved by the requester on 14 November 2026 and reconfirmed on 15 November for synthetic lab development ([approval records](docs/approval/2026-11-15-phase0-phase1.md)). The requester also reviewed and approved completed Phase 1 local work; the public repository has enforced `main` protection, while target hardware/network checks and independent review remain open in [G0A evidence](docs/phase-1/gate.md). Phase 2 has a working synthetic Core, Console, retrieval and local-model flow on a Mac; [G1 evidence](docs/phase-2/gate.md) keeps the target hardware and disconnected-WAN gate open. Phase 3 local ingestion, indexed retrieval, Keycloak identity and audit work remains under test; its [gate record](docs/phase-3/gate.md) and [external review brief](docs/review/phase-0-3-external-review.md) list remaining controls. Phase 4 synthetic alert analysis is merged; its [gate record](docs/phase-4/gate.md) keeps independent Wazuh and outage proof open. This baseline does not authorise vessel access, production data, procurement or deployment.

**Unfinished work:** [Blockers and build queue](docs/blockers-and-build-queue.md) is the current index of deferred gate evidence and software we can build locally. Phase 5 signed offline bundle, [health diagnostics](docs/phase-5/diagnostics.md), [synthetic encrypted recovery](docs/phase-5/backup-recovery.md), [synthetic installer](docs/phase-5/installer.md), [adversarial hardening](docs/phase-5/security-hardening.md) and the [direct API role matrix](docs/phase-5/role-bypass-matrix.md) are local software slices. The [Phase 6 operator and engineer pack](docs/phase-6/operator-engineer-pack.md) documents those flows and open handover evidence. They do not close G2/G3 or certify a release.

## Product milestones

| Milestone | Result | Detailed phases |
|---|---|---|
| Working private AI | Crew use Console and Core with a local model and cited answers from test documents. | 1: reproducible lab; 2: Core, Console and inference; initial retrieval in 2–3 |
| Security and document permissions | Knowledge and Policy Engines enforce source permissions and audit access. | 3: ingestion and access control; security verification through 5–6 |
| Cybersecurity intelligence | Intelligence Engine explains Wazuh and representative network events using approved context. | 4: read-only security analysis and adapters |
| Production deployment | Installer, configurations, signed offline updates, health checks, encrypted backups and recovery form a pilot-ready appliance. | 5: hardening and recovery; 6: release kit; 7A–7C: authorised pilot |
| Fleet management and expansion | Company portal manages customers, licences, releases and support across installations. | Expansion after pilot; post-launch delivery section of the plan |

## Engineering phases and gates

| Phase | Work | Exit |
|---|---|---|
| 0 | Requirements, architecture, threat model, stack and test plan | **G0 passed** for synthetic lab development |
| 1 | Repository, isolated lab and reproducible build | G0A: fresh build and documented lab reproduction |
| 2 | Local model serving, Sovereign Core and Console, basic cited retrieval | G1: chat and citations with WAN disconnected |
| 3 | Knowledge ingestion, source permissions, Policy Engine and audit enforcement | Role, revocation, citation and injection tests pass |
| 4 | Read-only cybersecurity intelligence and vessel adapters | Representative alerts have evidence and explanations |
| 5 | Security hardening, offline release, backup and recovery | G2: MVP-critical lab controls pass |
| 6 | MVP validation and pilot-ready installation package | G3: security-reviewed release and installation rehearsal |
| 7A–7C | Approved site survey, installation, commissioning and handover | G4: signed site acceptance and handover |
| Post-launch | Maintenance, signed updates, recovery checks and repeatable deployments | Operational records and release gates |

The five milestones describe product outcomes; the engineering phases set their delivery order. Phase 2 and 3 demonstrations use synthetic data. Full vessel permissions and security review are later gates.

## Proprietary modules

| Module | Responsibility |
|---|---|
| Sovereign Console | Crew chat, documents, citations, history, workspaces and administration |
| Sovereign Core | Authenticated APIs, request orchestration, model connection and controlled tool use |
| Knowledge Engine | Parsing, indexing, NAS synchronisation and permission-aware retrieval |
| Policy Engine | Resource authorisation, source permission mapping and audit events |
| Intelligence Engine | Read-only security event normalisation, analysis and reporting |
| Vessel Connect & Deploy | Integration adapters, installation, offline updates, diagnostics and recovery |
| Sovereign Fleet | Separate company portal for customers, vessels, licences, releases and support |

Strict Sovereign Mode is the V1 default: prompts, vessel documents, embeddings and security telemetry remain onboard. Sovereign Fleet has no standing live connection to a strict-mode vessel.

## Repository layout

```text
Development/
├── README.md                 Product roadmap and repository map
├── apps/                     FastAPI Core and React Console; later product apps
├── services/                 Knowledge retrieval, Policy, Intelligence and connectors
├── infrastructure/           Synthetic lab, release, backup and deployment staging
├── scripts/                  Build, repository checks and lab control
├── tests/                    Lab, retrieval and Core API tests
├── .github/                  CI and dependency update configuration
├── Makefile                  One-command build, tests and lab bring-up
├── pyproject.toml            Pinned Python application dependencies
├── uv.lock                   Resolved Python dependency lock
├── requirements.lock         Hashed Python requirements for audit
├── docs/                     Build plan and technical documentation
│   ├── Sovereign_AI_Technical_Development_and_Implementation_Plan.docx
│   ├── Soverign AI build plan 14_11_2026.txt
│   ├── 01-scope-and-requirements.md
│   ├── 02-architecture.md
│   ├── 03-threat-model-and-data-policy.md
│   ├── 04-stack-and-provenance.md
│   ├── 05-acceptance-tests.md
│   ├── 06-decision-and-signoff.md
│   ├── candidate-sbom.json
│   ├── fixtures.md
│   ├── phase-1/              Runbook, inventory, controls and gate evidence
│   ├── phase-2/              Core/Console runbook, model card and G1 evidence
│   ├── phase-3/              Ingestion, identity, retrieval and gate evidence
│   ├── phase-4/              Security intelligence runbook, host worksheet and open gate
│   ├── phase-5/              Offline release procedure and future G2 evidence
│   ├── phase-6/              Synthetic operator and engineer SOP draft
│   ├── blockers-and-build-queue.md
│   └── approval/2026-11-14-g0.md
└── fixtures/                 Synthetic generators, manifests and local generated data
    ├── generate.py
    ├── evaluation.csv
    ├── manifest.csv
    ├── roles.json
    ├── negative-prompt-injection.txt
    ├── phase-1/              Mixed formats, negative cases and events
    ├── phase-4/              Synthetic security alerts and asset mapping
    └── sources/              100 generated fictional text documents (Git ignored)
```

Generated fixture payloads are reproducible with `make fixtures` and ignored by Git; their generators, expected results and manifests are versioned. The Phase 2 local app uses only synthetic text fixtures and a preinstalled loopback model. Its authentication and storage are lab-only. G0A hardware/network checks and G1 offline proof remain open. See the [Phase 2 runbook](docs/phase-2/runbook.md) to reproduce the app.

## Phase 0 evidence

| Plan task | Evidence |
|---|---|
| T-001 Operating model | [Scope and requirements](docs/01-scope-and-requirements.md) |
| T-002 Trust boundaries | [Architecture](docs/02-architecture.md) |
| T-003 Threat model | [Threat model and data policy](docs/03-threat-model-and-data-policy.md) |
| T-004 Reference stack | [Stack and provenance](docs/04-stack-and-provenance.md), [candidate SBOM](docs/candidate-sbom.json) |
| T-005 Acceptance tests | [Test plan](docs/05-acceptance-tests.md), [fixture guide](docs/fixtures.md) |
| G0 Technical baseline | [Decision and sign-off](docs/06-decision-and-signoff.md), [approval record](docs/approval/2026-11-14-g0.md) |

The candidate SBOM records selected top-level components. A resolved SBOM, artifact hashes, specialist security review and licence distribution review belong to later gates.
