# V1 operating model and requirements

**Purpose.** Define what the first onboard release can do, what it must never do, and what evidence must support a sovereignty claim. All requirements below apply to the isolated lab first. Production use requires G3, written vessel approval and a site-specific data plan.

## Users and permitted workflows

| Actor | V1 action | Boundary |
|---|---|---|
| Approved crew member | Sign in locally; ask questions of approved collections; receive source-cited answers; view own permitted history | No global document search or inherited NAS administrator privileges |
| Department lead | Same, within vessel-approved department sources; review draft reports | Department name alone does not grant access |
| AV/IT or security analyst | View approved Wazuh alerts, asset context and AI explanations | Read-only tools; technical access does not imply private owner-document access |
| Vessel identity/data administrator | Provision and revoke users; approve source mappings; inspect audit events | Administrative changes are logged and constrained by the vessel-approved matrix |
| Break-glass custodian | Use a time-limited emergency process | Separate custody, recorded reason and post-use review |
| Company support engineer | Maintain signed releases and assist under a vessel-approved procedure | No standing remote account or automatic telemetry in Strict Sovereign Mode |

Illustrative roles are captain, chief engineer, chief stewardess, deckhand and AV/IT administrator. Their exact permissions are **not** predetermined by these titles; the vessel approver signs a resource-by-action matrix before live data is connected.

## Functional requirements

| ID | Requirement | Proof target |
|---|---|---|
| FR-01 | Console authenticates against a local identity provider without WAN and uses short-lived sessions. | AT-01, AT-08 |
| FR-02 | Core routes chat requests only to a local model endpoint behind the application boundary. | AT-02, AT-10 |
| FR-03 | Knowledge ingests allowlisted local sources and retains owner, classification, hash, source path, version and access labels per chunk. | AT-03, AT-04 |
| FR-04 | Policy denies by default and authorises before retrieval, model context assembly, citation, preview, download, export, history access and tool execution. | AT-05, AT-06 |
| FR-05 | Revocation, source deletion and ACL changes invalidate stale retrieval and cached answers within an approved maximum interval. | AT-07 |
| FR-06 | Answers display verifiable citations and uncertainty or no-answer behaviour when evidence is absent. | AT-09 |
| FR-07 | Wazuh independently collects approved host/network events; Intelligence reads findings and explains with source event IDs and permitted asset context. | AT-11, AT-12 |
| FR-08 | No model-driven write-capable API to firewall, switches, NAS administration or safety-critical systems exists. | AT-13 |
| FR-09 | Security-relevant actions produce tamper-evident local audit records without unnecessary prompt/document text. | AT-14 |
| FR-10 | Offline installation, signed updates, rollback, backups and restore are reproducible. | AT-15, AT-16 |

## Nonfunctional and security requirements

| ID | Requirement | Proof target |
|---|---|---|
| NFR-01 | No required external AI, OCR, embedding, reranking, identity or monitoring call at run time. All artifacts are staged and versioned locally. | AT-02 |
| NFR-02 | AI application and model containers have default-deny public egress, including IPv4, IPv6, DNS, proxy, package manager and tool routes. | AT-10 |
| NFR-03 | The security monitor continues collecting and displaying events while the AI host is unavailable. | AT-12 |
| NFR-04 | All human ingress uses HTTPS and local trust anchors; service-to-service traffic is restricted by source, destination, port and identity. | AT-17 |
| NFR-05 | Secrets and backup keys are kept out of images, source control, logs and model context; storage is encrypted where technically feasible. | AT-14, AT-16 |
| NFR-06 | The release records component versions, hashes, licence texts, model provenance and a software bill of materials. | AT-15 |
| NFR-07 | Performance is measured on a fixed corpus at the target concurrency and context size. No latency or corpus-size promise is made before Phase 2 benchmarks. | AT-18 |

## Hard exclusions

- Autonomous firewall, router, switch, OT, navigation, propulsion or safety-system changes.
- Production owner/guest/crew medical records, credentials or unrestricted NAS indexing in development.
- Live Legacy 4 probing, packet mirroring, agents or configuration changes without separate written scope, change window and rollback plan.
- Cloud AI inference, cloud embedding/OCR, automatic vendor telemetry, automatic update downloads, or central Fleet ingestion of vessel prompts, files, embeddings or security logs.
- Claims of certification, impenetrability, true physical air gap or fleet-wide real-time visibility from a strict-mode vessel.

## Deployment modes and data movement

The V1 baseline is **Strict Sovereign Mode**. A future remote-support or fleet-telemetry mode would be a separately approved product configuration with a new data-flow map, threat model, consent, logging and product claim. A connected preparation workstation may download vetted packages outside the vessel; it cannot be a covert bridge to the onboard AI network. Signed bundles cross through an inspected offline transfer process.

## Measurable working assumptions to confirm

- Development corpus: at least 100 synthetic documents across five illustrative roles, including malformed and adversarial files. This is a fixture size, not a production capacity promise.
- Initial load test: 5 concurrent named test users, 30-minute run, 50 scripted requests per role. Latency, GPU memory and quality baselines are recorded, then the pilot threshold is set before G2.
- Revocation target for lab design: effective by the next request and no later than 60 seconds for derived indexes/caches; fail closed if confirmation is unavailable. The vessel approver must accept the final target.
- Initial backup recovery objectives for design exercises: RPO 24 hours and RTO 4 hours in the lab. These are proposals, not vessel service commitments.
- Log retention, document retention and encryption-key custody are open vessel-specific decisions in the sign-off log.

## G0 output

The requesting user approved this scope together with the architecture, threat model, stack and test plan for synthetic lab development on 14 November 2026. The [approval record](approval/2026-11-14-g0.md) is the electronic G0 baseline record. It is not approval of production data or vessel network access.
