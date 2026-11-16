# Blockers and build queue

Updated: 16 November 2026. This is the single index for unfinished work and
gate evidence. The linked phase records hold the detailed test results. A
locally implemented feature remains **open** until its specified gate passes.
Use synthetic data only until site, data and deployment approvals exist.

## External dependencies and resolved control items

| ID | Gate / task | Required next evidence or decision | Dependency | State |
|---|---|---|---|---|
| B-01 | G0A / T-007–009 | Repeat build, fixtures, observability and network segmentation on the target Ubuntu GPU lab; independent QA record | Purchased/accessible target lab and QA reviewer | Deferred |
| B-02 | G1 / T-010, T-013, AT-02 | Pin target model/runtime and prove cold start, cited chat and no runtime downloads with WAN disconnected | GPU lab, model artifacts and packet capture | Deferred |
| B-03 | Phase 3 / T-014–017, AT-07–09 | Qualify NAS read-only identity and ACL mapping, parser limits, target database and Keycloak topology; human claim/citation review and independent role-bypass test | Target lab and independent reviewer | Open |
| B-04 | Phase 4 / T-018–021, AT-11–13, AT-23 | Install independent Wazuh manager/indexer/dashboard, feed synthetic FortiGate/switch/host events, reconcile AI outage, inspect read-only credentials/routes and review explanations | Isolated Wazuh lab host/VM and security/QA reviewer; [worksheet](phase-4/wazuh-lab-acceptance.md) | Open |
| B-05 | Repository control / PR #11–15 | [PR #11](https://github.com/AttractAcq/Advocate-AI/pull/11) carried the checked stack into `main` on 16 November using the [requester-directed exception](approval/2026-11-16-pr11-15-review-exception.md). One required independent review and last-push approval were restored and verified immediately afterward | Resolved for this merge only; future PRs use normal protection | Closed |
| B-06 | G2 / T-022–023, AT-10, AT-17, AT-20 | Verify hardening, TLS/PKI, storage encryption, route matrix and public no-egress with WAN present and disconnected | Target network, hardware and independent security review | Deferred |
| B-07 | G2→G3 / T-024–025, AT-15–16 | Stage a signed release from approved media; demonstrate install and rollback; restore database, configuration, identity and model on clean equipment within proposed RTO/RPO | Staging host, protected backup media, key custodians and reviewer | Open |
| B-08 | G2–G3 / T-026, T-030 | Independent application, parser, retrieval and network assessment; resolve or formally accept findings | Named external security tester and completed lab evidence | Open |
| B-09 | G3 / T-027–029 | Qualify reference server, security host, NAS/UPS and vessel fit; rehearse clean-room offline install | Purchased reference hardware and maritime/site constraints | Deferred |
| B-10 | Before real data or vessel access | Owner-approved role map, retention, key custody, break-glass and vessel-specific integration/scope decisions | Vessel owner/management and security authority | Open |
| B-11 | Before release distribution | Commercial redistribution/licence review, resolved SBOM and release-signing key custody | Legal/security release owners | Open |

Phase 0 G0 has requester approval for the synthetic baseline. This table does
not reopen that decision. Phase 1 local deliverables have also been reviewed
and approved; B-01 tracks the separate target-lab gate. PR approval is distinct
from independent product security review.

## Buildable now, still open

| ID | Work | Next locally verifiable result | State |
|---|---|---|---|
| W-01 | Signed offline release directory (T-024) | [PR #12](https://github.com/AttractAcq/Advocate-AI/pull/12) contains Ed25519 signing, exact inventory and tamper rejection; [runbook](phase-5/offline-release.md). A synthetic pointer rollback is now rehearsed in W-04. Approved artifact intake, SBOM, media scan and full-stack rollback remain | Signing slice locally complete; T-024 open |
| W-02 | Health and diagnostic checks (T-025/T-028) | [PR #13](https://github.com/AttractAcq/Advocate-AI/pull/13) implements bounded HTTPS and read-only SQLite probes with a metadata-only report; [runbook](phase-5/diagnostics.md). Test real model, Wazuh, PostgreSQL, Keycloak and target-host routes when available | Local probe slice complete; target checks open |
| W-03 | Backup/restore software (T-025) | [PR #14](https://github.com/AttractAcq/Advocate-AI/pull/14) contains AES-256-GCM archive, SQLite snapshot, tamper/wrong-key rejection and [local recovery rehearsal](phase-5/backup-recovery.md). PostgreSQL/Keycloak/full-stack restore, protected media, key custody and clean-host timing remain B-07 | Local slice complete; T-025/AT-16 open |
| W-04 | Installer/configuration validation (T-028) | [PR #15](https://github.com/AttractAcq/Advocate-AI/pull/15) implements idempotent staging of verified signed bundles, strict loopback config, checked pointer rollback and six-service local postcheck; [runbook and rehearsal](phase-5/installer.md). PKI provisioning, real service install, target topology and clean-host tests remain | Synthetic slice complete; T-028/G3 open |
| W-05 | Security hardening and tests (T-022/T-026) | [Local adversarial hardening](phase-5/security-hardening.md) adds source-symlink, active Office, hostile alert and model-output checks. Container/configuration scans, wider parser and role bypass testing, host/network proof and independent review remain B-06/B-08 | Local slice in progress; T-026/AT-19 open |
| W-06 | Operator and engineer documentation (T-031) | Offline update, recovery, identity/permission and alert-triage SOPs based on tested local flows | Open |

When a row is completed, link its commit, CI result and evidence; then change
its state to **locally complete**. Do not remove it until its external gate is
closed. Phase-specific gate records: [G0A](phase-1/gate.md), [G1](phase-2/gate.md),
[Phase 3](phase-3/gate.md), [Phase 4](phase-4/gate.md) and
[Phase 0–3 closure audit](review/phase-0-3-closure-audit.md).
