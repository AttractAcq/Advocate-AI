# Operator and engineer pack — synthetic draft

**Status:** synthetic operator draft updated 21 November 2026. This pack is not a vessel as-built record, an approved installation method statement, a production operating procedure, or G3 acceptance. Use fictional data and disposable lab keys for the linked commands. The [build queue](../blockers-and-build-queue.md) holds the open gates.

## Document map

| Audience | Procedure | Purpose |
|---|---|---|
| Installation engineer and witness | [Installation and handover](installation-and-handover.md) | Check the package, stage the synthetic release, run local checks and record handover evidence |
| Release and recovery engineer | [Maintenance and recovery](maintenance-and-recovery.md) | Verify offline updates, check health, back up, restore and roll back the current local software slice |
| Identity administrator and source owner | [Identity and permissions](identity-and-permissions.md) | Request, approve, change and test a role or document source mapping |
| AV/IT operator and incident lead | [Alert triage and escalation](alert-triage-and-escalation.md) | Check source events, preserve evidence and route incidents to the right authority |

The earlier software-pointer path is documented in the [installer](../phase-5/installer.md), [offline release](../phase-5/offline-release.md) and [file backup](../phase-5/backup-recovery.md) runbooks. The current signed vessel image path is documented in the [stopped release](../phase-5/vessel-release-switch.md), [Core/Knowledge recovery](../phase-5/vessel-recovery-set.md), [paired Keycloak recovery](../phase-5/vessel-identity-recovery-pair.md) and [diagnostics](../phase-5/diagnostics.md) runbooks. The [identity design](../phase-3/identity-operations.md) and [Phase 4 runbook](../phase-4/runbook.md) cover their respective boundaries. If a command or capability conflicts with this pack, verify the implementation and correct the pack before use.

## Reference drawing and as-built status

The [logical architecture and route matrix](../02-architecture.md) is the design drawing. The recorded [Phase 1 inventory](../phase-1/as-built-inventory.json) describes a Mac loopback simulation: no NVIDIA host, segmented network, NAS appliance or independent Wazuh host. The synthetic installer [configuration](../../infrastructure/deploy/lab-config.json) describes six loopback service names and ports. Neither file is a vessel as-built inventory.

Before a vessel installation pack can be approved, the installation engineer and vessel technical authority must attach a versioned physical and logical drawing with host and rack identifiers; ports, VLANs and routes; NAS share and identity scope; independent Wazuh path; local DNS/NTP and PKI; backup target and key custody; power/UPS; and a measured no-egress boundary. Record drawing version, survey date, owner and approver. Do not copy synthetic addresses into the vessel design.

## Handover record to fill for each installation

| Field | Required entry |
|---|---|
| Change and authority | Approved change ID, vessel/site, installation window, technical owner, vessel approver |
| Build and source | Repository commit, release version, signed manifest hash, trusted public-key fingerprint, resolved SBOM reference |
| Equipment and routes | Approved as-built drawing/version, asset inventory, route/TLS/no-egress evidence |
| Data and identities | Approved source/ACL matrix, retention decision, service identities, MFA and emergency-access owners |
| Recovery | Backup inventory, protected-media location reference, separate key custodian, measured restore and rollback records |
| Tests and decisions | AT IDs, fixture versions, observed result, evidence paths, defects, tester, independent reviewer, gate decision |
| Training | Named operator and engineer attendees, exercises completed, unanswered questions, handover recipient |

Record values in the controlled installation evidence store, not in this template or the public repository. The [acceptance specification](../05-acceptance-tests.md) defines the test record fields and gate rules. Missing evidence is **not run**, not a pass.

## Training exercise

1. Crew user: sign in, ask a fictional document question, inspect the citation, and report a missing or unexpected source without copying its body into a support ticket.
2. AV/IT operator: open a fictional alert, locate the source Wazuh event by index and document ID, distinguish observed facts from AI explanation, and use the escalation tree.
3. Identity administrator: walk through a proposed role or source change, second-person check, denial regression and audit record. Do not grant access during a tabletop exercise.
4. Release engineer: verify an offline bundle, describe a stopped update and rollback, then locate the health and recovery evidence.
5. Witness: record who performed each exercise, the build/fixture IDs, observed outcome and follow-up action. No exercise closes G2/G3 without its required target-lab evidence and reviewer.
