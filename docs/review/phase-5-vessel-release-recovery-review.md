# External review brief: vessel release and recovery

**Status: pending independent execution.** This brief packages the synthetic
Phase 5 vessel release and recovery work for an external security and QA
reviewer. It is not a review result, pilot acceptance, or GitHub PR approval.
Use fictional data and disposable infrastructure only. The [blocker index](../blockers-and-build-queue.md)
keeps the separate deployment and security gates open.

## Exact review surface

Review the stack from [PR #151](https://github.com/AttractAcq/Advocate-AI/pull/151)
through [PR #180](https://github.com/AttractAcq/Advocate-AI/pull/180), including
their ancestors, at a recorded commit SHA. These are stacked, unmerged PRs;
the reviewer must identify the exact final tree tested. The main paths are:

| Boundary | Implementation | Focus |
|---|---|---|
| Signed stage and active record | `infrastructure/deploy/vessel_installer.py`, `infrastructure/deploy/vessel_release_switch.py` | Bundle, configuration and image identity; stopped resource inventory; candidate cleanup; when the active pointer changes |
| Signed compatibility | `infrastructure/release/bundle.py`, `infrastructure/release/upstream.py`, `infrastructure/containers/Core.Dockerfile`, `infrastructure/deploy/vessel_installer.py` | Version declarations in the signed manifest and hash-bound Core image labels; refusal of mismatch or unsupported formats before resource creation; whether Core code actually implements its labels |
| Knowledge persistence | `infrastructure/deploy/knowledge_volume.py`, `services/knowledge/postgres_index.py` | Schema version, source/index comparison, role grants and data-volume ownership |
| Core state and runtime | `infrastructure/deploy/vessel_runtime.py`, `services/policy/audit.py` | Private mounts, audit chain, conversation history and service health |
| Encrypted recovery | `infrastructure/deploy/vessel_recovery_set.py` | Frozen snapshot, signed receipt, restic verification, clean activation, interrupted restore abandonment and retry |
| Operator entry points | `scripts/vesselctl.py`, [switch runbook](../phase-5/vessel-release-switch.md), [recovery runbook](../phase-5/vessel-recovery-set.md) | Required inputs, refusal paths and operator-visible state |
| Actual images and tests | `scripts/phase5_three_image_release.py`, `tests/test_vessel_release_switch.py`, `tests/test_vessel_recovery_set.py`, `.github/workflows/ci.yml` | What is exercised with signed images versus mocks; review the engineer/deckhand API probe in PR #162 |
| Signed model artifact and request route | `infrastructure/release/bundle.py`, `infrastructure/deploy/vessel_runtime.py`, `scripts/phase5_three_image_release.py`, [model bundle procedure](../phase-5/model-artifact-bundle.md) | Exact model tree and ID binding, stage capacity preflight, Core runtime configuration, container-loopback request, wrong-name refusal and outage behavior |

## Claims to verify

1. A switch starts only from a signed, stopped installation with the expected
   labelled Knowledge volume and no unexpected installation-scoped resources.
   The candidate bundle and exact Console configuration identify its stage.
2. The switch checks the existing stage, candidate image evidence, Knowledge
   schema and complete approved source index before starting Core and Console.
   It records the new active release only after health and image checks. A
   failed candidate must leave the previous release and data recoverable.
3. Rollback is one stopped-release step. Before it starts the prior release,
   it must verify a signed, clean-restorable recovery set of the currently
   active release and compare Core state and the canonical Knowledge row digest.
   Partial candidate discard must reject active and prior stages, unsafe
   filesystem entries and a running runtime.
4. Recovery capture stops writes, freezes private Core files, verifies the
   source index, and places those files with a bounded PostgreSQL custom dump
   in one encrypted restic snapshot. Its schema-2 Ed25519 receipt binds
   installation, release, snapshot, dump, audit checkpoint and a canonical
   digest of all Knowledge rows. Capture must check that digest before and
   after the dump. Receipt verification alone must not imply that the encrypted
   bytes can be restored.
5. Clean activation verifies the signed bundle, receipt, restored files and
   database contents before starting the signed images. It creates fresh
   restricted database credentials, preserves the recorded installation ID,
   audit trail and conversation history, and leaves the dump outside running
   Core state. Interrupted activation must retain inspectable evidence;
   abandonment may delete only the exact partial volume identified by its
   unique restore-attempt label. Retry uses a new private root.
6. A schema-7 bundle binds the exact model file tree and request ID to its
   release signature. Before stage creation, the installer checks local free
   space for a complete staged copy plus reserve. Core receives that signed
   model ID and a fixed loopback endpoint; vessel status rejects configuration
   drift. The actual-image probe sends the signed ID through Core to a
   temporary responder, rejects a wrong requested name before that responder,
   and returns 503 after the responder stops.

These are implementation claims for the reviewer to challenge, not accepted
security findings. The second Core image in CI has a distinct image identity
but the same application code and schema. The rehearsal does not establish
upgrade compatibility between real software or database versions.

**Evidence correction, 21 November 2026:** The retained vessel results for
PRs #175–179 all report `three_image_bundle=denied-findings`. Their green CI
jobs prove that image intake refused a Knowledge image with a HIGH `libxml2`
finding; they do not prove the signed vessel install, switch, model route or
recovery paths on those heads. [PR #180](https://github.com/AttractAcq/Advocate-AI/pull/180)
updates the Knowledge package and makes a skipped signed rehearsal fail CI.
Three successive Linux runs exposed stale conversation-count assumptions and
an empty history record from a failed model request; those findings are retained
in the [build queue](../blockers-and-build-queue.md). The
[PR #180 implementation-head result](https://github.com/AttractAcq/Advocate-AI/actions/runs/44843503603)
is `signed-and-verified`, has zero unresolved findings for all three images,
and reports passing signed install, model route, release switch, initial and
updated clean restore, and interrupted retry. This supersedes the skipped
actual-image evidence, while production model inference and external gates
remain open.

## Reproducible evidence

| Slice | Retained CI evidence | Expected observation |
|---|---|---|
| Persistent Core audit and history | [PR #151 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44758588926) | History and audit survive a stopped recovery |
| Paired encrypted set and clean activation | [PR #152 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44763626666), [PR #153 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44767060728) | Receipt-bound file and database recovery into a clean second installation |
| Interrupted restore protection | [PR #154–156 runs](https://github.com/AttractAcq/Advocate-AI/actions/runs/44772378731) | Exact partial-volume abandonment and clean-root retry; inspect each PR's CI for its own assertion |
| Switch, distinct image and stage cleanup | [PR #157 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44782675989), [PR #158 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44788271162), [PR #159 run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44792631764) | Signed switch, one-step rollback, different Core image ID and interrupted-stage discard |
| Post-switch recovery | [PR #160 implementation-head run](https://github.com/AttractAcq/Advocate-AI/actions/runs/44796531764) | Updated-release receipt, clean second install, audit/history and database-role continuity |
| Source permissions through release changes | [PR #162 final-head CI](https://github.com/AttractAcq/Advocate-AI/actions/runs/44803530310) | The running Core API permitted the engineer's engineering source and denied it to the deckhand at first install, after switch, rollback and clean restore; all 12 CI jobs passed |
| Signed schema compatibility | [PR #164 final-head CI](https://github.com/AttractAcq/Advocate-AI/actions/runs/44808448854) | Current release declares Knowledge and Core state format 1; a signed future declaration is rejected before first-install resources or a stopped candidate stage; all 12 CI jobs passed |
| Core image label binding | [PR #165 final-head CI](https://github.com/AttractAcq/Advocate-AI/actions/runs/44810754082) | Exact Core image configuration labels match the signed contract on signing and copied-bundle verification; all 12 CI jobs passed |
| Pre-version Knowledge migration | [PR #166 final-head CI](https://github.com/AttractAcq/Advocate-AI/actions/runs/44811781751) | In a disposable pgvector database, altered source and unknown table shape are refused before the version ledger; the known prior shape migrates transactionally; all 12 CI jobs passed |
| Core history format and migration | [PR #167](https://github.com/AttractAcq/Advocate-AI/pull/167), [PR #169](https://github.com/AttractAcq/Advocate-AI/pull/169) and [migration procedure](../phase-5/stopped-vessel-history-migration.md) | Core and stopped recovery capture reject old, future or malformed SQLite history; the stopped migration signs release-bound evidence and separately clean-restores the old history. [All 12 migration CI jobs passed](https://github.com/AttractAcq/Advocate-AI/actions/runs/44818648370) |
| Pre-update and rollback recovery gates | [PR #170](https://github.com/AttractAcq/Advocate-AI/pull/170), [PR #172](https://github.com/AttractAcq/Advocate-AI/pull/172) and [switch procedure](../phase-5/vessel-release-switch.md) | Both directions require a signed recovery set of the active release, clean-restore it and compare current Core state before activation. The actual-image rehearsal captures one set on each side of the transition; [all 12 PR #172 CI jobs passed](https://github.com/AttractAcq/Advocate-AI/actions/runs/44825084735), including the signed vessel rehearsal. |
| Knowledge row equality | [PR #171](https://github.com/AttractAcq/Advocate-AI/pull/171), [schema-2 recovery set](../phase-5/vessel-recovery-set.md) and [all 12 final-head CI jobs](https://github.com/AttractAcq/Advocate-AI/actions/runs/44823012458) | A changed pgvector value with unchanged row counts alters the signed row digest. Restore and release activation compare the digest before starting Core. |
| Managed Core file aliases | [PR #174](https://github.com/AttractAcq/Advocate-AI/pull/174) and [recovery procedure](../phase-5/vessel-recovery-set.md) | Capture refuses hard-linked managed configuration, audit, history and source files; local tests cover each class. Target filesystem semantics and non-cooperating writers remain separate review questions. |
| Signed model tree and staging capacity | [PR #175](https://github.com/AttractAcq/Advocate-AI/pull/175), [PR #176](https://github.com/AttractAcq/Advocate-AI/pull/176) and [model bundle procedure](../phase-5/model-artifact-bundle.md) | Local tests cover signed fictional bytes, tamper refusal and low-space refusal. The [PR #175](https://github.com/AttractAcq/Advocate-AI/actions/runs/44828966126) and [PR #176](https://github.com/AttractAcq/Advocate-AI/actions/runs/44831181328) jobs passed, but retained vessel results say `denied-findings`; their signed staging paths did not run. |
| Signed model request route | [PR #177](https://github.com/AttractAcq/Advocate-AI/pull/177) and [PR #178](https://github.com/AttractAcq/Advocate-AI/pull/178) | Core is configured with the signed model ID and container-loopback endpoint. The intended actual-image probe uses a temporary responder for request ID, wrong-name denial and 503 after shutdown. The [PR #177](https://github.com/AttractAcq/Advocate-AI/actions/runs/44831684982) and [PR #178](https://github.com/AttractAcq/Advocate-AI/actions/runs/44833680520) jobs passed, but retained vessel results say `denied-findings`; the route probe did not run. |
| Authenticated model advertisement | [PR #179](https://github.com/AttractAcq/Advocate-AI/pull/179), `apps/api/model.py`, `apps/api/main.py`, `tests/test_core_api.py` | Local tests cover AV/IT-only loopback `/v1/models` readiness and 503 for wrong or malformed advertisements. [All 12 implementation-head jobs passed](https://github.com/AttractAcq/Advocate-AI/actions/runs/44835630041) after a Fleet browser DNS retry, but the retained vessel result says `denied-findings`; the signed vessel readiness probe did not run. This is a control-plane signal, not a model inference or GPU acceptance test. |
| Signed three-image vessel path restored | [PR #180](https://github.com/AttractAcq/Advocate-AI/pull/180) and [retained CI result](https://github.com/AttractAcq/Advocate-AI/actions/runs/44843503603) | The artifact reports `signed-and-verified`, zero unresolved Core, Console and Knowledge findings, model tamper refusal, signed request and outage behavior, release switch and rollback, initial and updated clean restore, and interrupted-restore retry. All 12 implementation-head CI jobs passed. |

At the PR #180 implementation head, `make check` passed 419 tests with 16
expected skips. For an independent reproduction, record the commit and
tool versions, then run `make check`. The `upstream-release-rehearsal` job in
`.github/workflows/ci.yml` runs the pinned actual-image script and retains its
synthetic result artifact. Inspect the artifact and command logs, not only the
green job badge. `python -m scripts.vesselctl --help` lists the operator entry
points. The reviewer should run destructive cases only in a fresh disposable
lab and retain the observed output, resource inventory and timing.

## Independent challenge matrix

| Attempt | Required decision or observation |
|---|---|
| Alter bundle, image archive, signed scan/SBOM evidence, Console configuration or stage after verification | Determine whether every entry point refuses it before image use or pointer change |
| Declare a future schema in the signed contract or the Core image labels alone | Check that signer and verifier refuse mismatched declarations, and installer/recovery refuse unsupported but matched future formats |
| Supply an altered legacy table or source before explicit migration | Confirm no version ledger is committed and no normal startup path silently migrates it |
| Replace source bytes, source index, audit tail, history or PostgreSQL schema version | Check whether status, switch, capture and restore refuse it before Core sees altered data |
| Substitute a wrong receipt key, restic password, snapshot ID, release ID or old receipt | Check signature, repository and release binding in both switch and rollback; an old receipt from the prior active release must not authorise rollback from the updated release |
| Change one Knowledge row or vector after capture while preserving source and passage counts | Confirm schema-2 digest mismatch prevents Core and Console startup on switch, rollback and clean restore |
| Hard-link a managed Core file to an outside path before capture | Confirm configuration, audit, history and approved source aliases are rejected before an encrypted recovery snapshot is made; test host filesystem semantics separately |
| Alter a model file, add an unlisted model file, or change the Core model name or endpoint | Confirm signature and tree verification refuse altered bytes, and active status refuses runtime drift; try both stopped and running states |
| Name an unapproved model in a chat request, then stop the loopback responder | Confirm Core denies the name before forwarding and returns 503 after the responder stops, without a remote or fallback route |
| Advertise a different model ID, return malformed or oversized metadata, or remove the model service | Check AV/IT readiness returns 503 while other roles remain denied; separately determine whether an actual prompt can be answered after a cold start |
| Add a labelled container, network, extra volume or different restore-attempt label | Check that cleanup and abandonment do not remove ambiguous resources |
| Interrupt stage, switch, capture, activation and rollback at each durable write | Inventory resulting files, containers and volumes; show which command can safely resume, discard or escalate |
| Revoke a document permission before capture and after restore | Test search, retrieval, citations, cached answers and history against the current policy |
| Restore on a constrained or networked host | Measure actual disk, time and traffic behavior; compare with the proposed recovery objective |

Report any test that cannot be run separately from a pass. In particular,
inspect path ownership, symlink and hard-link handling, lock scope, concurrent
operator commands, power loss, clock rollback, key rotation and retention. The
local synthetic results do not settle those properties on the purchased host.

## Required reviewer record and gate decisions

The attributable report should name the reviewer and independence basis,
commit SHA, host and tool versions, test dates, commands, artifacts, observed
results, findings with severity and exploit path, remediation/retest evidence,
and explicit accept/reject/defer decisions for each claim above. Critical and
high findings need retest before pilot acceptance. Store the report and defect
register under `docs/review/` without credentials, owner data or real vessel
logs.

| Gate | Current decision | Evidence still needed |
|---|---|---|
| B-07 signed release and recovery | Open | Approved media and keys, target-host install/rollback, clean recovery of database, configuration, identity and model within approved RTO/RPO |
| B-08 independent assessment | Open | App, parser, retrieval, release and network testing by an appointed external reviewer, plus finding closure |
| B-09 target hardware | Deferred | Reference server, security host, NAS/UPS and vessel-fit rehearsal |
| B-10 vessel authority | Open | Owner-approved data, role, retention, key custody and site scope |
| B-11 distribution | Open | Qualified production image provenance, licence review and release-signing custody |

Independent GitHub approval of the stacked PRs is a separate repository
control. No reviewer identity, finding closure or gate sign-off is recorded by
this brief.
