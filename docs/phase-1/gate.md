# G0A evidence and remaining work

| Task | Evidence now | State |
|---|---|---|
| T-006 source structure | Monorepo, public GitHub repository, CI, full-history secret scan, Python/npm dependency audits; `main` protection now requires pull request, one independent approval, fresh review after a push, resolved conversations, linear history and `quality`, `secrets`, `dependency-review` checks | Appoint an external reviewer and obtain an attributable review of the current changes; qualify remaining action provenance before release |
| T-007 isolated lab | Loopback topology, disposable local DNS/PKI, lab command and as-built inventory | Incomplete: GPU Ubuntu host, container runtime, segmented network, test NAS and separate Wazuh host/VM absent; local DNS/PKI does not replace the target lab services |
| T-008 safe fixtures | Deterministic 100-text corpus; mixed PDF/DOCX/XLSX, duplicate, malformed, encoded injection, ACL and event cases in `fixtures/phase-1` | Local hashes, file structure, expected cases and event normalisation pass; independent fixture review remains |
| T-009 observability | Structured request logs, TLS health and metrics endpoints, local dashboard, runbook and one-command lab bring-up | Local simulation smoke checks pass; target host observability unverified |
| G0A fresh build and documented reproduction | `make check`, `make lab-smoke`, fresh-clone procedure | Local tests pass; target Ubuntu lab reproduction and the above task closures remain |

The requester chose a **local simulation for now**, then authorised publication to [AttractAcq/Advocate-AI](https://github.com/AttractAcq/Advocate-AI). Hardware-dependent lab work remains deferred until the equipment is purchased; software work continues with synthetic fixtures. These choices do not change the original G0A criteria. The Phase 0 G0 approval still applies only to synthetic lab work. Do not mark G0A passed from the Mac simulation.

On 15 November 2026 the requester authorised making the repository public. `AttractAcq/Advocate-AI` is now public and GitHub's branch-protection API confirms the `main` rules listed above. The dependency gate audits the locked Python base and Phase 3 dependency sets with pip-audit and the Console lock with npm audit. An external reviewer has been selected in principle but not appointed. These remote controls do not substitute for the target lab and its independent QA record.

## Local reproduction evidence — 14 November 2026

- Source commit: `f4ef748` on local `main`.
- A fresh clone under `/private/tmp` ran `make fixtures` and recreated 100 fictional text documents, 12 mixed-format/negative files and four synthetic events. Generated manifests and expected results matched their committed versions without a diff.
- `make check` passed the deterministic source build, Python compilation, four unit tests and all 100 source-hash checks.
- `make lab-smoke` passed in the fresh clone: six loopback health probes, dashboard, metrics and the read-only event feed. Loopback bind required local sandbox escalation during this session.
- Source archive SHA-256 matched between workspace and fresh clone: `9ac3facb2b44233cbbcee58b849855077eb6f0e8f9968e39063d397e356d33f4`.

This proves local source reproducibility on macOS. It does not prove GPU inference, segmented network isolation or target container deployment. Remote CI and branch protection were configured later, as recorded above.

## Expanded local checks — 14 November 2026

At commit `2ecc15e`, `make check` passed the code archive build, four unit tests, all 100 source hashes, 12 mixed-format fixture hashes and structural checks, and four normalised event cases. `make lab-smoke` passed six HTTPS health and metrics probes, the dashboard, event feed, local no-forwarding DNS answers and rejection of an untrusted certificate. The code archive excluded generated certificates, private keys and runtime state.

A second fresh-clone checkout was attempted for this commit but did not finish while reading the Desktop-backed Git objects. The earlier fresh-clone result above remains valid for `f4ef748`; fresh-clone reproduction of `2ecc15e` is **not claimed**. G0A remains open for the target Ubuntu lab and an attributable independent review of the latest baseline.

## Current branch reproduction — 15 November 2026

A new public-repository clone under `/private/tmp/sovereign-phase3-repro`
checked out the Phase 3 hardening branch. It installed the locked Phase 3
Python set and Console npm lock, regenerated the 100 text and 12 mixed-format
fixtures, and built the Console. The first `make check` failed because one
otherwise valid source missed the parser worker's 45-second cold conversion
budget. A second ingestion indexed all 109 expected sources and quarantined
the three expected negative cases. The worker now allows 120 seconds for its
first conversion and 45 seconds thereafter, without removing the timeout.

After a fast-forward to commit `151e014`, the clone passed `make check` with
33 tests and the repository fixture checks. `make lab-smoke` passed the
dashboard, six HTTPS service health/metrics probes, synthetic event feed,
local DNS and untrusted-certificate rejection. The sandbox denied loopback
binds initially; the smoke run succeeded with explicit local bind permission.
The source archive SHA-256 matched the active worktree at the same commit:
`7b4e8d36e2e2fb0e0ca8616cc786628a8da2d31699a723e378904597eb3ad47d`.
Both Git worktrees were clean after the run. This is a macOS synthetic
reproduction, not the G0A Ubuntu/GPU/segmented-network exit test.
