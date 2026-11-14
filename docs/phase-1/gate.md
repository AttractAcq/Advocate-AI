# G0A evidence and remaining work

| Task | Evidence now | State |
|---|---|---|
| T-006 source structure | Monorepo skeleton, local Git, CI workflow, unit tests | Local portion implemented; remote CI, reviewer identities and enforced branch protection unverified |
| T-007 isolated lab | Loopback topology, lab command and as-built inventory | Incomplete: GPU Ubuntu host, container runtime, segmented network, DNS/PKI, test NAS and separate Wazuh host/VM absent |
| T-008 safe fixtures | Deterministic 100-text corpus; mixed PDF/DOCX/XLSX, duplicate, malformed, encoded injection, ACL and event cases in `fixtures/phase-1` | Local corpus and hash checks pass; independent fixture review remains |
| T-009 observability | Structured request logs, health and metrics endpoints, local dashboard, runbook and one-command lab bring-up | Local simulation smoke checks pass; target host observability unverified |
| G0A fresh build and documented reproduction | `make check`, `make lab-smoke`, fresh-clone procedure | Local tests pass; target Ubuntu lab reproduction and the above task closures remain |

The requester chose a **local simulation for now** and asked to keep the repository **local for now**. Those choices defer the target GPU lab and remote GitHub enforcement; they do not change the original G0A criteria. The Phase 0 G0 approval still applies only to synthetic lab work. Do not mark G0A passed from the Mac simulation.

## Local reproduction evidence — 14 November 2026

- Source commit: `f4ef748` on local `main`.
- A fresh clone under `/private/tmp` ran `make fixtures` and recreated 100 fictional text documents, 12 mixed-format/negative files and four synthetic events. Generated manifests and expected results matched their committed versions without a diff.
- `make check` passed the deterministic source build, Python compilation, four unit tests and all 100 source-hash checks.
- `make lab-smoke` passed in the fresh clone: six loopback health probes, dashboard, metrics and the read-only event feed. Loopback bind required local sandbox escalation during this session.
- Source archive SHA-256 matched between workspace and fresh clone: `9ac3facb2b44233cbbcee58b849855077eb6f0e8f9968e39063d397e356d33f4`.

This proves local source reproducibility on macOS. It does not prove GPU inference, segmented network isolation, container deployment or remote CI/branch protection.
