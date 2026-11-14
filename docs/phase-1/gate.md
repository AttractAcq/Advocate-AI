# G0A evidence and remaining work

| Task | Evidence now | State |
|---|---|---|
| T-006 source structure | Monorepo skeleton, local Git, CI workflow, unit tests | Local portion implemented; remote CI, reviewer identities and enforced branch protection unverified |
| T-007 isolated lab | Loopback topology, disposable local DNS/PKI, lab command and as-built inventory | Incomplete: GPU Ubuntu host, container runtime, segmented network, test NAS and separate Wazuh host/VM absent; local DNS/PKI does not replace the target lab services |
| T-008 safe fixtures | Deterministic 100-text corpus; mixed PDF/DOCX/XLSX, duplicate, malformed, encoded injection, ACL and event cases in `fixtures/phase-1` | Local hashes, file structure, expected cases and event normalisation pass; independent fixture review remains |
| T-009 observability | Structured request logs, TLS health and metrics endpoints, local dashboard, runbook and one-command lab bring-up | Local simulation smoke checks pass; target host observability unverified |
| G0A fresh build and documented reproduction | `make check`, `make lab-smoke`, fresh-clone procedure | Local tests pass; target Ubuntu lab reproduction and the above task closures remain |

The requester chose a **local simulation for now** and asked to keep the repository **local for now**. Those choices defer the target GPU lab and remote GitHub enforcement; they do not change the original G0A criteria. The Phase 0 G0 approval still applies only to synthetic lab work. Do not mark G0A passed from the Mac simulation.

## Local reproduction evidence — 14 November 2026

- Source commit: `f4ef748` on local `main`.
- A fresh clone under `/private/tmp` ran `make fixtures` and recreated 100 fictional text documents, 12 mixed-format/negative files and four synthetic events. Generated manifests and expected results matched their committed versions without a diff.
- `make check` passed the deterministic source build, Python compilation, four unit tests and all 100 source-hash checks.
- `make lab-smoke` passed in the fresh clone: six loopback health probes, dashboard, metrics and the read-only event feed. Loopback bind required local sandbox escalation during this session.
- Source archive SHA-256 matched between workspace and fresh clone: `9ac3facb2b44233cbbcee58b849855077eb6f0e8f9968e39063d397e356d33f4`.

This proves local source reproducibility on macOS. It does not prove GPU inference, segmented network isolation, container deployment or remote CI/branch protection.

## Expanded local checks — 14 November 2026

At commit `2ecc15e`, `make check` passed the code archive build, four unit tests, all 100 source hashes, 12 mixed-format fixture hashes and structural checks, and four normalised event cases. `make lab-smoke` passed six HTTPS health and metrics probes, the dashboard, event feed, local no-forwarding DNS answers and rejection of an untrusted certificate. The code archive excluded generated certificates, private keys and runtime state.

A second fresh-clone checkout was attempted for this commit but did not finish while reading the Desktop-backed Git objects. The earlier fresh-clone result above remains valid for `f4ef748`; fresh-clone reproduction of `2ecc15e` is **not claimed**. G0A remains open for the target Ubuntu lab and remote repository controls.
