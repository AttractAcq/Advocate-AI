# G0A evidence and remaining work

| Task | Evidence now | State |
|---|---|---|
| T-006 source structure | Monorepo skeleton, local Git, CI workflow, unit tests | Local portion implemented; remote CI, reviewer identities and enforced branch protection unverified |
| T-007 isolated lab | Loopback topology, lab command and as-built inventory | Incomplete: GPU Ubuntu host, container runtime, segmented network, DNS/PKI, test NAS and separate Wazuh host/VM absent |
| T-008 safe fixtures | Deterministic 100-text corpus; mixed PDF/DOCX/XLSX, duplicate, malformed, encoded injection, ACL and event cases in `fixtures/phase-1` | Local corpus and hash checks pass; independent fixture review remains |
| T-009 observability | Structured request logs, health and metrics endpoints, local dashboard, runbook and one-command lab bring-up | Local simulation smoke checks pass; target host observability unverified |
| G0A fresh build and documented reproduction | `make check`, `make lab-smoke`, fresh-clone procedure | Local tests pass; target Ubuntu lab reproduction and the above task closures remain |

The requester chose a **local simulation for now** and asked to keep the repository **local for now**. Those choices defer the target GPU lab and remote GitHub enforcement; they do not change the original G0A criteria. The Phase 0 G0 approval still applies only to synthetic lab work. Do not mark G0A passed from the Mac simulation.
