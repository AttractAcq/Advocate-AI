# Phase 2 evidence and G1 gate

**Status: G1 open.** The software flow runs locally with synthetic data. The
target NVIDIA/Ubuntu lab and a WAN-disconnected demonstration have not been
tested. The requester instructed us to defer physical hardware work until the
equipment is purchased.

| Plan task | Evidence | Remaining work |
|---|---|---|
| T-010 Local inference and benchmark | [Mac model card](model-card.md), [recorded benchmark](benchmark-mac.json), local Ollama 2B flow | Install and pin NVIDIA driver/runtime, vLLM or approved NIM, Qwen3-8B weights/tokenizer on target host; record exact artifacts, context, quality, concurrency, throughput and offline cold start |
| T-011 Sovereign Core | `apps/api` FastAPI endpoints for synthetic login, chat, history, model selection, read-only routing, source list, admin status and bounded errors; `tests/test_core_api.py` | Replace lab authentication with local identity integration, add deployment network controls and persistent sessions; repeat API tests in target topology |
| T-012 Sovereign Console | `apps/console/web` React/TypeScript/Tailwind sign-in, chat, documents, citations, department scope, history and read-only admin view; local build passes | Interactive browser/accessibility review and target reverse-proxy/TLS deployment still required |
| T-013 End-to-end demo | [Synthetic demo record](demo-result.json), [runbook](runbook.md); five active roles sign in, removed users denied, engineer receives `ENG-001` cited answer, restricted query denied | Repeat with WAN physically disconnected, record packet capture/egress proof, build/host/fixture evidence and issue review on target lab |

## G1 acceptance check

| Required evidence | Current result |
|---|---|
| AT-01 local sign-in for five roles, invalid/removed denied | Synthetic in-memory lab identity tested; target local identity provider and WAN-disconnected check not run |
| AT-02 cold model/parser/embedding startup without WAN or runtime downloads | Local model was preinstalled and cold load measured on Mac; no WAN-disconnected or packet-capture proof; parser/embeddings not provisioned |
| Basic AT-03/09 synthetic document Q&A and citations | 40/40 permitted retrieval questions select the expected source; 10/10 restricted questions return no source; one live local-model answer cites `ENG-001` and includes expected marker; mixed-format ingestion and full answer-quality assessment not run |
| G1 chat and citations while WAN disconnected | **Not demonstrated** |

The Phase 2 demo uses a shared test-only passphrase, volatile sessions and
generated text files. It is not a permission-reviewed vessel assistant. The
Phase 3 Knowledge and Policy work remains necessary before confidential
documents are used.

## Open issues

1. **P2-01 — Hardware and candidate inference:** target GPU server, NVIDIA
   runtime, vLLM/NIM and planned Qwen3-8B are not available. The Mac/Ollama
   fallback does not close T-010.
2. **P2-02 — Offline proof:** WAN remained connected for the local demo and no
   packet capture was recorded. G1 remains open.
3. **P2-03 — Interactive QA:** the computer-use browser service was unavailable
   during this run. Console compilation and HTTP proxy flow passed; rendered
   browser interaction and accessibility still need direct review.
4. **P2-04 — Synthetic identity:** the lab passphrase and volatile session store
   are test-only. Local OIDC and source-permission enforcement are planned for
   Phase 3 and must precede real data.
