# Phase 2 evidence and G1 gate

**Status: G1 open.** The software flow runs locally with synthetic data. The
target NVIDIA/Ubuntu lab and a WAN-disconnected demonstration have not been
tested. The requester instructed us to defer physical hardware work until the
equipment is purchased.

| Plan task | Evidence | Remaining work |
|---|---|---|
| T-010 Local inference and benchmark | [Mac model card](model-card.md), [recorded benchmark](benchmark-mac.json), local Ollama 2B flow | Install and pin NVIDIA driver/runtime, vLLM or approved NIM, Qwen3-8B weights/tokenizer on target host; record exact artifacts, context, quality, concurrency, throughput and offline cold start |
| T-011 Sovereign Core | `apps/api` FastAPI endpoints for chat, history, model routing, source search/preview and audit; Phase 3 adds local Keycloak OIDC/JWT integration and persistent logout revocation in the synthetic lab | Production identity administration, deployment network controls and durable conversation storage; repeat API tests in target topology |
| T-012 Sovereign Console | `apps/console/web` React/TypeScript/Tailwind sign-in, chat, documents, inspectable citations, department scope, mobile history and read-only admin view; local build and [accessibility source review](console-accessibility.md) pass | Interactive keyboard/screen-reader/zoom review and target reverse-proxy/TLS deployment still required |
| T-013 End-to-end demo | [Synthetic demo record](demo-result.json), [runbook](runbook.md); five active roles sign in, removed users denied, engineer receives `ENG-001` cited answer, restricted query denied | Repeat with WAN physically disconnected, record packet capture/egress proof, build/host/fixture evidence and issue review on target lab |

## G1 acceptance check

| Required evidence | Current result |
|---|---|
| AT-01 local sign-in for five roles, invalid/removed denied | Synthetic identity tested; Phase 3 local Keycloak sign-in/JWT flow also exercised. Target identity provider, MFA and WAN-disconnected check not run |
| AT-02 cold model/parser/embedding startup without WAN or runtime downloads | Local model, Docling parser and embeddings run on Mac with preinstalled assets; no disconnected cold start or packet-capture proof on target host |
| Basic AT-03/09 synthetic document Q&A and citations | Phase 3 indexed retrieval selects 40/40 expected permitted sources and denies 10/10 restricted questions. Local model answer evaluation has 40/40 expected markers and 10/10 no-answer denials; 32/40 answers explicitly name source/version. Human claim-support review is pending |
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
4. **P2-04 — Identity deployment:** the original lab passphrase and volatile
   session store remain test-only. Phase 3 now has local Keycloak OIDC and
   source-permission enforcement in a synthetic lab. Production-grade identity
   operations and target topology qualification remain open before real data.
