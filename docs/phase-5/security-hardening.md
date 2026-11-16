# Local adversarial hardening slice

**Status: local software checks only. T-026, AT-19 and G2 remain open.**

The fixed [fictional adversarial corpus](../../fixtures/phase-5/adversarial.json)
now exercises four trust boundaries:

| Boundary | Local control and test result | Remaining qualification |
|---|---|---|
| Document path | Ingestion, indexed retrieval and the legacy fixture path reject a source symlink or symlinked parent. A source replaced by a same-content symlink after indexing is no longer returned or cited. | Read-only NAS mount, ACL propagation and filesystem race testing on target topology. |
| Office import | Preflight rejects macro binaries, ActiveX/embedded content, external links and external relationships before calling the parser. Synthetic DOCX cases are quarantined. | Broader malicious PDF/Office corpus, parser resource isolation and specialist assessment. |
| Security alert facts | Wazuh event IDs use a restricted identifier shape; Bearer-like credentials in descriptions are rejected. Asset hostnames and equipment classes are constrained before they can become model facts. | Real decoder samples, sensitive-field review and approved vessel asset vocabulary. |
| Wazuh response | The read-only indexer adapter stops after 2 MiB of decoded response data and refuses redirects. A synthetic oversized result and external redirect are rejected. | Target indexer load, TLS trust, read-only identity and network-route verification. |
| Model analysis | A short single-sentence response containing instructions, write actions, URLs, credentials, unsupported confirmed-compromise claims or new IP addresses falls back to cited evidence. Prompt-injected alert descriptions remain visible for direct analyst review but do not reach the model. | Human claim-support evaluation, red-team prompts and independent security review. This text filter cannot prove factual correctness. |

The code retains the incident evidence and read-only tool boundary when the
model output is rejected. These checks complement the existing role, audit,
deletion and outage tests. They do not establish a complete prompt-injection
defence, a sandbox for Docling, zero public egress or a pass on production
permissions. The [blocker tracker](../blockers-and-build-queue.md) keeps the
lab and reviewer evidence open.

**Local verification, 16 November 2026:** `make check` passed 74 tests and
repository checks. The new output guard accepted all three previously recorded
synthetic [local-model summaries](../phase-4/answer-evaluation.json); this is
a compatibility check on stored text, not a new model-quality assessment.
