# Reference stack, licensing and initial SBOM

**Decision level:** Phase 0 candidate baseline, checked 14 November 2026. These are selections for a reproducible lab build, not a claim that artifacts have been acquired, installed, benchmarked or legally cleared for redistribution. Phase 1 must capture exact image digests, package hashes, transitive SBOM and notices in a signed release manifest. Any change to a major version, model, parser or licence reopens the compatibility and threat review.

## Selected baseline and alternatives

| Layer | Candidate baseline | Why it is selected | Licence / verification status | Gate before use |
|---|---|---|---|---|
| Host OS | Ubuntu Server **24.04.5 LTS** for AI/security lab hosts | Matches existing hardware plan; maintained LTS; 26.04 is a possible later qualification | Canonical terms/package licences vary; [release list](https://ubuntu.com/project/docs/release-team/list-of-releases/) and [24.04 notes](https://documentation.ubuntu.com/release-notes/24.04/) verified | Driver, GPU, Wazuh and disk-encryption compatibility |
| Container format/runtime | OCI images; rootless or restricted engine to be chosen during lab setup | Reproducible offline imports without assuming a particular daemon is safe | Engine/image base licences to be recorded | Build/restore and isolation tests |
| Local LLM serving | **vLLM 0.32.0** candidate; NVIDIA NIM kept as licensed alternative | OpenAI-compatible local API, suitable for Core adapter; no cloud call required once assets are staged | [vLLM release history](https://github.com/vllm-project/vllm/releases) and [serving security warning](https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/) checked; exact licence/third-party notices to package | GPU/CUDA, Qwen support, offline startup, exposed endpoint review |
| Generation model | **Qwen/Qwen3-8B** as initial lab model | 8B-class asset is plausible for 32 GB VRAM development workstation; production model chosen by quality/capacity benchmark | [Publisher model card](https://huggingface.co/Qwen/Qwen3-8B) labels Apache-2.0; capture exact revision and licence file | Offline load, quality, context and concurrency benchmark |
| Embeddings | **BAAI/bge-m3** | Multilingual local embeddings suited to mixed vessel documents | [Publisher model card](https://huggingface.co/BAAI/bge-m3) labels MIT; capture exact revision | Retrieval quality and offline test |
| Reranking | **BAAI/bge-reranker-v2-m3**, optional | Candidate quality improvement; not a hard dependency for G1 | [Publisher model card](https://huggingface.co/BAAI/bge-reranker-v2-m3) labels Apache-2.0; capture exact revision | Latency/quality trade-off benchmark |
| Parsing/OCR | **Docling 2.139.0** with explicit local artifact path; no remote services | Structured PDF/DOCX processing; model weights can be prefetched for offline use | [Published release](https://pypi.org/project/docling/2.139.0/) labels MIT; OCR/model subcomponents require separate notices; [offline prefetch guide](https://docling-project.github.io/docling/usage/advanced_options/) | Model artifacts, sandbox and file limits |
| Database/vector | **PostgreSQL 18.7 + pgvector 0.8.7** | Single local store for metadata, ACLs and vectors; current supported versions at baseline date | [PostgreSQL 18.7](https://www.postgresql.org/docs/release/18.7/); [pgvector 0.8.7 changelog](https://github.com/pgvector/pgvector/blob/master/CHANGELOG.md) and [licence](https://github.com/pgvector/pgvector/blob/master/LICENSE); package notices to record | Extension build, filter-first query plan, backup/restore |
| Identity | **Keycloak 26.8.2** | Local OIDC/MFA and group/role management; proprietary Policy service remains the enforcement point | [Official downloads](https://www.keycloak.org/downloads) and [Apache-2.0 licence](https://github.com/keycloak/keycloak/blob/main/LICENSE.txt); third-party notices linked from downloads | Offline auth, admin separation, session revocation |
| Security monitoring | **Wazuh 4.14.10** on independent host | Existing SIEM/agent pipeline; supports offline installation and REST API | [Official packages](https://documentation.wazuh.com/current/installation-guide/packages-list.html), [offline guide](https://documentation.wazuh.com/current/deployment-options/offline-installation/index.html); core [GPLv2 licence](https://github.com/wazuh/wazuh/blob/main/LICENSE), component notices require review | Offline install, API scope, CTI snapshot, independent outage test |
| Application | **React 19.3.0**, **TypeScript 7.0.2**, **Tailwind CSS 4.3.5** Console; Python with **FastAPI 0.162.6** Core/services | Matches the proprietary module plan and team skill assumptions | [React release](https://github.com/facebook/react/releases), [TypeScript stable tag](https://www.npmjs.com/package/typescript?activeTab=versions), [Tailwind release](https://github.com/tailwindlabs/tailwindcss/releases), [FastAPI release](https://pypi.org/project/fastapi/0.162.6/); transitive versions to lock in Phase 1 | Build, SAST, API contracts, browser support |

**Why vLLM is only a candidate:** its documented `--api-key` does not protect every endpoint. The service must bind to a protected interface with network policy and possibly a reverse proxy. NIM would require separate licence, commercial use and offline deployment checks; it is not implicitly approved by this baseline.

## Initial dependency and artifact register (SBOM seed)

The machine-readable [candidate SBOM](candidate-sbom.json) records selected top-level components. It is explicitly not a resolved build SBOM: hashes, transitive dependencies and exact model revisions are absent until the Phase 1 build.

| ID | Component / artifact | Source of truth | Required manifest fields |
|---|---|---|---|
| S-01 | Ubuntu base image and packages | Canonical repository/mirror | release, package list, checksums, source mirror, notices |
| S-02 | NVIDIA driver, CUDA/container toolkit | NVIDIA official distribution | exact versions, GPU compatibility, EULA, hashes |
| S-03 | OCI runtime and base images | Official signed distribution | version, image digest, registry, licence and transitive SBOM |
| S-04 | vLLM or NIM image and runtime | Official project/vendor | image digest, CUDA/PyTorch matrix, licence, exposed ports |
| S-05 | Generation, embedding and rerank weights/tokenizers | Publisher repository | revision commit, file hashes, model card, licence, source URL |
| S-06 | Docling parser and OCR/layout weights | Official project and model publishers | parser wheel/image hash, model revision, licences, local artifact path |
| S-07 | PostgreSQL and pgvector | Official project/package source | major/minor, extension version, package hashes, backup compatibility |
| S-08 | Keycloak and third-party dependencies | Official release | distribution/image digest, notices, admin configuration |
| S-09 | Wazuh manager/indexer/dashboard and CTI snapshot | Official release | exact component versions/hashes, GPL/other notices, snapshot date |
| S-10 | Sovereign proprietary modules | Internal signed release | commit, image digest, build provenance, SBOM, test report, signer |

The first actual build must generate a machine-readable CycloneDX or SPDX SBOM from resolved artifacts, compare it to an approved allowlist, preserve licence texts/attributions, and document how obligations are met when software is delivered to a client. Wazuh/GPL redistribution and NVIDIA terms require specialist review before distribution; this document does not interpret legal rights.

## Model and hardware decision criteria

Use the existing plan's 32 GB VRAM workstation only as a development target. Do not infer that a model fits or meets latency targets from parameter count alone. Benchmark the exact model revision, precision/quantisation, context, KV-cache, concurrency and document workload. Record input/output token mix, GPU memory, thermal/power load, answer quality and citation faithfulness. A production GPU and model are selected after these measurements, not before.

## Offline supply-chain procedure to prove in later phases

1. On a controlled connected preparation host, download only allowlisted releases and record publisher, version/revision, digest, licence and advisory status.
2. Generate dependency SBOM, scan artifacts and stage all model/OCR/runtime assets so startup cannot download anything.
3. Sign the bundle manifest with an offline-protected signing key; transfer by inspected encrypted media.
4. Onboard, verify signature and per-file hashes before installation. Record release ID and rollback image. Any missing or altered artifact fails closed.
5. Test installation and model/Docling/Wazuh startup with WAN disconnected; collect packet evidence.

## Open compatibility and licensing decisions

- Verify 24.04.5 kernel, NVIDIA driver, CUDA, vLLM 0.32.0 and the actual RTX 5090 workstation as a compatible set. Newer vLLM releases may change CUDA requirements.
- Decide OCI engine and base image after a rootless/restricted deployment rehearsal.
- Confirm full commercial redistribution obligations for every shipped model weight, OCR weight, Wazuh component, NVIDIA artifact and package dependency; legal/technical lead sign-off required.
- Verify Keycloak 26.8.2 and Wazuh 4.14.10 against pinned container/OS builds in Phase 1.
- Do not adopt optional OCR/reranker/VLM components solely because Docling supports them; each adds artifact, licence and security scope.
