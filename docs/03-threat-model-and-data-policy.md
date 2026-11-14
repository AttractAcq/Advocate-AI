# Threat model, risk register and data policy

**Method.** The boundary and flows in [02 Architecture](02-architecture.md) are the basis for a STRIDE-style review of identity, tampering, repudiation, disclosure, denial of service and privilege escalation. This is a design assessment, not a penetration test. The [OWASP threat-modeling guide](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) calls for explicit flows and boundaries; [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) and [LLM08](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) inform the AI-specific cases.

## Assets and adversaries

Protected assets are vessel documents and permissions, conversation and index data, security events, identities/sessions, credentials and signing/encryption keys, backups, release artifacts, and the availability of independent monitoring. Plausible adversaries include an external attacker through a compromised crew device, malicious or mistaken crew member, compromised source document, compromised update or dependency, stolen appliance, and a support insider. A safety-critical system is outside the product boundary but must remain unreachable from model tools.

## Risk scale

Impact **H/M/L** is the plausible effect on confidentiality, safety, availability or recovery; likelihood **H/M/L** is a design-stage estimate before controls are tested. `H×H`, `H×M` and `M×H` are **critical/high** for pilot gating. Ratings are provisional and require review with the vessel and independent tester. A control listed here is planned, not verified.

| ID | Threat / boundary | Impact × likelihood | Required control and verification | Owner / residual decision |
|---|---|---|---|---|
| R-01 | Compromised crew laptop steals session or calls Core outside UI (Z0→Z1) | H×M | HTTPS, local MFA approach, short sessions, CSRF/session binding, server-side policy on every path; AT-01/05/08/17 | Security architect; accept only after lab and independent review |
| R-02 | Role or source ACL mapping error exposes owner/department content through search, answer, citation, preview, download or cache | H×M | Default deny, source ACL synchronisation, pre-retrieval filter and response recheck, negative role matrix, revocation tests; AT-05/06/07 | Policy lead; no high-risk exception for pilot |
| R-03 | Malicious PDF/DOCX instructions cause model to disclose data or invoke tools (Z4→Z1/Z2) | H×H | Treat document text as untrusted, tool allowlist/read-only, no shell/network tools, parser isolation, adversarial fixtures; AT-19 | AI + security; independent assessment required |
| R-04 | Unsafe parser or malformed upload executes code or exhausts resources | H×M | MIME/content validation, file/CPU/page limits, sandboxed parser, quarantine, dependency scans; AT-04/19 | Knowledge lead; no critical/high finding open |
| R-05 | Model or application sends prompt/document data via DNS, IPv6, proxy, telemetry or runtime download (Z1/Z2→Z8) | H×M | Default-deny network and host rules, pre-staged artifacts, packet captures with WAN up/down; AT-02/10 | Network lead; no undocumented exception |
| R-06 | vLLM endpoint bypasses Core because API key does not cover all endpoints | H×M | Bind to internal interface, isolate segment, reverse proxy/ACL if needed; no crew route; AT-17 | DevSecOps; [vLLM warning](https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/) |
| R-07 | Stolen AI/security server or removable backup reveals data or keys | H×M | Full-disk encryption where feasible, protected backup encryption, separate key custody, physical lock and incident process; AT-16/20 | Infrastructure + vessel custodian; hardware feasibility open |
| R-08 | Compromised update, model or dependency poisons appliance (Z7→Z1/Z2) | H×M | Source allowlist, SBOM, checksums, detached signatures, media scan, offline verification, rollback; AT-15 | DevSecOps; final artefact/legal review open |
| R-09 | Wazuh failure or AI host outage hides security events | H×M | Independent security host, local alert on collector gap, retention and outage injection; AT-11/12 | Security operations; recovery target open |
| R-10 | Security adapter has write privileges or model attempts device reconfiguration | H×M | Read-only API/service credentials, no write endpoints, route/permission tests; AT-13 | Network + security; no exception |
| R-11 | Insider administrator silently widens source scope or uses emergency access | H×M | Separation of duties, approval workflow, immutable/forwarded local audit, break-glass review; AT-14/21 | Vessel approver + security; custody decision open |
| R-12 | Ransomware or faulty release destroys index/configuration and backup | H×M | Isolated protected copy, versioned backups, clean-hardware restore, signed rollback; AT-15/16 | Infrastructure; RPO/RTO open |
| R-13 | Stale offline threat intelligence misses vulnerability context | M×H | Signed snapshot cadence, age shown in dashboard, do not claim live coverage; AT-22 | Security operations; cadence open |
| R-14 | Wrong asset mapping turns a FortiGate IP into misleading incident advice | M×M | Provenance, asset confidence, human review, fixed alert fixtures; AT-11/23 | Intelligence lead; quality threshold open |
| R-15 | Central Fleet/support process receives vessel data contrary to sovereignty claim | H×M | No standing Fleet route, field-level import allowlist, approval and audit for offline/admin records; AT-24 | Product + security; separate mode needs new review |
| R-16 | Clock/DNS/PKI failure invalidates audit chronology or trust | M×M | Local time/DNS/CA design, alarms, cert rotation and failure tests; AT-17/25 | Infrastructure; site source open |

## Information classification and handling

| Class | Examples | V1 development handling | Vessel pilot rule |
|---|---|---|---|
| C0 Public/test | Fictional manuals, invented log events, generated role fixtures | Allowed in isolated lab | Allowed if labelled; never mixed silently with real records |
| C1 Vessel operational | Approved SOPs, equipment manuals, non-sensitive inventory | Synthetic version in lab; real copy only under written export scope | Scoped source, named owner, retention and ACL mapping |
| C2 Restricted vessel | Private owner/guest information, HR/medical/financial material, sensitive security topology and logs | Prohibited by default | Requires explicit class-specific approval, need-to-know roles, stricter retention and testing |
| C3 Secrets | Passwords, tokens, private keys, recovery material | Test-only placeholders; never in model context or logs | Dedicated secret/key store; separate custodian; no document ingestion |

**Default rule:** only C0 may enter the development lab without new written approval. C1/C2 exports from Legacy 4 or another vessel need a named approver, exact dataset, sanitisation, transfer method, purpose, expiry and disposal evidence. C3 is never indexed. A “technical” document can still contain C2 or C3 content and must be reviewed before import.

## Source credentials and permissions

- Use one read-only service identity per source/connector where feasible. Store its secret outside source code, image layers, logs and prompts; rotate on crew/administrator change or suspected compromise.
- The source manifest records owner, path/share, class, allowed actions, mapping method, approval ID, import schedule and deletion/revocation behaviour.
- Role labels are examples only. Source ACLs must be mapped to the vessel-approved matrix. If the connector cannot prove an ACL, the item is quarantined or denied, never assigned a permissive default.
- Admin access to system records does not confer owner-document access. Break-glass credentials are sealed, time-limited, audited and reviewed after use.

## Retention, logs and key custody

Proposed lab defaults: synthetic source files and indexes persist for the test duration; request/audit metadata 90 days; synthetic Wazuh events 30 days; backups 30 days with one separate protected copy. These are **design proposals**. Vessel retention must be approved by the data owner and reconciled with local rules before production. Audit events store timestamp, pseudonymous or internal user ID, resource ID/class, action, decision, policy version and correlation ID; avoid prompt bodies, document excerpts, credentials and raw medical/owner data.

The vessel-specific key-custody design is open. At minimum separate (1) appliance encryption/recovery keys, (2) source service credentials, (3) update signing keys and (4) backup decryption material. The signing private key never travels onboard; the onboard verifier holds only trusted public keys. Record key owners, rotation, loss recovery and emergency access in the site design.

## Required review points

1. Product/technical lead confirms permitted V1 workflows and hard exclusions.
2. Security architect validates STRIDE coverage against the final diagrams and adjusts ratings.
3. Vessel authorised representative approves the source/ACL matrix, retention, key custody and any Legacy 4 data transfer **separately** from G0.
4. Independent tester reviews isolation, authorisation, prompt injection, parsing, release channel and recovery before G3.

No risk in this register is declared closed merely because a mitigation is designed. Closure requires the mapped test evidence and an accountable reviewer.
