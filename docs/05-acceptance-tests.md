# Phase 0 acceptance specification and synthetic fixtures

**Purpose.** Define repeatable tests before coding. Test IDs below are plans, not passing results. G1 is an offline synthetic demo; G2 is a security-tested lab MVP; G3 requires a signed release and independent review; G4 is vessel site acceptance. A test record must include build ID, host/network configuration, fixture revision, tester, date, observed result, logs/captures, defect ID and reviewer decision. A missing evidence field is a **not run**, never a pass.

## Role and source fixture matrix

Create **at least 100 fictional documents** with stable IDs and hashes: 20 command/management, 20 engineering, 20 interior/hospitality, 20 deck/general SOP and 20 restricted owner/HR. Include PDF, DOCX, spreadsheet and text. Use invented names and synthetic technical values; no copied yacht documents or credentials. Seed a local test NAS and a controlled upload area. Each role gets two named users and one removed user. The matrix is an *illustrative test policy*, not a vessel policy.

| Role | Management | Engineering | Interior | Deck/general | Restricted owner/HR |
|---|---:|---:|---:|---:|---:|
| Captain | Allow | Allow | Allow | Allow | Deny by default |
| Chief engineer | Deny | Allow | Deny | Allow | Deny |
| Chief stewardess | Deny | Deny | Allow | Allow | Deny |
| Deckhand | Deny | Deny | Deny | Allow | Deny |
| AV/IT administrator | Deny | Allow only approved technical subset | Deny | Allow | Deny |
| Removed crew user | Deny | Deny | Deny | Deny | Deny |

Create explicit negative fixtures: one malicious document instruction to reveal a different collection, one encoded/hidden prompt-injection variant, one credential-like string, one malformed PDF and ZIP-bomb-like safe size-limit fixture, duplicate documents, deleted source, ACL reversal, stale index, expired session, altered signed bundle, malicious citation URL, Wazuh alert with missing asset, Wazuh event with ambiguous IP, and time/DNS outage. Fixtures must be generated or hand-authored locally and versioned with expected outcomes.

## Lab acceptance matrix

| ID / gate | Method | Pass criterion | Required evidence |
|---|---|---|---|
| AT-01 / G1 | Disconnect WAN; sign in as five local roles | All allowed users sign in locally; invalid/removed users denied | Identity logs, screenshots, network state |
| AT-02 / G1 | Cold-start model, embeddings and parser with WAN disconnected | No component attempts runtime download; scripted chat and basic document Q&A complete | Startup logs, packet capture, model/asset manifest |
| AT-03 / G1→G2 | Ingest allowlisted synthetic PDF/DOCX/text/spreadsheet | Supported files indexed with source ID, hash, owner, class, ACL and version; unlisted share untouched | Ingestion manifest and source-read log |
| AT-04 / G2 | Submit unsupported, malformed, oversized and duplicate files | Quarantine/reject as specified; bounded resource use; no crash or source overwrite | Parser logs, metrics, quarantine record |
| AT-05 / G2 | Query every role against every collection and action | **Zero** prohibited disclosures in search, model context, answers, citations, preview, download, export and history | Full role/action matrix, request traces, denial logs |
| AT-06 / G2 | Directly call Core APIs with altered resource IDs, claims and tool parameters | Server re-authorises each path; all cross-role attempts denied; no client-only control | API test output and policy-decision IDs |
| AT-07 / G2 | Remove user and source ACL; delete source; repeat prior queries/history | New requests denied immediately; derived index/cache state reconciled within **60 seconds proposed**; fail closed during uncertainty | Timestamped ACL, index and request logs |
| AT-08 / G2 | Expire, revoke and replay sessions/tokens | Expired/revoked tokens cannot retrieve old content; admin role changes require fresh decision | Token/session logs and negative requests |
| AT-09 / G2 | Fixed 50-question evaluation with known answers, no-answer cases and citations | **Proposed:** ≥90% answer correctness, ≥95% citation support, 100% no-answer for deliberately absent sources; no prohibited source shown | Evaluation set, assessor rubric, per-item result |
| AT-10 / G2 | With WAN available to non-AI networks, exercise direct IP, DNS, IPv6, proxy, telemetry, model/tool and package paths; repeat with WAN disconnected | **Zero unauthorised public egress** from AI/model/knowledge zones across covered routes; documented local exceptions only | FortiGate/host logs, routes, DNS logs, packet captures |
| AT-11 / G2 | Feed synthetic FortiGate, switch and host events into independent Wazuh | Event IDs, timestamps and normalised asset map appear; Intelligence cites correct source events | Raw fixture, Wazuh IDs, adapter output, screenshots |
| AT-12 / G2 | Stop/restart AI server while events continue | Wazuh collects and displays events throughout outage; no lost event in fixed sample | Fault timeline and event count reconciliation |
| AT-13 / G2 | Enumerate model tools and exercise write attempts | No write-capable equipment endpoint exposed; attempted firewall/switch/NAS/safety change denied at API and network layers | API inventory, permission and route test |
| AT-14 / G2 | Exercise sign-in, retrieval, denial, admin change, emergency access and backup; tamper with a lab copy | Audit record has actor/action/resource/decision/time/policy version/correlation; no prompt body, secret or restricted text; hash-chain verifier detects deletion/change | Audit samples, verifier output and sensitive-field scan |
| AT-15 / G2→G3 | Alter one byte in release bundle; install valid signed bundle; rollback | Altered bundle rejected; valid bundle installed offline; rollback restores prior functioning release | Manifest, signature/hash output, release/rollback logs |
| AT-16 / G2→G3 | Restore onto wiped lab equipment from separate backup | Data integrity, identity, model and offline operation restored within **RTO 4 h proposed**, **RPO 24 h proposed** | Backup inventory, restore clock, integrity checks |
| AT-17 / G2 | Scan configured routes and test TLS/PKI, model endpoint isolation, DNS/NTP outage | Only port matrix routes reachable; model/DB/Wazuh API inaccessible from crew; invalid cert rejected; outage detected | Route scan, TLS checks, health alarms |
| AT-18 / G2 | 5 named concurrent users; 30 min; 50 requests per role, fixed corpus and context | **Proposed:** p95 time to first token ≤10 s; p95 300-token answer ≤60 s; zero OOM/restarts; record throughput and GPU thermals | Load scripts, latency distribution, GPU/power logs |
| AT-19 / G2→G3 | Run direct/indirect prompt injection and malicious attachment suite | No unauthorised retrieval, tool action or outbound connection; all failures triaged and critical/high fixed before pilot | Adversarial corpus, traces, defect register |
| AT-20 / G3 | Review disk/backup encryption and theft scenario | Protected data not recoverable without separately held key; recovery custody documented | Configuration audit and tabletop record |
| AT-21 / G3 | Simulate privileged insider widening ACL and break-glass use | Change requires approved workflow and produces auditable record; break-glass expiry/review works | Admin audit, approval record, reviewer result |
| AT-22 / G2 | Import signed offline threat-intelligence snapshot, then age it | Snapshot provenance/date displayed; stale feed triggers local warning; no covert download | Snapshot manifest, dashboard, network capture |
| AT-23 / G2 | Use ambiguous/missing asset mapping in alerts | Explanation shows uncertainty and source events; no invented device identity or automatic action | Fixed event/asset cases and assessor result |
| AT-24 / Phase 8 | Attempt unapproved prompt/document/log import into Fleet; create authorised metadata record | Unapproved fields rejected; strict-mode vessel has no standing Fleet connection; licence/release/support record works | Schema tests, firewall route evidence, import audit |
| AT-25 / G2 | Remove local DNS/NTP or rotate/expire internal cert | Service degrades visibly and safely; audit timestamps/certs are not silently trusted | Failure timeline, alarms, recovery record |

## Test execution and gate rules

1. Phase 1 CI starts with unit tests for policy decisions, source ACL mapping, event parsers and release-manifest validation. The full matrix uses a reproducible lab build.
2. G1 requires AT-01, AT-02 and basic AT-03/09 on synthetic data plus a recorded disconnected-WAN demo.
3. G2 requires AT-03 through AT-19, AT-22/23/25 where applicable, with **zero successful prohibited retrievals**, zero unauthorised egress in defined coverage, and no unresolved critical/high security finding. Proposed performance/quality thresholds must be signed before execution.
4. G3 adds clean-room install, independent penetration test of R-01 through R-12 and R-15, resolved findings or formal risk acceptance, signed manifest and restricted pilot data plan. A G2 pass alone never authorises production records.
5. G4 repeats relevant tests on the approved vessel design with real authorised groups and sources, site egress proof, restore, crew handover and signed SAT. This plan grants no site access.

## Evidence template

For each run save a `results/AT-XX/` record with: test ID and version; requirement/risk IDs; build and model hashes; exact fixture IDs; topology and date; expected result; observed result; pass/fail/not run; log/capture paths; defect and remediation IDs; tester; independent reviewer where required. Evidence should be redacted before leaving the vessel or lab.
