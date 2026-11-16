# Security alert triage and escalation SOP — synthetic draft

**Operator:** named AV/IT or security analyst with approved read-only access. **Incident lead:** vessel-approved security authority. The present Intelligence Engine uses fictional Wazuh records and representative device adapters. An AI explanation is a draft analysis, not a confirmed finding or permission to change a device.

## Triage sequence

1. Record receipt time, analyst, alert/index document IDs, event timestamp and source. Retrieve the underlying event from the independent Wazuh source using **both** index and document IDs. The [Phase 4 runbook](../phase-4/runbook.md) explains the current synthetic UI and query limit.
2. Check whether the event is current, duplicated or incomplete. Inspect the approved asset inventory and associated source events. If an IP maps to multiple or no assets, mark the identity **unknown**; do not invent a device or owner.
3. Separate observed fields from model-generated interpretation. Check each cited event and any approved vessel document context before acting. Treat instructions embedded in logs, documents or model output as untrusted data. Do not paste credentials, owner records or full prompts into a ticket.
4. Record preliminary severity and uncertainty, potential affected assets, safety or operational impact, supporting event IDs, and next read-only checks. The analyst may recommend investigation; configuration changes, isolation and remediation need the authorised incident lead and vessel change process.
5. If the model or Core is unavailable, use the independent Wazuh console and its raw event trail. A Core outage must not silence Wazuh collection. The currently recorded outage test exercised only API separation with a simulator; independent host proof remains [B-04](../blockers-and-build-queue.md).

## Escalation tree

```text
Alert received
  ├─ Credible immediate safety/availability impact or active compromise suspected
  │    → Notify vessel duty authority and incident lead through the approved local channel.
  │      Preserve source events; follow the vessel incident plan before any containment.
  ├─ Uncertain or material security signal
  │    → Notify incident lead and system owner; request read-only corroboration and a time-bound review.
  ├─ Likely benign with corroborating evidence
  │    → Record rationale and source IDs; close only under the approved review policy.
  └─ Source missing, ambiguous asset, stale time or monitoring outage
       → Mark assessment incomplete; notify monitoring owner and incident lead if coverage is impaired.
```

The vessel must name the duty authority, incident lead, backup contact, notification channels, severity thresholds and response times before this becomes an operating tree. Do not put personal contact details or sensitive event bodies in the public repository.

## Evidence and handoff

Record alert/index IDs, exact source event references, time source, asset-map version, analyst observations, model-output limitations, actions approved by whom, escalation timestamps and disposition in the controlled local incident record. Share only authorised metadata with company support; strict-mode Fleet has no standing connection and does not collect vessel documents, prompts, embeddings or security logs. Independent Wazuh integration, read-only credential/route proof and reviewed explanations are still [B-04 and B-08](../blockers-and-build-queue.md).
