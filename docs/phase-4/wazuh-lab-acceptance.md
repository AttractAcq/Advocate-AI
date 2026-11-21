# Independent Wazuh lab acceptance worksheet

**Execution status: not run.** This worksheet prepares T-018, T-019 and T-021. It must be filled with evidence from an isolated Wazuh host or VM; the Mac fixture and mock transport cannot satisfy it.

## Before installation

- Record host/VM identifier, CPU architecture, RAM, disk capacity, OS image checksum, network segment, operator and date. Size the host and alert retention against the [Wazuh indexer requirements](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html) and the planned number of agents. Record the approved retention period and measured free space.
- Record the exact Wazuh manager, indexer, dashboard and Filebeat package versions and hashes. Prepare them on a connected staging machine using the [official offline installation workflow](https://documentation.wazuh.com/current/deployment-options/offline-installation/index.html), then transfer them through the approved media path.
- Record the source and checksum of the installation archive and generated certificates. Remove or rotate installation defaults before connecting any collector. Do not put passwords, tokens or private keys in this worksheet or repository.

## Independent service and access checks

1. Start manager, indexer, Filebeat and dashboard on the isolated host. Record their versions, service status and startup timestamps with WAN physically disconnected.
2. Confirm the Wazuh dashboard displays alerts while Sovereign Core and the model are stopped. Record a screenshot and the corresponding indexer alert IDs.
3. Create a dedicated Sovereign indexer identity limited to reading `wazuh-alerts*`. Use [Wazuh's read-only role guidance](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html) as the starting point, then narrow permissions to this integration. Test that alert search succeeds and index creation, alert modification, deletion, cluster settings and dashboard administration are denied. Record request IDs and status codes without tokens.
4. Verify the indexer certificate chain and IP SAN from the Core host. The application requires a private numeric HTTPS endpoint and validates certificates. Record the CA fingerprint, not the private key.
5. Confirm the route matrix permits Core to reach only the indexer search service. Record network policy and packet or flow evidence for blocked outbound Internet, firewall management, switch management and safety-system paths.

## Representative alert proof (AT-11 and AT-23)

1. Feed a synthetic FortiGate denial, switch management event and host alert through the approved Wazuh collectors. Use unique test IDs and record original event timestamps. [Wazuh's syslog collector guide](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html) requires an `allowed-ips` setting for network device syslog.
2. Capture each Wazuh alert's `_index`, `_id`, `_source.id`, timestamp, decoder, rule ID and decoded source-device field. Confirm the IDs can differ and that the Console cites both. Reconcile the three input events to manager alert storage, indexer search results and Console evidence.
3. Test a missing asset and two assets sharing an IP/VLAN. Confirm the Console reports unresolved/ambiguous mapping and the explanation does not invent an owner or device. Record any unsupported decoder and verify it is not presented as a supported incident.
4. Do not forward the parser's credential-canary fixture to Wazuh: the current parser test is not wired into the collector path. Inspect the actual collector's sample logs and indexing configuration for secret-bearing fields, and verify that Core, model context, Console and audit events do not expose raw log or credential fields. If the collector retains raw logs, document their access and retention controls separately. Add an approved pre-ingest redaction test before claiming that Wazuh never stores credentials.
5. Add a second synthetic alert from the same approved source device within one hour of the first, an alert from a different device, and another alert from the original device more than one hour away. Verify that the related view includes only the in-window same-source alert, shows its own `_index`, `_id` and event ID, and labels the 100-alert query and 20-result display as bounded samples. Repeat with an unmapped source: no device association or related window query should occur. Record the asset-map version used for these decisions.
6. With the local model available, explain the first alert and verify that **Evidence supplied** lists only the primary alert and up to five in-window same-source alerts. Check the generated sentence against those exact fields; reject any claim of common cause, compromise, equipment action or unsupported duration. Repeat after disrupting only the related search: primary-only explanation should remain available with a clear sample-unavailable notice. Record the model identity and the analyst's claim-by-claim assessment; the [one-run evaluation](contextual-answer-evaluation.json) and [four-case matrix](contextual-answer-matrix.json) are synthetic development references, not site results.

## AI outage proof (AT-12 and AT-13)

1. Record Wazuh alert count and the last unique test ID. Stop Sovereign Core and the model, leaving Wazuh manager, indexer, dashboard and collectors running.
2. Send a fixed sequence of new synthetic events during the outage. Confirm the Wazuh dashboard displays them before Core restarts. Record manager and indexer counts and timestamps.
3. Restart Core and model. Search the same IDs through Sovereign. Reconcile input count, Wazuh alert count and Console evidence, including any duplicate or missing ID. An empty or estimated count is **not run**, not a pass.
4. Enumerate Core's model tools and attempt disallowed firewall, switch, NAS and safety-system changes at application and network boundaries. Record denials. No equipment write is part of the Phase 4 API.

## Offline threat snapshot proof (AT-22)

1. Record the approved feed publisher, licence, Ed25519 public-key fingerprint, signing custody, media transfer and update cadence. Keep private keys and indicator values out of this worksheet.
2. Import a signed fictional snapshot with the [offline procedure](offline-threat-intelligence.md). Confirm the AV/IT Security view shows its publisher, issue time, age and count without exposing indicator values; other crew roles and unauthenticated callers must be denied.
3. Alter the package and repeat import; verify the existing snapshot remains intact. Attempt an older signed package and a changed feed ID; both must be denied. Age the installed package past seven days and verify the visible stale warning.
4. Capture host routes and packet or flow data during import, status reads and aging. Confirm no public feed request or covert download. Record the test window and negative network evidence rather than inferring it from application code.

## Result record

Record the build commit, Wazuh version, host/network configuration, fixture revision, tester, execution date, commands and redacted logs, screenshots, counts, deviations, defect IDs and independent reviewer decision. Mark each of T-018, AT-11, AT-12, AT-13, AT-22 and AT-23 **pass**, **fail** or **not run** separately. Do not close [the Phase 4 gate](gate.md) on an unexecuted worksheet.
