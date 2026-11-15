# Phase 4 synthetic intelligence runbook

1. From the repository root, run `make check` and `cd apps/console/web && npm run build`.
2. Start the existing local Core and Console per the [Phase 2 runbook](../phase-2/runbook.md). Sign in as `lab-avit_admin-1` using the configured lab passphrase.
3. Open **Security**. The three synthetic incidents come from `fixtures/phase-4/wazuh-alerts.json`; their asset map is `fixtures/phase-4/assets.json`. Inspect the event ID, timestamp, asset match, source location, confidence limit and suggested checks.
4. Select **Explain with local AI** only when the loopback model is running. The model produces an unverified explanation. Core attaches the event citation, and the analyst checks the independent alert source before acting.
5. Stop the local model. The incident list and detail should still load; explanation should report unavailable. This exercises API separation only. It does not simulate independent Wazuh collection.

Optional future lab configuration: set `SOVEREIGN_WAZUH_INDEXER_ENDPOINT` to the private HTTPS indexer URL, `SOVEREIGN_WAZUH_READ_TOKEN` to a separately scoped read token, and `SOVEREIGN_WAZUH_CA_BUNDLE` to the trusted CA bundle. The endpoint and token must be provided together. The reader calls only `POST /wazuh-alerts*/_search` with at most 100 alerts and an explicit field list. No secret belongs in the repository, command history or test fixtures. Confirm the token's permissions and source network path separately on the actual lab host.

The current switch and host alerts are representative structured Wazuh records. Their vendor-specific collector mappings are not yet implemented or verified. The FortiGate parser accepts a representative key-value syslog line and returns only approved fields. This is a software adapter test, not a claim that a FortiGate or Wazuh appliance generated the event.
