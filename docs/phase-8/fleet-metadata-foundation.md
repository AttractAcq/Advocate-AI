# Sovereign Fleet metadata foundation

Fleet is a company-side application. This synthetic local API has no vessel
connector or scheduled telemetry path. The Core vessel image copies only its
onboard services, and its container smoke check confirms Fleet code is absent.
Its request models allow only coded
customer, release, deployment, licence, support, maintenance and approved
offline deployment-receipt metadata. There are no free-text descriptions or
fields for vessel documents, prompts, embeddings or security logs. Unknown
fields are rejected before storage. A receipt's source value records that a
lab administrator performed an approved offline entry; it is not itself a
cryptographic approval or proof of a vessel handoff.

The API stores records in an owner-only SQLite database and appends a
transaction-bound hash-chain event containing record type, code and digest.
Reads verify the chain, each record digest and the strict schema. The audit
does not store the raw request body. The hash chain is not signed: someone
with database write access could recompute it. Production Fleet needs its own
identity, key custody, database operations and independent review.

For a local synthetic run, create an owner-only directory and token file,
set `SOVEREIGN_FLEET_DB` and `SOVEREIGN_FLEET_TOKEN_FILE`, then start:

```sh
.venv/bin/python -m uvicorn 'apps.fleet.main:create_app' --factory \
  --host 127.0.0.1 --port 18800
```

Every `/api/fleet/*` request needs `X-Fleet-Lab-Token` with the token file's
value. `/health` returns only a static status. The local lab token is not a
production authentication design. `POST` and `GET` routes cover customers,
releases, deployments, licences, tickets, maintenance and
`import/deployment-receipts`; `GET /api/fleet/audit` returns metadata-only
events. Records use fixed codes and enums. Licence dates must increase,
deployments must reference known customers and releases, and offline receipts
must match the deployment's release.

The [AT-24](../05-acceptance-tests.md) synthetic tests submit forbidden
prompt, document, embedding and security-log fields and confirm 422 responses
with no stored content. They create authorised metadata and verify audit
events, references and tamper detection. A real company portal, customer user
accounts, lifecycle transitions, signed offline import, support workflow,
retention, network route proof and independent review remain open.
