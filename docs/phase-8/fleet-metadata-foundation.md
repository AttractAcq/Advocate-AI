# Sovereign Fleet metadata foundation

Fleet is a company-side application. This synthetic local API has no vessel
connector or scheduled telemetry path. The Core vessel image copies only its
onboard services, and its container smoke check confirms Fleet code is absent.
Its request models allow only coded
customer, release, deployment, licence, support, maintenance and approved
offline deployment-receipt metadata. There are no free-text descriptions or
fields for vessel documents, prompts, embeddings or security logs. Unknown
fields are rejected before storage. A receipt's source value records that a
lab administrator performed an approved offline entry. The signed import
proves possession of a configured issuer key; it does not prove owner approval
or a physical vessel handoff.

The API stores records in an owner-only SQLite database and appends a
transaction-bound hash-chain event containing record type, code and digest.
The API rejects any POST, PUT or PATCH body above 16 KiB before JSON parsing,
including streamed bodies without a declared length. This keeps the
metadata-only import boundary bounded even when a client sends unexpected
document content.
Reads verify the chain, each record digest and the strict schema. The audit
does not store the raw request body. The hash chain is not signed: someone
with database write access could recompute it. Production Fleet needs its own
identity, key custody, database operations and independent review.

For a local synthetic run, create an owner-only directory and choose one
identity mode. Set `SOVEREIGN_FLEET_DB` and either
`SOVEREIGN_FLEET_TOKEN_FILE` (owner-only shared lab token) or both
`SOVEREIGN_FLEET_OIDC_ISSUER` and `SOVEREIGN_FLEET_ROLES_FILE` (owner-only
separate Fleet user/role map). The OIDC issuer must be a numeric loopback
Keycloak realm for this lab candidate. Then start:

```sh
.venv/bin/python -m uvicorn 'apps.fleet.main:create_app' --factory \
  --host 127.0.0.1 --port 18800
```

In token mode, every `/api/fleet/*` request needs `X-Fleet-Lab-Token` with the
token file's value. In OIDC mode, it needs `Authorization: Bearer` with a
signed `sovereign-fleet` audience token issued to `sovereign-fleet-portal`;
the shared lab token is rejected. The current role map is re-read on every
request, so revocation fails closed. `/health` returns only a static status.
The local lab token is not a production authentication design. `POST` and
`GET` routes cover customers,
deployments, licences, tickets, maintenance and signed
`import/deployment-receipts`; releases are read through `GET` and imported
locally from a verified bundle. `GET /api/fleet/audit` returns metadata-only
events. Records use fixed codes and enums. Licence dates must increase,
deployments must reference known customers and releases, and offline receipts
must match the deployment's release.

| Synthetic Fleet role | Allowed API actions |
|---|---|
| `fleet_viewer` | Read coded records except the audit history |
| `fleet_support` | Read coded records; create and change ticket/maintenance records |
| `fleet_release_manager` | Read coded records and audit history; approve/retire imported releases |
| `fleet_admin` | All metadata API routes, including receipt import and customer/licence/deployment changes |

The portal uses this same role matrix to show permitted controls and hide the
audit view from support and viewer roles. The API enforces every action even
when a client bypasses the portal. Per-customer scoping, MFA policy, named
release approvers and approved company identity operations remain open under
B-12. Core's vessel audience and Console client cannot access Fleet.

Import a signed Core and Console product bundle from an approved local
administrative workstation with:

```sh
.venv/bin/python -m services.fleet.release_import \
  --db /private/fleet/fleet.db --code REL-EXAMPLE1 \
  --bundle /private/releases/product-bundle \
  --trusted-key /private/keys/release-public.pem
```

The trust key must be an owner-only Ed25519 PEM public-key file. Import calls
the existing bundle verifier, requires product schema 4 with both images and
their evidence, and records the signed manifest SHA-256 and trusted signing
key ID as a `candidate`. It never stores or serves the image archives in
Fleet. `POST /api/fleet/releases` is unavailable, preventing a client from
submitting an arbitrary digest as release provenance. A local lab
administrator can change an imported candidate to `approved`, then to
`retired`, through `PATCH /api/fleet/releases/{code}/status`. A deployment
requires an approved release. The lab token and transition are not a
production release approval; named approvers, signing-key custody, release
review and target-vessel validation remain B-11/B-12.
Existing synthetic Fleet databases with the earlier arbitrary `bundle_sha256`
release field fail schema verification. Start a fresh lab catalog and reimport
signed product bundles; do not relabel an unverified digest as proven release
provenance.

The separate React/TypeScript Fleet portal runs locally from `apps/fleet/web`:

```sh
cd apps/fleet/web
npm ci --ignore-scripts
npm run dev
```

The development server listens on `127.0.0.1:18801` and proxies only
`/api/fleet` to the loopback Fleet API on port 18800. It shows company
customers, verified release metadata, deployments, licences, coded support
and maintenance, signed receipt results and audit events. It can create
strictly structured customer, deployment, licence, ticket and maintenance
records and use the lab status-transition routes. Release import remains a
local signed-bundle operation. With `SOVEREIGN_FLEET_TOKEN_FILE`, the portal
uses its shared lab-token form. With Fleet OIDC mode, set
`VITE_FLEET_OIDC_ISSUER` to the same loopback issuer before `npm run dev`.
The development server provides `/fleet-config.json`; the browser validates
that response before rendering and uses an authorization-code PKCE redirect
for the `sovereign-fleet-portal` public client. Register
`http://127.0.0.1:18801/` as that client's exact redirect and logout URI in
the local realm. The API verifies the token's separate audience and client,
then `/api/fleet/me` supplies the current mapped role. The access token stays
in browser-tab memory and goes only to same-origin Fleet API paths; PKCE state
and verifier are removed from session storage when the callback is processed.
The token mode and OIDC mode cannot be active together. A production static
server and approved OIDC configuration are still needed. This portal is a
synthetic company-side candidate; per-customer scope, approved offline
handoff, large-catalog performance, retention and independent
usability/security review remain B-12.

Record list endpoints accept `limit=1..100` and an `after` cursor containing
the last record code. The audit list accepts the last numeric event `seq` as
its cursor. Results are stable in code/sequence order; the portal fetches
additional pages on demand. Every page still verifies the full local audit
chain and catalog, so production-sized databases need measured performance
and an approved integrity/checkpoint design under B-12.

The receipt view also has a fixed-field import form for receipt, vessel and
release codes, observation date, health, issuer key ID and Base64 signature.
It constructs the strict schema-1 envelope without accepting document or log
fields, then submits it to the signature-verifying Fleet API. The browser does
not sign receipts or store signature material after a successful import.
The issuer must generate the signature over the exact record through the
approved offline process; production handoff and key revocation remain B-12.

Receipt import requires `SOVEREIGN_FLEET_IMPORT_KEY_FILE` pointing to an
owner-only regular PEM file containing the offline issuer's Ed25519 public
key. If unset, import returns 503 while the rest of Fleet remains available.
The API accepts a strict JSON envelope with `schema_version: 1`, `key_id`
(SHA-256 of the raw 32-byte public key), `receipt` (the strict metadata-only
record) and a standard Base64 `signature`. The issuer signs the ASCII bytes
of `SOVEREIGN-FLEET-DEPLOYMENT-RECEIPT-V1\n` followed by JSON containing
only `schema_version` and `receipt`, encoded with sorted keys, compact
separators and ASCII escaping. Invalid signatures, wrong keys and altered
receipt fields fail before storage. Duplicate receipt codes reject replay.
The audit event records the trusted issuer key ID and record digest, without
the signature or raw request. The import key is a synthetic lab trust anchor;
production key custody, revocation and approved offline handoff remain B-12.

The local lifecycle candidate exposes authenticated `PATCH` routes for
`/licences/{code}/status`, `/tickets/{code}/status` and
`/maintenance/{code}/status`. A request body contains only a `status` enum.
Licences may move pending → active/suspended → expired; expired is terminal.
Tickets must be triaged before waiting or resolution; resolved is terminal.
Maintenance may be deferred and returned to planned before completion.
Each allowed transition replaces the record and appends a digest-bound audit
event in one SQLite transaction. Invalid transitions and foreign body fields
are rejected without changing the record. These rules are synthetic workflow
defaults; vessel/customer policy owners must approve production lifecycle rules,
operator roles and expiry automation.

The [AT-24](../05-acceptance-tests.md) synthetic tests submit forbidden
prompt, document, embedding and security-log fields and confirm 422 responses
with no stored content. They create authorised metadata and verify audit
events, references and tamper detection. A real company portal, customer user
accounts, approved lifecycle rules and role enforcement, approved offline handoff, support workflow,
retention, network route proof and independent review remain open.
