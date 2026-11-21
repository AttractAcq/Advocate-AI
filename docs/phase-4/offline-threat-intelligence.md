# Signed offline threat intelligence candidate

**Status:** local synthetic AT-22 software candidate. No publisher, feed cadence,
release media or vessel network route has been approved.

The AV/IT Security view now shows the status of an optional signed offline
snapshot: feed ID, publisher label, issue and expiry times, age, indicator count
and package SHA-256. It shows a warning when the package is more than seven days
old or past its signed expiry. It never calls a feed URL. The indicator values
are not returned by Core, sent to the model, correlated with alerts or used to
change equipment. This is provenance and freshness visibility, not live threat
coverage or a finding about the vessel.

The package is a small JSON envelope with `payload` and Base64 Ed25519
`signature`. The signed payload has schema 1, a feed ID, publisher label, UTC
issue and expiry times and 1–500 indicator records (`id`, `kind`, `value`).
Supported kinds are IPv4, domain and SHA-256. Parsing rejects duplicate fields,
duplicate indicators, malformed values, unsupported schema, non-finite JSON,
overlong validity and files above 256 KiB. The signer must hold the private key
outside the repository. A trusted public key must be provisioned through an
approved offline process; a valid signature does not by itself authenticate the
publisher or approve the feed's licence.

Use only fictional data in the local rehearsal. From the repository root:

```sh
.venv/bin/python -m scripts.phase4_threat_snapshot sign \
  --payload /path/to/fictional-payload.json \
  --private-key /path/to/private-ed25519-key.pem \
  --output /path/to/new-signed-package.json
.venv/bin/python -m scripts.phase4_threat_snapshot import \
  --package /path/to/new-signed-package.json \
  --trusted-key /path/to/approved-public-key.pem \
  --store /path/to/private-existing-store
.venv/bin/python -m scripts.phase4_threat_snapshot status \
  --trusted-key /path/to/approved-public-key.pem \
  --store /path/to/private-existing-store
```

The store must exist, be owned by the importing Core user and allow no group or
other access. Import verifies the signature and rejects future issue times,
older or equal issue times, and a changed feed ID. It writes a new package
atomically after verification. Imports take an owner-only, no-follow store
lock while comparing the prior issue time and replacing the snapshot, so two
concurrent approved-media imports cannot install an older package last. Core
loads the trusted key at startup, then
verifies the installed package on each AV/IT-only status read. A missing package
is visible as `missing`; invalid or tampered content returns 503. Set both
`SOVEREIGN_THREAT_SNAPSHOT_STORE` and `SOVEREIGN_THREAT_SNAPSHOT_KEY` in the
local Core environment. If neither is set, the AV/IT view says `unconfigured`.
The Security view shows only metadata and a freshness warning.
The vessel runtime has an opt-in `ThreatFeedMount` that checks owner-only,
separate host inputs and mounts the feed store and trusted key read-only for
Core. The signed vessel installer accepts `--threat-feed-store` and
`--threat-feed-key` together. It pins the host store and key identity in the
private install intent and active record, then carries that binding through
status, stopped restart and release switch. A replaced store, key or invalid
signed snapshot fails closed. Feed-backed recovery receipts bind the exact
signed snapshot and key; clean activation and retry require those external
inputs again, while an interrupted finish uses its pinned intent. A feed-backed
three-image install, capture and clean restore passed in the synthetic
[PR #237 release rehearsal](https://github.com/AttractAcq/Advocate-AI/actions/runs/44946229877).
Its retained result records a schema-4 receipt, stale feed status, withheld
indicator values and a signed healthy restore. W-193 in the
[build queue](../blockers-and-build-queue.md) tracks the remaining external gates.

The focused tests sign and import a fictional package, age it past seven days,
reject a rollback, changed signed content, duplicate JSON and a linked store
file, and exercise direct API role denial and tamper failure. The synthetic
Keycloak/Console browser rehearsal also imports an eight-day-old
package, signs in as AV/IT, checks the visible stale warning and publisher,
and checks that the indicator value is absent from the page. This is a browser
software test, not a target network trace. To close AT-22,
the target lab must repeat import and aging with approved media, verify the
publisher and key custody, capture packet/route evidence proving no covert
download, and have an independent reviewer decide the feed cadence and result.
