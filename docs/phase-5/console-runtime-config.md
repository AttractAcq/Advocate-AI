# Console runtime identity configuration

**Status:** software integration for a reusable Console build. It does not
qualify a production web server, vessel identity provider or deployment.

The Console now loads `/console-config.json` from its own origin before React
renders. The response must be JSON, is fetched without cache or redirects,
and may contain only `schema` and `oidc_issuer`:

```json
{"schema":1,"oidc_issuer":"https://identity.vessel.example/realms/sovereign"}
```

The example hostname is fictional. A missing, malformed or oversized file
shows a configuration error and does not show a sign-in form. An absent issuer
is accepted only when the browser is on `localhost` or `127.0.0.1`, for the
synthetic passphrase lab. Non-loopback Console pages require HTTPS; a
non-loopback issuer also requires HTTPS. Issuer URLs with credentials, query
strings or fragments are rejected. The Console still uses same-origin `/api`
requests, so it does not accept an API URL from this public file.

Vite's development server generates the JSON from `VITE_OIDC_ISSUER` on
loopback. The built `dist/` directory contains **no** runtime configuration
file and no baked issuer. Local tests built with both a loopback issuer and a
fictional HTTPS issuer and found identical JavaScript asset hashes. A deployer
must supply the JSON through the same-origin web server with `Cache-Control:
no-store`, protect it under local TLS, and validate it against the approved
site identity design before opening the Console to crew.

The current Console and Core are still synthetic lab software. Vessel
configuration signing, web server packaging, approved issuer/redirect URI,
MFA, persistence, PKI, no-egress and target browser tests remain in B-03,
B-06, B-07 and B-09. This runtime change does not enable production mode.
