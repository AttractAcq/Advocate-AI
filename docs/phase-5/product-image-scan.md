# Synthetic product image scan triage

**Current synthetic candidate:** the pinned Nginx Console and Alpine Core
images passed exact archive preflight with zero HIGH, CRITICAL or UNKNOWN
findings in the [PR #32 CI run](https://github.com/AttractAcq/Advocate-AI/actions/runs/43890872823).
The combined bundle verified under an ephemeral synthetic key. The Caddy
findings below are retained as the reason for changing the Console server;
they do not describe the current candidate.

## Earlier Caddy baseline

The [CI run for PR #29](https://github.com/AttractAcq/Advocate-AI/actions/runs/43886246571)
built the pinned Core and Console images and retained `synthetic-product-image-trivy`
reports. Trivy 0.76.2 reported **zero HIGH/CRITICAL findings in Core** and **two
HIGH findings in Console** on 16 November 2026. The Core report SHA-256 is
`6d0a62df128a33a92c5e9c50a52fb9f0a8b4f0de56997e80b026f5f4657b9a5f`;
the Console report SHA-256 is
`484887f66dc66445bd06b91c81f4b83ef405f7c15479a7fab3dd0f4e989e3b6f`.
These reports identify local build tags, not a signed release digest.

| Image | Package | Finding | Reported fixed version | Disposition |
|---|---|---|---|---|
| Console | `github.com/go-jose/go-jose/v3` 3.0.5 in Caddy | CVE-2026-116587, HIGH | None in report | Open: verify upstream advisory and Caddy reachability; obtain updated upstream image or reviewed rebuild |
| Console | `golang.org/x/net` 0.60.0 in Caddy | CVE-2026-78661, HIGH | 0.62.0 | Open: wait for a qualified Caddy image containing the fixed module or reviewed rebuild |

The first Debian Core build reported 54 HIGH findings. A pinned Alpine base
reduced that to five, all in pip's vendored packages; removing build-only pip
from the runtime image reduced the report to zero. The final Core image still
needs exact digest, archive/SBOM/scan binding, distribution licence review and
target validation through [release intake](release-intake.md). The Caddy
findings were not accepted for release.

## Exact archive rehearsal

The [PR #30 CI run](https://github.com/AttractAcq/Advocate-AI/actions/runs/43888305815)
retained `synthetic-product-image-release-evidence` generated from the actual
Core and Console Docker archives. Core image manifest
`sha256:af84f0ed0dda7c0bb769bab97b7c86179b0d1a7118d51e731a5634d542d47a6d`
passed intake with 960 SBOM components and zero unresolved findings; its
ephemeral-key candidate bundle verified. Console manifest
`sha256:26b7919c64880d479dfe2f8cc00461aa31ba34cd27a6765d6fbd36ef6aa22a6a`
had 405 SBOM components and four unresolved findings, so intake denied it.
The full offline archive scan includes UNKNOWN findings that the earlier
HIGH/CRITICAL-only tag scan omitted:

| Console package | Finding | Severity | Next action |
|---|---|---|---|
| `github.com/go-jose/go-jose/v3` 3.0.5 | CVE-2026-116587 | HIGH | Verify reachability and upstream fix |
| `golang.org/x/crypto` 0.57.0 | GO-2026-5932 | UNKNOWN | Review advisory and fixed Go module build |
| `golang.org/x/net` 0.60.0 | CVE-2026-78661 | HIGH | Obtain build with 0.62.0 or later |
| Go standard library 1.27.3 | CVE-2026-97054 | UNKNOWN | Obtain patched upstream Go toolchain build |

The exact Console scan JSON SHA-256 is
`9b8b6e04e2a83a237e326109c43745ea63ee7bee6ef1f466ed2559b2656a227c`.
The Core scan JSON SHA-256 is
`f43103a86a005efdaca6dc9e8940020d48686af291b002863d55dd2030617399`.
The registry names in the result are synthetic digest identifiers; no image
was pushed to that registry. The signing key was temporary and is not a
release trust anchor.

## Current Nginx candidate

The [PR #32 evidence artifact](https://github.com/AttractAcq/Advocate-AI/actions/runs/43890872823)
records Core manifest
`sha256:faa0b5ed28a23e822d2b989f4de5a3363121bce323b01bd2c5d6814bb9ba3312`
and Console manifest
`sha256:2b779dddec18c7e07ff9abd41608b451ab81d2b03159568a9242e77be0d95dd4`.
Syft identified 960 Core and 724 Console components. Pinned Trivy 0.76.2
reported zero HIGH, CRITICAL or UNKNOWN findings in each saved archive. Both
preflights passed and the schema-4 product bundle was signed and verified with
an ephemeral synthetic key. The Core scan SHA-256 is
`7edb69ff286fa436b19ec44dede610ab88132fc8e403a2372a04fc2bed45500c`;
the Console scan SHA-256 is
`96e28a07d6a5f9afdec3a83aa7c74f96a54d0bc86c791e43a4b6e750f088bcf4`.
The key and archives were discarded after CI; the retained scans and SBOMs
are rehearsal evidence, not a distributable release. Production image
provenance, publisher authentication, licence rights, protected signing keys,
target tests and independent security approval remain open.
