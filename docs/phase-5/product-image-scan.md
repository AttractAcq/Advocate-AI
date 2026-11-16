# Synthetic product image scan triage

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
target validation through [release intake](release-intake.md). Neither the
Console findings nor any other product image findings are accepted for release.

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
