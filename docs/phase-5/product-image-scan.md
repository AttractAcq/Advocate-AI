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
