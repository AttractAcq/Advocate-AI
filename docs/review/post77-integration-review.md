# Post-#77 synthetic candidate integration review

**Review status: open.** This branch starts at the head of [PR #77](https://github.com/AttractAcq/Advocate-AI/pull/77) and collects the later stacked synthetic-lab changes through [PR #261](https://github.com/AttractAcq/Advocate-AI/pull/261). It gives an independent reviewer one aggregate diff. PR #77 must be reviewed and integrated first; this branch still requires its own final-head CI and independent approval before integration. A GitHub approval does not close the product security assessment or any target-hardware gate.

## Review order

1. Read the [blocker index](../blockers-and-build-queue.md), especially B-01–B-04 and B-06–B-14. The synthetic evidence does not authorise vessel access, production data or deployment.
2. Check the [Phase 0–3 review pack](phase-0-3-external-review.md), [vessel release and recovery pack](phase-5-vessel-release-recovery-review.md), and [AT-18 performance brief](phase-5-performance-review.md). Record independent findings against exact commits and artifacts.
3. Review the changed trust boundaries: Core OIDC/Keycloak and policy enforcement; document approval, parsing and PostgreSQL retrieval; Wazuh and threat feed inputs; offline bundle signing, image intake, installer, switch, backup and recovery; Fleet identity and offline release handling.
4. Reproduce the repository checks with `make check`, then inspect the aggregate PR's **final-head** CI. The upstream release rehearsal must pass on the aggregate head, not just on its component PRs.
5. Download the named `synthetic-three-image-bundle-evidence` artifact from that run, record its `result.json` SHA-256 and run the [offline consistency verifier](../phase-5/retained-release-evidence-review.md). It checks reported outcomes, four scan/SBOM pairs and the initial and updated detached manifest signatures. The artifact omits image archives and the complete release bundle; its synthetic public key is not externally trusted, so it does not prove release provenance or archive bytes.
6. Record reviewer identity, independence, findings and final-head approval in GitHub. Keep the separate external assessment, reference hardware, network, NAS, Wazuh and vessel-owner decisions open until their own acceptance evidence exists.

## Scope and evidence map

| Area | Entry point | Main unresolved gate |
|---|---|---|
| Core, Console, retrieval and policy | [Phase 3 gate](../phase-3/gate.md) and [Phase 0–3 review pack](phase-0-3-external-review.md) | Target model/NAS/identity tests and independent role, citation and claim review |
| Cybersecurity intelligence | [Phase 4 gate](../phase-4/gate.md) | Independent Wazuh and network integration rehearsal |
| Signed offline vessel release and recovery | [Vessel review pack](phase-5-vessel-release-recovery-review.md) | Target installation, protected media, key custody and cross-version recovery decision |
| Performance | [AT-18 brief](phase-5-performance-review.md) | Target GPU run, user-visible first-token method and approved thresholds |
| Fleet management | [Fleet foundation](../phase-8/fleet-metadata-foundation.md) | Company production identity, licence process and strict-mode route proof |

The component PRs remain available for narrow code history and CI evidence. This aggregate PR is a review surface, not evidence that those external gates have passed. After both integration PRs are independently approved and merged in order, reconcile redundant component PRs against the resulting `main` history.
