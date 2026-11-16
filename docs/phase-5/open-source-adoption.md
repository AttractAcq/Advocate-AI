# Open source integration decisions

Updated 16 November 2026. These are bounded software decisions for the
synthetic build. No upstream repository was copied into Sovereign; the
integration uses pinned official binaries and our own small adapters.

| Candidate | Local outcome | Decision |
|---|---|---|
| [crane v0.22.1](https://github.com/google/go-containerregistry/releases/tag/v0.22.1) | Validated a saved image's layers and manifest digest; candidate signing binds its archive hash | Integrate for offline release preparation; production image still unqualified |
| [Syft v1.57.1](https://github.com/anchore/syft/releases/tag/v1.57.1) | Generated a real CycloneDX 1.6 inventory from the same saved image; adapter adds digest and archive provenance | Integrate; retain package coverage and licence review gate |
| [restic v0.19.1](https://github.com/restic/restic/releases/tag/v0.19.1) | Encrypted local repository, full data check and clean SQLite/configuration restore passed | Integrate behind the synthetic snapshot interface; target recovery remains open |
| [Cosign v3](https://github.com/sigstore/cosign) | Official [offline image guidance](https://github.com/sigstore/cosign#verify-a-container-in-an-air-gapped-environment) requires locally available image/signatures and managed trust material; keyless flows also require a trusted root | Do not add a second signing path before release-key and publisher-trust custody are approved. Re-evaluate for publisher signatures on production images |
| [OpenFGA v1.22.1](https://github.com/openfga/openfga/releases/tag/v1.22.1) | Isolated, loopback, in-memory prototype matched 25 synthetic role/collection allow-deny cases and denied access after membership revocation | Keep as a prototype. Do not replace the current Policy Engine until direct document denies, NAS ACL change propagation, outage behavior, OIDC integration and independent review are proven |

The [OpenFGA probe](../../scripts/phase5_openfga_probe.py) starts only on
loopback with authentication and persistence disabled, compares the existing
fictional role matrix, and stops. It does not serve a vessel or process real
documents. CI downloads a checksum-pinned Linux binary and reruns the probe.
The current Policy Engine remains the enforcement point for search, preview,
citations, model context and history revocation.

The first [lab Keycloak scan](keycloak-lab-image-scan.json) still has six HIGH
findings. No tool adoption accepts those findings, closes G2/G3, or replaces
target hardware and independent security evidence in the
[blocker tracker](../blockers-and-build-queue.md).
