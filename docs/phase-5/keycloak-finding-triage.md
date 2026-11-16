# Keycloak lab image finding review

**Status:** preliminary package triage, 16 November 2026. No vulnerability is
accepted or released. The image is a synthetic `start-dev` lab identity server.

The [latest CI scan](https://github.com/AttractAcq/Advocate-AI/actions/runs/43880636263)
of `quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0`
reported six HIGH and zero CRITICAL findings with Trivy 0.76.2. The retained
`keycloak-lab-trivy` JSON artifact has SHA-256
`29e11bdb451283d96647c386021d49983687d60ba2322d8999a43f605874ff13`.
The image is Keycloak 26.8.2. Keycloak's [official downloads](https://www.keycloak.org/downloads)
listed 26.8.2 as the current release at this review, so there is no newer
official release to pin and test today.

| Finding | Installed package in scan | Scanner status | Review action |
|---|---|---|---|
| [CVE-2026-91403](https://access.redhat.com/security/cve/cve-2026-91403) | `java-21-openjdk-headless` 1:21.0.13.0.9-1.2.el9 | `will_not_fix`; no package fix listed | Red Hat says its OpenJDK treatment was through `ca-certificates`, not an OpenJDK update. Check the exact trust-store package and image build before specialist disposition. |
| [CVE-2026-119373](https://access.redhat.com/security/cve/cve-2026-119373) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review FTS5 exposure and patched vendor package availability for this image. |
| [CVE-2026-119374](https://access.redhat.com/security/cve/cve-2026-119374) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review FTS5 exposure and patched vendor package availability. |
| [CVE-2026-119379](https://access.redhat.com/security/cve/cve-2026-119379) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review SQLite session changeset exposure and patched vendor package availability. |
| [CVE-2026-119586](https://access.redhat.com/security/cve/cve-2026-119586) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review command-line recovery tool presence and use, plus patched vendor package availability. |
| [CVE-2026-102554](https://github.com/google/guava/releases/tag/v33.7.2) | `com.google.guava:guava` 33.6.0-jre | `fixed`; scanner lists 33.7.2 | Wait for a tested Keycloak build with a fixed Guava dependency, or have the identity owner qualify a custom image; do not swap a JAR in place without testing. |

The scan's package presence is not proof that each vulnerable code path is
reachable. Equally, an inferred lack of reachability is not a risk acceptance.
Before B-11 can close, use an approved image, rerun the scan with its exact
digest and database version, record vendor fix or VEX evidence for each ID,
test identity behavior, and obtain security-owner disposition. The separate
production Keycloak topology, MFA, persistent store, TLS, backup and network
tests remain B-03/B-06/B-07. The current image must not be promoted.
