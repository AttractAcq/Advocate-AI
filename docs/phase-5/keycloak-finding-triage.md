# Keycloak lab image finding review

**Status:** preliminary package triage, updated 21 November 2026. No vulnerability is
accepted or released. The image is a synthetic `start-dev` lab identity server.

The [current CI scan](https://github.com/AttractAcq/Advocate-AI/actions/runs/44854299539)
of `quay.io/keycloak/keycloak@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`
reports six HIGH and zero CRITICAL findings with Trivy 0.76.2. The retained
`keycloak-lab-trivy` JSON artifact has SHA-256
`3d357c18e841e221fc3f6e23465b5e93fc891cc0a193ce0c3a5470c33d1ec2fa`.
The image is Keycloak 26.8.2, rebuilt as `26.8.2-3`. Keycloak's
[official downloads](https://www.keycloak.org/downloads) still list 26.8.2.
It remains a lab fixture, not an approved production image.

The same six findings present in the original 16 November scan remain in the
rebuilt image:

| Finding | Installed package in scan | Scanner status | Review action |
|---|---|---|---|
| [CVE-2026-91403](https://access.redhat.com/security/cve/cve-2026-91403) | `java-21-openjdk-headless` 1:21.0.13.1.2-1.2.el9 | `will_not_fix`; no package fix listed | Red Hat says its OpenJDK treatment was through `ca-certificates`, not an OpenJDK update. Check the exact trust-store package and image build before specialist disposition. |
| [CVE-2026-119373](https://access.redhat.com/security/cve/cve-2026-119373) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review FTS5 exposure and patched vendor package availability for this image. |
| [CVE-2026-119374](https://access.redhat.com/security/cve/cve-2026-119374) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review FTS5 exposure and patched vendor package availability. |
| [CVE-2026-119379](https://access.redhat.com/security/cve/cve-2026-119379) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review SQLite session changeset exposure and patched vendor package availability. |
| [CVE-2026-119586](https://access.redhat.com/security/cve/cve-2026-119586) | `sqlite-libs` 3.34.1-11.el9_8 | `affected`; no fix listed | Review command-line recovery tool presence and use, plus patched vendor package availability. |
| [CVE-2026-102554](https://github.com/google/guava/releases/tag/v33.7.2) | `com.google.guava:guava` 33.6.0-jre | `fixed`; scanner lists 33.7.2 | Wait for a tested Keycloak build with a fixed Guava dependency, or have the identity owner qualify a custom image; do not swap a JAR in place without testing. |

The scan's package presence is not proof that each vulnerable code path is
reachable. Equally, an inferred lack of reachability is not a risk acceptance.

## Earlier OpenJDK findings and interim mitigation

On 18 November 2026, Keycloak [warned about CVE-2026-114938](https://www.keycloak.org/2026/11/java4shell-vulnerability-cve-2026-114938)
in unpatched OpenJDK Base64 intrinsics on x86-64 hosts exposing AVX-512 VBMI.
The vendor identified affected OpenJDK in earlier 26.8.2 container tags. The
[previous digest's scan](https://github.com/AttractAcq/Advocate-AI/actions/runs/44850898282)
reported ten HIGH and one CRITICAL finding, with artifact SHA-256
`ff59358a55b035601955514077343bb50b380956bf86fa834d5e83a302d01530`.
Five findings were against the old
`java-21-openjdk-headless` 1:21.0.13.0.9-1.2.el9 package:

| Finding | Severity | Scanner status and listed fixed package |
|---|---|---|
| CVE-2026-114938 | CRITICAL | `fixed`; 1:21.0.13.1.2-1.2.el9 |
| CVE-2026-114939 | HIGH | `fixed`; 1:21.0.13.1.2-1.2.el9 |
| CVE-2026-114940 | HIGH | `fixed`; 1:21.0.13.1.2-1.2.el9 |
| CVE-2026-114941 | HIGH | `fixed`; 1:21.0.13.1.2-1.2.el9 |
| CVE-2026-114942 | HIGH | `fixed`; 1:21.0.13.1.2-1.2.el9 |

None of these five appears in the current scan of the rebuilt image. That
absence and the vendor announcement support the lab candidate; they do not
accept the six remaining findings or qualify production identity.
The synthetic Phase 3 and Fleet Keycloak launch commands now set
`JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics`. Fleet's CI rehearsal checks the
running JVM with `jcmd` after initial start and clean recovery, and fails if
`UseBASE64Intrinsics = false` is not observed. This is the vendor's interim
mitigation, not a patched image or proof about a future production host.
Every production Keycloak instance still needs its actual CPU, Java build and
live JVM flags checked; a vendor-confirmed fixed runtime must be qualified.

## Rebuilt official image candidate

Keycloak's [repository announcement](https://github.com/keycloak/keycloak/discussions/55303)
identifies `26.8.2-3` as a rebuilt official image containing Red Hat OpenJDK
21.0.13.1 for CVE-2026-114938. The synthetic lab now pins the tag's resolved
multi-platform digest
`sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`.
The registry manifest lists amd64 and arm64 variants. An isolated local ARM64
container at that digest reports OpenJDK 21.0.13.1, runtime build
`Red_Hat-21.0.13.1.2-1`. The Linux exact-image scan confirms the six remaining
HIGH findings; the x86-64 Fleet identity and recovery flows are still running
in CI. The interim JVM flag remains enabled during this qualification.

Before B-11 can close, use an approved image, rerun the scan with its exact
digest and database version, record vendor fix or VEX evidence for each ID,
test identity behavior, and obtain security-owner disposition. The separate
production Keycloak topology, MFA, persistent store, TLS, backup and network
tests remain B-03/B-06/B-07. The current image must not be promoted.
