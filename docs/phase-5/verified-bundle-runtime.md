# Verified two-image runtime rehearsal

The synthetic runtime accepts only a trusted schema-4 Core and Console bundle.
It revalidates both saved archives with the pinned crane binary, checks the
Docker/OCI image identifiers inside each archive, loads the images without a
registry pull, and launches them by content ID. The containers run as their
non-root image users on a new internal Docker network, with read-only roots,
temporary `/tmp` storage, no capabilities, no privilege escalation and no
published host ports. A synthetic Console configuration with no identity
issuer is mounted read-only. Core health, Console static serving, configuration
and unauthenticated API denial are checked before the runtime handle is
returned. Failed starts remove the resources created by that attempt.

The rehearsal also tests a runtime switchover: a bad candidate is rejected
while the previous runtime still passes health checks; a verified candidate
starts and passes those checks before the previous containers are retired.
This operation is in-memory and uses disposable synthetic images. It is not
a persistent installer transaction or a crash-safe rollback procedure.

The [product-image CI rehearsal](product-image-release-rehearsal.md) invokes
this launcher only after both image intakes pass and the ephemeral-key product
bundle verifies. It exercises the rejected candidate and healthy switchover,
then stops the runtime. This is a local
software and Docker exercise; it does not install a persistent service,
provision TLS or Keycloak, attach a model, connect to Wazuh/NAS, configure a
vessel firewall, or prove target hardware behavior. The separate
[product installer](product-installer-activation.md) now stages releases and
checks rollback; clean-host and
site recovery remain [open gates](../blockers-and-build-queue.md).
