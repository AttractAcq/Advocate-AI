# Phase 3 synthetic ingestion register

| Format | Current parser | Lab limit | Verification |
|---|---|---|---|
| UTF-8 `.txt` | Strict local decode | 8 MiB source, 2 MiB parsed text | 100 generated text sources indexed |
| PDF with text layer | Docling native PDF pipeline | 8 MiB, 100 pages | 5 generated PDFs indexed |
| `.docx` | Local Docling converter | 8 MiB | 2 generated documents indexed |
| `.xlsx` | Local Docling converter | 8 MiB | 1 generated workbook indexed |

The manifest includes 112 synthetic entries. The 109 unique supported sources
index; the duplicate DOCX, malformed PDF and unsupported JSON are quarantined.
The import records source ID, relative origin, owner, classification, collection,
version and SHA-256. Missing or changed source bytes fail closed. The worker
reads only paths listed in the manifest under the approved root. The local
database stores parsed passages and vectors, not a copy of the source file.
Ingestion, retrieval and the poller now accept the approved manifest only as
a regular, non-symlink file of at most 8 MiB. Oversized or linked input is
rejected before JSON parsing; Core reports the knowledge source unavailable
instead of using a prior index snapshot.
The [synthetic reconciler](runbook.md) polls the approved manifest every
30 seconds and runs `sync_manifest` when its digest changes; it also repeats a
full source check every ten minutes. Unchanged approved sources skip parsing.
Core's retrieval path independently rechecks manifest, policy and source hash
on each read, so an unapproved source change is denied before the next scan.
The poller does not map NAS ACLs or prove a target service-account mount.

The current PDF path extracts an existing text layer. Office files now have
ZIP member-count, expanded-byte, compression-ratio and path checks before
conversion. The Phase 5 local hardening pass also rejects source symlinks,
macro binaries, ActiveX/embedded content and external Office relationships
before parser invocation; post-index retrieval rechecks the no-symlink rule.
PDF and Office conversion runs in a persistent offline worker with
a 120-second first-request budget for Docling cold initialization, a 45-second
subsequent request timeout and a parsed-text size limit. On Linux the worker
also caps virtual address space at 8 GiB and cumulative CPU at 1,800 seconds,
with a fresh 135-second cold or 60-second warm CPU deadline before each parse.
Stricter inherited limits are kept. These limits are not applied on the macOS
development host. This is still a bounded lab parser, not a complete process
sandbox: file-system and syscall isolation, target container/cgroup limits,
and exhaustion behavior need Linux qualification. Scanned PDFs, OCR, encrypted
files, large spreadsheets and third-party NAS ACL semantics need separate
qualification before they enter the supported register. Docling supports the local conversion API used here; see its
[usage guide](https://docling-project.github.io/docling/usage/) and
[supported formats](https://docling-project.github.io/docling/usage/supported_formats/).

The later [synthetic parser regression](../phase-5/security-scan-and-parser-corpus.md)
rejects malformed PDF envelopes and recognizable active, encrypted and
compressed-object PDF names before conversion. It also rejects duplicate and
symlinked Office ZIP entries. These checks narrow the accepted subset; they do
not qualify arbitrary PDF/Office content for vessel ingestion.

