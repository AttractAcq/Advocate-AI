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

The current PDF path extracts an existing text layer. Office files now have
ZIP member-count, expanded-byte, compression-ratio and path checks before
conversion. PDF and Office conversion runs in a persistent offline worker with
a 120-second first-request budget for Docling cold initialization, a 45-second
subsequent request timeout and a parsed-text size limit. This is a bounded
lab parser, not an OS-level memory/CPU sandbox. Scanned PDFs, OCR, encrypted
files, large spreadsheets and third-party NAS ACL semantics need separate
qualification before they enter the supported register. Docling supports the local conversion API used here; see its
[usage guide](https://docling-project.github.io/docling/usage/) and
[supported formats](https://docling-project.github.io/docling/usage/supported_formats/).

