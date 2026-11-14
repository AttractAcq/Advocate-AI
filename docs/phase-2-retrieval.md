# Phase 2 synthetic retrieval slice

`services/knowledge/retrieval.py` performs exact-term search of the generated text corpus from
`fixtures/manifest.csv`. It checks the fixture policy before opening a source,
rejects paths outside the fixture root, verifies each file hash, and returns
source ID, version, collection, hash and a bounded excerpt. It reloads policy
and manifest data on each call so local fixture revocation and deletion are
observed on the next search.

This is a small, deterministic search prototype for synthetic documents. It
does not parse PDF/DOCX/XLSX, build a persistent index, connect to a NAS,
authenticate users, call a model or meet the G1 offline assistant gate.
Those require the Phase 2/3 services and the target lab for final verification.

Run `make fixtures` followed by `make check`. `tests/test_retrieval.py` covers
allowed citations, denied and revoked users, tampered content, path escape and
query limits.
