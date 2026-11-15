# Phase 2 synthetic retrieval slice

`services/knowledge/retrieval.py` performs stop-word-normalised exact-term search of the generated text corpus from
`fixtures/manifest.csv`. It checks the fixture policy before opening a source,
rejects paths outside the fixture root, verifies each file hash, and returns
source ID, version, collection, hash and a bounded excerpt. It reloads policy
and manifest data on each call so local fixture revocation and deletion are
observed on the next search.

The search filters by permitted collection and selected source IDs before
ranking. All 40 permitted questions in `fixtures/evaluation.csv` select the
expected source first; the 10 restricted questions yield no source. Core uses
these excerpts for the local model flow. This module does not parse PDF/DOCX/XLSX,
build a persistent index, connect to a NAS, or independently meet G1.

Run `make fixtures` followed by `make check`. `tests/test_retrieval.py` covers
allowed citations, denied and revoked users, tampered content, path escape,
query limits and the fixed 50-question retrieval fixture.
