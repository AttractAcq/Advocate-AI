# Synthetic Phase 0 corpus

From the repository root, run `python3 fixtures/generate.py` to deterministically create 100 fictional UTF-8 source files, a SHA-256 manifest, 50 question/answer cases and 11 named test identities. The `restricted` collection is deliberately denied to every role in this fixture. All files are local and contain invented content only.

This corpus is for planning and the first retrieval/permission tests. It is not a realistic vessel corpus or a performance benchmark. Phase 1 T-008 must add safe PDF, DOCX, spreadsheet, malformed-file and event fixtures, then version and review them. `fixtures/negative-prompt-injection.txt` tests that retrieved text is treated as untrusted data.

The question set intentionally asks the deckhand about restricted markers; the expected result is denial. Other questions use the captain against non-restricted collections. The role matrix lives in `fixtures/roles.json` and is illustrative only.
