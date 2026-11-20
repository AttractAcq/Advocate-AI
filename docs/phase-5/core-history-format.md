# Versioned Core conversation history

The persistent Core `history.db` now records SQLite `user_version=1` when a
fresh database is created. Core verifies that version, the three conversation
columns, owner index and database integrity before serving requests. It refuses
an existing version-0, future-version or malformed database rather than
silently creating missing tables. The vessel runtime checks an existing file
before creating Core containers, and stopped recovery capture checks the same
format before and after its SQLite backup copy.

The Core image build compares the signed bundle's Knowledge and Core-state
schema labels with the implementation constants. The release verifier still
checks those labels against the signed compatibility contract in the exact
Core archive.

`migrate_legacy_history(path)` is an explicit local helper for a known
pre-version history database. It checks the old table shape and stored turn
JSON, then sets `user_version=1` in one transaction. It is never called by
normal startup or vessel installation. Stop Core and retain a tested encrypted
backup before using it; an unknown shape or invalid row is rejected without
changing the version.

This is a synthetic compatibility boundary. A production vessel migration
still needs a signed release procedure, recoverable pre-update set, key
custody, rollback rehearsal and independent review. The wider Core state also
contains policy, source manifest and audit files; their validators remain
separate from this SQLite version marker.
