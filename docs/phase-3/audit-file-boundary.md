# Synthetic Core audit file boundary

Core verifies the hash chain before each audited API request and before each
append. The log is opened without following its final symlink, checked as a
regular file, and parsed one record at a time with an 8 KiB record cap. Duplicate
JSON keys and non-finite constants invalidate the trail. An existing log's
device and inode must still match when Core opens it for append; a missing log
is created exclusively. A failed check denies the request or append.

The regression suite replaces the log with a symlink to an unrelated file,
copies the same valid records to a different inode, supplies a FIFO, and adds
ambiguous or excessive records. The API check returns 503 on a symlinked log
without writing the target. A restored original log remains usable.

This is local consistency evidence, not a trusted audit anchor. A party able
to rewrite the entire file can recalculate an unkeyed hash chain. Deployment
still needs protected parent-directory and file ownership, independent log
retention or anchoring, rotation, a trusted time source, target-host recovery
and external security review. No vessel audit data was used.
