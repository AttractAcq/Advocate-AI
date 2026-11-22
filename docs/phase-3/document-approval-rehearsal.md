# Synthetic staged-document approval

The Console submits a file to a private quarantine. An offline operator can
promote one reviewed submission only after two distinct trusted Ed25519
signers approve a proposal. The requester must be one of the signers. The
proposal binds the staged content hash, current approved-manifest hash,
destination document ID, collection, classification, owner, version, pinned
inspection profile and a one-hour expiry. It is domain-separated from
role-policy changes.

Use fictional files only. An authorised reviewer must inspect the file outside
Core, confirm its digest and metadata, and follow the vessel's approved content
inspection process before signing. The tool validates the source envelope and
hash and invokes an offline, pinned ClamAV binary and signature database on a
private snapshot of the exact staged bytes. The proposal and apply steps both
require a clean scan. Detection, scanner failure, stale or changed database,
changed binary and scan timeout all stop promotion. The scan does not decide
document access or prove that a file is safe; the reviewer must still inspect
content and approve the collection and classification.

Prepare an owner-only inspection profile from an approved, locally provisioned
ClamAV database. Use the actual import timestamp; the tool rejects profiles
older than 30 days. The running promotion tool never downloads signatures.
ClamAV's [scanning guide](https://docs.clamav.net/manual/Usage/Scanning.html)
documents explicit database paths, and its [manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in)
documents scan exit codes and resource-limit alerts.

```sh
python -m scripts.phase3_document_inspection_profile \
  --scanner /path/to/clamscan --database /path/to/approved-clamav-db \
  --database-as-of 2026-11-19T00:00:00+00:00 \
  --out inspection-profile.json
```

The profile binds the scanner binary hash, exact database file names and
hashes, and database date. Review those values before signing. The adapter
copies verified signature files into a private temporary directory for each
scan, so an update to the source database cannot change what the scanner
loads during that scan. Production database provenance, update cadence and
target-host resource limits still require approval.
Trust and private keys use the same owner-only file format as the
[policy-change rehearsal](policy-change-rehearsal.md), but the owner must
approve the document signer roster separately.

The offline procedure, run with a writable synthetic fixture tree and a
private upload area, is:

```sh
python -m scripts.phase3_document_approval propose \
  --sources "$PWD/fixtures" --uploads "$PWD/infrastructure/lab/runtime/phase3-uploads" \
  --manifest "$PWD/fixtures/phase-3/approved-sources.json" \
  --upload-id UPLOAD_ID --requester lab-captain-1 --document-id ENG-999 \
  --collection engineering --classification C0_SYNTHETIC_ENGINEERING \
  --owner 'fictional engineering custodian' \
  --scan-profile inspection-profile.json --out proposal.json
python -m scripts.phase3_document_approval sign --proposal proposal.json \
  --signer-id lab-captain-1 --key captain.pem --out captain-approval.json
python -m scripts.phase3_document_approval sign --proposal proposal.json \
  --signer-id lab-chief_engineer-1 --key engineer.pem --out engineer-approval.json
python -m scripts.phase3_document_approval apply \
  --sources "$PWD/fixtures" --uploads "$PWD/infrastructure/lab/runtime/phase3-uploads" \
  --manifest "$PWD/fixtures/phase-3/approved-sources.json" \
  --proposal proposal.json --approval captain-approval.json \
  --approval engineer-approval.json --trust trusted-reviewers.json \
  --audit "$PWD/infrastructure/lab/runtime/phase3-audit/events.jsonl" \
  --scan-profile inspection-profile.json
```

The fixture tree in Git is an example. Run the rehearsal on a copy, not on the
tracked fixture corpus. The tool takes the same policy-directory lock as Core,
copies the verified source to a new owner-only file, atomically updates the
manifest, appends an audit event, and then marks the submission approved.
It retains an owner-only evidence packet with the exact signed proposal,
approvals and trust snapshot. An `approved-sources.json.pending` marker contains the
prior manifest and keeps retrieval and indexing closed during an interrupted
change. If the process stops unexpectedly, inspect the marker and evidence,
then roll back with:

```sh
python -m scripts.phase3_document_approval recover \
  --sources "$PWD/fixtures" \
  --manifest "$PWD/fixtures/phase-3/approved-sources.json" \
  --audit "$PWD/infrastructure/lab/runtime/phase3-audit/events.jsonl"
```

Recovery verifies the signed evidence and current source digest, restores the
exact old manifest, removes the newly copied source and records a rollback
event before clearing the marker. Tampered evidence leaves retrieval closed.
It rejects a changed upload or manifest, an existing document ID or content
hash, an unmapped collection, untrusted or duplicate signatures, and replay.
The index reconciler must run before the new document becomes searchable; Core
still checks the manifest, source hash and caller permissions per request.

This is a synthetic candidate. Production still needs independent retention
outside the Core host, human content inspection, an approved ClamAV signature
feed and update process, source ownership and read-only mount handoff,
approved signer roles, retention and target-host recovery review.
