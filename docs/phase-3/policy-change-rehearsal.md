# Synthetic two-person policy change

The offline tool changes only the lab `roles.json` file. It does not configure
Keycloak accounts or grant vessel access. A proposal binds the current and
candidate policy hashes, requester, reason and expiry. Two distinct approved
Ed25519 signers, including the requester, sign those exact proposal bytes.
The trust file maps signer IDs to base64-encoded raw public keys and must be
an owner-only regular file. Signer private keys must be separate owner-only
Ed25519 PEM files; no keys are included in the repository.

Run these commands with synthetic policy files and an independently prepared
trust store. Each signer uses their own key and writes a separate approval:

```sh
python -m scripts.phase3_policy_admin propose --current roles.json --candidate candidate.json --requester admin_a --reason 'Synthetic reviewed role change' --out proposal.json
python -m scripts.phase3_policy_admin approve --proposal proposal.json --signer-id admin_a --key admin-a.pem --out approval-a.json
python -m scripts.phase3_policy_admin approve --proposal proposal.json --signer-id admin_b --key admin-b.pem --out approval-b.json
python -m scripts.phase3_policy_admin apply --current roles.json --candidate candidate.json --proposal proposal.json --approval approval-a.json --approval approval-b.json --trust trusted-admins.json --audit audit.jsonl
```

The tool preserves an owner-only `policy-change-evidence/<request-id>.json`
packet containing the exact proposal, approvals, trust snapshot and candidate
bytes. An existing packet blocks reuse of that request ID. Before replacement,
it creates `roles.json.pending`; Core denies policy reads while that marker
exists. The candidate is written through a private temporary file and
atomically renamed, then an audit event records activation. An interruption
leaves the marker in place. After investigating the interruption, restore the
prior policy with:

```sh
python -m scripts.phase3_policy_admin recover --current roles.json --audit audit.jsonl
```

The test suite covers exact-hash activation, two distinct signatures,
owner-only signer keys, tamper and expiry rejection, old-token role rejection,
API 503 during a pending change, rollback after a simulated interruption and
request-ID replay denial. `make check` passes 202 tests with five skips in the
synthetic workspace.

Core now rechecks the active identity immediately before sending retrieved
context to the model and again after a model call. A role change or revocation
at either checkpoint denies the chat or incident-explanation response; a
discarded chat answer is not stored. The local regression changes the policy
after retrieval and during model completion. This closes those two observed
windows. Core also holds a cooperative shared lock on the policy directory
for each API or health request. The offline change tool creates the pending
marker first, then waits up to 30 seconds for those requests to finish before
taking an exclusive directory lock, replacing the file and clearing the marker.
New requests fail closed while pending or while the writer owns the lock. A
timeout leaves the marker in place for investigated recovery. The local
concurrency test verifies that the old policy remains active until an existing
reader releases its lock. Direct file writers that ignore the lock can still
bypass this drain; target storage locking and a controlled administrative
service remain open.

Before vessel use, management must approve the signer roster and access model,
separate and protect private keys, establish MFA and maintenance quiescence,
retain evidence outside Core's writable state, review audit anchoring, and
rehearse the process on target storage. The current tool does not implement
emergency credential release or a production administrative API.
