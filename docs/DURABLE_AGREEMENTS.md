# Durable agreements and safe retries

The optional `nex.Store` persists bilateral contracts across local process
restarts. It stores immutable terms, admitted public identities, consent, the
step meter, exact receipts, ciphertexts, Paillier custody material and successful
operation results in one authenticated encrypted checkpoint.

The in-memory `Contract` API remains available and keeps its existing behavior:
replaying a successful raw `Command` is refused as stale. Use `Store.Apply`
and a signed `Operation` when a caller may lose a response and retry.

## Integrate

Use a private local directory on macOS/iOS or Linux. Its parent must exist.
Provision a random 32-byte storage key once and keep it in the application's
protected key store, separate from agreement files. Reuse it when reopening.
There is no default key, password derivation, identity recovery or automatic key
rotation. Go-to-Swift bindings and iOS background execution are separate work.

```go
// storageKey comes from your protected key store; it is not a password.
// buyer and seller are admitted nex.Public identities.
store, err := nex.OpenStore(privateDirectory, storageKey)
if err != nil { return err }

contract, err := nex.New("work.bounty", buyer, seller, 10, specification,
    now, deadline)
if err != nil { return err }
if err := store.Create(contract); err != nil { return err }
id := contract.ID() // persist this in the application's agreement index

op, err := store.Prepare(id, stableOperationID, "lock", "")
if err != nil { return err }
signature := nex.Sign(buyerIdentity, "operation", op)

// Persist op + signature in the sender's outbox BEFORE submission.
result, err := store.Apply(id, op, signature, now)
if err != nil { return err }
// Acknowledge/remove the outbox item only after recording result.
```

The storage API is local. A transport can carry the operation and signature to
the authoritative owner, which calls `Store.Apply` with trusted server time.
Do not expose arbitrary file paths or storage keys to remote peers. Tenant
admission, transport authentication and request limits belong to that adapter.

Creation is insert-only: `ErrExists` never replaces an existing agreement.
`Create` accepts a new unused contract, not an in-flight memory-only contract.
If creation had an uncertain outcome, call `View(contract.ID())` with the same
key. Do not silently replace it. A successful creation retry is not assumed.

`View(id)` returns a detached copy of terms, status, consent and receipts without
private custody material. Keep using the store after creation: mutating the
original in-memory contract does not update the stored agreement.

## Retry exactly the signed operation

An `Operation` contains an ID and the complete `Command` (terms commitment,
prior receipt head, action and evidence). Sign the entire object using the
`"operation"` domain; a legacy `"contract"` signature is not interchangeable.

Operation IDs are scoped to a contract. Generate a unique ID for each intended
operation, retain it in an outbox, and resend the identical operation/signature
until its outcome is known. Do not call `Prepare` again on retry: that may capture
a different head. IDs contain 1–128 UTF-8 bytes without surrounding whitespace;
evidence must be valid UTF-8 and is limited to 64 KiB and encrypted checkpoints to 16 MiB.

- An exact successful retry returns its original `Result`, after authentication,
  even after a restart, after later operations, or after the deadline.
- Reusing a committed ID with different content returns `ErrOperationConflict`.
- A fresh operation ID does not bypass stale-head or terminal-state checks.
- Failed validation, authorization, proof or metering checks commit nothing.
  They do not consume the ID; a retry can succeed after its cause is resolved.
- `ErrCommitUncertain` means replacement occurred but durability confirmation
  failed. Retry the same signed operation to resolve it. Do not send a new ID.

A historical retry result describes the original commit, not necessarily the
current status. Use `View` for current state. Successful IDs/results are retained
with the contract; there is no automatic expiry or garbage collection that could
turn a late retry into duplicate execution.

## Storage and recovery guarantees

Each contract uses a persistent OS lock file. Writers acquire it, load and
authenticate the latest checkpoint, evaluate the command, and write a replacement
containing both state and result. The replacement is encrypted with AES-256-GCM
and a fresh nonce; authentication binds the file format and contract ID.

The writer syncs the temporary file, atomically renames it over the prior
checkpoint, then syncs the directory before returning success. A process crash
before replacement leaves the prior state; after replacement, state and result
are both present. Recovery restores the exact receipt head and proof randomness,
rather than replaying encryption with new randomness.

Files use 0600 and the store directory must be 0700. Unknown versions, wrong
keys, damaged ciphertext, invalid receipt chains and inconsistent operation
history fail closed. Never recover by silently creating a fresh contract.
The format version is 1; no migration from raw Agreement JSON is supported.

This requires local filesystem locking, atomic rename and fsync semantics.
It is not a network-filesystem or multi-host failover protocol. OS locks are
released when a process exits. Never delete active lock files. Abrupt process
exit can leave encrypted `.pending-*` files; readers ignore them. Remove such
files only while all writers are stopped. This implementation has no compactor.
Storage-device or filesystem guarantees still bound power-loss durability.

## What remains outside this guarantee

- The sender's durable outbox and index of contract IDs are application-owned.
- Encryption protects stored data, not against the running host or someone with
  its key. Losing the key prevents recovery. Key rotation needs a migration.
- Restoring an old authenticated backup can roll back both state and the retry
  index. Independent checkpoints/fencing are needed for anti-rollback protection.
- Currency transfers, tool calls, message delivery and other external effects
  are not executed or made transactional by `Store.Apply`. Their destination
  needs idempotency or reconciliation. Do not equate accepted with funds moved.
- Council, delegation, workflow and encrypted message records do not acquire
  durable storage through this bilateral-contract API.
- Caller-supplied time remains trusted input. Distributed ownership, trusted
  clocks and a complete portable signature encoding are separate protocols.

## Evidence

`go test -race ./nex` covers creation and terminal-state recovery, preserved
consent and metering, exact replay after later commands, invalid signatures,
ID conflicts, damaged storage, conflicting writers, and concurrent retries
across handles and processes. Child-process tests exit without cleanup before
rename, after rename and after sync, then recover in another process. Settlement
is also interrupted after sync to simulate losing its successful response.

Run `go run ./examples/durable-retry` for a local demonstration. It creates
temporary keys/data and removes them on exit; copy its operation flow, not its
temporary key lifecycle, into an application.
