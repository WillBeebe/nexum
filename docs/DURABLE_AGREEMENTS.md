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

## Protocol commands

`ProtocolStore` uses the same exact-retry rule. Persist the signed protocol
command before sending it. A lost response is not proof the peer missed it.
Resend those stored bytes. Do not call `Prepare` again, and do not invent a
new request ID for the same command. The optional adapter does this through
`Reconcile`. A transport may carry those bytes; it must not treat them as
speech or replay speech to recover them. Comlink carries them on an `agree`
packet and recovers a lost response with `agreement_reconcile`.

A directory-sync failure after an already-committed protocol command is
`ErrCommitUncertain` on both the latest-command retry and an older event whose
current head did not advance. Retry the same signed bytes. That uncertainty is
not a definitive refusal. A historical protocol response does not copy a later
phase or work outcome onto the old command head. Current phase is a separate
view. `WorkSucceeded` means a complete phase, an accepted resolution, a return,
and no incomplete record. It does not authenticate caller-built JSON.

`Store.Apply` still takes the time its caller supplies. The service adapter
ignores `ApplyAt` inside a signed payload and uses the receiver clock for a
first application. Tests may inject that receiver clock. An exact committed
retry still returns the historical result after the deadline.

The optional adapter outbox uses `pending`, retryable `unknown`,
`awaiting-verification`, `resolved`, `conflict`, and definitive `refused`.
Automatic retry skips `resolved`, `conflict`, and `refused`. `Unresolved` still
lists conflicts and definitive refusals. A successful authority response stays
unverified evidence until `RecordVerified` checks a signature. The same verified
terminal can be recorded again. A different terminal is refused and is not
applied again. New verified records keep that signature and the authority
public key. Older rows without a signature stay locally authenticated vault
history; loading them does not invent a portable signature. `Outbox` persists an
AEAD-authenticated `admission.gate` record inside the vault (excluded from
`*.box` item scans and included in `CopyPrivateDir` handoff manifests).
`StopAdmission` latches the in-process flag and writes `Stopped: true` under the
vault lock; `SealAdmission(generation)` and `ResumeAdmission(generation)` enforce
monotonic fence generations across restarts, separate OS processes opening the
same vault, and copied handoff directories (`AdmissionSealed` reports the
persisted gate state and generation). Pending quota counts non-terminal
rows. A separate history bound refuses new admission when retained rows reach
it. Neither bound deletes retained evidence to free a slot.

`CoordinationStore.Current` returns the latest lease, including one that a
trusted height would treat as expired or finished. `StatusAt` derives
`accepted`, `active`, `finalized`, or `reclaimable` from that height and does
not persist expiry. Height zero is refused. A checkpoint may retain incomplete
history and at most one accepted task result. An attempt completion is evidence.
It does not by itself select the task result.

`AccordStore` uses the same AES-256-GCM checkpointing, OS `flock` serialization,
bounded authenticated cache, and exact signed retry semantics for `nex.Accord`
collective decisions. Re-applying an already-committed signed `AccordCommand`
returns the original receipt hash across restarts without mutating state, while
reusing a request ID with different content fails with `ErrOperationConflict`.
In `adapter`, `AccordAuthority` (`KindAccord`, `EncodeAccord`) connects
`Outbox` retry/reconciliation and signed `AuthenticatedResponse` verification
to `AccordStore` using a required host-supplied monotone `Height` callback.

For conditional policy graphs, `CoordinationStore.RecordAccord` verifies an
exported `AccordBundle` offline against the `GoalStore`'s pinned `AccordGate`
(`GoalStore.Gate`), persists the terminal `GateResolution` under the
domain-separated key `gateRecordKey(goalID, gateID)` (preserving idempotency on
identical `(AccordID, Head)` retries and refusing conflicting terminal heads with
`ErrOperationConflict`), and enforces gate dependencies in `DiscoverGoal` and
`Claim` (`GateStatus`).

For stateless multi-pod failover without local filesystem state or directory
copies, `OpenSQLStore`, `OpenSQLProtocolStore`, `OpenSQLGoalStore`,
`OpenSQLCoordinationStore`, and `OpenSQLAccordStore` back all five stores with
a shared stdlib `*sql.DB` (`SQLDialectPostgres` advisory locks or
`SQLDialectSQLite` serialized lock rows), distinct per-store namespaces,
`(namespace, id)`-bound AES-256-GCM AAD, and per-read authenticated cache
validation against the current stored checkpoint version and plaintext digest.
Run `go run ./examples/accord` for a local end-to-end Accord demonstration, or
`go run ./examples/policy-graph` for stateless SQL failover, `AccordAuthority`,
`BallotPrivacySealedPaillier` CDS94 voting, and `AccordGate` branch unlocking.

## What remains outside this guarantee

- The sender's durable outbox and index of contract IDs are application-owned.
- Encryption protects stored data, not against the running host or someone with
  its key. Losing the key prevents recovery. Key rotation needs a migration.
- Ownership fencing is provided in three `adapter.FenceCoordinator` tiers with
  distinct guarantees: `Coordinator` is in-memory for single-process tests and
  does not survive process restart; `DurableCoordinator` (`OpenCoordinator`)
  persists AEAD-authenticated lease state (`coordinator.gate`) under cross-process
  OS `flock` (`coordinator.lock`), recovering crash-safe monotonic generations
  (`Issue` is refused once `Generation >= 1`); and `SQLCoordinator`
  (`OpenSQLCoordinator`) stores AEAD-sealed leases in a shared SQL table
  (`nex_fence_leases`) over `database/sql` (verifying AES-256-GCM tags across
  every read, write, and authorize path, including genesis generation 0),
  pairing `Authorize` / `AuthorizeTx` (PostgreSQL `FOR SHARE` and SQLite
  immediate write locks) with `StopAndFence` (`FOR UPDATE` / immediate write
  lock) so all in-flight destination writes finish before fence proof is
  recorded. Both durable coordinators support `EpochSealer`
  (`StopAndFence` / `ConfirmFenceProof`) to seal external destinations before
  activating a replacement owner. Restoring an isolated offline full-VM or
  full-directory snapshot that rolls back both local `Store`/`Vault` files and a
  co-located local `DurableCoordinator` together still requires an external SQL
  witness (`SQLCoordinator` on an independent PostgreSQL host) or an L2 receipt
  anchor to detect rollback.
- Currency transfers, tool calls, message delivery and other external effects
  are not executed or made transactional by `Store.Apply`. The optional effect
  adapter is a separate operation. It writes a durable `dispatching` record,
  with the attempt count already incremented, before `Execute`. A confirmed
  return is not success until a later durable record has phase `confirmed` and
  confirmation evidence. After restart, `dispatching` and `unknown` reconcile
  before another attempt. Automatic re-execution requires a destination that
  guarantees durable idempotency for the full intent key, and it does not apply
  to a legacy migrated row. Do not equate an accepted agreement with funds moved.
- Council, delegation, workflow and encrypted message records do not acquire
  durable storage through this bilateral-contract API.
- Bilateral `Store.Apply` still trusts the time its caller passes. The service
  path does not: `StoreAuthority.Apply` uses the receiver clock, so a signed
  `ApplyAt` cannot backdate a first application. Distributed ownership and a
  complete portable signature encoding for every historical record remain
  separate protocols. Task height is a trusted monotone input, not a caller clock.

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
