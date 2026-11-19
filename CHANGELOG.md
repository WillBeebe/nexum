# Changelog

## v2.0.0

### Major module & protocol upgrades

- Go module major version path moves to `github.com/WillBeebe/nexum/v2`
  (client package `github.com/WillBeebe/nexum/v2/nex`, adapter
  `github.com/WillBeebe/nexum/v2/adapter`, CLI
  `github.com/WillBeebe/nexum/v2/cmd/nex`).
- `ProtocolVersionV2` adds content-addressed `EvidenceManifest` output review,
  explicit `IncompleteReturn` deadline closeout (`incomplete` action), and
  optional `TaskID` / `Generation` lease binding.
- Multi-agent coordination & portable proof handoffs: `GoalSpec`, `GoalStore`,
  `CoordinationStore` (`Claim`, `Finalize`, `StatusAt`, `DiscoverGoal`),
  `TaskHandoff` (`ExportHandoff`, `VerifyTaskHandoff`), and the runnable
  `examples/coordination` suite.
- Durable and distributed SQL fencing in `adapter`: `DurableCoordinator`
  (encrypted local lease vault), `SQLCoordinator` (PostgreSQL `FOR SHARE` /
  `FOR UPDATE` and SQLite immediate-lock leases using stdlib `database/sql`),
  and durable outbox admission gating (`SealAdmission`, `ResumeAdmission`,
  `AdmissionSealed`).
- Two-profile verification (`l2.ProfileReceiptChain` vs
  `l2.ProfileSealedSettlement`) with `SealedProofBundle` /
  `Agreement.VerifySealedSettlement`, plus Format 2 sealed/plaintext mode
  commitment and Format 0 council/workflow state replay (`AssuranceStateReplay`
  / `AssurancePathReplay`).

### Scale & durability hardening

- Bounded `ProtocolStore` and `CoordinationStore` authenticated in-memory caches
  (`256`-entry cap with compacted FIFO eviction) so long-running coordinators
  maintain `O(1)` memory across thousands of agreements and tasks.
- `ProtocolStore.Export` confirms directory durability (`syncDir`) before
  returning a `ProtocolBundle` for handoff verification, matching `View`.
- `CoordinationStore.Claim` and `Finalize` invalidate cached entries before
  atomic checkpoint replacement so uncertain post-rename sync failures cannot
  retain stale pre-rename entries.

### Security hardening

- Paillier equality verification requires ciphertexts, proof commitments, and
  responses to belong to their required multiplicative groups. A public-data
  proof that collapsed both sides of the equation to zero is rejected.
- Agreement receipt verification derives status, recipient, and lock/close
  timestamps from the recorded transitions. Unit changes enforce the shared
  budget and step limits before mutation.
- Receipt chains now commit to the agreement's binding terms (ID, kind,
  parties, amount, unit, creation time). Rewriting `Amount`, a party or the
  unit off-ledger fails `VerifyReceipts`. The unit is set by a chained
  `unit` receipt (`WithUnit`/`WithUnitAt`) rather than a silent struct write.
- Receipts can carry an Ed25519 signature (`SignReceipts`). Shared consumers
  must independently bind the embedded key to the named actor and require the
  expected signatures. Unsigned legacy ledgers still verify.
- Receipt hashing is JSON-canonical: the old `"|"`-separated encoding
  allowed distinct receipts to share a hash.
- Council, workflow and delegation ledgers gained the same terms digests and
  optional receipt signatures.
- The L2 batch root derives its terms commitment from the kernel terms
  digest and separately commits the deadline and complete meter snapshot.
  Rewriting execution policy invalidates the existing seal.
- Relay request replay tracking retains nonces for their full signed validity
  window, including epoch boundaries. A full cache refuses new requests until
  entries expire.
- Optional `ReplyChain` on offers lets receiving agents verify a drained
  conversation has no gaps (`VerifyConversationOrder`).
- PoW search is cancellable (`SearchContext`); `Meter.MaxSteps` is clamped
  to 1..128 at open. Callers own accruing `CostUSD`.
- Format note: receipt hashes differ from earlier releases because the terms
  digest and canonical encoding are new. Existing stored records verify only
  against the ledger version that produced them; re-verify stored chains
  before cross-version comparison.

### Other

- Task handoffs can be exported with the original signed claim and verified
  independently against authenticated task and result pins. Verification binds
  the task, worker, generation, signed history, explicit outcome, and artifacts.
  The coordination example transfers and verifies three handoffs as JSON.
- Document that a lost protocol response is recovered by resending the stored
  signed bytes. A transport such as Comlink's `agree` packet must not Prepare
  again and must not replay speech. The circuit implementation stays out of
  this module.

## v0.3.0

- Protocol is an amount-free agreement and delegation API: admission, scoped
  roles, work and failure reports, independent witness review, resolution and
  a required return manifest. Completion means return obligations were met;
  a failed attempt can complete without being rewritten as success.
- ProtocolStore reuses the encrypted local checkpoint, exact signed retries
  and conflict rules already used by Store.
- The optional adapter package retains exact signed commands, reconciles lost
  responses, keeps external effects uncertain unless the destination can prove
  them, and proves stopped-writer fenced owner replacement in a synthetic
  harness. It is not a consensus or fleet coordinator.
- Examples: `return-handoff` and `reconcile-handoff`.

Existing bilateral Contract and Store APIs remain compatible. Distributed
ownership and production fencing remain application responsibilities.

## v0.2.0

- Optional encrypted local Store persists complete bilateral agreement state,
  custody, consent, step accounting, receipts and successful operation results.
- Signed operation IDs make exact successful retries stable across restarts and
  later commands; conflicting ID reuse and unauthenticated retries are refused.
- Crash-boundary and concurrent-process tests exercise recovery and serialization.
- The existing in-memory Command API retains its replay-refusal behavior.

The durable file format starts at version 1 and requires a separately protected
32-byte storage key. Local storage currently supports macOS/iOS and Linux;
iOS native bindings are not included. External effects and backup anti-rollback
remain application responsibilities.

## v0.1.1

- General contracts initialize their final kind through OpenAgreement. The
  OpenEscrow example API and its original opening receipt remain available.
- Direct Accept and dispatched acceptance enforce the same sealed equality proof.
- Failed bilateral settlement leaves evidence, receipt head, status and steps
  unchanged. Failed sealing also preserves encryption randomness and locks.
- Regression coverage verifies underfunded refusal, metering failures and retry
  of the same signed command after a failed settlement.
- All five collaboration examples use the updated module.

New general contracts record “agreement opened” instead of “escrow opened”;
their receipt hashes therefore differ from v0.1.0. Empty contract kinds are
rejected. Existing stored receipts are not rewritten. Atomicity is in memory,
not durable crash recovery; callers must serialize access.
