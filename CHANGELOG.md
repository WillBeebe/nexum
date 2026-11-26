# Changelog

## v2.1.0

### Sealed-ballot Paillier Accords (`internal/he`, `nex`)

- **`BallotPrivacySealedPaillier`:** Adds encrypted collective ballots via
  `SealedTallyConfig`, `SealedTallyKey` (`NewSealedTallyKey`, `PublicKey`,
  `TallyAccord`), `EncryptSealedBallot`, `EncryptSealedBallotWithVetoes`,
  `EncryptSealedBallotWithOpenings`, and `SealedTallyProof`. Individual ballot
  choices remain hidden Paillier ciphertexts during voting and after resolution
  (no plaintext `Votes`, `WinningOptionDissents`, or voter lists in tallies),
  enforced with 8-round parallel CDS94 `{0,1}` OR-proofs (`he.ProveBit` /
  `he.VerifyBit`, `< 2^-128` soundness against small-factor moduli `> 65537`),
  `ExclusiveProof`, optional `SingleChoiceProof`, veto `DissentRandomness`
  openings against vote-plus-veto equivocation, and GMR-backed `he.VerifyEqual`
  aggregate proofs (`he.DecryptAndProve`). Trust boundary: hides individual
  ballots from public observers via additive Paillier, while the
  `TallyAuthority` key holder retains decryption capability (not general FHE or
  threshold DKG).

### Conditional DAG policy gates (`nex`)

- **`AccordGate` and `TaskGateDependency`:** Adds native policy-gate nodes in
  `PlanRevision.Gates` (`(*GoalStore).Gate`) and explicit terminal outcome
  dependencies in `TaskSpec.GateDependencies` (`decided`, `deadlocked`,
  `expired`, optional `AllowedOptions`, `ExpectedCommitment`, and
  `ExpectedDeadlockReason`). Preserves backward-compatible `TaskSpec.ID()`,
  `SignedPlanRevision.Head()`, and gate-free `goalRecord` JSON via
  `omitempty`.
- **`GateResolution` and enforcement:** Adds `(*CoordinationStore).RecordAccord`
  and `(*CoordinationStore).GateStatus` backed by offline `VerifyAccordBundle`
  verification and domain-separated `gateRecordKey` authenticated checkpoints
  (with idempotent retries and `ErrOperationConflict` on conflicting terminal
  heads). Extends `TaskDiscovery` with `GatesReady` and `GatesMismatch` in
  `DiscoverGoal` and enforces gate satisfaction on `CoordinationStore.Claim`.

### Encrypted SQL checkpoint stores & durable Accord outbox (`nex`, `adapter`)

- **Stateless SQL checkpoint stores (`nex`):** Adds `OpenSQLStore`,
  `OpenSQLProtocolStore`, `OpenSQLGoalStore`, `OpenSQLCoordinationStore`, and
  `OpenSQLAccordStore` over stdlib `database/sql` for `SQLDialectPostgres`
  (`pg_advisory_xact_lock`) and `SQLDialectSQLite` (immediate transaction lock
  via `nex_checkpoint_locks`), encrypting rows client-side with AES-256-GCM
  and `(namespace, id)`-bound AAD alongside authenticated warm-cache checks
  for stateless pod failover without local directory copies.
- **Outbox `AccordAuthority` (`adapter`):** Adds `KindAccord`,
  `EncodeAccord`, and `AccordAuthority` (`Apply`, `View`) for `adapter.Outbox`
  submission, lost-response reconciliation, and signed response verification
  against `nex.AccordStore`.

### Integrated demo, fuzzing, adversarial tests, and CI

- **New runnable example:** Added `examples/policy-graph`
  (`go run ./examples/policy-graph`) exercising shared SQL checkpoint failover,
  ProtocolV2 `TaskHandoff` attestations, `adapter.Outbox` + `AccordAuthority`,
  `BallotPrivacySealedPaillier`, and `AccordGate` conditional branch unlocking.
- **Security & CI:** Added `nex/v210_adversarial_test.go`, 7 native Go fuzz
  targets (`nex`, `internal/nexum`, `adapter`), and `.github/workflows/ci.yml`
  verifying formatting, `go vet`, `-race` tests, fuzz smoke, demos, docs site
  build, and `SOURCE_MANIFEST.json`.

## v2.0.2

### Evidence-gated collective decisions (`nex.Accord`)

- **`nex.Accord` and `nex.AccordStore`:** Adds an evidence-gated collective
  decision kernel (`Accord`, `AccordSpec`, `AccordStore`, `AccordBundle`,
  `VerifyAccordBundle`, and downstream authorizers
  `AuthorizeProtocolFromAccord`, `CreateProtocolFromAccord`,
  `AuthorizeTaskFromAccord`, and `AuthorizeDispositionFromAccord`). Supports
  authenticated multi-role deliberation over competing options, deterministic
  in-kernel replay of upstream `TaskHandoff` and `ProtocolBundle` proofs into
  `VerifiedEvidenceFact` records (with `ArtifactRefs` strictly filtered against
  returned artifacts), weighted/threshold/margin/mandatory-role voting, bounded
  evidence-cited vetoes, preserved signed dissent, deterministic tie-free
  resolution, and AES-256-GCM durable checkpointing with exact signed retries.
- **New runnable example:** Added `examples/accord` (`go run ./examples/accord`)
  demonstrating evidence-gated release governance over real upstream
  coordination handoffs, plus unit and adversarial suites (`nex/accord_test.go`,
  `nex/accord_adversarial_test.go`, `examples/accord/main_test.go`).

### Cryptography, Merkle, L2, PoW, and Keccak hardening

- **Paillier modulus & equality proof soundness (`internal/he`, `internal/settle`):**
  `NewPaillier` enforces `gcd(N, lambda) == 1`. `FromPublic` rejects empty or
  leading-zero moduli, enforces `128..1024` bytes (`BitLen >= 1024`), oddness,
  trial division through `65537`, compositeness, and non-square checks.
  `ProveEqual` and `VerifyEqual` embed and verify a Gennaro-Micciancio-Rabin
  coprimality NIZK (`k = 8` deterministic `Z_N^*` roots over domain-separated
  canonical `N`) closing prime-power modulus equivocation end-to-end across
  `he`, `settle`, `nexum`, and `l2`.
- **Transcript framing & canonical encoding (`internal/he`, `internal/settle`):**
  `zkChallenge` is domain-separated and length-framed with canonical `N.Bytes()`,
  `ct`, `m`, and `commit`; leading-zero non-canonical encodings on ciphertexts,
  aggregates, and proof fields are rejected; `zkProof` JSON decoding uses
  `DisallowUnknownFields` and rejects trailing bytes. `he.RestorePrivate`
  enforces full modulus checks, Carmichael `lambda` validity, and encrypt/decrypt
  self-verification.
- **Merkle root & aggregation (`internal/settle`):** `settle.Root` now applies
  domain separation across empty, 32-byte hex leaf, length-framed raw leaf,
  internal node, and leaf-count-committed final digests (closing odd-leaf
  duplication, leaf/internal, hex-split, and empty-slice collisions).
  `EncryptedLedger.Aggregate` validates ciphertext group membership and returns
  a defensive copy on single-lock inputs.
- **L2, PoW, and Keccak (`internal/l2`, `internal/pow`, `quarry/keccak`):**
  `l2.Root`, `l2.Seal`, `l2.Verify`, and `l2.VerifyBatch` reject empty batches
  and non-positive difficulty floors (`bits < 1` / `minBits < 1` / `DiffBits < 1`).
  `pow.Header.Hash` encodes full 64-bit `DiffBits`. Vendored `quarry/keccak`
  `UnmarshalBinary` rejects `n >= d.rate` in `spongeAbsorbing` state and
  validates into a local buffer before mutating receiver state.

### Agreement kernel and encrypted message hardening

- **Sealed settlement & custody (`internal/nexum`):** `PublicSealedProof` and
  `VerifySealedSettlement` require `StatusAccepted`, valid receipt chains, and
  binding of `SealedEqualityProof` to the `"accept"` receipt commitment.
  `WithUnitAt` enforces private custody; Format-1 `StartSealed` snapshots detect
  `Scheme`/`PublicKey` so decoded snapshots cannot downgrade to plaintext `Lock`
  or overwrite `PublicKey`.
- **Receipt replay, keys, and metering (`internal/nexum`):**
  `Agreement.VerifyReceipts` validates binding terms (`ID`, `Kind`, distinct
  non-empty parties, `Amount > 0`, valid `Format`/`Mode`), mode-consistent
  lock/seal transitions (forbidding mixed `lock`+`seal`), and future deadlines;
  `OpenAgreement`, `OpenAgreementV2`, and `OpenEscrow` reject empty `id`.
  `SignReceipts` across `Agreement`, `Council`, `Delegate`, and `Workflow`
  verifies Ed25519 seed/public-key consistency and deep-clones caller key maps
  and slices. IEEE-754 `NaN`/`Inf` meter values are rejected everywhere;
  `OpenCouncil`, `OpenDelegate`, and `OpenWorkflow` enforce `MaxSteps <= 128`;
  Format-0 `Workflow` deduplicates `Node.Next` edges during replay.
- **Encrypted messages (`internal/message`):** `VerifyConversationOrder` enforces
  consistent `ConversationID`, non-dangling `ReplyTo`, `ReplyChain`-to-`ReplyTo`
  binding, and duplicate/cycle rejection. `ValidateTradeSuccessor` verifies
  parent/child signatures, `"agree"` decision, and `ReplyChain`. `Decide`
  validates `Offer.Verify()` before signing and returns a zero `Decision` on
  error. `Record.State(now)` reports `"expired"` at or after `ReleaseBy`.

### Protocol, coordination, and contract hardening

- **Protocol canonicalization & validation (`nex`):** `NewProtocol` and
  `Protocol.Apply` enforce valid UTF-8 on all v1/v2 spec and command strings
  before and after `cloneProtocol` so invalid UTF-8 cannot expand or coalesce
  and brick `ProtocolStore`. `Protocol.Apply` verifies signatures and
  `ProtocolID` (`ErrProtocolStale`) before `(Actor, RequestID)` conflict lookup.
  `validateReturn` compares `Resources` order-insensitively with `nil` equal to
  `[]ResourceUse{}`.
- **Coordination discovery & bilateral contracts (`nex`):**
  `CoordinationStore.DiscoverGoal` no longer swallows `ErrCorruptStore` or runs
  redundant Pass-2 `s.Result` lookups/locks on Pass-1 unclaimed tasks, preserving
  internally consistent snapshots. `nex.New` validates UTF-8/non-NUL `kind`,
  rejects shared Ed25519 signing keys (`ErrSameParty`), normalizes `now` and
  `deadline` to `.UTC()`, and validates RFC3339 year bounds `[0, 9999]` before
  hashing. `Contract.rebuildConsent` verifies `r.Actor == Seller`.

### Durable adapter, fencing, outbox, and effect safety

- **SQL & durable fence coordinators (`adapter`):** `SQLCoordinator.Authorize`
  on SQLite now acquires the immediate write lock via `AuthorizeTx` across `fn()`,
  closing multi-handle/multi-process split-brain races. `SQLCoordinator` seals a
  genesis token at `generation == 0` and unconditionally verifies AES-256-GCM
  tags on all read, write, and authorize paths, plus adds nil-receiver checks on
  `StopAndFenceContext`/`ConfirmFenceProofContext`. `DurableCoordinator` releases
  `coordinator.lock` before invoking `EpochSealer.SealFenceEpoch`.
  `HandoffCoordinatorDir` enforces exported `HandoffReady` (fence proof and
  non-empty checkpoint head) even across wrapped coordinators. `CopyPrivateDir`
  resolves symlinks (`os.SameFile` / subpath checks) and rejects non-empty
  destinations before modifying files.
- **Outbox, vault, and effect isolation (`adapter`):** `EffectAdapter` isolates
  records to `*.effect` with distinct AAD so shared vault directories never brick
  or overwrite `Outbox` `*.box` records. `validateID` rejects NUL bytes and
  length-frames `recordID` and `EffectRef.slot()`. `Outbox.SealAdmission`
  validates generation under lock before latching stopped state and syncs across
  handles on `ResumeAdmission`. `Outbox.Reconcile` rejects invalid/error
  candidates and clears stale candidates on `StatusUnknown`; `validateItem` and
  authorities enforce `payload.Kind == item.Kind`; duplicate `Enqueue` rejects
  metadata conflicts; `ReconcileDue` checks `NextTry` atomically under lock;
  `sameTerminal` includes `Phase`, `WorkOutcome`, and `Definitive`.
  `EffectAdapter` preserves `EffectPhaseUnknown` / `Reconcile = true` when a
  retry returns `OutcomeNotDispatched` after a prior uncertain attempt.
- **Regression suites:** Added 14 `-race` `*_v202_regression_test.go` suites
  covering all 44 verified fixes across all 9 affected packages.

## v2.0.1

### Concurrency & multi-planner scale fixes

- **`adapter.SQLCoordinator.AuthorizeTx` (SQLite WAL):** Upgrades the caller's
  SQLite transaction to an immediate write lock on `nex_fence_leases` before
  reading lease state (`UPDATE nex_fence_leases SET version = version WHERE
  scope = ?`), matching PostgreSQL `FOR SHARE` / `FOR UPDATE` linearizability
  against concurrent `StopAndFence` across multi-connection and multi-process
  SQLite WAL callers without mid-transaction `SQLITE_BUSY` lock-upgrade races.
- **`nex.GoalSpec` multi-planner scale:** Lifted the hardcoded 16-planner cap
  in `GoalSpec.validate()` to `maxPlanPlanners = 256`, enabling large
  multi-planner shared DAG goals while keeping serialized key payloads bounded.
- Added `-race` regression tests `TestSQLCoordinatorSQLiteMultiConnLinearizability`
  and `TestGoalSpecMultiPlannerScale`.

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
