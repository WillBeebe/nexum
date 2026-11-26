# Sealed-Ballot Conditional Policy Graph (v2.1.0)

Run `go run ./examples/policy-graph` from the repository root (or verify with
`go test -race ./examples/policy-graph`).

This example showcases all five Nexum v2.1.0 pillars working together in a
single zero-external-dependency scenario:

1. **Shared encrypted SQL checkpoint stores** (`OpenSQLGoalStore`,
   `OpenSQLProtocolStore`, `OpenSQLCoordinationStore`, `OpenSQLAccordStore`):
   A self-contained stdlib `database/sql/driver` simulates a shared PostgreSQL
   instance with `pg_advisory_xact_lock` and atomic transactions across four
   isolated AES-256-GCM namespaces (`policy-graph-goals`,
   `policy-graph-protocols`, `policy-graph-coordination`,
   `policy-graph-accords`).
2. **Upstream ProtocolV2 tasks and portable `TaskHandoff` proofs**:
   Pod A runs three upstream ProtocolV2 tasks (`patch` accepted, `window`
   accepted, `safety` honestly closed as `incomplete` when the required witness
   is unavailable at `ReturnByHeight`) and exports wire-portable `TaskHandoff`
   proofs.
3. **Sealed-ballot Paillier Accord + `AccordGate` conditional DAG**:
   Pod A creates a `BallotPrivacySealedPaillier` single-choice Accord with a
   mandatory `safety` role and three competing options (`full-rollout`,
   `canary-rollout`, `hold-and-remediate`), then appends a signed `PlanRevision`
   declaring `AccordGate` (`release-gate`) gating three mutually exclusive
   downstream tasks (`full-rollout-task`, `canary-rollout-task`,
   `hold-remediation-task`) pinned by both option ID and binding commitment.
4. **Encrypted CDS94 `{0,1}` ballots via `adapter.Outbox` + `adapter.AccordAuthority` (`KindAccord`)**:
   Attestations, the independent safety witness's bounded evidence-cited veto
   on `full-rollout`, and all four voters' Paillier-encrypted sealed ballots are
   enqueued and reconciled through `adapter.Outbox` + `adapter.AccordAuthority`.
   `safety`'s sealed ballot simulates a dropped transport response
   (`DropNext: true`) recovered cleanly via exact signed retry
   (`Outbox.Reconcile` + `RecordVerified`), while all individual ballots remain
   opaque ciphertexts with zero plaintext votes exposed.
5. **Stateless Pod B failover, GMR homomorphic tally, offline verification, and exclusive branch unlocking**:
   Pod A closes its database pool and Pod B opens fresh `OpenSQL*Store` handles
   against the same shared SQL database with zero directory copy. Pod B computes
   the aggregate `SealedTallyProof` via `SealedTallyKey.TallyAccord` (GMR-backed
   Paillier equality proofs without decrypting any individual ballot), resolves
   the Accord, verifies the wire-exported `AccordBundle` offline with zero
   private keys (`nex.VerifyAccordBundle`), records the resolution on
   `release-gate` (`CoordinationStore.RecordAccord`), and runs `DiscoverGoal`:
   - Only `canary-rollout-task` unlocks (`DependenciesReady: true`,
     `GatesReady: true`).
   - `full-rollout-task` and `hold-remediation-task` remain blocked with
     `GatesMismatch: true`, and `Claim` refuses both with `ErrTaskDependency`.
   - Pod B claims, commits (`working`), completes, and finalizes
     `canary-rollout-task` (`accepted`).

## Trust boundaries

- The demo uses an in-process SQL driver, ephemeral Ed25519 and 2048-bit
  Paillier keys, and a temporary outbox directory discarded on exit. Production
  deployments must connect `OpenSQL*Store` to a durable PostgreSQL or SQLite
  database, protect the 32-byte AES-GCM checkpoint key and `SealedTallyKey` in
  platform key management, and supply an authoritative monotone host height.
