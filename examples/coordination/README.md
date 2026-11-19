# Coordinate work under a shared goal

Run `go run ./examples/coordination` from the repository root.

The example creates a signed release-planning goal. Three independent
agreements produce a retry configuration, find a common release window, and
check rollback readiness. The same task and evidence interfaces carry all
three kinds of work. Each attempt has its own receipt head.

The first configuration worker finishes an agreement but loses its lease
before finalization. A replacement signs a fresh attempt and the original
worker's late finalization is rejected. When the safety witness is unavailable,
the coordinator explicitly closes that agreement as incomplete. A deployment
task that requires accepted safety evidence cannot start.

A separate synthesis task pins the two accepted outputs and the incomplete
safety observation by attempt, return head, output slot, and digest. Its own
reviewed recommendation is to hold the release. The application checks artifact
bytes before use and supplies its own review logic.

The upstream attempts are exported as JSON handoffs. The receiving code uses
`VerifyTaskHandoff` with separately obtained task and result pins to check
the authority's signed claim, the complete signed attempt, and the derived
outcome before consuming each artifact. Verification requires no source store
or private key.

The demo uses temporary encrypted stores, separate signing keys for the
simulated agents, and a deterministic host clock. It runs locally and performs
no deployment.

## Integration contract

Pin a `GoalSpec` ID through your admission policy. Authorized planners sign
append-only revisions that add immutable `TaskSpec` records. Add a downstream
task once you know the exact handoffs it should consume. Each dependency
selects an explicit outcome, including when it consumes an incomplete return.

The task authority signs a `ClaimRequest` for the exact Protocol v2 spec,
worker, and next generation. Use the receiver's monotone height when applying
protocol commands, claiming, and finalizing. A v2 agreement binds the evidence
manifest before review. A successful return must match the reviewed output
slots and digests. Verify bytes with `ArtifactRef.Verify` before consuming
them. The host controls artifact storage and access, and witnesses decide what
the evidence actually supports.

Finalization checks the authoritative attempt and stores a handoff. Any
external destination must enforce generation and its resource precondition
atomically with the external mutation. Claiming a lease alone grants no
access to that destination. An incomplete return preserves missing obligations
and partial artifacts without authorizing success.

The stores coordinate on one host. Attempts have independent heads and routine
task progress does not write to the goal plan. A warm task lookup uses an
immutable index. The goal plan and each task history still use bounded local
checkpoints. The application decides which tasks to offer or schedule.

`ExportHandoff` requires the original claim and signature retained by the
sender. Obtain the expected task ID from an authorized plan and the expected
result hash from the coordinator over an authenticated channel. A hash copied
from an untrusted handoff establishes no independent trust. The coordinator's
result pin identifies its finalized generation. Offline verification checks
the signed work, while clock correctness, external effects, and upstream
dependency validity retain their existing trust boundaries.
