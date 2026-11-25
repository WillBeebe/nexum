# Evidence-gated release governance Accord

Run `go run ./examples/accord` from the repository root (or verify with
`go test -race ./examples/accord`).

This example upgrades `examples/coordination` from post-hoc imperative Go glue
to a kernel-enforced collective decision using `nex.Accord` and `nex.AccordStore`.

## Why prior Nexum constructs were not enough

Before `nex.Accord`, expressing a multi-agent release decision gated by upstream
verification required gluing together four disconnected layers in application code:

- `internal/nexum.Council` only supported unauthenticated party strings, 3-7
  parties, 100% unanimity, and one static decision string fixed at genesis.
- `internal/nexum.Workflow` only allowed single-actor branching over unverified
  self-asserted `map[string]bool` host facts (`FactsCommitted`).
- `nex.Protocol` (v1/v2) executed a single linear plan with binary witness
  `DissentPolicy` (`record` vs `block`), without enforceable successor authority.
- `nex.GoalSpec` / `nex.CoordinationStore` pinned upstream results after the fact,
  leaving `examples/coordination` to synthesize `"Hold ... release"` inside
  imperative Go rather than verifiable decision rules.

`nex.Accord` replaces that glue with one deterministic, locally verifiable
deliberation kernel over cryptographically replayed upstream evidence.

## Scenario walkthrough

1. **Upstream coordination (`GoalStore`, `ProtocolStore`, `CoordinationStore`)**:
   Three independent Protocol v2 tasks execute concurrently under a signed
   `GoalSpec` and export portable JSON `TaskHandoff` proofs:
   - `patch` (`config` artifact): independently reviewed and `accepted`.
   - `window` (`window` artifact): independently reviewed and `accepted`.
   - `safety` (`observation` artifact): required witness is unavailable at
     `ReturnByHeight`, so the coordinator closes the attempt honestly as
     `incomplete` while preserving the partial observation artifact.
2. **Multi-role `AccordSpec` with verified handoff predicates**:
   Five authenticated `nex.Public` participants deliberate over three competing
   options bound to concrete downstream commitments:
   - `planner` (`coordinator` grant): independent attester and deterministic
     resolver (`RequireIndependentResolver: true`; cannot vote, veto, or propose).
   - `release` (role `release`, weight 2), `sre` (role `sre`, weight 2),
     `safety` (role `safety`, weight 3, bounded `veto`), and `security`
     (role `security`, weight 2, bounded `veto`).
   - Competing options:
     - `full-rollout` (`BindingProtocolSpec` -> full rollout v2 `ProtocolSpec`):
       requires `accepted` `patch` and `window` artifacts, `accepted` `safety`,
       `GuardNoWitnessDissent` on `safety`, and mandatory `security` approval.
     - `canary-rollout` (`BindingProtocolSpec` -> 5% canary v2 `ProtocolSpec`):
       requires `accepted` `patch` and `window` artifacts, verified `observation`
       slot on `safety` (`accepted` or `incomplete`), and mandatory `sre` approval
       (plus global mandatory `safety` approval).
     - `hold-and-remediate` (`BindingDisposition` -> `"hold"`): eligible whenever
       `safety` is `incomplete`, `rejected`, or has witness dissent.
3. **Automatic evidence disqualification, bounded veto, and preserved dissent**:
   - The kernel replays all three wire-decoded `TaskHandoff` proofs inside
     `Accord.Apply` (`attest`), deriving `VerifiedEvidenceFact` records with
     `Assurance: "verified"`.
   - `full-rollout` fails its guard automatically on the incomplete `safety`
     handoff (`outcome_mismatch` and `protocol_not_complete` — `GuardNoWitnessDissent`
     fails closed on incomplete/unwitnessed handoffs even though
     `HasWitnessDissent` is `false`).
   - `release` approves `full-rollout` and records an explicit signed `dissent`
     (with `RationaleHash`) on `canary-rollout`.
   - `safety` dissents and casts a bounded, evidence-cited blocking `veto` on
     `full-rollout` citing `["safety"]`. A second veto attempt by `safety` is
     rejected with `ErrAccordAuthority` (`MaxVetoesPerActor: 1`).
   - `safety`, `sre`, and `security` approve `canary-rollout` (3 approvers,
     weight 7 vs dissent weight 2, margin 5 >= 3, mandatory `safety` and `sre`
     roles satisfied).
4. **Durable encrypted store, reopen, and exact retry**:
   - `AccordStore` checkpoints every transition with AES-256-GCM and OS `flock`.
   - After `release`'s dissent vote (and again after terminal resolution), the
     store is reopened with the same key and the exact signed command is retried
     without re-calling `Prepare`, returning the identical original `ReceiptHash`.
5. **Offline verification and enforceable downstream binding**:
   - The exported `AccordBundle` is JSON-encoded across a wire boundary and
     replayed offline via `nex.VerifyAccordBundle` with zero private keys and
     zero source stores.
   - Raw upstream artifact bytes are verified offline against the kernel-derived
     `VerifiedEvidenceFact.ArtifactRefs`.
   - `nex.AuthorizeProtocolFromAccord` rejects the disqualified `full-rollout`
     spec (`ErrAccordBinding`), while `nex.CreateProtocolFromAccord` creates the
     exact winning `canary-rollout` v2 protocol in a downstream `ProtocolStore`
     matching `WinningCommitment`, which its participants then admit and commit
     (transitioning it to the `working` phase).

## Sample output

```json
{
  "example": "accord",
  "upstream_outcomes": {
    "patch": "accepted",
    "safety": "incomplete",
    "window": "accepted"
  },
  "accord_phase": "decided",
  "winning_option": "canary-rollout",
  "winning_binding_kind": "protocol_spec",
  "participating_count": 4,
  "participating_weight": 9,
  "options": [
    {
      "option_id": "canary-rollout",
      "guard_passed": true,
      "satisfied_evidence": [
        "patch",
        "safety",
        "window"
      ],
      "approve_count": 3,
      "approve_weight": 7,
      "dissent_count": 1,
      "dissent_weight": 2,
      "veto_effective": false,
      "eligible": true
    },
    {
      "option_id": "full-rollout",
      "guard_passed": false,
      "satisfied_evidence": [
        "patch",
        "window"
      ],
      "failed_predicates": [
        "safety:outcome_in:outcome_mismatch",
        "safety:no_witness_dissent:protocol_not_complete"
      ],
      "approve_count": 1,
      "approve_weight": 2,
      "dissent_count": 1,
      "dissent_weight": 3,
      "veto_effective": true,
      "eligible": false,
      "disqualification_reasons": [
        "guard_failed",
        "vetoed",
        "below_approval_count",
        "below_approval_weight",
        "below_approval_margin",
        "missing_mandatory_role"
      ]
    },
    {
      "option_id": "hold-and-remediate",
      "guard_passed": true,
      "satisfied_evidence": [
        "safety"
      ],
      "approve_count": 0,
      "approve_weight": 0,
      "dissent_count": 0,
      "dissent_weight": 0,
      "veto_effective": false,
      "eligible": false,
      "disqualification_reasons": [
        "below_approval_count",
        "below_approval_weight",
        "below_approval_margin",
        "missing_mandatory_role"
      ]
    }
  ],
  "winning_dissents_preserved": 1,
  "winning_dissent_rationale_hash": "afc5827e642b640d151ae93b43753052802932b8567f089a825dca1356f28afe",
  "bounded_veto_cap_enforced": true,
  "reopen_retry_idempotent": true,
  "terminal_retry_idempotent": true,
  "offline_bundle_verified": true,
  "offline_artifacts_verified": 3,
  "disqualified_binding_rejected": true,
  "authorized_downstream_phase": "working",
  "downstream_matches_commitment": true
}
```

## Verification and trust boundaries

- The demo uses temporary directories, in-process Ed25519 keys, and a random
  32-byte storage key discarded on exit; production applications must keep
  storage keys in a protected platform key store and retain signed commands in a
  durable outbox before submission.
- `VerifyAccordBundle` proves signature validity, pinned upstream evidence
  replay, deterministic guard and tally evaluation, preserved dissent, and
  downstream commitment authorization offline. Host clock monotonicity, external
  deployment side effects, and authenticating the expected `(accordID, head)`
  pins remain explicit application trust boundaries.
