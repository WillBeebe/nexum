package nex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func gateTestStores(t *testing.T) (string, []byte, *GoalStore, *ProtocolStore, *CoordinationStore, *AccordStore) {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{91}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := OpenCoordinationStore(filepath.Join(dir, "tasks"), key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	accords, err := OpenAccordStore(filepath.Join(dir, "accords"), key)
	if err != nil {
		t.Fatal(err)
	}
	return dir, key, goals, attempts, tasks, accords
}

func makeBranchTask(goalID, nonce string, pf protocolFixture, owner Public, deps []TaskDependency, gateDeps ...TaskGateDependency) TaskSpec {
	return TaskSpec{
		GoalID:            goalID,
		Nonce:             nonce,
		Purpose:           pf.spec.Purpose,
		Scope:             pf.spec.Scope,
		SpecificationHash: pf.spec.SpecificationHash,
		AcceptanceHash:    pf.spec.AcceptanceHash,
		FailurePolicyHash: pf.spec.FailurePolicyHash,
		Authority:         owner,
		Outputs:           append([]string(nil), pf.spec.Return.SuccessArtifacts...),
		FailureOutputs:    append([]string(nil), pf.spec.Return.FailureArtifacts...),
		Dependencies:      deps,
		GateDependencies:  gateDeps,
	}
}

func makeClaimForTask(t *testing.T, pf protocolFixture, goalID string, task TaskSpec, nonce string, gen, leaseUntil uint64) (ProtocolSpec, ClaimRequest, []byte) {
	t.Helper()
	spec := pf.spec
	spec.Version = ProtocolVersionV2
	spec.TaskID = task.ID()
	spec.Generation = gen
	spec.Nonce = nonce
	spec.WorkByHeight = 20
	spec.ReturnByHeight = 40
	spec.Roles = append([]RoleGrant(nil), pf.spec.Roles...)
	for i := range spec.Roles {
		spec.Roles[i].ExpiresAtHeight = 40
	}
	p, err := NewProtocol(spec)
	if err != nil {
		t.Fatalf("NewProtocol(%s): %v", nonce, err)
	}
	req := ClaimRequest{
		GoalID:             goalID,
		TaskID:             task.ID(),
		WorkerID:           protocolPublic(pf.worker).ID(),
		RequestID:          nonce,
		ProtocolID:         p.View().ID,
		ExpectedGeneration: gen - 1,
		LeaseUntilHeight:   leaseUntil,
	}
	return spec, req, Sign(pf.owner, ClaimSignatureDomain, req)
}

func completeTaskAttempt(t *testing.T, pf protocolFixture, attempts *ProtocolStore, tasks *CoordinationStore, lease TaskLease, spec ProtocolSpec, artifactContent string, height uint64) (TaskResult, string, string) {
	t.Helper()
	pRun, err := NewProtocol(spec)
	if err != nil {
		t.Fatal(err)
	}
	ansRef := testArtifactRef(artifactContent)
	step := func(who Identity, grant, scope, action, reqID string, fill func(*ProtocolCommand)) {
		cmd := pRun.Prepare(protocolPublic(who).ID(), grant, scope, action, reqID, height)
		if fill != nil {
			fill(&cmd)
		}
		sig := Sign(who, "protocol", cmd)
		if _, err := pRun.Apply(cmd, sig, height); err != nil {
			t.Fatalf("in-mem %s: %v", action, err)
		}
		if _, err := attempts.Apply(pRun.View().ID, cmd, sig, height); err != nil {
			t.Fatalf("store %s: %v", action, err)
		}
	}
	step(pf.owner, "", "", "admit", "admit-owner", nil)
	step(pf.worker, "", "", "admit", "admit-worker", nil)
	step(pf.witness, "", "", "admit", "admit-witness", nil)
	step(pf.owner, "owner", spec.Scope, "commit", "commit-owner", nil)
	step(pf.worker, "worker", spec.Scope, "report", "report-worker", func(c *ProtocolCommand) {
		c.Report = &WorkReport{
			Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{ansRef.Digest},
			Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: "answer", Ref: ansRef}}},
		}
	})
	step(pf.witness, "witness", spec.Scope, "review", "review-witness", func(c *ProtocolCommand) {
		c.Review = &WitnessReview{ReportHash: Hash(pRun.View().Report), AssessmentHash: Hash("ok")}
	})
	step(pf.owner, "owner", spec.Scope, "resolve", "resolve-owner", func(c *ProtocolCommand) {
		c.Resolution = &Resolution{ReportHash: Hash(pRun.View().Report), Outcome: "accept", ReasonHash: Hash("ok")}
	})
	step(pf.worker, "worker", spec.Scope, "return", "return-worker", func(c *ProtocolCommand) {
		v := pRun.View()
		c.Return = &ReturnManifest{
			ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews), Evidence: v.Report.Evidence,
			Resources: v.Report.Resources, Uncertainty: "bounded", SafeAssumptions: []string{"verified"},
			Artifacts: []ReturnArtifact{{ID: "answer", Commitment: ansRef.Digest, ReuseRestrictions: "none"}}, Disposition: "continue",
		}
	})
	v := pRun.View()
	res, err := tasks.Finalize(lease, v.Head, height)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return res, v.Head, ansRef.Digest
}

func driveAccordInStore(t *testing.T, accords *AccordStore, fx accordFixture, winningOption string, sealed *SealedTallyKey, tallyActor accordActor) (string, AccordBundle) {
	t.Helper()
	aid, err := accords.Create(fx.spec)
	if err != nil {
		t.Fatalf("accords.Create: %v", err)
	}
	apply := func(actor accordActor, grant, action, reqID string, height uint64, fill func(*AccordCommand)) string {
		cmd, err := accords.Prepare(aid, actor.pub.ID(), grant, fx.spec.Scope, action, reqID, height)
		if err != nil {
			t.Fatalf("Prepare(%s): %v", reqID, err)
		}
		if fill != nil {
			fill(&cmd)
		}
		sig, err := SignAccordCommand(actor.id, cmd)
		if err != nil {
			t.Fatalf("SignAccordCommand(%s): %v", reqID, err)
		}
		h, err := accords.Apply(aid, cmd, sig, height)
		if err != nil {
			t.Fatalf("accords.Apply(%s): %v", reqID, err)
		}
		return h
	}
	if sealed != nil {
		cast := func(actor accordActor, grant string, height uint64, reqID string, choices map[string]BallotPosition) {
			b, err := accords.Export(aid)
			if err != nil {
				t.Fatal(err)
			}
			sb, err := EncryptSealedBallot(b.Spec, aid, actor.pub.ID(), choices, Hash(reqID))
			if err != nil {
				t.Fatal(err)
			}
			apply(actor, grant, "vote", reqID, height, func(c *AccordCommand) {
				c.Vote = &VotePayload{Sealed: sb}
			})
		}
		cast(fx.safety, "safety-vote", 2, "v-safety", map[string]BallotPosition{winningOption: BallotApprove})
		cast(fx.sre, "sre-vote", 3, "v-sre", map[string]BallotPosition{winningOption: BallotApprove})
		cast(fx.security, "security-vote", 4, "v-sec", map[string]BallotPosition{winningOption: BallotApprove})
		b, err := accords.Export(aid)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := sealed.TallyAccord(b)
		if err != nil {
			t.Fatal(err)
		}
		head := apply(tallyActor, "tally-resolve", "resolve", "resolve-1", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("sealed"), SealedTally: proof}
		})
		bundle, err := accords.Export(aid)
		if err != nil {
			t.Fatal(err)
		}
		return head, bundle
	}
	apply(fx.safety, "safety-vote", "vote", "v-safety", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: winningOption, Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	apply(fx.sre, "sre-vote", "vote", "v-sre", 3, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: winningOption, Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	apply(fx.security, "security-vote", "vote", "v-sec", 4, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: winningOption, Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	head := apply(fx.release, "release-vote", "resolve", "resolve-1", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("decided")}
	})
	bundle, err := accords.Export(aid)
	if err != nil {
		t.Fatal(err)
	}
	return head, bundle
}

func TestAccordGatePlanValidationAndLookup(t *testing.T) {
	_, _, goals, _, _, _ := gateTestStores(t)
	pf := newProtocolFixture(t)
	owner := protocolPublic(pf.owner)
	goalID, err := goals.Create(GoalSpec{
		Nonce: "gate-val", Purpose: "Validate gate specs and task dependencies",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	accordID := Hash("accord-spec-1")
	validGate := AccordGate{
		ID:             "release-gate",
		GoalID:         goalID,
		AccordID:       accordID,
		Purpose:        "Approve rollout strategy",
		AllowedOptions: []string{"full-rollout", "canary-rollout"},
	}

	applyRev := func(head, reqID string, gates []AccordGate, tasks ...TaskSpec) (string, error) {
		rev := PlanRevision{GoalID: goalID, Head: head, Planner: owner.ID(), RequestID: reqID, Gates: gates, Tasks: tasks}
		return goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev))
	}

	// Empty revision (neither tasks nor gates) rejected.
	if _, err := applyRev(goalID, "empty", nil); !errors.Is(err, ErrPlan) {
		t.Fatalf("empty revision got %v, want ErrPlan", err)
	}

	// Gate validation failures.
	badGates := []struct {
		name   string
		mutate func(*AccordGate)
	}{
		{"empty_id", func(g *AccordGate) { g.ID = "" }},
		{"space_id", func(g *AccordGate) { g.ID = " release-gate" }},
		{"nul_id", func(g *AccordGate) { g.ID = "gate\x00x" }},
		{"ctrl_id", func(g *AccordGate) { g.ID = "gate\nx" }},
		{"invalid_utf8_id", func(g *AccordGate) { g.ID = "gate\xff" }},
		{"wrong_goal_id", func(g *AccordGate) { g.GoalID = Hash("other-goal") }},
		{"bad_accord_id", func(g *AccordGate) { g.AccordID = "not-hex" }},
		{"uppercase_accord_id", func(g *AccordGate) { g.AccordID = strings.ToUpper(accordID) }},
		{"empty_purpose", func(g *AccordGate) { g.Purpose = "" }},
		{"ctrl_purpose", func(g *AccordGate) { g.Purpose = "ok\nline" }},
		{"invalid_utf8_purpose", func(g *AccordGate) { g.Purpose = "bad\xffpurpose" }},
		{"dup_allowed_option", func(g *AccordGate) { g.AllowedOptions = []string{"opt-a", "opt-a"} }},
		{"bad_allowed_option", func(g *AccordGate) { g.AllowedOptions = []string{"opt a"} }},
		{"utf8_ufffd_allowed_option", func(g *AccordGate) { g.AllowedOptions = []string{"opt-\xff", "opt-\xfe"} }},
		{"too_many_allowed_options", func(g *AccordGate) {
			opts := make([]string, maxAccordOptions+1)
			for i := range opts {
				opts[i] = string(rune('a'+i/26)) + string(rune('a'+i%26))
			}
			g.AllowedOptions = opts
		}},
	}
	for _, tc := range badGates {
		t.Run("bad_gate/"+tc.name, func(t *testing.T) {
			g := cloneAccordGate(validGate)
			tc.mutate(&g)
			if _, err := applyRev(goalID, "bad-"+tc.name, []AccordGate{g}); !errors.Is(err, ErrPlan) {
				t.Fatalf("got %v, want ErrPlan", err)
			}
		})
	}

	// Duplicate gate ID in same revision and > maxPlanGates rejected.
	if _, err := applyRev(goalID, "dup-same-rev", []AccordGate{validGate, validGate}); !errors.Is(err, ErrPlan) {
		t.Fatalf("duplicate gate in same revision got %v, want ErrPlan", err)
	}
	tooManyGates := make([]AccordGate, maxPlanGates+1)
	for i := range tooManyGates {
		g := validGate
		g.ID = "g-" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		tooManyGates[i] = g
	}
	if _, err := applyRev(goalID, "too-many-gates", tooManyGates); !errors.Is(err, ErrPlan) {
		t.Fatalf("too many gates got %v, want ErrPlan", err)
	}

	// Gate-only revision (0 tasks, 1 gate) succeeds, and forward gate reference in same revision also succeeds!
	sameRevGate := cloneAccordGate(validGate)
	sameRevGate.ID = "same-rev-gate"
	sameRevTask := makeBranchTask(goalID, "same-rev-task", pf, owner, nil, TaskGateDependency{
		GateID: "same-rev-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
	})
	head1, err := applyRev(goalID, "rev-gate-only", []AccordGate{validGate})
	if err != nil {
		t.Fatalf("gate-only rev failed: %v", err)
	}
	// Duplicate gate across revisions rejected.
	if _, err := applyRev(head1, "dup-prior-rev", []AccordGate{validGate}); !errors.Is(err, ErrPlan) {
		t.Fatalf("duplicate gate across revisions got %v, want ErrPlan", err)
	}
	head2, err := applyRev(head1, "rev-same-gate-and-task", []AccordGate{sameRevGate}, sameRevTask)
	if err != nil {
		t.Fatalf("same-rev gate+task failed: %v", err)
	}

	// Invalid TaskGateDependency cases.
	badDeps := []struct {
		name string
		deps []TaskGateDependency
	}{
		{"dangling_gate", []TaskGateDependency{{GateID: "missing-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout"}}},
		{"duplicate_gate_dep", []TaskGateDependency{
			{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout"},
			{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout"},
		}},
		{"wildcard_phase", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: "*"}}},
		{"open_phase", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseOpen}}},
		{"empty_phase", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: ""}}},
		{"decided_missing_option", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided}}},
		{"decided_option_not_in_allowlist", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "hold-release"}}},
		{"decided_with_deadlock_reason", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout", ExpectedDeadlockReason: DeadlockTie}}},
		{"decided_bad_commitment", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout", ExpectedCommitment: "bad-hex"}}},
		{"deadlocked_with_option", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDeadlocked, OptionID: "full-rollout"}}},
		{"deadlocked_with_commitment", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDeadlocked, ExpectedCommitment: Hash("x")}}},
		{"deadlocked_unknown_reason", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDeadlocked, ExpectedDeadlockReason: "made_up_reason"}}},
		{"expired_with_option", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseExpired, OptionID: "full-rollout"}}},
		{"expired_with_commitment", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseExpired, ExpectedCommitment: Hash("x")}}},
		{"expired_with_deadlock_reason", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseExpired, ExpectedDeadlockReason: DeadlockNoQuorum}}},
		{"invalid_utf8_gate_id", []TaskGateDependency{{GateID: "gate\xff", RequiredPhase: AccordPhaseExpired}}},
		{"nul_option_id", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "opt\x00a"}}},
		{"ctrl_commitment", []TaskGateDependency{{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout", ExpectedCommitment: "abc\ndef"}}},
	}
	for _, tc := range badDeps {
		t.Run("bad_dep/"+tc.name, func(t *testing.T) {
			tsk := makeBranchTask(goalID, "bad-dep-"+tc.name, pf, owner, nil, tc.deps...)
			if _, err := applyRev(head2, "bad-dep-"+tc.name, nil, tsk); !errors.Is(err, ErrTaskSpec) {
				t.Fatalf("got %v, want ErrTaskSpec", err)
			}
		})
	}

	// GoalStore.Gate ID validation, cache hit/miss, detached copy, and nil vs []T{} exact retry.
	if _, err := goals.Gate("not-64-hex", "release-gate"); err == nil {
		t.Fatal("expected error for invalid goalID")
	}
	if _, err := goals.Gate(goalID, " bad "); !errors.Is(err, ErrPlan) {
		t.Fatalf("invalid gateID got %v, want ErrPlan", err)
	}
	if _, err := goals.Gate(goalID, "bad\xff"); !errors.Is(err, ErrPlan) {
		t.Fatalf("invalid UTF-8 gateID got %v, want ErrPlan", err)
	}
	if _, err := goals.Gate(goalID, "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing gate got %v, want ErrNotFound", err)
	}

	gotGate, err := goals.Gate(goalID, "release-gate")
	if err != nil || gotGate.AccordID != accordID {
		t.Fatalf("Gate failed: %+v err=%v", gotGate, err)
	}
	beforeHits := goals.Stats().CacheHits
	gotGate2, err := goals.Gate(goalID, "release-gate")
	if err != nil {
		t.Fatal(err)
	}
	if goals.Stats().CacheHits <= beforeHits {
		t.Fatalf("expected GoalStore.Gate cache hit: before=%d after=%d", beforeHits, goals.Stats().CacheHits)
	}
	gotGate2.AllowedOptions[0] = "tampered-option"
	gotGate3, err := goals.Gate(goalID, "release-gate")
	if err != nil || gotGate3.AllowedOptions[0] != "full-rollout" {
		t.Fatalf("GoalStore.Gate returned non-detached slice: %+v err=%v", gotGate3, err)
	}

	// Verify TaskSpec detached GateDependencies.
	gotTask, err := goals.Task(goalID, sameRevTask.ID())
	if err != nil {
		t.Fatal(err)
	}
	gotTask.GateDependencies[0].OptionID = "tampered"
	gotTask2, err := goals.Task(goalID, sameRevTask.ID())
	if err != nil || gotTask2.GateDependencies[0].OptionID != "canary-rollout" {
		t.Fatalf("GoalStore.Task returned non-detached GateDependencies: %+v err=%v", gotTask2, err)
	}

	// Exact retry with nil vs non-nil empty Gates/GateDependencies succeeds!
	emptySliceTask := makeBranchTask(goalID, "empty-slice-task", pf, owner, nil)
	emptySliceTask.GateDependencies = []TaskGateDependency{}
	revEmpty := PlanRevision{
		GoalID: goalID, Head: head2, Planner: owner.ID(), RequestID: "empty-slice-rev",
		Gates: []AccordGate{}, Tasks: []TaskSpec{emptySliceTask},
	}
	sigEmpty := Sign(pf.owner, PlanSignatureDomain, revEmpty)
	head3, err := goals.Apply(revEmpty, sigEmpty)
	if err != nil {
		t.Fatal(err)
	}
	revNil := revEmpty
	revNil.Gates = nil
	revNil.Tasks = []TaskSpec{makeBranchTask(goalID, "empty-slice-task", pf, owner, nil)}
	if retried, err := goals.Apply(revNil, sigEmpty); err != nil || retried != head3 {
		t.Fatalf("nil vs empty omitempty slice retry failed: head=%s want=%s err=%v", retried, head3, err)
	}

	// VerifyGoalPlan validates full gated plan and rejects tampered plan.
	plan, err := goals.View(goalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGoalPlan(plan, goalID, head3); err != nil {
		t.Fatalf("VerifyGoalPlan failed: %v", err)
	}
	tamperedPlan := plan
	tamperedPlan.Revisions = slices.Clone(plan.Revisions)
	tamperedPlan.Revisions[0].Revision.Gates = nil
	if err := VerifyGoalPlan(tamperedPlan, goalID, head3); err == nil {
		t.Fatal("VerifyGoalPlan accepted plan with removed gate")
	}

	// Exceeding maxTaskGateDependencies rejected.
	tooManyDeps := make([]TaskGateDependency, maxTaskGateDependencies+1)
	for i := range tooManyDeps {
		tooManyDeps[i] = TaskGateDependency{GateID: "release-gate", RequiredPhase: AccordPhaseExpired}
	}
	overDepsTask := makeBranchTask(goalID, "over-deps", pf, owner, nil, tooManyDeps...)
	if _, err := applyRev(head3, "over-deps-rev", nil, overDepsTask); !errors.Is(err, ErrTaskSpec) {
		t.Fatalf("exceeding maxTaskGateDependencies got %v, want ErrTaskSpec", err)
	}

	// Verify TaskSpec embedded in OptionBinding enforces validTaskSpecStrings & cloneTaskSpec on GateDependencies.
	fx := newAccordFixture(t)
	badEmbeddedTask := fx.taskSpec
	badEmbeddedTask.GateDependencies = []TaskGateDependency{{
		GateID: "g1", RequiredPhase: AccordPhaseDecided, OptionID: "opt\x00bad",
	}}
	fx.spec.Options[2].Binding = OptionBinding{Kind: BindingTaskSpec, TaskSpec: &badEmbeddedTask}
	if err := fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
		t.Fatalf("NUL in embedded TaskSpec.GateDependencies accepted: %v", err)
	}
	goodEmbeddedTask := fx.taskSpec
	goodEmbeddedTask.GateDependencies = []TaskGateDependency{{
		GateID: "g1", RequiredPhase: AccordPhaseDecided, OptionID: "opt-ok",
	}}
	clonedEmbedded := cloneTaskSpec(goodEmbeddedTask)
	clonedEmbedded.GateDependencies[0].OptionID = "mutated"
	if goodEmbeddedTask.GateDependencies[0].OptionID != "opt-ok" {
		t.Fatal("cloneTaskSpec did not deep-clone GateDependencies")
	}
}

func TestAccordGateBackwardCompatibilityV202HashesAndGoalRecord(t *testing.T) {
	pf := newProtocolFixture(t)
	owner := protocolPublic(pf.owner)
	goalSpec := GoalSpec{
		Nonce: "v202-compat", Purpose: "Ensure v2.0.2 hash and checkpoint compatibility",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	}
	goalID := goalSpec.ID()

	type legacyTaskSpec struct {
		GoalID, Nonce, Purpose, Scope                        string
		SpecificationHash, AcceptanceHash, FailurePolicyHash string
		Authority                                            Public
		Outputs, FailureOutputs                              []string
		Dependencies                                         []TaskDependency
	}
	type legacyPlanRevision struct {
		GoalID, Head, Planner, RequestID string
		Tasks                            []TaskSpec
	}

	taskNil := makeBranchTask(goalID, "v202-task", pf, owner, nil)
	taskEmpty := taskNil
	taskEmpty.GateDependencies = []TaskGateDependency{}
	legacyTask := legacyTaskSpec{
		GoalID: taskNil.GoalID, Nonce: taskNil.Nonce, Purpose: taskNil.Purpose, Scope: taskNil.Scope,
		SpecificationHash: taskNil.SpecificationHash, AcceptanceHash: taskNil.AcceptanceHash,
		FailurePolicyHash: taskNil.FailurePolicyHash, Authority: taskNil.Authority,
		Outputs: taskNil.Outputs, FailureOutputs: taskNil.FailureOutputs, Dependencies: taskNil.Dependencies,
	}
	legacyTaskID := Hash(struct {
		Domain string
		Spec   legacyTaskSpec
	}{"coordination-task/v1", legacyTask})
	if taskNil.ID() != legacyTaskID || taskEmpty.ID() != legacyTaskID {
		t.Fatalf("TaskSpec.ID() drifted: nil=%s empty=%s want=%s", taskNil.ID(), taskEmpty.ID(), legacyTaskID)
	}

	rawTask, err := json.Marshal(taskNil)
	if err != nil || bytes.Contains(rawTask, []byte(`"gate_dependencies"`)) {
		t.Fatalf("gate-free TaskSpec serialized gate_dependencies: %s err=%v", rawTask, err)
	}

	revNil := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskNil}}
	revEmpty := revNil
	revEmpty.Gates = []AccordGate{}
	sig := Sign(pf.owner, PlanSignatureDomain, revNil)
	signedNil := SignedPlanRevision{Revision: revNil, Signature: sig}
	signedEmpty := SignedPlanRevision{Revision: revEmpty, Signature: sig}
	legacyRev := legacyPlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskNil}}
	legacyHead := Hash(struct {
		Revision  legacyPlanRevision
		Signature []byte
	}{legacyRev, sig})
	if signedNil.Head() != legacyHead || signedEmpty.Head() != legacyHead {
		t.Fatalf("SignedPlanRevision.Head() drifted: nil=%s empty=%s want=%s", signedNil.Head(), signedEmpty.Head(), legacyHead)
	}

	// Simulate an older v2.0.2 goalRecord checkpoint on disk lacking the Gates field (Gates unmarshals as nil).
	dir := filepath.Join(t.TempDir(), "legacy-goals")
	key := bytes.Repeat([]byte{55}, 32)
	goals, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	type legacyGoalRecord struct {
		Version  int
		Plan     GoalPlan
		Tasks    map[string]goalTaskLocation
		Requests map[string]int
	}
	legacyRec := legacyGoalRecord{
		Version: goalRecordVersion,
		Plan: GoalPlan{
			Spec:      goalSpec,
			Head:      signedNil.Head(),
			Revisions: []SignedPlanRevision{signedNil},
		},
		Tasks:    map[string]goalTaskLocation{taskNil.ID(): {Revision: 0, Task: 0}},
		Requests: map[string]int{owner.ID() + "/r1": 0},
	}
	if err := goals.store.write(goalID, legacyRec); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.View(goalID); err != nil {
		t.Fatalf("View on legacy goalRecord failed: %v", err)
	}
	if gotTask, err := reopened.Task(goalID, taskNil.ID()); err != nil || gotTask.ID() != taskNil.ID() {
		t.Fatalf("Task on legacy goalRecord failed: %v", err)
	}
	if _, err := reopened.Gate(goalID, "missing-gate"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Gate on legacy goalRecord with nil Gates got %v, want ErrNotFound", err)
	}

	// Extending a legacy v2.0.2 goalRecord with a new gate + gated task works cleanly.
	gate := AccordGate{
		ID: "post-upgrade-gate", GoalID: goalID, AccordID: Hash("accord"), Purpose: "Post-upgrade gate",
	}
	gatedTask := makeBranchTask(goalID, "gated-after-upgrade", pf, owner, nil, TaskGateDependency{
		GateID: "post-upgrade-gate", RequiredPhase: AccordPhaseDecided, OptionID: "proceed",
	})
	rev2 := PlanRevision{
		GoalID: goalID, Head: signedNil.Head(), Planner: owner.ID(), RequestID: "r2",
		Gates: []AccordGate{gate}, Tasks: []TaskSpec{gatedTask},
	}
	head2, err := reopened.Apply(rev2, Sign(pf.owner, PlanSignatureDomain, rev2))
	if err != nil {
		t.Fatalf("Apply gated rev onto legacy goalRecord: %v", err)
	}
	if gotGate, err := reopened.Gate(goalID, "post-upgrade-gate"); err != nil || gotGate.AccordID != gate.AccordID {
		t.Fatalf("Gate after upgrade failed: %+v err=%v", gotGate, err)
	}
	planAfter, err := reopened.View(goalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGoalPlan(planAfter, goalID, head2); err != nil {
		t.Fatalf("VerifyGoalPlan after upgrade failed: %v", err)
	}
}

func TestConditionalMultiBranchDAGPlaintextAndSealedAccords(t *testing.T) {
	for _, sealedMode := range []bool{false, true} {
		name := "plaintext"
		if sealedMode {
			name = "sealed_paillier"
		}
		t.Run(name, func(t *testing.T) {
			_, _, goals, attempts, tasks, accords := gateTestStores(t)
			pf := newProtocolFixture(t)
			owner := protocolPublic(pf.owner)

			var (
				fx         accordFixture
				tallyKey   *SealedTallyKey
				tallyActor accordActor
			)
			if sealedMode {
				sf := newSealedAccordFixture(t, nil)
				fx = sf.fx
				tallyKey = sf.tallyKey
				tallyActor = sf.tally
			} else {
				fx = newAccordFixture(t)
			}
			accordID := fx.spec.ID()

			goalID, err := goals.Create(GoalSpec{
				Nonce: "conditional-dag-" + name, Purpose: "Multi-branch rollout DAG",
				ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
			})
			if err != nil {
				t.Fatal(err)
			}

			// Upstream preflight task produces the artifact consumed by winning/losing branches.
			preflight := makeBranchTask(goalID, "preflight", pf, owner, nil)
			preSpec, preReq, preSig := makeClaimForTask(t, pf, goalID, preflight, "preflight-attempt", 1, 50)
			preExpectedAnswer := testArtifactRef("preflight-report").Digest

			gate := AccordGate{
				ID:             "release-gate",
				GoalID:         goalID,
				AccordID:       accordID,
				Purpose:        "Choose rollout branch",
				AllowedOptions: []string{"full-rollout", "canary-rollout", "hold-release"},
			}

			rev1 := PlanRevision{
				GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "rev-1",
				Gates: []AccordGate{gate}, Tasks: []TaskSpec{preflight},
			}
			head1, err := goals.Apply(rev1, Sign(pf.owner, PlanSignatureDomain, rev1))
			if err != nil {
				t.Fatal(err)
			}

			preLease, err := tasks.Claim(preReq, preSig, preSpec, 1)
			if err != nil {
				t.Fatalf("Claim preflight: %v", err)
			}
			preRes, preHead, _ := completeTaskAttempt(t, pf, attempts, tasks, preLease, preSpec, "preflight-report", 2)

			preDep := TaskDependency{
				Input: "preflight-answer", TaskID: preflight.ID(), ProtocolID: preReq.ProtocolID,
				Head: preHead, Slot: "answer", Digest: preExpectedAnswer, Outcome: TaskAccepted,
			}
			if preRes.Head != preHead {
				t.Fatalf("unexpected preflight head")
			}

			// Verify combined TaskDependency + TaskGateDependency matrix before RecordAccord:
			// preflight is accepted, so full/canary have taskDepsReady=true & gatesReady=false -> DependenciesReady=false, GatesMismatch=false.
			// Also add a task whose TaskDependency is still pending (never finalized) alongside a winning gate dep.
			neverDoneTask := makeBranchTask(goalID, "never-done", pf, owner, nil)
			neverDoneDep := TaskDependency{
				Input: "pending", TaskID: neverDoneTask.ID(), ProtocolID: Hash("pending-proto"),
				Head: Hash("pending-head"), Slot: "answer", Digest: Hash("pending-digest"), Outcome: TaskAccepted,
			}
			taskBlockedWinGate := makeBranchTask(goalID, "task-blocked-win-gate", pf, owner, []TaskDependency{neverDoneDep}, TaskGateDependency{
				GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
			})

			fullCommit := fx.spec.Options[0].Binding.Commitment()
			canaryCommit := fx.spec.Options[1].Binding.Commitment()
			holdCommit := fx.spec.Options[2].Binding.Commitment()

			fullTask := makeBranchTask(goalID, "full-branch", pf, owner, []TaskDependency{preDep}, TaskGateDependency{
				GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout", ExpectedCommitment: fullCommit,
			})
			canaryTask := makeBranchTask(goalID, "canary-branch", pf, owner, []TaskDependency{preDep}, TaskGateDependency{
				GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout", ExpectedCommitment: canaryCommit,
			})
			holdTask := makeBranchTask(goalID, "hold-branch", pf, owner, nil, TaskGateDependency{
				GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "hold-release", ExpectedCommitment: holdCommit,
			})
			deadlockTask := makeBranchTask(goalID, "deadlock-fallback", pf, owner, nil, TaskGateDependency{
				GateID: "release-gate", RequiredPhase: AccordPhaseDeadlocked,
			})

			rev2 := PlanRevision{
				GoalID: goalID, Head: head1, Planner: owner.ID(), RequestID: "rev-2",
				Tasks: []TaskSpec{fullTask, canaryTask, holdTask, deadlockTask, neverDoneTask, taskBlockedWinGate},
			}
			if _, err := goals.Apply(rev2, Sign(pf.owner, PlanSignatureDomain, rev2)); err != nil {
				t.Fatal(err)
			}

			// Before RecordAccord: GateStatus is ErrNotFound, DiscoverGoal shows unresolved gates (GatesMismatch=false), Claim fails with ErrTaskDependency.
			if _, err := tasks.GateStatus(goalID, "release-gate"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("GateStatus before RecordAccord got %v, want ErrNotFound", err)
			}
			discBefore, _, err := tasks.DiscoverGoal(goalID, 3)
			if err != nil || len(discBefore) != 7 {
				t.Fatalf("DiscoverGoal before RecordAccord: len=%d err=%v", len(discBefore), err)
			}
			if !discBefore[0].GatesReady || discBefore[0].GatesMismatch || !discBefore[0].DependenciesReady {
				t.Fatalf("preflight should have GatesReady=true: %+v", discBefore[0])
			}
			for _, d := range discBefore[1:5] {
				if d.GatesReady || d.GatesMismatch || d.DependenciesReady || d.DependenciesMismatch {
					t.Fatalf("unresolved gate branch %s unexpected discovery: %+v", d.Task.Nonce, d)
				}
			}

			canSpec, canReq, canSig := makeClaimForTask(t, pf, goalID, canaryTask, "canary-attempt", 1, 50)
			if _, err := tasks.Claim(canReq, canSig, canSpec, 3); !errors.Is(err, ErrTaskDependency) {
				t.Fatalf("Claim canary before RecordAccord got %v, want ErrTaskDependency", err)
			}

			// Deliberate & decide on "canary-rollout", then RecordAccord offline.
			finalHead, bundle := driveAccordInStore(t, accords, fx, "canary-rollout", tallyKey, tallyActor)
			recorded, err := tasks.RecordAccord(goalID, "release-gate", bundle, finalHead)
			if err != nil {
				t.Fatalf("RecordAccord: %v", err)
			}
			if recorded.GoalID != goalID || recorded.GateID != "release-gate" || recorded.AccordID != accordID ||
				recorded.Head != finalHead || recorded.Phase != AccordPhaseDecided ||
				recorded.WinningOptionID != "canary-rollout" || recorded.WinningCommitment != canaryCommit ||
				recorded.DeadlockReason != "" || recorded.ResolvedAtHeight != 10 || !protocolHash(recorded.OutcomeHash) {
				t.Fatalf("unexpected GateResolution: %+v", recorded)
			}

			// Idempotent retry of RecordAccord does NOT write a new checkpoint.
			writesBefore := tasks.Stats().CheckpointWrites
			retried, err := tasks.RecordAccord(goalID, "release-gate", bundle, finalHead)
			if err != nil || retried != recorded {
				t.Fatalf("RecordAccord retry: %+v err=%v", retried, err)
			}
			if tasks.Stats().CheckpointWrites != writesBefore {
				t.Fatalf("idempotent RecordAccord incremented CheckpointWrites")
			}

			statusRes, err := tasks.GateStatus(goalID, "release-gate")
			if err != nil || statusRes != recorded {
				t.Fatalf("GateStatus mismatch: %+v err=%v", statusRes, err)
			}

			// DiscoverGoal after RecordAccord: canary ready, full/hold/deadlock mismatched!
			discAfter, missesAfter, err := tasks.DiscoverGoal(goalID, 3)
			if err != nil || missesAfter == 0 || len(discAfter) != 7 {
				t.Fatalf("DiscoverGoal after RecordAccord: misses=%d len=%d err=%v", missesAfter, len(discAfter), err)
			}
			byNonce := make(map[string]TaskDiscovery, len(discAfter))
			for _, d := range discAfter {
				byNonce[d.Task.Nonce] = d
			}
			if !byNonce["canary-branch"].GatesReady || byNonce["canary-branch"].GatesMismatch ||
				!byNonce["canary-branch"].DependenciesReady || byNonce["canary-branch"].DependenciesMismatch {
				t.Fatalf("winning branch should be ready: %+v", byNonce["canary-branch"])
			}
			if !byNonce["task-blocked-win-gate"].GatesReady || byNonce["task-blocked-win-gate"].GatesMismatch ||
				byNonce["task-blocked-win-gate"].DependenciesReady || byNonce["task-blocked-win-gate"].DependenciesMismatch {
				t.Fatalf("task-blocked-win-gate should have GatesReady=true and DependenciesReady=false: %+v", byNonce["task-blocked-win-gate"])
			}
			for _, loser := range []string{"full-branch", "hold-branch", "deadlock-fallback"} {
				d := byNonce[loser]
				if d.GatesReady || !d.GatesMismatch || d.DependenciesReady || !d.DependenciesMismatch {
					t.Fatalf("losing branch %s should report GatesMismatch=true: %+v", loser, d)
				}
			}

			// Second DiscoverGoal hits gate & task caches (misses == 0).
			beforeStats := tasks.Stats()
			discCached, missesCached, err := tasks.DiscoverGoal(goalID, 3)
			afterStats := tasks.Stats()
			if err != nil || missesCached != 0 || len(discCached) != 7 {
				t.Fatalf("cached DiscoverGoal: misses=%d len=%d err=%v", missesCached, len(discCached), err)
			}
			if afterStats.CacheHits <= beforeStats.CacheHits || afterStats.ReplayValidationOps != beforeStats.ReplayValidationOps {
				t.Fatalf("expected gate+task cache hit without replay: before=%+v after=%+v", beforeStats, afterStats)
			}

			// Claim succeeds on winning branch, fails with ErrTaskDependency on all losing branches.
			canLease, err := tasks.Claim(canReq, canSig, canSpec, 3)
			if err != nil {
				t.Fatalf("Claim winning branch failed: %v", err)
			}
			if _, err := tasks.Finalize(canLease, preHead, 3); !errors.Is(err, ErrTaskStale) {
				// Confirm Finalize still requires canary's own protocol completion.
				t.Fatalf("expected ErrTaskStale before canary protocol completes, got %v", err)
			}
			fullSpec, fullReq, fullSig := makeClaimForTask(t, pf, goalID, fullTask, "full-attempt", 1, 50)
			if _, err := tasks.Claim(fullReq, fullSig, fullSpec, 3); !errors.Is(err, ErrTaskDependency) {
				t.Fatalf("Claim losing full-branch got %v, want ErrTaskDependency", err)
			}
			holdSpec, holdReq, holdSig := makeClaimForTask(t, pf, goalID, holdTask, "hold-attempt", 1, 50)
			if _, err := tasks.Claim(holdReq, holdSig, holdSpec, 3); !errors.Is(err, ErrTaskDependency) {
				t.Fatalf("Claim losing hold-branch got %v, want ErrTaskDependency", err)
			}
			dlSpec, dlReq, dlSig := makeClaimForTask(t, pf, goalID, deadlockTask, "dl-attempt", 1, 50)
			if _, err := tasks.Claim(dlReq, dlSig, dlSpec, 3); !errors.Is(err, ErrTaskDependency) {
				t.Fatalf("Claim losing deadlock-fallback got %v, want ErrTaskDependency", err)
			}
		})
	}
}

func TestAccordGateDeadlockedExpiredPinsConflictsAndTamper(t *testing.T) {
	t.Run("deadlocked_fallback_and_expected_reason", func(t *testing.T) {
		_, _, goals, _, tasks, _ := gateTestStores(t)
		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		fx := newAccordFixture(t)
		accordID := fx.spec.ID()

		goalID, err := goals.Create(GoalSpec{
			Nonce: "deadlock-dag", Purpose: "Deadlock fallback branches",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		gate := AccordGate{ID: "gate-dl", GoalID: goalID, AccordID: accordID, Purpose: "Decision gate"}
		tDecided := makeBranchTask(goalID, "decided", pf, owner, nil, TaskGateDependency{
			GateID: "gate-dl", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
		})
		tDeadlockAny := makeBranchTask(goalID, "dl-any", pf, owner, nil, TaskGateDependency{
			GateID: "gate-dl", RequiredPhase: AccordPhaseDeadlocked,
		})
		tDeadlockQuorum := makeBranchTask(goalID, "dl-quorum", pf, owner, nil, TaskGateDependency{
			GateID: "gate-dl", RequiredPhase: AccordPhaseDeadlocked, ExpectedDeadlockReason: DeadlockNoQuorum,
		})
		tDeadlockVeto := makeBranchTask(goalID, "dl-veto", pf, owner, nil, TaskGateDependency{
			GateID: "gate-dl", RequiredPhase: AccordPhaseDeadlocked, ExpectedDeadlockReason: DeadlockAllVetoed,
		})
		tExpired := makeBranchTask(goalID, "expired", pf, owner, nil, TaskGateDependency{
			GateID: "gate-dl", RequiredPhase: AccordPhaseExpired,
		})

		rev := PlanRevision{
			GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
			Gates: []AccordGate{gate}, Tasks: []TaskSpec{tDecided, tDeadlockAny, tDeadlockQuorum, tDeadlockVeto, tExpired},
		}
		if _, err := goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		// Resolve with 0 votes -> DeadlockNoQuorum.
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		dlHead := accordMustApply(t, a, fx.release, "release-vote", "resolve", "res-quorum", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("no-quorum")}
		})
		res, err := tasks.RecordAccord(goalID, "gate-dl", a.Bundle(), dlHead)
		if err != nil {
			t.Fatal(err)
		}
		if res.Phase != AccordPhaseDeadlocked || res.DeadlockReason != DeadlockNoQuorum {
			t.Fatalf("unexpected deadlock resolution: %+v", res)
		}

		disc, _, err := tasks.DiscoverGoal(goalID, 11)
		if err != nil {
			t.Fatal(err)
		}
		byNonce := make(map[string]TaskDiscovery, len(disc))
		for _, d := range disc {
			byNonce[d.Task.Nonce] = d
		}
		for _, readyNonce := range []string{"dl-any", "dl-quorum"} {
			if !byNonce[readyNonce].GatesReady || byNonce[readyNonce].GatesMismatch {
				t.Fatalf("%s should be ready: %+v", readyNonce, byNonce[readyNonce])
			}
		}
		for _, mismatchNonce := range []string{"decided", "dl-veto", "expired"} {
			if byNonce[mismatchNonce].GatesReady || !byNonce[mismatchNonce].GatesMismatch {
				t.Fatalf("%s should mismatch: %+v", mismatchNonce, byNonce[mismatchNonce])
			}
		}

		for _, okTask := range []TaskSpec{tDeadlockAny, tDeadlockQuorum} {
			sp, rq, sg := makeClaimForTask(t, pf, goalID, okTask, "claim-"+okTask.Nonce, 1, 50)
			if _, err := tasks.Claim(rq, sg, sp, 11); err != nil {
				t.Fatalf("Claim(%s) failed: %v", okTask.Nonce, err)
			}
		}
		for _, badTask := range []TaskSpec{tDecided, tDeadlockVeto, tExpired} {
			sp, rq, sg := makeClaimForTask(t, pf, goalID, badTask, "claim-"+badTask.Nonce, 1, 50)
			if _, err := tasks.Claim(rq, sg, sp, 11); !errors.Is(err, ErrTaskDependency) {
				t.Fatalf("Claim(%s) got %v, want ErrTaskDependency", badTask.Nonce, err)
			}
		}
	})

	t.Run("expired_fallback_unlocking", func(t *testing.T) {
		_, _, goals, _, tasks, _ := gateTestStores(t)
		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		fx := newAccordFixture(t)

		goalID, err := goals.Create(GoalSpec{
			Nonce: "expired-dag", Purpose: "Expired fallback branch",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		gate := AccordGate{ID: "gate-exp", GoalID: goalID, AccordID: fx.spec.ID(), Purpose: "Expiring gate"}
		tDecided := makeBranchTask(goalID, "decided", pf, owner, nil, TaskGateDependency{
			GateID: "gate-exp", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
		})
		tExpired := makeBranchTask(goalID, "expired-fallback", pf, owner, nil, TaskGateDependency{
			GateID: "gate-exp", RequiredPhase: AccordPhaseExpired,
		})
		rev := PlanRevision{
			GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
			Gates: []AccordGate{gate}, Tasks: []TaskSpec{tDecided, tExpired},
		}
		if _, err := goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		expHead := accordMustApply(t, a, fx.release, "release-vote", "expire", "exp-1", fx.spec.ResolveByHeight, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("timed-out")}
		})
		res, err := tasks.RecordAccord(goalID, "gate-exp", a.Bundle(), expHead)
		if err != nil || res.Phase != AccordPhaseExpired {
			t.Fatalf("RecordAccord expired: %+v err=%v", res, err)
		}

		disc, _, err := tasks.DiscoverGoal(goalID, 1)
		if err != nil || len(disc) != 2 {
			t.Fatalf("DiscoverGoal: len=%d err=%v", len(disc), err)
		}
		if disc[0].GatesReady || !disc[0].GatesMismatch {
			t.Fatalf("decided task should mismatch on expired gate: %+v", disc[0])
		}
		if !disc[1].GatesReady || disc[1].GatesMismatch {
			t.Fatalf("expired fallback should be ready: %+v", disc[1])
		}

		spExp, rqExp, sgExp := makeClaimForTask(t, pf, goalID, tExpired, "claim-exp", 1, 50)
		if _, err := tasks.Claim(rqExp, sgExp, spExp, 1); err != nil {
			t.Fatalf("Claim expired fallback failed: %v", err)
		}
		spDec, rqDec, sgDec := makeClaimForTask(t, pf, goalID, tDecided, "claim-dec", 1, 50)
		if _, err := tasks.Claim(rqDec, sgDec, spDec, 1); !errors.Is(err, ErrTaskDependency) {
			t.Fatalf("Claim decided on expired gate got %v, want ErrTaskDependency", err)
		}
	})

	t.Run("commitment_pin_conflict_invalid_bundles_and_tamper", func(t *testing.T) {
		_, _, goals, _, tasks, _ := gateTestStores(t)
		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		fx := newAccordFixture(t)
		accordID := fx.spec.ID()

		goalID, err := goals.Create(GoalSpec{
			Nonce: "pin-conflict-tamper", Purpose: "Test pin, conflict, bundle rejection, and tamper",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Restrict AllowedOptions to full-rollout and canary-rollout (excluding hold-release).
		gate := AccordGate{
			ID: "gate-1", GoalID: goalID, AccordID: accordID, Purpose: "Policy gate",
			AllowedOptions: []string{"full-rollout", "canary-rollout"},
		}
		badCommitTask := makeBranchTask(goalID, "bad-commit-pin", pf, owner, nil, TaskGateDependency{
			GateID: "gate-1", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout", ExpectedCommitment: Hash("wrong-commitment"),
		})
		goodCommitTask := makeBranchTask(goalID, "good-commit-pin", pf, owner, nil, TaskGateDependency{
			GateID: "gate-1", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout", ExpectedCommitment: fx.spec.Options[1].Binding.Commitment(),
		})
		rev := PlanRevision{
			GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
			Gates: []AccordGate{gate}, Tasks: []TaskSpec{badCommitTask, goodCommitTask},
		}
		if _, err := goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		// 1. Open bundle rejected with ErrAccordPhase.
		aOpen, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		openHead := accordMustApply(t, aOpen, fx.sre, "sre-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		if _, err := tasks.RecordAccord(goalID, "gate-1", aOpen.Bundle(), openHead); !errors.Is(err, ErrAccordPhase) {
			t.Fatalf("open bundle got %v, want ErrAccordPhase", err)
		}

		// 2. Wrong AccordID bundle rejected with ErrAccordStale.
		fxWrong := newAccordFixture(t)
		aWrong, err := NewAccord(fxWrong.spec)
		if err != nil {
			t.Fatal(err)
		}
		wrongHead := accordMustApply(t, aWrong, fxWrong.release, "release-vote", "expire", "exp", fxWrong.spec.ResolveByHeight, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("exp")}
		})
		if _, err := tasks.RecordAccord(goalID, "gate-1", aWrong.Bundle(), wrongHead); !errors.Is(err, ErrAccordStale) {
			t.Fatalf("wrong AccordID got %v, want ErrAccordStale", err)
		}

		// 3. Disallowed winning option ("hold-release") rejected with ErrAccordBinding.
		aDisallowed, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, aDisallowed, fx.safety, "safety-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		accordMustApply(t, aDisallowed, fx.sre, "sre-vote", "vote", "v2", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		accordMustApply(t, aDisallowed, fx.security, "security-vote", "vote", "v3", 4, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		disallowedHead := accordMustApply(t, aDisallowed, fx.release, "release-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("hold")}
		})
		if _, err := tasks.RecordAccord(goalID, "gate-1", aDisallowed.Bundle(), disallowedHead); !errors.Is(err, ErrAccordBinding) {
			t.Fatalf("disallowed option got %v, want ErrAccordBinding", err)
		}

		// 4. Build honest winning bundle on canary-rollout, check tampered copy + expectedHead mismatch.
		aWin, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, aWin, fx.safety, "safety-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		accordMustApply(t, aWin, fx.sre, "sre-vote", "vote", "v2", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		accordMustApply(t, aWin, fx.security, "security-vote", "vote", "v3", 4, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		winHead := accordMustApply(t, aWin, fx.release, "release-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("win")}
		})
		winBundle := aWin.Bundle()

		// Tampered signature rejected, wrong expectedHead rejected.
		tampered := winBundle
		tampered.Events = slices.Clone(winBundle.Events)
		tampered.Events[0].Signature = bytes.Clone(tampered.Events[0].Signature)
		tampered.Events[0].Signature[0] ^= 0xff
		if _, err := tasks.RecordAccord(goalID, "gate-1", tampered, winHead); err == nil {
			t.Fatal("tampered bundle accepted")
		}
		if _, err := tasks.RecordAccord(goalID, "gate-1", winBundle, Hash("other-head")); !errors.Is(err, ErrAccordStale) {
			t.Fatalf("wrong expectedHead got %v, want ErrAccordStale", err)
		}
		if _, err := tasks.GateStatus(goalID, "gate-1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rejected bundles leaked gate status: %v", err)
		}

		// 5. Commit uncertainty on RecordAccord returns ErrCommitUncertain and retry recovers cleanly.
		tasks.store.commitHook = func(stage string) error {
			if stage == "after-rename" {
				return errors.New("injected sync failure")
			}
			return nil
		}
		if _, err := tasks.RecordAccord(goalID, "gate-1", winBundle, winHead); !errors.Is(err, ErrCommitUncertain) {
			t.Fatalf("expected ErrCommitUncertain, got %v", err)
		}
		tasks.store.commitHook = nil
		if _, err := tasks.RecordAccord(goalID, "gate-1", winBundle, winHead); err != nil {
			t.Fatalf("retry after ErrCommitUncertain failed: %v", err)
		}

		// 6. Conflicting terminal head for same (goalID, gateID) returns ErrOperationConflict!
		aConflict, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		conflictHead := accordMustApply(t, aConflict, fx.release, "release-vote", "expire", "exp-alt", fx.spec.ResolveByHeight, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("alt-expired")}
		})
		if _, err := tasks.RecordAccord(goalID, "gate-1", aConflict.Bundle(), conflictHead); !errors.Is(err, ErrOperationConflict) {
			t.Fatalf("conflicting terminal head got %v, want ErrOperationConflict", err)
		}

		// 7. ExpectedCommitment pin mismatch blocks Claim & flags GatesMismatch in DiscoverGoal.
		disc, _, err := tasks.DiscoverGoal(goalID, 11)
		if err != nil || len(disc) != 2 {
			t.Fatalf("DiscoverGoal: len=%d err=%v", len(disc), err)
		}
		if disc[0].GatesReady || !disc[0].GatesMismatch {
			t.Fatalf("bad commitment pin should report GatesMismatch=true: %+v", disc[0])
		}
		if !disc[1].GatesReady || disc[1].GatesMismatch {
			t.Fatalf("good commitment pin should report GatesReady=true: %+v", disc[1])
		}
		spBad, rqBad, sgBad := makeClaimForTask(t, pf, goalID, badCommitTask, "claim-bad-pin", 1, 50)
		if _, err := tasks.Claim(rqBad, sgBad, spBad, 11); !errors.Is(err, ErrTaskDependency) {
			t.Fatalf("Claim with mismatched ExpectedCommitment got %v, want ErrTaskDependency", err)
		}
		spGood, rqGood, sgGood := makeClaimForTask(t, pf, goalID, goodCommitTask, "claim-good-pin", 1, 50)
		if _, err := tasks.Claim(rqGood, sgGood, spGood, 11); err != nil {
			t.Fatalf("Claim with matching ExpectedCommitment failed: %v", err)
		}

		// 8. In-place ciphertext tamper on gate checkpoint (preserving inode/size/mtime) fails closed across DiscoverGoal, GateStatus, and Claim!
		gatePath := tasks.store.path(gateRecordKey(goalID, "gate-1"))
		origInfo, err := os.Lstat(gatePath)
		if err != nil {
			t.Fatal(err)
		}
		origBytes, err := os.ReadFile(gatePath)
		if err != nil {
			t.Fatal(err)
		}
		tamperedFile := bytes.Clone(origBytes)
		tamperedFile[len(tamperedFile)-1] ^= 0xff
		fh, err := os.OpenFile(gatePath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fh.WriteAt(tamperedFile, 0); err != nil {
			fh.Close()
			t.Fatal(err)
		}
		_ = fh.Sync()
		_ = fh.Close()
		_ = os.Chtimes(gatePath, origInfo.ModTime(), origInfo.ModTime())

		if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("DiscoverGoal on tampered gate checkpoint got %v, want ErrCorruptStore", err)
		}
		if _, err := tasks.GateStatus(goalID, "gate-1"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("GateStatus on tampered gate checkpoint got %v, want ErrCorruptStore", err)
		}
		spGood2, rqGood2, sgGood2 := makeClaimForTask(t, pf, goalID, goodCommitTask, "claim-corrupt", 1, 50)
		if _, err := tasks.Claim(rqGood2, sgGood2, spGood2, 11); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Claim on tampered gate checkpoint got %v, want ErrCorruptStore (must not swallow!)", err)
		}
	})
}

func TestSQLConditionalDAGAndTwoPodFailover(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		if dialect == SQLDialectSQLite {
			dbA.SetMaxOpenConns(1)
			dbB.SetMaxOpenConns(1)
		}
		key := randomTestKey(t)

		goalsA, err := OpenSQLGoalStore(ctx, dbA, dialect, "gate-goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsA, err := OpenSQLProtocolStore(ctx, dbA, dialect, "gate-attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		tasksA, err := OpenSQLCoordinationStore(ctx, dbA, dialect, "gate-tasks", key, goalsA, attemptsA)
		if err != nil {
			t.Fatal(err)
		}
		accordsA, err := OpenSQLAccordStore(ctx, dbA, dialect, "gate-accords", key)
		if err != nil {
			t.Fatal(err)
		}

		goalsB, err := OpenSQLGoalStore(ctx, dbB, dialect, "gate-goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsB, err := OpenSQLProtocolStore(ctx, dbB, dialect, "gate-attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		tasksB, err := OpenSQLCoordinationStore(ctx, dbB, dialect, "gate-tasks", key, goalsB, attemptsB)
		if err != nil {
			t.Fatal(err)
		}
		accordsB, err := OpenSQLAccordStore(ctx, dbB, dialect, "gate-accords", key)
		if err != nil {
			t.Fatal(err)
		}

		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		fx := newAccordFixture(t)
		accordID := fx.spec.ID()

		goalID, err := goalsA.Create(GoalSpec{
			Nonce: "sql-conditional-dag", Purpose: "Stateless two-pod conditional DAG failover",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}

		gate := AccordGate{
			ID:             "sql-release-gate",
			GoalID:         goalID,
			AccordID:       accordID,
			Purpose:        "Coordinate release choice across pods",
			AllowedOptions: []string{"full-rollout", "canary-rollout"},
		}
		canaryCommit := fx.spec.Options[1].Binding.Commitment()
		canaryTask := makeBranchTask(goalID, "sql-canary", pf, owner, nil, TaskGateDependency{
			GateID: "sql-release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout", ExpectedCommitment: canaryCommit,
		})
		fullTask := makeBranchTask(goalID, "sql-full", pf, owner, nil, TaskGateDependency{
			GateID: "sql-release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout",
		})
		dlTask := makeBranchTask(goalID, "sql-deadlock", pf, owner, nil, TaskGateDependency{
			GateID: "sql-release-gate", RequiredPhase: AccordPhaseDeadlocked, ExpectedDeadlockReason: DeadlockAllVetoed,
		})
		rev := PlanRevision{
			GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "sql-plan-1",
			Gates: []AccordGate{gate}, Tasks: []TaskSpec{canaryTask, fullTask, dlTask},
		}
		if _, err := goalsA.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		// Pod B warms GoalStore cache on gate & sees unresolved gate in DiscoverGoal and Claim refusal.
		if gB, err := goalsB.Gate(goalID, "sql-release-gate"); err != nil || gB.AccordID != accordID {
			t.Fatalf("Pod B GoalStore.Gate: %+v err=%v", gB, err)
		}
		discB0, missesB0, err := tasksB.DiscoverGoal(goalID, 1)
		if err != nil || missesB0 != 0 || len(discB0) != 3 {
			t.Fatalf("Pod B initial DiscoverGoal: misses=%d len=%d err=%v", missesB0, len(discB0), err)
		}
		if discB0[0].GatesReady || discB0[0].GatesMismatch {
			t.Fatalf("Pod B initial canary discovery unexpected: %+v", discB0[0])
		}
		canSpec, canReq, canSig := makeClaimForTask(t, pf, goalID, canaryTask, "sql-can-1", 1, 50)
		if _, err := tasksB.Claim(canReq, canSig, canSpec, 1); !errors.Is(err, ErrTaskDependency) {
			t.Fatalf("Pod B Claim before RecordAccord got %v, want ErrTaskDependency", err)
		}

		// Pod A creates Accord and starts voting; Pod B finishes voting + resolves + exports bundle!
		if _, err := accordsA.Create(fx.spec); err != nil {
			t.Fatal(err)
		}
		applyAccord := func(store *AccordStore, actor accordActor, grant, action, reqID string, height uint64, fill func(*AccordCommand)) string {
			cmd, err := store.Prepare(accordID, actor.pub.ID(), grant, fx.spec.Scope, action, reqID, height)
			if err != nil {
				t.Fatal(err)
			}
			if fill != nil {
				fill(&cmd)
			}
			sig, err := SignAccordCommand(actor.id, cmd)
			if err != nil {
				t.Fatal(err)
			}
			h, err := store.Apply(accordID, cmd, sig, height)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		applyAccord(accordsA, fx.safety, "safety-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		applyAccord(accordsB, fx.sre, "sre-vote", "vote", "v2", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		applyAccord(accordsB, fx.security, "security-vote", "vote", "v3", 4, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
		})
		finalHead := applyAccord(accordsB, fx.release, "release-vote", "resolve", "res-1", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("decided")}
		})
		bundle, err := accordsB.Export(accordID)
		if err != nil {
			t.Fatal(err)
		}

		// Pod A records the Accord and warms DiscoverGoal gate cache.
		resA, err := tasksA.RecordAccord(goalID, "sql-release-gate", bundle, finalHead)
		if err != nil {
			t.Fatalf("Pod A RecordAccord: %v", err)
		}
		discA1, missesA1, err := tasksA.DiscoverGoal(goalID, 11)
		if err != nil || missesA1 != 1 || !discA1[0].GatesReady || discA1[0].GatesMismatch {
			t.Fatalf("Pod A DiscoverGoal after RecordAccord: misses=%d disc=%+v err=%v", missesA1, discA1, err)
		}
		if _, missesA2, err := tasksA.DiscoverGoal(goalID, 11); err != nil || missesA2 != 0 {
			t.Fatalf("Pod A warm DiscoverGoal: misses=%d err=%v", missesA2, err)
		}

		// Fail over to Pod B: GateStatus, DiscoverGoal, Claim & Finalize winning branch!
		resB, err := tasksB.GateStatus(goalID, "sql-release-gate")
		if err != nil || resB != resA {
			t.Fatalf("Pod B GateStatus mismatch: %+v vs %+v err=%v", resB, resA, err)
		}
		discB1, missesB1, err := tasksB.DiscoverGoal(goalID, 11)
		if err != nil || missesB1 != 1 {
			t.Fatalf("Pod B DiscoverGoal after Pod A RecordAccord: misses=%d err=%v", missesB1, err)
		}
		if !discB1[0].GatesReady || discB1[0].GatesMismatch ||
			discB1[1].GatesReady || !discB1[1].GatesMismatch ||
			discB1[2].GatesReady || !discB1[2].GatesMismatch {
			t.Fatalf("Pod B DiscoverGoal branch mismatch: %+v", discB1)
		}

		leaseB, err := tasksB.Claim(canReq, canSig, canSpec, 11)
		if err != nil {
			t.Fatalf("Pod B Claim winning branch: %v", err)
		}
		_, _, _ = completeTaskAttempt(t, pf, attemptsB, tasksB, leaseB, canSpec, "sql-canary-answer", 11)

		// Losing branches refused on Pod B, and conflicting terminal head refused with ErrOperationConflict on Pod B.
		fullSpec, fullReq, fullSig := makeClaimForTask(t, pf, goalID, fullTask, "sql-full-1", 1, 50)
		if _, err := tasksB.Claim(fullReq, fullSig, fullSpec, 11); !errors.Is(err, ErrTaskDependency) {
			t.Fatalf("Pod B Claim losing branch got %v, want ErrTaskDependency", err)
		}
		aAlt, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		altHead := accordMustApply(t, aAlt, fx.release, "release-vote", "expire", "exp-sql", fx.spec.ResolveByHeight, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("alt")}
		})
		if _, err := tasksB.RecordAccord(goalID, "sql-release-gate", aAlt.Bundle(), altHead); !errors.Is(err, ErrOperationConflict) {
			t.Fatalf("Pod B conflicting head got %v, want ErrOperationConflict", err)
		}
		if retryB, err := tasksB.RecordAccord(goalID, "sql-release-gate", bundle, finalHead); err != nil || retryB != resA {
			t.Fatalf("Pod B exact retry RecordAccord: %+v err=%v", retryB, err)
		}

		// Pod A immediately detects Pod B's Claim+Finalize of winning branch.
		discA2, missesA3, err := tasksA.DiscoverGoal(goalID, 11)
		if err != nil || missesA3 != 1 || discA2[0].Status != "accepted" {
			t.Fatalf("Pod A post-failover DiscoverGoal: misses=%d disc=%+v err=%v", missesA3, discA2, err)
		}

		// SQL security: wrong key & in-place ciphertext tamper on gate row at same SQL version with warm cache fails closed!
		wrongKey := bytes.Clone(key)
		wrongKey[0] ^= 0xff
		tasksWrong, err := OpenSQLCoordinationStore(ctx, dbA, dialect, "gate-tasks", wrongKey, goalsA, attemptsA)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tasksWrong.GateStatus(goalID, "sql-release-gate"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("GateStatus with wrong key got %v, want ErrCorruptStore", err)
		}

		gateKey := gateRecordKey(goalID, "sql-release-gate")
		origVer, origPayload, ok := backing.rawRow("gate-tasks", gateKey)
		if !ok {
			t.Fatalf("missing raw SQL row for gate checkpoint")
		}
		tampered := bytes.Clone(origPayload)
		tampered[len(tampered)-1] ^= 0xff
		backing.setRawRow("gate-tasks", gateKey, origVer, tampered)
		if _, _, err := tasksA.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Pod A DiscoverGoal on in-place SQL gate tamper (warm cache) got %v, want ErrCorruptStore", err)
		}
		if _, err := tasksB.GateStatus(goalID, "sql-release-gate"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Pod B GateStatus on tampered SQL gate row got %v, want ErrCorruptStore", err)
		}

		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("expected 0 non-tx queries, got %d", backing.metrics().nonTxQueries)
		}

		// Concurrent multi-pod RecordAccord race on a fresh gate: exact retries succeed while conflicting terminal head gets ErrOperationConflict!
		raceGate := AccordGate{
			ID: "sql-race-gate", GoalID: goalID, AccordID: accordID, Purpose: "Concurrent RecordAccord race",
		}
		raceRev := PlanRevision{
			GoalID: goalID, Head: rev.Head, Planner: owner.ID(), RequestID: "sql-race-gate-rev",
			Gates: []AccordGate{raceGate},
		}
		planCur, err := goalsA.View(goalID)
		if err != nil {
			t.Fatal(err)
		}
		raceRev.Head = planCur.Head
		if _, err := goalsA.Apply(raceRev, Sign(pf.owner, PlanSignatureDomain, raceRev)); err != nil {
			t.Fatal(err)
		}
		const racePods = 6
		raceErrs := make(chan error, racePods)
		var raceWG sync.WaitGroup
		raceStart := make(chan struct{})
		for i := 0; i < racePods; i++ {
			peerDB := openPeerSQLDB(t, backing)
			if dialect == SQLDialectSQLite {
				peerDB.SetMaxOpenConns(1)
			}
			gPeer, _ := OpenSQLGoalStore(ctx, peerDB, dialect, "gate-goals", key)
			aPeer, _ := OpenSQLProtocolStore(ctx, peerDB, dialect, "gate-attempts", key)
			tPeer, _ := OpenSQLCoordinationStore(ctx, peerDB, dialect, "gate-tasks", key, gPeer, aPeer)
			bUse, hUse := bundle, finalHead
			if i%2 == 1 {
				bUse, hUse = aAlt.Bundle(), altHead
			}
			raceWG.Add(1)
			go func(st *CoordinationStore, b AccordBundle, h string) {
				defer raceWG.Done()
				<-raceStart
				_, err := st.RecordAccord(goalID, "sql-race-gate", b, h)
				raceErrs <- err
			}(tPeer, bUse, hUse)
		}
		close(raceStart)
		raceWG.Wait()
		close(raceErrs)
		winCnt, conflictCnt := 0, 0
		for err := range raceErrs {
			if err == nil {
				winCnt++
			} else if errors.Is(err, ErrOperationConflict) {
				conflictCnt++
			} else {
				t.Fatalf("unexpected concurrent RecordAccord error: %v", err)
			}
		}
		if winCnt != racePods/2 || conflictCnt != racePods/2 {
			t.Fatalf("concurrent RecordAccord race: win=%d conflict=%d want %d/%d", winCnt, conflictCnt, racePods/2, racePods/2)
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("expected 0 non-tx queries after race, got %d", backing.metrics().nonTxQueries)
		}
	})
}
