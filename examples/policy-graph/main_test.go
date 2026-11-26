package main

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/WillBeebe/nexum/v2/nex"
)

var (
	sharedRunOnce sync.Once
	sharedRunRes  runArtifacts
	sharedRunErr  error
)

func getSharedRun(t *testing.T) runArtifacts {
	t.Helper()
	sharedRunOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nex-policy-graph-test-")
		if err != nil {
			sharedRunErr = err
			return
		}
		defer os.RemoveAll(dir)
		sharedRunRes, sharedRunErr = execute(dir)
	})
	if sharedRunErr != nil {
		t.Fatal(sharedRunErr)
	}
	return sharedRunRes
}

func TestPolicyGraphExample(t *testing.T) {
	t.Parallel()
	got := getSharedRun(t).report
	if got.Example != "policy-graph" || got.SQLDialect != nex.SQLDialectPostgres {
		t.Fatalf("unexpected header: example=%q dialect=%q", got.Example, got.SQLDialect)
	}
	if !got.ZeroDirectoryCopyFailover {
		t.Fatal("expected zero-directory-copy failover to succeed")
	}
	wantRows := map[string]int{
		nsGoals:        1,
		nsProtocols:    4,
		nsCoordination: 5,
		nsAccords:      1,
	}
	for ns, want := range wantRows {
		if got.SQLNamespaces[ns] != want {
			t.Fatalf("namespace %q rows = %d, want %d (all=%v)", ns, got.SQLNamespaces[ns], want, got.SQLNamespaces)
		}
	}

	if got.UpstreamOutcomes["patch"] != nex.TaskAccepted ||
		got.UpstreamOutcomes["window"] != nex.TaskAccepted ||
		got.UpstreamOutcomes["safety"] != nex.TaskIncomplete {
		t.Fatalf("unexpected upstream outcomes: %+v", got.UpstreamOutcomes)
	}

	if got.BallotPrivacy != nex.BallotPrivacySealedPaillier ||
		got.BallotMode != nex.BallotSingleChoice ||
		got.SealedBallotsRecorded != 4 ||
		got.PlaintextVotesExposed != 0 ||
		got.OpaqueCiphertextsVerified != 24 {
		t.Fatalf("unexpected sealed ballot summary: %+v", got)
	}

	if !got.OutboxLostResponseRecovered || got.OutboxRecoveryAttempts != 2 || got.OutboxUnresolvedCount != 0 {
		t.Fatalf("unexpected outbox recovery summary: recovered=%v attempts=%d unresolved=%d",
			got.OutboxLostResponseRecovered, got.OutboxRecoveryAttempts, got.OutboxUnresolvedCount)
	}

	if got.AccordPhase != nex.AccordPhaseDecided ||
		got.WinningOption != "canary-rollout" ||
		got.ParticipatingCount != 4 ||
		got.ParticipatingWeight != 9 {
		t.Fatalf("unexpected accord outcome: phase=%q winner=%q count=%d weight=%d",
			got.AccordPhase, got.WinningOption, got.ParticipatingCount, got.ParticipatingWeight)
	}

	if !got.OfflineBundleVerified || !got.OfflineGoalPlanVerified ||
		got.GateRecordedPhase != nex.AccordPhaseDecided ||
		got.GateWinningOption != "canary-rollout" ||
		!got.GateRetryIdempotent {
		t.Fatalf("unexpected offline/gate verification summary: %+v", got)
	}

	if !got.FullRolloutClaimRefused || !got.HoldRemediationClaimRefused ||
		!got.CanaryTaskClaimed || got.CanaryCommittedPhase != "working" ||
		got.CanaryFinalOutcome != nex.TaskAccepted {
		t.Fatalf("unexpected downstream execution summary: %+v", got)
	}

	byOpt := make(map[string]optionSummary, len(got.Options))
	for _, o := range got.Options {
		byOpt[o.OptionID] = o
	}
	canary, ok := byOpt["canary-rollout"]
	if !ok || !canary.GuardPassed || !canary.Eligible || canary.VetoEffective ||
		canary.ApproveCount != 3 || canary.ApproveWeight != 7 ||
		canary.DissentCount != 1 || canary.DissentWeight != 2 {
		t.Fatalf("unexpected canary-rollout tally: %+v", canary)
	}
	full, ok := byOpt["full-rollout"]
	if !ok || full.GuardPassed || !full.VetoEffective || full.Eligible ||
		!slices.Contains(full.DisqualificationReasons, "guard_failed") ||
		!slices.Contains(full.DisqualificationReasons, "vetoed") {
		t.Fatalf("unexpected full-rollout tally: %+v", full)
	}
	hold, ok := byOpt["hold-and-remediate"]
	if !ok || !hold.GuardPassed || hold.Eligible || hold.ApproveCount != 0 {
		t.Fatalf("unexpected hold-and-remediate tally: %+v", hold)
	}

	byTask := make(map[string]gateTaskSummary, len(got.DownstreamTasks))
	for _, ts := range got.DownstreamTasks {
		byTask[ts.TaskName] = ts
	}
	canaryTask := byTask["canary-rollout-task"]
	if canaryTask.GatesReadyBefore || !canaryTask.GatesReadyAfter || canaryTask.GatesMismatchAfter ||
		!canaryTask.DependenciesReady || canaryTask.DependenciesMismatch {
		t.Fatalf("expected canary-rollout-task unlocked after gate: %+v", canaryTask)
	}
	for _, blocked := range []string{"full-rollout-task", "hold-remediation-task"} {
		bt := byTask[blocked]
		if bt.GatesReadyBefore || bt.GatesReadyAfter || !bt.GatesMismatchAfter ||
			bt.DependenciesReady || !bt.DependenciesMismatch {
			t.Fatalf("expected %s blocked with GatesMismatch=true: %+v", blocked, bt)
		}
	}
}

func TestPolicyGraphDeterministicOutput(t *testing.T) {
	t.Parallel()
	firstRes := getSharedRun(t)
	var first, second bytes.Buffer
	enc := json.NewEncoder(&first)
	enc.SetIndent("", "  ")
	if err := enc.Encode(firstRes.report); err != nil {
		t.Fatal(err)
	}
	if err := runTo(t.TempDir(), &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("non-deterministic output:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
}

func TestPolicyGraphOfflineTamperRejection(t *testing.T) {
	t.Parallel()
	res := getSharedRun(t)

	// 1. Sealed AccordBundle offline verification rejects tampered ciphertexts and GMR tally proofs.
	var bundle nex.AccordBundle
	if err := json.Unmarshal(res.bundleJSON, &bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := nex.VerifyAccordBundle(bundle, res.accordID, res.finalHead); err != nil {
		t.Fatalf("valid sealed AccordBundle failed verification: %v", err)
	}

	var tamperedBallot nex.AccordBundle
	if err := json.Unmarshal(res.bundleJSON, &tamperedBallot); err != nil {
		t.Fatal(err)
	}
	mutatedCT := false
	for i := range tamperedBallot.Events {
		if tamperedBallot.Events[i].Command.Vote != nil && tamperedBallot.Events[i].Command.Vote.Sealed != nil {
			tamperedBallot.Events[i].Command.Vote.Sealed.Options[0].ApproveCT[0] ^= 0x01
			mutatedCT = true
			break
		}
	}
	if !mutatedCT {
		t.Fatal("failed to locate sealed ballot ciphertext in exported bundle")
	}
	if _, err := nex.VerifyAccordBundle(tamperedBallot, res.accordID, res.finalHead); err == nil {
		t.Fatal("VerifyAccordBundle accepted tampered sealed ballot ciphertext")
	}

	var tamperedTally nex.AccordBundle
	if err := json.Unmarshal(res.bundleJSON, &tamperedTally); err != nil {
		t.Fatal(err)
	}
	mutatedTally := false
	for i := range tamperedTally.Events {
		if tamperedTally.Events[i].Command.Resolve != nil && tamperedTally.Events[i].Command.Resolve.SealedTally != nil {
			tamperedTally.Events[i].Command.Resolve.SealedTally.Options[0].ApproveCountProof[0] ^= 0x01
			mutatedTally = true
			break
		}
	}
	if !mutatedTally {
		t.Fatal("failed to locate SealedTallyProof in exported bundle")
	}
	if _, err := nex.VerifyAccordBundle(tamperedTally, res.accordID, res.finalHead); err == nil {
		t.Fatal("VerifyAccordBundle accepted tampered GMR SealedTallyProof")
	}

	// 2. GoalPlan offline verification rejects tampered AccordGate or TaskGateDependency pins.
	var plan nex.GoalPlan
	if err := json.Unmarshal(res.planJSON, &plan); err != nil {
		t.Fatal(err)
	}
	if err := nex.VerifyGoalPlan(plan, res.goalID, res.planHead); err != nil {
		t.Fatalf("valid GoalPlan failed verification: %v", err)
	}

	var tamperedGate nex.GoalPlan
	if err := json.Unmarshal(res.planJSON, &tamperedGate); err != nil {
		t.Fatal(err)
	}
	tamperedGate.Revisions[1].Revision.Gates[0].AllowedOptions[0] = "forged-option"
	if err := nex.VerifyGoalPlan(tamperedGate, res.goalID, res.planHead); err == nil {
		t.Fatal("VerifyGoalPlan accepted tampered AccordGate")
	}

	var tamperedDep nex.GoalPlan
	if err := json.Unmarshal(res.planJSON, &tamperedDep); err != nil {
		t.Fatal(err)
	}
	tamperedDep.Revisions[1].Revision.Tasks[0].GateDependencies[0].OptionID = "canary-rollout"
	if err := nex.VerifyGoalPlan(tamperedDep, res.goalID, res.planHead); err == nil {
		t.Fatal("VerifyGoalPlan accepted tampered TaskGateDependency")
	}
}
