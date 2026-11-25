// Regression tests for Nexum v2.0.2 CoordinationStore.DiscoverGoal fixes (BUG-19):
//   - Unclaimed upstream tasks do not trigger redundant s.Result calls, extra OS locks,
//     or inflated cacheMissValidations counts.
//   - Corrupt checkpoints and storage errors are never swallowed by DiscoverGoal.
//   - Returned GoalDiscovery snapshots are internally consistent under concurrent Claim+Finalize.

package nex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func v202DiscoverSetup(t *testing.T) (protocolFixture, Public, *GoalStore, *ProtocolStore, *CoordinationStore) {
	t.Helper()
	f := newProtocolFixture(t)
	owner := protocolPublic(f.owner)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{77}, 32)
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
	return f, owner, goals, attempts, tasks
}

func v202MakeTask(goalID, nonce string, f protocolFixture, owner Public, deps ...TaskDependency) TaskSpec {
	return TaskSpec{
		GoalID:            goalID,
		Nonce:             nonce,
		Purpose:           f.spec.Purpose,
		Scope:             f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash,
		AcceptanceHash:    f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash,
		Authority:         owner,
		Outputs:           append([]string(nil), f.spec.Return.SuccessArtifacts...),
		FailureOutputs:    append([]string(nil), f.spec.Return.FailureArtifacts...),
		Dependencies:      deps,
	}
}

func v202WaitForLockAdvance(t *testing.T, tasks *CoordinationStore, baseline int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for tasks.Stats().LockAcquisitions <= baseline {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for DiscoverGoal to advance past taskA lock")
		}
		runtime.Gosched()
	}
}

// BUG-19 (metrics & lock amplification): when a goal contains an unclaimed upstream task
// referenced by K downstream dependencies, DiscoverGoal must NOT invoke s.Result, must
// acquire exactly 1 lock per task, and must report cacheMissValidations == 0 == ReplayValidationOps.
func TestV202_DiscoverGoalUnclaimedDepDoesNotInflateValidations(t *testing.T) {
	f, owner, goals, _, tasks := v202DiscoverSetup(t)
	goalID, err := goals.Create(GoalSpec{
		Nonce: "dg-unclaimed-no-inflate", Purpose: "verify unclaimed dependency metrics",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"),
		Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	taskA := v202MakeTask(goalID, "task-a", f, owner)
	taskB := v202MakeTask(goalID, "task-b", f, owner,
		TaskDependency{
			Input: "in1", TaskID: taskA.ID(), ProtocolID: Hash("p1"), Head: Hash("h1"),
			Slot: "answer", Digest: Hash("d1"), Outcome: TaskAccepted,
		},
		TaskDependency{
			Input: "in2", TaskID: taskA.ID(), ProtocolID: Hash("p2"), Head: Hash("h2"),
			Slot: "answer", Digest: Hash("d2"), Outcome: TaskAccepted,
		},
	)
	rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskA, taskB}}
	if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	before := tasks.Stats()
	disc, cacheMissValidations, err := tasks.DiscoverGoal(goalID, 1)
	after := tasks.Stats()
	if err != nil {
		t.Fatalf("DiscoverGoal returned unexpected error: %v", err)
	}
	if len(disc) != 2 {
		t.Fatalf("expected 2 discovered tasks, got %d", len(disc))
	}
	replayOps := after.ReplayValidationOps - before.ReplayValidationOps
	lockOps := after.LockAcquisitions - before.LockAcquisitions
	readOps := after.CheckpointReads - before.CheckpointReads
	if cacheMissValidations != 0 || replayOps != 0 || readOps != 0 {
		t.Fatalf("unexpected validation work for unclaimed tasks: cacheMissValidations=%d ReplayValidationOps=%d CheckpointReads=%d",
			cacheMissValidations, replayOps, readOps)
	}
	if lockOps != 2 {
		t.Fatalf("expected exactly 2 lock acquisitions (1 per task), got %d", lockOps)
	}
	if disc[0].Status != "unclaimed" || !disc[0].DependenciesReady {
		t.Fatalf("unexpected taskA discovery: %+v", disc[0])
	}
	if disc[1].Status != "unclaimed" || disc[1].DependenciesReady || disc[1].DependenciesMismatch {
		t.Fatalf("unexpected taskB discovery: %+v", disc[1])
	}
}

// BUG-19 (fail-closed corruption handling): DiscoverGoal must never swallow ErrCorruptStore
// on corrupted checkpoints, and must never redundantly re-read unclaimed tasks in pass 2.
func TestV202_DiscoverGoalNeverSwallowsCorruptStoreError(t *testing.T) {
	t.Run("corrupt_upstream_fails_closed", func(t *testing.T) {
		f, owner, goals, _, tasks := v202DiscoverSetup(t)
		goalID, err := goals.Create(GoalSpec{
			Nonce: "dg-corrupt-upstream", Purpose: "corrupt upstream fails closed",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"),
			Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		taskA := v202MakeTask(goalID, "task-a", f, owner)
		taskB := v202MakeTask(goalID, "task-b", f, owner, TaskDependency{
			Input: "in1", TaskID: taskA.ID(), ProtocolID: Hash("p1"), Head: Hash("h1"),
			Slot: "answer", Digest: Hash("d1"), Outcome: TaskAccepted,
		})
		rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskA, taskB}}
		if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(tasks.store.path(taskA.ID()), []byte("NEXSTORE1corrupted-ciphertext-bytes-padding-padding"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := tasks.DiscoverGoal(goalID, 1); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("DiscoverGoal on corrupt upstream returned %v, want ErrCorruptStore", err)
		}
	})

	t.Run("corrupt_written_after_pass1_probe_never_swallowed", func(t *testing.T) {
		f, owner, goals, _, tasks := v202DiscoverSetup(t)
		goalID, err := goals.Create(GoalSpec{
			Nonce: "dg-corrupt-mid-scan", Purpose: "no pass-2 fallback error swallowing",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"),
			Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		taskA := v202MakeTask(goalID, "task-a", f, owner)
		taskB := v202MakeTask(goalID, "task-b", f, owner, TaskDependency{
			Input: "in1", TaskID: taskA.ID(), ProtocolID: Hash("p1"), Head: Hash("h1"),
			Slot: "answer", Digest: Hash("d1"), Outcome: TaskAccepted,
		})
		rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskA, taskB}}
		if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		lockHeld := make(chan struct{})
		releaseLock := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tasks.store.withLock(taskB.ID(), func() error {
				close(lockHeld)
				<-releaseLock
				return nil
			})
		}()
		<-lockHeld

		baseLocks := tasks.Stats().LockAcquisitions
		type dgOut struct {
			disc   []TaskDiscovery
			misses int
			err    error
		}
		done := make(chan dgOut, 1)
		go func() {
			d, m, err := tasks.DiscoverGoal(goalID, 1)
			done <- dgOut{d, m, err}
		}()

		// Wait until DiscoverGoal checked taskA (unclaimed) and is paused on taskB.
		v202WaitForLockAdvance(t, tasks, baseLocks)

		// Write corrupt checkpoint for taskA after Pass 1 already observed it as unclaimed.
		if err := os.WriteFile(tasks.store.path(taskA.ID()), []byte("NEXSTORE1corrupted-ciphertext-bytes-padding-padding"), 0600); err != nil {
			close(releaseLock)
			t.Fatal(err)
		}
		close(releaseLock)
		wg.Wait()

		res := <-done
		// Pass 2 must NOT re-read taskA via s.Result (no inflated misses, no swallowed error).
		if res.err != nil {
			if !errors.Is(res.err, ErrCorruptStore) {
				t.Fatalf("unexpected error: %v", res.err)
			}
		} else {
			if res.misses != 0 {
				t.Fatalf("pass-2 redundantly queried unclaimed dep: misses=%d, want 0", res.misses)
			}
			if len(res.disc) != 2 || res.disc[0].Status != "unclaimed" || res.disc[1].DependenciesReady {
				t.Fatalf("unexpected in-flight snapshot: %+v", res.disc)
			}
		}

		// Subsequent DiscoverGoal MUST fail closed with ErrCorruptStore.
		if _, _, err := tasks.DiscoverGoal(goalID, 1); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("subsequent DiscoverGoal returned %v, want ErrCorruptStore", err)
		}
	})
}

// BUG-19 (snapshot consistency): under a concurrent Claim+Finalize of taskA between
// checking taskA and taskB in Pass 1, DiscoverGoal must return an internally consistent
// snapshot: if taskA is reported as Status=="unclaimed" (Generation==0), dependent taskB
// MUST NOT report DependenciesReady==true in that same snapshot.
func TestV202_DiscoverGoalConsistentSnapshotUnderConcurrentFinalize(t *testing.T) {
	f, owner, goals, attempts, tasks := v202DiscoverSetup(t)
	goalID, err := goals.Create(GoalSpec{
		Nonce: "dg-consistent-snap", Purpose: "verify snapshot consistency",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"),
		Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	taskA := v202MakeTask(goalID, "task-a", f, owner)

	specA := f.spec
	specA.Version = ProtocolVersionV2
	specA.TaskID = taskA.ID()
	specA.Generation = 1
	specA.Nonce = "attempt-a"
	specA.WorkByHeight = 10
	specA.ReturnByHeight = 20
	specA.Roles = append([]RoleGrant(nil), f.spec.Roles...)
	for i := range specA.Roles {
		specA.Roles[i].ExpiresAtHeight = 20
	}
	pTmp, err := NewProtocol(specA)
	if err != nil {
		t.Fatal(err)
	}
	ansRef := testArtifactRef("exact-answer")
	runScript := func(p *Protocol, applyStore bool) string {
		step := func(who Identity, grant, scope, action, reqID string, fill func(*ProtocolCommand)) {
			cmd := p.Prepare(protocolPublic(who).ID(), grant, scope, action, reqID, 2)
			if fill != nil {
				fill(&cmd)
			}
			sig := Sign(who, "protocol", cmd)
			if _, err := p.Apply(cmd, sig, 2); err != nil {
				t.Fatalf("in-mem %s: %v", action, err)
			}
			if applyStore {
				if _, err := attempts.Apply(p.View().ID, cmd, sig, 2); err != nil {
					t.Fatalf("store %s: %v", action, err)
				}
			}
		}
		step(f.owner, "", "", "admit", "admit-owner", nil)
		step(f.worker, "", "", "admit", "admit-worker", nil)
		step(f.witness, "", "", "admit", "admit-witness", nil)
		step(f.owner, "owner", specA.Scope, "commit", "commit-owner", nil)
		step(f.worker, "worker", specA.Scope, "report", "report-worker", func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{ansRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: "answer", Ref: ansRef}}},
			}
		})
		step(f.witness, "witness", specA.Scope, "review", "review-witness", func(c *ProtocolCommand) {
			c.Review = &WitnessReview{ReportHash: Hash(p.View().Report), AssessmentHash: Hash("ok")}
		})
		step(f.owner, "owner", specA.Scope, "resolve", "resolve-owner", func(c *ProtocolCommand) {
			c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: "accept", ReasonHash: Hash("ok")}
		})
		step(f.worker, "worker", specA.Scope, "return", "return-worker", func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews), Evidence: v.Report.Evidence,
				Resources: v.Report.Resources, Uncertainty: "bounded", SafeAssumptions: []string{"verified"},
				Artifacts: []ReturnArtifact{{ID: "answer", Commitment: ansRef.Digest, ReuseRestrictions: "none"}}, Disposition: "continue",
			}
		})
		return p.View().Head
	}
	expectedHead := runScript(pTmp, false)

	reqA := ClaimRequest{
		GoalID: goalID, TaskID: taskA.ID(), WorkerID: protocolPublic(f.worker).ID(),
		RequestID: "attempt-a", ProtocolID: pTmp.View().ID, ExpectedGeneration: 0, LeaseUntilHeight: 30,
	}
	sigA := Sign(f.owner, ClaimSignatureDomain, reqA)

	taskB := v202MakeTask(goalID, "task-b", f, owner, TaskDependency{
		Input: "in-a", TaskID: taskA.ID(), ProtocolID: reqA.ProtocolID, Head: expectedHead,
		Slot: "answer", Digest: ansRef.Digest, Outcome: TaskAccepted,
	})
	rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{taskA, taskB}}
	if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tasks.store.withLock(taskB.ID(), func() error {
			close(lockHeld)
			<-releaseLock
			return nil
		})
	}()
	<-lockHeld

	baseLocks := tasks.Stats().LockAcquisitions
	type dgOut struct {
		disc []TaskDiscovery
		err  error
	}
	done := make(chan dgOut, 1)
	go func() {
		d, _, err := tasks.DiscoverGoal(goalID, 2)
		done <- dgOut{d, err}
	}()

	v202WaitForLockAdvance(t, tasks, baseLocks)

	// Legitimately Claim + complete + Finalize taskA while DiscoverGoal is paused on taskB.
	leaseA, err := tasks.Claim(reqA, sigA, specA, 2)
	if err != nil {
		close(releaseLock)
		t.Fatal(err)
	}
	pLive, err := NewProtocol(specA)
	if err != nil {
		close(releaseLock)
		t.Fatal(err)
	}
	headA := runScript(pLive, true)
	if headA != expectedHead {
		close(releaseLock)
		t.Fatalf("head mismatch %s != %s", headA, expectedHead)
	}
	if _, err := tasks.Finalize(leaseA, headA, 2); err != nil {
		close(releaseLock)
		t.Fatal(err)
	}
	close(releaseLock)
	wg.Wait()

	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if len(res.disc) != 2 {
		t.Fatalf("expected 2 discovered tasks, got %d", len(res.disc))
	}
	if res.disc[0].Status != "unclaimed" || res.disc[0].Generation != 0 {
		t.Fatalf("expected concurrent snapshot to show taskA unclaimed, got %+v", res.disc[0])
	}
	if res.disc[1].DependenciesReady {
		t.Fatalf("inconsistent snapshot: taskA={Status:%q Generation:%d} while dependent taskB={DependenciesReady:%v}",
			res.disc[0].Status, res.disc[0].Generation, res.disc[1].DependenciesReady)
	}

	// Next DiscoverGoal sees taskA accepted and taskB ready — also internally consistent.
	afterDisc, misses, err := tasks.DiscoverGoal(goalID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if misses != 1 || len(afterDisc) != 2 {
		t.Fatalf("after finalize: misses=%d len=%d", misses, len(afterDisc))
	}
	if afterDisc[0].Status != "accepted" || afterDisc[0].Generation != 1 || !afterDisc[1].DependenciesReady || afterDisc[1].DependenciesMismatch {
		t.Fatalf("expected accepted taskA and ready taskB, got %+v", afterDisc)
	}
}
