package nex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func planFixture(t *testing.T) (Identity, GoalSpec, TaskSpec) {
	t.Helper()
	planner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public, err := planner.Public()
	if err != nil {
		t.Fatal(err)
	}
	goal := GoalSpec{
		Nonce: "product-cycle", Purpose: "Produce a reproducible answer and ship the verified change",
		ConstraintsHash: Hash("local fixtures"), CompletionPolicyHash: Hash("verified handoff"),
		Planners: []Public{public},
	}
	task := TaskSpec{
		GoalID: goal.ID(), Nonce: "first task", Purpose: "Produce the proposed change", Scope: "project/change",
		SpecificationHash: Hash("requirements"), AcceptanceHash: Hash("tested"), FailurePolicyHash: Hash("explain gaps"),
		Authority: public, Outputs: []string{"change"},
	}
	return planner, goal, task
}

func TestGoalStoreSignedRevisionsAndExactRetries(t *testing.T) {
	planner, goal, first := planFixture(t)
	key := bytes.Repeat([]byte{23}, 32)
	dir := filepath.Join(t.TempDir(), "goals")
	store, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil || id != goal.ID() {
		t.Fatal(id, err)
	}
	a := PlanRevision{GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "one", Tasks: []TaskSpec{first}}
	aSignature := Sign(planner, PlanSignatureDomain, a)
	head, err := store.Apply(a, aSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Task(id, first.ID()); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Nonce, second.Purpose = "second task", "Review the proposed change"
	second.Dependencies = []TaskDependency{{
		Input: "review input", TaskID: first.ID(), ProtocolID: Hash("attempt"), Head: Hash("return"),
		Slot: "change", Digest: Hash("patch"), Outcome: TaskAccepted,
	}}
	b := PlanRevision{GoalID: id, Head: id, Planner: a.Planner, RequestID: "two", Tasks: []TaskSpec{second}}
	if _, err = store.Apply(b, Sign(planner, PlanSignatureDomain, b)); !errors.Is(err, ErrPlanHead) {
		t.Fatal(err)
	}
	b.Head = head
	finalHead, err := store.Apply(b, Sign(planner, PlanSignatureDomain, b))
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if retried, err := reopened.Apply(a, aSignature); err != nil || retried != head {
		t.Fatal(retried, err)
	}
	a.Tasks = []TaskSpec{second}
	if _, err = reopened.Apply(a, Sign(planner, PlanSignatureDomain, a)); !errors.Is(err, ErrOperationConflict) {
		t.Fatal(err)
	}
	task, err := store.Task(id, second.ID())
	if err != nil || task.ID() != second.ID() {
		t.Fatal(task, err)
	}
	task.Dependencies[0].Digest = Hash("replacement")
	task, err = store.Task(id, second.ID())
	if err != nil || task.ID() != second.ID() {
		t.Fatal("returned task was not detached", err)
	}
	plan, err := reopened.View(id)
	if err != nil || len(plan.Revisions) != 2 {
		t.Fatal(plan.Head, err)
	}
	if err = VerifyGoalPlan(plan, id, finalHead); err != nil {
		t.Fatal(err)
	}
	plan.Revisions = plan.Revisions[:1]
	if err = VerifyGoalPlan(plan, id, finalHead); !errors.Is(err, ErrPlanHead) {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(reopened.store.path(id))
	if err != nil || bytes.Contains(contents, []byte(goal.Purpose)) {
		t.Fatal("goal checkpoint is not encrypted", err)
	}
}

func TestGoalStoreRejectsUnboundOrForwardDependencies(t *testing.T) {
	planner, goal, first := planFixture(t)
	store, err := OpenGoalStore(filepath.Join(t.TempDir(), "goals"), bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Nonce = "follow-on"
	dependency := TaskDependency{
		Input: "prior attempt", TaskID: first.ID(), ProtocolID: Hash("attempt"), Head: Hash("head"),
		Slot: "change", Digest: Hash("artifact"), Outcome: TaskIncomplete,
	}
	second.Dependencies = []TaskDependency{dependency}
	rev := PlanRevision{GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "one", Tasks: []TaskSpec{second, first}}
	apply := func() error {
		_, err := store.Apply(rev, Sign(planner, PlanSignatureDomain, rev))
		return err
	}
	if err = apply(); !errors.Is(err, ErrTaskSpec) {
		t.Fatal("forward dependency accepted", err)
	}
	rev.Tasks = []TaskSpec{first, second}
	second.Dependencies[0].Slot = "undeclared output"
	if err = apply(); !errors.Is(err, ErrTaskSpec) {
		t.Fatal("unknown output accepted", err)
	}
	second.Dependencies[0] = dependency
	second.Dependencies[0].Outcome = "*"
	if err = apply(); !errors.Is(err, ErrTaskSpec) {
		t.Fatal("wildcard outcome accepted", err)
	}
	second.Dependencies[0] = dependency
	second.Dependencies[0].Outcome = TaskRejected
	if err = apply(); !errors.Is(err, ErrTaskSpec) {
		t.Fatal("a success slot cannot satisfy a rejected dependency", err)
	}
	second.Dependencies[0] = dependency
	if _, err = store.Apply(rev, []byte("forged")); err == nil {
		t.Fatal("invalid planner signature accepted")
	}
	if err = apply(); err != nil {
		t.Fatal(err)
	}
}

func TestGoalStoreResendsAfterUncertainCommit(t *testing.T) {
	planner, goal, task := planFixture(t)
	dir := filepath.Join(t.TempDir(), "goals")
	key := bytes.Repeat([]byte{23}, 32)
	store, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	rev := PlanRevision{GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "one", Tasks: []TaskSpec{task}}
	signature := Sign(planner, PlanSignatureDomain, rev)
	store.store.commitHook = func(stage string) error {
		if stage == "after-rename" {
			return errors.New("injected directory sync failure")
		}
		return nil
	}
	head, err := store.Apply(rev, signature)
	if !errors.Is(err, ErrCommitUncertain) {
		t.Fatal(err)
	}
	reopened, err := OpenGoalStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := reopened.Apply(rev, signature)
	if err != nil || retried != head {
		t.Fatal(retried, err)
	}
	plan, err := reopened.View(id)
	if err != nil || len(plan.Revisions) != 1 {
		t.Fatal(plan.Head, err)
	}
}

func TestGoalSpecMultiPlannerScale(t *testing.T) {
	planners := make([]Public, 0, 32)
	for i := 0; i < 32; i++ {
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := id.Public()
		if err != nil {
			t.Fatal(err)
		}
		planners = append(planners, pub)
	}
	spec := GoalSpec{
		Nonce:                "multi-planner-32",
		Purpose:              "coordinate 32 independent planners on one shared goal",
		ConstraintsHash:      Hash("c"),
		CompletionPolicyHash: Hash("p"),
		Planners:             planners,
	}
	store, err := OpenGoalStore(filepath.Join(t.TempDir(), "goals"), bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(spec); err != nil {
		t.Fatalf("32 planners should be accepted, got %v", err)
	}

	tooMany := make([]Public, 0, maxPlanPlanners+1)
	for i := 0; i <= maxPlanPlanners; i++ {
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := id.Public()
		if err != nil {
			t.Fatal(err)
		}
		tooMany = append(tooMany, pub)
	}
	over := spec
	over.Nonce = "multi-planner-over"
	over.Planners = tooMany
	if _, err := store.Create(over); !errors.Is(err, ErrGoalSpec) {
		t.Fatalf("expected ErrGoalSpec above maxPlanPlanners=%d, got %v", maxPlanPlanners, err)
	}
}

func TestGoalPlanReadyTasksDAGScheduling(t *testing.T) {
	planner, goal, base := planFixture(t)
	store, err := OpenGoalStore(filepath.Join(t.TempDir(), "goals"), bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil {
		t.Fatal(err)
	}

	makeTask := func(nonce string, deps ...TaskDependency) TaskSpec {
		ts := base
		ts.Nonce = nonce
		ts.Purpose = "build " + nonce
		ts.Outputs = []string{"package"}
		ts.FailureOutputs = []string{"diagnostic"}
		ts.Dependencies = deps
		return ts
	}
	depOn := func(input string, upstream TaskSpec, outcome TaskOutcome) TaskDependency {
		slot := "package"
		if outcome == TaskRejected {
			slot = "diagnostic"
		}
		return TaskDependency{
			Input: input, TaskID: upstream.ID(), ProtocolID: Hash("proto:" + upstream.Nonce),
			Head: Hash("head:" + upstream.Nonce), Slot: slot, Digest: Hash("digest:" + upstream.Nonce),
			Outcome: outcome,
		}
	}

	// Build a diamond + straggler DAG:
	//   spec -> {crypto, query (slow straggler)}
	//   crypto -> wal (does NOT wait for slow query!)
	//   wal + query -> engine
	//   wal(rejected) -> wal_repair (only triggers on TaskRejected!)
	tSpec := makeTask("spec")
	tCrypto := makeTask("crypto", depOn("spec", tSpec, TaskAccepted))
	tQuery := makeTask("query", depOn("spec", tSpec, TaskAccepted))
	tWAL := makeTask("wal", depOn("spec", tSpec, TaskAccepted), depOn("crypto", tCrypto, TaskAccepted))
	tEngine := makeTask("engine", depOn("wal", tWAL, TaskAccepted), depOn("query", tQuery, TaskAccepted))
	tWALRepair := makeTask("wal-repair", depOn("wal_fail", tWAL, TaskRejected))

	rev := PlanRevision{
		GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "dag-v1",
		Tasks: []TaskSpec{tSpec, tCrypto, tQuery, tWAL, tEngine, tWALRepair},
	}
	head, err := store.Apply(rev, Sign(planner, PlanSignatureDomain, rev))
	if err != nil {
		t.Fatal(err)
	}
	// Apply must warm the Task cache so immediate lookups across parallel workers hit RAM cache.
	statsBefore := store.Stats()
	if _, err := store.Task(id, tEngine.ID()); err != nil {
		t.Fatal(err)
	}
	if store.Stats().CacheHits <= statsBefore.CacheHits {
		t.Fatalf("expected GoalStore.Apply to warm Task cache: before=%+v after=%+v", statsBefore, store.Stats())
	}

	plan, err := store.View(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGoalPlan(plan, id, head); err != nil {
		t.Fatal(err)
	}

	nonces := func(ts []TaskSpec) []string {
		out := make([]string, len(ts))
		for i, x := range ts {
			out[i] = x.Nonce
		}
		return out
	}

	completed := map[string]TaskOutcome{}
	if got := nonces(plan.ReadyTasks(completed)); len(got) != 1 || got[0] != "spec" {
		t.Fatalf("initial ready = %v, want [spec]", got)
	}

	// Completing spec unblocks both crypto and query.
	completed[tSpec.ID()] = TaskAccepted
	if got := nonces(plan.ReadyTasks(completed)); len(got) != 2 || got[0] != "crypto" || got[1] != "query" {
		t.Fatalf("after spec ready = %v, want [crypto query]", got)
	}

	// Completing crypto IMMEDIATELY unblocks wal WITHOUT waiting for slow straggler query!
	completed[tCrypto.ID()] = TaskAccepted
	if got := nonces(plan.ReadyTasks(completed)); len(got) != 2 || got[0] != "query" || got[1] != "wal" {
		t.Fatalf("after crypto ready = %v, want [query wal]", got)
	}

	// Verify returned TaskSpec slices are detached from plan.
	readyDetached := plan.ReadyTasks(completed)
	readyDetached[0].Dependencies[0].Digest = Hash("mutated")
	if plan.ReadyTasks(completed)[0].Dependencies[0].Digest == Hash("mutated") {
		t.Fatal("ReadyTasks returned shared mutable dependency slice")
	}

	// If wal is rejected, wal-repair unblocks while engine stays blocked.
	completed[tWAL.ID()] = TaskRejected
	if got := nonces(plan.ReadyTasks(completed)); len(got) != 2 || got[0] != "query" || got[1] != "wal-repair" {
		t.Fatalf("after wal rejected ready = %v, want [query wal-repair]", got)
	}

	// If wal and query are both accepted, engine unblocks and wal-repair does not.
	completed[tWAL.ID()] = TaskAccepted
	completed[tQuery.ID()] = TaskAccepted
	if got := nonces(plan.ReadyTasks(completed)); len(got) != 1 || got[0] != "engine" {
		t.Fatalf("after wal+query accepted ready = %v, want [engine]", got)
	}
}

func TestGoalStoreApplyClonesCallerSlices(t *testing.T) {
	planner, goal, first := planFixture(t)
	store, err := OpenGoalStore(filepath.Join(t.TempDir(), "goals"), bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	taskCopy := first
	taskCopy.Outputs = []string{"artifact-a"}
	wantID := taskCopy.ID()
	rev := PlanRevision{
		GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "clone-check",
		Tasks: []TaskSpec{taskCopy},
	}
	sig := Sign(planner, PlanSignatureDomain, rev)
	if _, err := store.Apply(rev, sig); err != nil {
		t.Fatal(err)
	}
	// Mutating caller slices after Apply must not corrupt the cached GoalStore record.
	rev.Tasks[0].Outputs[0] = "corrupted"
	sig[0] ^= 0xff
	got, err := store.Task(id, wantID)
	if err != nil {
		t.Fatalf("Task after caller slice mutation failed: %v", err)
	}
	if len(got.Outputs) != 1 || got.Outputs[0] != "artifact-a" {
		t.Fatalf("cached Task outputs mutated via caller alias: %v", got.Outputs)
	}
}

func TestGoalStoreLoadRejectsDivergentHead(t *testing.T) {
	planner, goal, first := planFixture(t)
	store, err := OpenGoalStore(filepath.Join(t.TempDir(), "goals"), bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	rev := PlanRevision{GoalID: id, Head: id, Planner: goal.Planners[0].ID(), RequestID: "r1", Tasks: []TaskSpec{first}}
	if _, err := store.Apply(rev, Sign(planner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	// Corrupt the stored record's Plan.Head so it diverges from Revisions[0].Head().
	if err := store.store.withLocked(id, func(tx checkpointTx) error {
		record, err := store.loadWith(tx, id)
		if err != nil {
			return err
		}
		record.Plan.Head = Hash("divergent-head")
		return store.store.writeWith(tx, id, record)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("View with divergent Plan.Head got %v, want ErrCorruptStore", err)
	}
}
