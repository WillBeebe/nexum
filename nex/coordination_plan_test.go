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
