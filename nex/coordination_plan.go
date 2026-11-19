package nex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sync/atomic"
	"unicode/utf8"
)

const PlanSignatureDomain = "coordination-plan/v1"

const (
	goalRecordVersion = 1
	maxPlanPlanners   = 256
	maxPlanTasks      = 64
	maxPlanRevision   = 1 << 20
)

var (
	ErrGoalSpec = errors.New("nex: invalid goal specification")
	ErrTaskSpec = errors.New("nex: invalid task specification or dependency")
	ErrPlan     = errors.New("nex: invalid plan revision")
	ErrPlanHead = errors.New("nex: plan head has advanced")
)

// GoalSpec fixes the shared purpose and which signing identities can extend the
// plan. Distribute and pin its ID through a trusted channel before accepting
// revisions. An application's admission policy establishes who owns each key.
type GoalSpec struct {
	Nonce, Purpose, ConstraintsHash, CompletionPolicyHash string
	Planners                                              []Public
}

func (s GoalSpec) ID() string {
	return Hash(struct {
		Domain string
		Spec   GoalSpec
	}{"coordination-goal/v1", s})
}

func (s GoalSpec) validate() error {
	if !coordinationText(s.Nonce) || !coordinationText(s.Purpose) ||
		!protocolHash(s.ConstraintsHash) || !protocolHash(s.CompletionPolicyHash) ||
		len(s.Planners) == 0 || len(s.Planners) > maxPlanPlanners {
		return ErrGoalSpec
	}
	signers := make(map[string]bool, len(s.Planners))
	for _, planner := range s.Planners {
		if planner.Validate() != nil || signers[string(planner.Signing)] {
			return ErrGoalSpec
		}
		signers[string(planner.Signing)] = true
	}
	return nil
}

type TaskOutcome string

const (
	TaskAccepted   TaskOutcome = "accepted"
	TaskRejected   TaskOutcome = "rejected"
	TaskIncomplete TaskOutcome = "incomplete"
)

// TaskDependency binds one named input to an exact returned artifact. Outcome
// is mandatory, including when consuming a rejected or incomplete attempt.
type TaskDependency struct {
	Input, TaskID, ProtocolID, Head, Slot, Digest string
	Outcome                                       TaskOutcome
}

// TaskSpec is an immutable contribution to a goal. Its policy hashes commit to
// application-defined terms. Outputs and FailureOutputs name the artifact
// slots that downstream tasks can reference for the corresponding outcome.
type TaskSpec struct {
	GoalID, Nonce, Purpose, Scope                        string
	SpecificationHash, AcceptanceHash, FailurePolicyHash string
	Authority                                            Public
	Outputs, FailureOutputs                              []string
	Dependencies                                         []TaskDependency
}

func (s TaskSpec) ID() string {
	return Hash(struct {
		Domain string
		Spec   TaskSpec
	}{"coordination-task/v1", s})
}

func (s TaskSpec) validate(goalID string) error {
	if s.GoalID != goalID || !coordinationText(s.Nonce) || !coordinationText(s.Purpose) ||
		!coordinationText(s.Scope) || !protocolHash(s.SpecificationHash) ||
		!protocolHash(s.AcceptanceHash) || !protocolHash(s.FailurePolicyHash) ||
		s.Authority.Validate() != nil || !uniqueStrings(s.Outputs, 32, coordinationName) ||
		!uniqueStrings(s.FailureOutputs, 32, coordinationName) ||
		len(s.Dependencies) > 64 {
		return ErrTaskSpec
	}
	inputs := make(map[string]bool, len(s.Dependencies))
	for _, dep := range s.Dependencies {
		if !coordinationName(dep.Input) || inputs[dep.Input] || !coordinationName(dep.Slot) ||
			!protocolHash(dep.TaskID) || !protocolHash(dep.ProtocolID) ||
			!protocolHash(dep.Head) || !protocolHash(dep.Digest) ||
			(dep.Outcome != TaskAccepted && dep.Outcome != TaskRejected && dep.Outcome != TaskIncomplete) {
			return ErrTaskSpec
		}
		inputs[dep.Input] = true
	}
	return nil
}

func coordinationText(s string) bool { return small(s) && utf8.ValidString(s) }

func coordinationName(s string) bool { return validateOperationID(s) == nil }

// PlanRevision adds immutable tasks. A dependency can reference a task in a
// prior revision or earlier in this revision. The initial head is the goal ID.
type PlanRevision struct {
	GoalID, Head, Planner, RequestID string
	Tasks                            []TaskSpec
}

type SignedPlanRevision struct {
	Revision  PlanRevision
	Signature []byte
}

func (r SignedPlanRevision) Head() string { return Hash(r) }

// GoalPlan is the complete signed history of task definitions for one goal.
type GoalPlan struct {
	Spec      GoalSpec
	Head      string
	Revisions []SignedPlanRevision
}

type goalTaskLocation struct {
	Revision, Task int
}

type goalRecord struct {
	Version  int
	Plan     GoalPlan
	Tasks    map[string]goalTaskLocation
	Requests map[string]int
}

func newGoalRecord(spec GoalSpec) goalRecord {
	return goalRecord{
		Version:  goalRecordVersion,
		Plan:     GoalPlan{Spec: spec, Head: spec.ID()},
		Tasks:    make(map[string]goalTaskLocation),
		Requests: make(map[string]int),
	}
}

func (r goalRecord) task(id string) (TaskSpec, bool) {
	location, ok := r.Tasks[id]
	if !ok || location.Revision < 0 || location.Revision >= len(r.Plan.Revisions) {
		return TaskSpec{}, false
	}
	tasks := r.Plan.Revisions[location.Revision].Revision.Tasks
	if location.Task < 0 || location.Task >= len(tasks) {
		return TaskSpec{}, false
	}
	return tasks[location.Task], true
}

func (r *goalRecord) apply(goalID string, signed SignedPlanRevision) (head string, advanced bool, err error) {
	rev := signed.Revision
	if rev.GoalID != goalID || !protocolHash(rev.Head) || validateOperationID(rev.RequestID) != nil ||
		len(rev.Tasks) == 0 || len(rev.Tasks) > maxPlanTasks {
		return "", false, ErrPlan
	}
	raw, err := json.Marshal(signed)
	if err != nil || len(raw) > maxPlanRevision {
		return "", false, ErrPlan
	}
	var authorized bool
	for _, planner := range r.Plan.Spec.Planners {
		if planner.ID() == rev.Planner {
			if err := Verify(planner, PlanSignatureDomain, rev, signed.Signature); err != nil {
				return "", false, err
			}
			authorized = true
			break
		}
	}
	if !authorized {
		return "", false, ErrProtocolAuthority
	}
	request := rev.Planner + "/" + rev.RequestID
	if index, found := r.Requests[request]; found {
		if index < 0 || index >= len(r.Plan.Revisions) {
			return "", false, ErrCorruptStore
		}
		old := r.Plan.Revisions[index]
		if !reflect.DeepEqual(old.Revision, rev) || !bytes.Equal(old.Signature, signed.Signature) {
			return "", false, ErrOperationConflict
		}
		return old.Head(), false, nil
	}
	if rev.Head != r.Plan.Head {
		return "", false, ErrPlanHead
	}

	added := make(map[string]int, len(rev.Tasks))
	for i, task := range rev.Tasks {
		if err := task.validate(goalID); err != nil {
			return "", false, err
		}
		id := task.ID()
		if _, exists := r.Tasks[id]; exists {
			return "", false, ErrTaskSpec
		}
		if _, exists := added[id]; exists {
			return "", false, ErrTaskSpec
		}
		for _, dep := range task.Dependencies {
			upstream, ok := r.task(dep.TaskID)
			if index, exists := added[dep.TaskID]; exists {
				upstream, ok = rev.Tasks[index], true
			}
			if !ok || !upstream.hasOutput(dep.Slot, dep.Outcome) {
				return "", false, ErrTaskSpec
			}
		}
		added[id] = i
	}
	index := len(r.Plan.Revisions)
	for id, i := range added {
		r.Tasks[id] = goalTaskLocation{Revision: index, Task: i}
	}
	head = signed.Head()
	r.Requests[request] = index
	r.Plan.Head = head
	r.Plan.Revisions = append(r.Plan.Revisions, signed)
	return head, true, nil
}

func (s TaskSpec) hasOutput(slot string, outcome TaskOutcome) bool {
	switch outcome {
	case TaskAccepted:
		return slices.Contains(s.Outputs, slot)
	case TaskRejected:
		return slices.Contains(s.FailureOutputs, slot)
	case TaskIncomplete:
		return slices.Contains(s.Outputs, slot) || slices.Contains(s.FailureOutputs, slot)
	default:
		return false
	}
}

// VerifyGoalPlan checks the signed revision chain against independently pinned
// goal and head IDs. An older valid prefix is not proof of the current head.
func VerifyGoalPlan(plan GoalPlan, expectedGoalID, expectedHead string) error {
	if err := plan.Spec.validate(); err != nil {
		return err
	}
	record := newGoalRecord(plan.Spec)
	if record.Plan.Head != expectedGoalID || plan.Head != expectedHead {
		return ErrPlanHead
	}
	for _, signed := range plan.Revisions {
		_, advanced, err := record.apply(expectedGoalID, signed)
		if err != nil {
			return err
		}
		if !advanced {
			return ErrPlan
		}
	}
	if record.Plan.Head != expectedHead {
		return ErrPlanHead
	}
	return nil
}

// GoalStore holds encrypted, atomically replaced plan checkpoints. The local
// goal owner authenticates revisions before adding them. Task lookups reuse
// the most recently loaded immutable index across append-only revisions.
// Open a new handle when restoring a backup.
type GoalStore struct {
	store  *Store
	cached atomic.Pointer[cachedGoal]
}

type cachedGoal struct {
	id     string
	record goalRecord
}

func OpenGoalStore(dir string, key []byte) (*GoalStore, error) {
	store, err := OpenStore(dir, key)
	if err != nil {
		return nil, err
	}
	return &GoalStore{store: store}, nil
}

func (s *GoalStore) Stats() StoreStats {
	if s == nil || s.store == nil {
		return StoreStats{}
	}
	return s.store.Stats()
}

func (s *GoalStore) load(id string) (goalRecord, error) {
	var record goalRecord
	raw, err := s.store.readEncrypted(id)
	if err != nil {
		return record, err
	}
	s.store.replayValidationOps.Add(1)
	if json.Unmarshal(raw, &record) != nil || record.Version != goalRecordVersion ||
		record.Plan.Spec.ID() != id || !protocolHash(record.Plan.Head) ||
		record.Tasks == nil || record.Requests == nil || len(record.Requests) != len(record.Plan.Revisions) {
		return record, ErrCorruptStore
	}
	return record, nil
}

func (s *GoalStore) Create(spec GoalSpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	record := newGoalRecord(spec)
	id := record.Plan.Head
	err := s.store.withLock(id, func() error {
		if _, err := os.Lstat(s.store.path(id)); err == nil {
			if _, err := s.load(id); err != nil {
				return err
			}
			return s.confirmPlan()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return s.store.write(id, record)
	})
	return id, err
}

func (s *GoalStore) confirmPlan() error {
	if err := s.store.syncDir(); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}

// Apply commits a planner-signed revision using head compare-and-swap. Exact
// resends return their original revision head even after later revisions.
func (s *GoalStore) Apply(rev PlanRevision, signature []byte) (string, error) {
	var head string
	err := s.store.withLock(rev.GoalID, func() error {
		record, err := s.load(rev.GoalID)
		if err != nil {
			return err
		}
		var advanced bool
		head, advanced, err = record.apply(rev.GoalID, SignedPlanRevision{rev, signature})
		if err != nil {
			return err
		}
		if !advanced {
			return s.confirmPlan()
		}
		return s.store.write(rev.GoalID, record)
	})
	return head, err
}

func (s *GoalStore) Task(goalID, taskID string) (TaskSpec, error) {
	if cached := s.cached.Load(); cached != nil && cached.id == goalID {
		if task, ok := cached.record.task(taskID); ok {
			s.store.cacheHits.Add(1)
			return detachedTask(task, goalID, taskID)
		}
	}
	s.store.cacheMisses.Add(1)
	var task TaskSpec
	err := s.store.withLock(goalID, func() error {
		record, err := s.load(goalID)
		if err != nil {
			return err
		}
		var ok bool
		task, ok = record.task(taskID)
		if !ok {
			return ErrNotFound
		}
		if err := s.confirmPlan(); err != nil {
			return err
		}
		s.cached.Store(&cachedGoal{id: goalID, record: record})
		return nil
	})
	if err != nil {
		return TaskSpec{}, err
	}
	return detachedTask(task, goalID, taskID)
}

func detachedTask(task TaskSpec, goalID, taskID string) (TaskSpec, error) {
	if task.ID() != taskID || task.GoalID != goalID {
		return TaskSpec{}, ErrCorruptStore
	}
	task.Authority.Signing = slices.Clone(task.Authority.Signing)
	task.Authority.Encryption = slices.Clone(task.Authority.Encryption)
	task.Outputs = slices.Clone(task.Outputs)
	task.FailureOutputs = slices.Clone(task.FailureOutputs)
	task.Dependencies = slices.Clone(task.Dependencies)
	return task, nil
}

func (s *GoalStore) View(goalID string) (GoalPlan, error) {
	var plan GoalPlan
	err := s.store.withLock(goalID, func() error {
		record, err := s.load(goalID)
		if err != nil {
			return err
		}
		plan = record.Plan
		return s.confirmPlan()
	})
	return plan, err
}
