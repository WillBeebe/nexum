package nex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
)

const ClaimSignatureDomain = "coordination-claim/v1"

const taskCheckpointVersion = 1

var (
	ErrTaskBusy       = errors.New("nex: task has an active claim")
	ErrTaskClosed     = errors.New("nex: task already has an accepted result")
	ErrTaskStale      = errors.New("nex: stale task generation, lease, or head")
	ErrTaskDependency = errors.New("nex: task dependency is unavailable or differs from its pin")
	ErrTaskResult     = errors.New("nex: attempt does not satisfy the task")
)

// ClaimRequest authorizes a single worker and exact protocol specification.
// The task authority signs this request. The receiving host supplies the height.
type ClaimRequest struct {
	GoalID, TaskID, WorkerID, RequestID, ProtocolID string
	ExpectedGeneration, LeaseUntilHeight            uint64
}

// TaskLease identifies one generation. A destination that accepts work during
// a lease must enforce its generation atomically with the external mutation.
type TaskLease struct {
	GoalID, TaskID, ProtocolID, WorkerID, RequestID string
	Generation, LeaseUntilHeight                    uint64
}

type TaskArtifact struct{ Slot, Digest string }

// TaskResult is an immutable handoff. Only TaskAccepted authorizes a
// success dependency. Other outcomes can be pinned explicitly.
type TaskResult struct {
	Lease     TaskLease
	Head      string
	Outcome   TaskOutcome
	Artifacts []TaskArtifact
}

type taskCheckpoint struct {
	Version   int
	Lease     TaskLease
	ClaimHash string
	Results   map[string]TaskResult // keyed by attempt protocol ID, including past generations
}

type cachedTaskCheckpoint struct {
	meta        checkpointMeta
	plainDigest [32]byte // SHA-256 of AES-256-GCM-authenticated taskCheckpoint JSON read under s.store.withLocked(taskID)
	state       taskCheckpoint
}

func cloneTaskCheckpoint(in taskCheckpoint) taskCheckpoint {
	out := in
	if in.Results != nil {
		out.Results = make(map[string]TaskResult, len(in.Results))
		for k, v := range in.Results {
			v.Artifacts = slices.Clone(v.Artifacts)
			out.Results[k] = v
		}
	}
	return out
}

// TaskDiscovery is one task's admission snapshot for a trusted height.
type TaskDiscovery struct {
	Task                 TaskSpec
	TaskID               string
	Status               string // "unclaimed", "active", "reclaimable", "accepted"
	Generation           uint64
	LeaseUntilHeight     uint64
	DependenciesReady    bool
	DependenciesMismatch bool
}

// CoordinationStore coordinates tasks on a single authoritative host. It uses
// per-task locks and checkpoints, independently of the goal's plan and other
// attempts. Use separate private directories for these stores and a trusted
// monotone height source. Checkpoints are not distributed consensus.
const maxCachedTasks = 256

type CoordinationStore struct {
	store      *Store
	goals      *GoalStore
	attempts   *ProtocolStore
	mu         sync.Mutex
	cache      map[string]cachedTaskCheckpoint
	cacheOrder []string
}

func OpenCoordinationStore(dir string, key []byte, goals *GoalStore, attempts *ProtocolStore) (*CoordinationStore, error) {
	if goals == nil || attempts == nil {
		return nil, ErrTaskResult
	}
	store, err := OpenStore(dir, key)
	if err != nil {
		return nil, err
	}
	return &CoordinationStore{store: store, goals: goals, attempts: attempts, cache: make(map[string]cachedTaskCheckpoint)}, nil
}

func (s *CoordinationStore) Stats() StoreStats {
	if s == nil || s.store == nil {
		return StoreStats{}
	}
	return s.store.Stats()
}

func deriveTaskStatus(state taskCheckpoint, height uint64) string {
	for _, result := range state.Results {
		if result.Outcome == TaskAccepted {
			return "accepted"
		}
	}
	_, finalized := state.Results[state.Lease.ProtocolID]
	if state.Lease.Generation != 0 && height < state.Lease.LeaseUntilHeight && !finalized {
		return "active"
	}
	return "reclaimable"
}

func (s *CoordinationStore) loadWith(tx checkpointTx, goalID, taskID string) (taskCheckpoint, error) {
	raw, _, err := s.store.readEncryptedWithMeta(tx, taskID)
	if err != nil {
		return taskCheckpoint{}, err
	}
	s.store.replayValidationOps.Add(1)
	var state taskCheckpoint
	if json.Unmarshal(raw, &state) != nil || validateTaskCheckpoint(state, goalID, taskID) != nil {
		return taskCheckpoint{}, ErrCorruptStore
	}
	return state, nil
}

// loadAuthenticatedCached authenticates current stored ciphertext bytes under s.store.withLocked(taskID)
// before consulting s.cache. Cached deserialization/validation is reused ONLY when both checkpoint identity
// (file metadata or SQL version) and AES-256-GCM-authenticated plaintext SHA-256 match.
func (s *CoordinationStore) loadAuthenticatedCached(tx checkpointTx, goalID, taskID string) (state taskCheckpoint, fromCache bool, err error) {
	plainJSON, meta, err := s.store.readEncryptedWithMeta(tx, taskID)
	if err != nil {
		return taskCheckpoint{}, false, err
	}
	plainDigest := sha256.Sum256(plainJSON)
	s.mu.Lock()
	entry, hit := s.cache[taskID]
	s.mu.Unlock()
	if hit && entry.meta.same(meta) && entry.plainDigest == plainDigest {
		s.store.cacheHits.Add(1)
		return cloneTaskCheckpoint(entry.state), true, nil
	}
	s.store.cacheMisses.Add(1)
	s.store.replayValidationOps.Add(1)
	if json.Unmarshal(plainJSON, &state) != nil || validateTaskCheckpoint(state, goalID, taskID) != nil {
		return taskCheckpoint{}, false, ErrCorruptStore
	}
	s.mu.Lock()
	if _, existed := s.cache[taskID]; !existed {
		if len(s.cacheOrder) >= maxCachedTasks*2 {
			compacted := s.cacheOrder[:0]
			seen := make(map[string]struct{}, len(s.cache))
			for _, k := range s.cacheOrder {
				if _, live := s.cache[k]; live {
					if _, dup := seen[k]; !dup {
						seen[k] = struct{}{}
						compacted = append(compacted, k)
					}
				}
			}
			s.cacheOrder = compacted
		}
		for len(s.cache) >= maxCachedTasks && len(s.cacheOrder) > 0 {
			evict := s.cacheOrder[0]
			s.cacheOrder = s.cacheOrder[1:]
			delete(s.cache, evict)
		}
		s.cacheOrder = append(s.cacheOrder, taskID)
	}
	s.cache[taskID] = cachedTaskCheckpoint{
		meta:        meta,
		plainDigest: plainDigest,
		state:       cloneTaskCheckpoint(state),
	}
	s.mu.Unlock()
	return state, false, nil
}

// validateTaskCheckpoint checks every retained result, not only the current
// lease. At most one accepted task result is legal. Caller clocks do not
// decide expiry; height is a trusted monotone input at admission.
func validateTaskCheckpoint(state taskCheckpoint, goalID, taskID string) error {
	if state.Version != taskCheckpointVersion || state.Lease.TaskID != taskID || state.Lease.GoalID != goalID ||
		state.Lease.Generation == 0 || state.Results == nil || state.ClaimHash == "" {
		return ErrCorruptStore
	}
	accepted := 0
	for id, result := range state.Results {
		if id == "" || id != result.Lease.ProtocolID || result.Lease.GoalID != goalID || result.Lease.TaskID != taskID ||
			result.Lease.Generation == 0 || result.Head == "" {
			return ErrCorruptStore
		}
		switch result.Outcome {
		case TaskAccepted:
			accepted++
		case TaskRejected, TaskIncomplete:
		default:
			return ErrCorruptStore
		}
	}
	if accepted > 1 {
		return ErrCorruptStore
	}
	return nil
}

func (s *CoordinationStore) confirm() error {
	if err := s.store.syncDir(); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}

// Current returns the latest lease record, which may have expired or finished.
// Claim uses its generation for comparison. A missing record starts at zero.
func (s *CoordinationStore) Current(goalID, taskID string) (TaskLease, error) {
	var lease TaskLease
	err := s.store.withLocked(taskID, func(tx checkpointTx) error {
		state, err := s.loadWith(tx, goalID, taskID)
		if err != nil {
			return err
		}
		lease = state.Lease
		return s.confirm()
	})
	if err != nil {
		return TaskLease{}, err
	}
	return lease, nil
}

// StatusAt derives active, reclaimable, or accepted from a trusted height.
// It does not persist expiry. Current remains the latest lease record.
func (s *CoordinationStore) StatusAt(goalID, taskID string, height uint64) (string, error) {
	if height == 0 {
		return "", ErrTaskStale
	}
	var status string
	err := s.store.withLocked(taskID, func(tx checkpointTx) error {
		state, err := s.loadWith(tx, goalID, taskID)
		if err != nil {
			return err
		}
		status = deriveTaskStatus(state, height)
		return s.confirm()
	})
	return status, err
}

// DiscoverGoal snapshots task statuses and dependency readiness for goalID at height.
// Each existing task checkpoint is locked and AEAD-authenticated on every call; the second
// return value counts cache-miss checkpoint deserializations/validations (not OS lock acquisitions;
// inspect Stats() for LockAcquisitions, CheckpointReads, AuthDecryptOps, and DirSyncOps).
func (s *CoordinationStore) DiscoverGoal(goalID string, height uint64) ([]TaskDiscovery, int, error) {
	if height == 0 {
		return nil, 0, ErrTaskStale
	}
	plan, err := s.goals.View(goalID)
	if err != nil {
		return nil, 0, err
	}
	states := make(map[string]taskCheckpoint)
	cacheMissValidations := 0
	sawCheckpoint := false
	seen := make(map[string]bool)
	var tasks []TaskSpec
	for _, rev := range plan.Revisions {
		for _, t := range rev.Revision.Tasks {
			tid := t.ID()
			if seen[tid] {
				continue
			}
			seen[tid] = true
			tasks = append(tasks, t)
		}
	}
	out := make([]TaskDiscovery, 0, len(tasks))
	for _, t := range tasks {
		tid := t.ID()
		d := TaskDiscovery{Task: t, TaskID: tid, Status: "unclaimed"}
		err := s.store.withLocked(tid, func(tx checkpointTx) error {
			loaded, fromCache, err := s.loadAuthenticatedCached(tx, goalID, tid)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			sawCheckpoint = true
			if !fromCache {
				cacheMissValidations++
			}
			states[tid] = loaded
			d.Status = deriveTaskStatus(loaded, height)
			d.Generation = loaded.Lease.Generation
			d.LeaseUntilHeight = loaded.Lease.LeaseUntilHeight
			return nil
		})
		if err != nil {
			return nil, cacheMissValidations, err
		}
		out = append(out, d)
	}
	if sawCheckpoint {
		if err := s.confirm(); err != nil {
			return nil, cacheMissValidations, err
		}
	}
	for i := range out {
		t := out[i].Task
		ready := true
		mismatch := false
		for _, dep := range t.Dependencies {
			depState, ok := states[dep.TaskID]
			if !ok {
				if !seen[dep.TaskID] {
					return nil, cacheMissValidations, ErrCorruptStore
				}
				// Pass 1 already locked and inspected dep.TaskID and observed it as
				// unclaimed in this snapshot; do not redundantly call s.Result,
				// inflate cacheMissValidations, swallow storage errors, or tear the snapshot.
				ready = false
				continue
			}
			res, found := depState.Results[dep.ProtocolID]
			if !found {
				ready = false
				continue
			}
			if res.Head != dep.Head || res.Outcome != dep.Outcome ||
				!slices.Contains(res.Artifacts, TaskArtifact{Slot: dep.Slot, Digest: dep.Digest}) {
				ready = false
				mismatch = true
			}
		}
		out[i].DependenciesReady = ready
		out[i].DependenciesMismatch = mismatch
	}
	return out, cacheMissValidations, nil
}

// Result loads a committed handoff by its attempt ID. It remains available
// after another generation has claimed the task.
func (s *CoordinationStore) Result(goalID, taskID, protocolID string) (TaskResult, error) {
	var result TaskResult
	err := s.store.withLocked(taskID, func(tx checkpointTx) error {
		state, err := s.loadWith(tx, goalID, taskID)
		if err != nil {
			return err
		}
		var found bool
		result, found = state.Results[protocolID]
		if !found {
			return ErrNotFound
		}
		return s.confirm()
	})
	if err != nil {
		return TaskResult{}, err
	}
	return result, nil
}

func (s *CoordinationStore) checkDependencies(task TaskSpec) error {
	for _, dep := range task.Dependencies {
		result, err := s.Result(task.GoalID, dep.TaskID, dep.ProtocolID)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrTaskDependency, dep.Input)
		}
		if err != nil {
			return err
		}
		if result.Head != dep.Head || result.Outcome != dep.Outcome ||
			!slices.Contains(result.Artifacts, TaskArtifact{Slot: dep.Slot, Digest: dep.Digest}) {
			return fmt.Errorf("%w: %s", ErrTaskDependency, dep.Input)
		}
	}
	return nil
}

func checkAttempt(task TaskSpec, request ClaimRequest, spec ProtocolSpec) error {
	if spec.Version != ProtocolVersionV2 || spec.TaskID != request.TaskID ||
		spec.Generation == 0 || spec.Generation != request.ExpectedGeneration+1 ||
		spec.Initiator != task.Authority.ID() || spec.Purpose != task.Purpose ||
		spec.Scope != task.Scope || spec.SpecificationHash != task.SpecificationHash ||
		spec.AcceptanceHash != task.AcceptanceHash || spec.FailurePolicyHash != task.FailurePolicyHash ||
		!sameTaskSlots(task.Outputs, spec.Return.SuccessArtifacts) ||
		!sameTaskSlots(task.FailureOutputs, spec.Return.FailureArtifacts) ||
		spec.ReturnByHeight >= request.LeaseUntilHeight {
		return ErrTaskResult
	}
	for _, grant := range spec.Roles {
		if hasPermission(grant, PermitWork) && grant.Actor != request.WorkerID {
			return ErrTaskResult
		}
	}
	return nil
}

func sameTaskSlots(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, slot := range a {
		if !slices.Contains(b, slot) {
			return false
		}
	}
	return true
}

// Claim installs a lease with compare-and-swap on ExpectedGeneration. A task
// may be reclaimed when its current lease expires or ends without acceptance.
// An exact resend can recover a still-active claim.
func (s *CoordinationStore) Claim(request ClaimRequest, signature []byte, spec ProtocolSpec, height uint64) (TaskLease, error) {
	var lease TaskLease
	if height == 0 || request.ExpectedGeneration == ^uint64(0) || validateOperationID(request.RequestID) != nil {
		return lease, ErrTaskResult
	}
	task, err := s.goals.Task(request.GoalID, request.TaskID)
	if err != nil {
		return lease, err
	}
	if err := Verify(task.Authority, ClaimSignatureDomain, request, signature); err != nil {
		return lease, err
	}
	if err := checkAttempt(task, request, spec); err != nil {
		return lease, err
	}
	p, err := NewProtocol(spec)
	if err != nil {
		return lease, err
	}
	if p.view.ID != request.ProtocolID {
		return lease, ErrTaskResult
	}
	if err := s.checkDependencies(task); err != nil {
		return lease, err
	}
	claimHash := Hash(request)
	err = s.store.withLocked(request.TaskID, func(tx checkpointTx) error {
		state, err := s.loadWith(tx, request.GoalID, request.TaskID)
		if errors.Is(err, ErrNotFound) {
			state = taskCheckpoint{Version: taskCheckpointVersion, Results: make(map[string]TaskResult)}
		} else if err != nil {
			return err
		}

		result, finalized := state.Results[state.Lease.ProtocolID]
		active := state.Lease.Generation != 0 && height < state.Lease.LeaseUntilHeight && !finalized
		if active && state.ClaimHash == claimHash {
			lease = state.Lease
			return s.confirm()
		}
		for _, prior := range state.Results {
			if prior.Outcome == TaskAccepted {
				return ErrTaskClosed
			}
		}
		if state.Lease.Generation != request.ExpectedGeneration {
			return ErrTaskStale
		}
		if result.Outcome == TaskAccepted {
			return ErrTaskClosed
		}
		if active {
			return ErrTaskBusy
		}
		if height >= spec.WorkByHeight {
			return ErrTaskStale
		}

		// Create the agreement first. If the task write is interrupted, a retry
		// can reuse that exact agreement. An orphan cannot finalize a task.
		if _, err := s.attempts.createWithParent(tx, spec); err != nil && !errors.Is(err, ErrExists) {
			return err
		}
		if _, err := s.attempts.viewWithParent(tx, request.ProtocolID); err != nil {
			return err
		}
		lease = TaskLease{
			GoalID: request.GoalID, TaskID: request.TaskID, ProtocolID: request.ProtocolID,
			WorkerID: request.WorkerID, RequestID: request.RequestID,
			Generation: spec.Generation, LeaseUntilHeight: request.LeaseUntilHeight,
		}
		state.Lease = lease
		state.ClaimHash = claimHash
		s.mu.Lock()
		delete(s.cache, request.TaskID)
		s.mu.Unlock()
		if err := s.store.writeWith(tx, request.TaskID, state); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return TaskLease{}, err
	}
	return lease, nil
}

// Finalize reads the authoritative protocol and requires an explicit terminal
// outcome and matching head. This records the handoff; external effects belong
// to a destination that enforces the task's generation and resource precondition.
func (s *CoordinationStore) Finalize(lease TaskLease, expectedHead string, height uint64) (TaskResult, error) {
	var result TaskResult
	if height == 0 || !protocolHash(expectedHead) {
		return result, ErrTaskStale
	}
	task, err := s.goals.Task(lease.GoalID, lease.TaskID)
	if err != nil {
		return result, err
	}
	err = s.store.withLocked(lease.TaskID, func(tx checkpointTx) error {
		state, err := s.loadWith(tx, lease.GoalID, lease.TaskID)
		if err != nil {
			return err
		}
		if prior, found := state.Results[lease.ProtocolID]; found {
			if prior.Lease != lease || prior.Head != expectedHead {
				return ErrTaskStale
			}
			result = prior
			return s.confirm()
		}
		if state.Lease != lease || height >= lease.LeaseUntilHeight {
			return ErrTaskStale
		}
		view, err := s.attempts.viewWithParent(tx, lease.ProtocolID)
		if err != nil {
			return err
		}
		if view.Head != expectedHead || view.Height > height {
			return ErrTaskStale
		}
		result, err = taskResult(task, lease, view)
		if err != nil {
			return err
		}
		if result.Outcome == TaskAccepted {
			for id, prior := range state.Results {
				if id != lease.ProtocolID && prior.Outcome == TaskAccepted {
					return ErrTaskClosed
				}
			}
		}
		state.Results[lease.ProtocolID] = result
		s.mu.Lock()
		delete(s.cache, lease.TaskID)
		s.mu.Unlock()
		if err := s.store.writeWith(tx, lease.TaskID, state); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return TaskResult{}, err
	}
	return result, nil
}

func taskResult(task TaskSpec, lease TaskLease, view ProtocolView) (TaskResult, error) {
	result := TaskResult{Lease: lease, Head: view.Head}
	switch {
	case view.Phase == "incomplete" && view.Incomplete != nil:
		result.Outcome = TaskIncomplete
		for _, artifact := range view.Incomplete.Artifacts {
			if slices.Contains(task.Outputs, artifact.Name) || slices.Contains(task.FailureOutputs, artifact.Name) {
				result.Artifacts = append(result.Artifacts, TaskArtifact{Slot: artifact.Name, Digest: artifact.Ref.Digest})
			}
		}
	case view.Phase == "complete" && view.Resolution != nil && view.Return != nil:
		slots := task.Outputs
		switch view.Resolution.Outcome {
		case "accept":
			if view.Report == nil || view.Report.Manifest == nil {
				return TaskResult{}, ErrTaskResult
			}
			for _, dep := range task.Dependencies {
				if !slices.ContainsFunc(view.Report.Manifest.Inputs, func(input NamedArtifact) bool {
					return input.Name == dep.Input && input.Ref.Digest == dep.Digest
				}) {
					return TaskResult{}, fmt.Errorf("%w: report input %s", ErrTaskDependency, dep.Input)
				}
			}
			result.Outcome = TaskAccepted
		case "reject", "breach":
			result.Outcome = TaskRejected
			slots = task.FailureOutputs
		default:
			return TaskResult{}, ErrTaskResult
		}
		for _, artifact := range view.Return.Artifacts {
			if slices.Contains(slots, artifact.ID) {
				result.Artifacts = append(result.Artifacts, TaskArtifact{Slot: artifact.ID, Digest: artifact.Commitment})
			}
		}
	default:
		return TaskResult{}, ErrTaskResult
	}
	return result, nil
}
