package nex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

const (
	maxPlanGates            = 32
	maxTaskGateDependencies = 64
	gateCheckpointVersion   = 1
	maxCachedGates          = 256
)

// AccordGate binds a named coordination gate in a goal plan to an immutable
// pinned AccordSpec ID and optional allowlist of permitted winning option IDs.
type AccordGate struct {
	ID             string   `json:"id"`
	GoalID         string   `json:"goal_id"`
	AccordID       string   `json:"accord_id"`
	Purpose        string   `json:"purpose"`
	AllowedOptions []string `json:"allowed_options,omitempty"`
}

// TaskGateDependency binds a task to an explicit terminal AccordGate outcome.
type TaskGateDependency struct {
	GateID                 string         `json:"gate_id"`
	RequiredPhase          AccordPhase    `json:"required_phase"`
	OptionID               string         `json:"option_id,omitempty"`
	ExpectedCommitment     string         `json:"expected_commitment,omitempty"`
	ExpectedDeadlockReason DeadlockReason `json:"expected_deadlock_reason,omitempty"`
}

type goalGateLocation struct {
	Revision, Gate int
}

// GateResolution is the authenticated, persisted terminal resolution of an
// AccordGate recorded from an offline-verified AccordBundle.
type GateResolution struct {
	GoalID            string         `json:"goal_id"`
	GateID            string         `json:"gate_id"`
	AccordID          string         `json:"accord_id"`
	Head              string         `json:"head"`
	Phase             AccordPhase    `json:"phase"`
	WinningOptionID   string         `json:"winning_option_id,omitempty"`
	WinningCommitment string         `json:"winning_commitment,omitempty"`
	DeadlockReason    DeadlockReason `json:"deadlock_reason,omitempty"`
	OutcomeHash       string         `json:"outcome_hash"`
	ResolvedAtHeight  uint64         `json:"resolved_at_height"`
}

type gateCheckpoint struct {
	Version    int
	Resolution GateResolution
}

type cachedGateCheckpoint struct {
	meta        checkpointMeta
	plainDigest [32]byte
	resolution  GateResolution
}

func gateRecordKey(goalID, gateID string) string {
	return Hash(struct {
		Domain string
		GoalID string
		GateID string
	}{"coordination-gate-record/v1", goalID, gateID})
}

func validAccordGateStrings(g AccordGate) bool {
	if !validUTF8NoControl(g.ID) || !validUTF8NoControl(g.GoalID) ||
		!validUTF8NoControl(g.AccordID) || !validUTF8NoControl(g.Purpose) {
		return false
	}
	for _, opt := range g.AllowedOptions {
		if !validUTF8NoControl(opt) {
			return false
		}
	}
	return true
}

func (g AccordGate) validate(goalID string) error {
	if !validAccordGateStrings(g) {
		return ErrPlan
	}
	if !coordinationName(g.ID) || g.GoalID != goalID || !protocolHash(g.GoalID) ||
		!protocolHash(g.AccordID) || !coordinationText(g.Purpose) ||
		!uniqueStrings(g.AllowedOptions, maxAccordOptions, validAccordID) {
		return ErrPlan
	}
	return nil
}

func cloneAccordGate(g AccordGate) AccordGate {
	out := g
	out.AllowedOptions = slices.Clone(g.AllowedOptions)
	return out
}

func validTaskGateDependenciesStrings(deps []TaskGateDependency) bool {
	for _, dep := range deps {
		if !validUTF8NoControl(dep.GateID) || !validUTF8NoControl(string(dep.RequiredPhase)) ||
			!validUTF8NoControl(dep.OptionID) || !validUTF8NoControl(dep.ExpectedCommitment) ||
			!validUTF8NoControl(string(dep.ExpectedDeadlockReason)) {
			return false
		}
	}
	return true
}

func isTerminalAccordPhase(phase AccordPhase) bool {
	switch phase {
	case AccordPhaseDecided, AccordPhaseDeadlocked, AccordPhaseExpired:
		return true
	default:
		return false
	}
}

func validDeadlockReason(reason DeadlockReason) bool {
	switch reason {
	case DeadlockNoQuorum,
		DeadlockNoOptions,
		DeadlockAllDisqualifiedByEvidence,
		DeadlockAllVetoed,
		DeadlockNoThresholdMet,
		DeadlockTie:
		return true
	default:
		return false
	}
}

func validateTaskGateDependencies(deps []TaskGateDependency) error {
	if !validTaskGateDependenciesStrings(deps) || len(deps) > maxTaskGateDependencies {
		return ErrTaskSpec
	}
	seenGates := make(map[string]bool, len(deps))
	for _, dep := range deps {
		if !coordinationName(dep.GateID) || seenGates[dep.GateID] || !isTerminalAccordPhase(dep.RequiredPhase) {
			return ErrTaskSpec
		}
		seenGates[dep.GateID] = true

		switch dep.RequiredPhase {
		case AccordPhaseDecided:
			if !validAccordID(dep.OptionID) || dep.ExpectedDeadlockReason != "" {
				return ErrTaskSpec
			}
			if dep.ExpectedCommitment != "" && !protocolHash(dep.ExpectedCommitment) {
				return ErrTaskSpec
			}
		case AccordPhaseDeadlocked:
			if dep.OptionID != "" || dep.ExpectedCommitment != "" {
				return ErrTaskSpec
			}
			if dep.ExpectedDeadlockReason != "" && !validDeadlockReason(dep.ExpectedDeadlockReason) {
				return ErrTaskSpec
			}
		case AccordPhaseExpired:
			if dep.OptionID != "" || dep.ExpectedCommitment != "" || dep.ExpectedDeadlockReason != "" {
				return ErrTaskSpec
			}
		default:
			return ErrTaskSpec
		}
	}
	return nil
}

func normalizePlanRevisionForCompare(rev PlanRevision) PlanRevision {
	out := rev
	if len(out.Gates) == 0 {
		out.Gates = nil
	} else {
		gates := make([]AccordGate, len(out.Gates))
		for i, g := range out.Gates {
			cg := g
			if len(cg.AllowedOptions) == 0 {
				cg.AllowedOptions = nil
			}
			gates[i] = cg
		}
		out.Gates = gates
	}
	if len(out.Tasks) > 0 {
		tasks := make([]TaskSpec, len(out.Tasks))
		for i, t := range out.Tasks {
			ct := t
			if len(ct.GateDependencies) == 0 {
				ct.GateDependencies = nil
			}
			tasks[i] = ct
		}
		out.Tasks = tasks
	}
	return out
}

func samePlanRevision(a, b PlanRevision) bool {
	return reflect.DeepEqual(normalizePlanRevisionForCompare(a), normalizePlanRevisionForCompare(b))
}

func detachedGate(gate AccordGate, goalID, gateID string) (AccordGate, error) {
	if gate.ID != gateID || gate.GoalID != goalID || gate.validate(goalID) != nil {
		return AccordGate{}, ErrCorruptStore
	}
	return cloneAccordGate(gate), nil
}

// Gate returns a detached copy of gateID from goalID's signed plan,
// leveraging GoalStore's cache safely and returning ErrNotFound if absent.
func (s *GoalStore) Gate(goalID, gateID string) (AccordGate, error) {
	if err := validateStoreID(goalID); err != nil {
		return AccordGate{}, err
	}
	if !coordinationName(gateID) || !validUTF8NoControl(gateID) {
		return AccordGate{}, ErrPlan
	}
	if cached := s.cached.Load(); cached != nil && cached.id == goalID {
		if gate, ok := cached.record.gate(gateID); ok {
			s.store.cacheHits.Add(1)
			return detachedGate(gate, goalID, gateID)
		}
	}
	s.store.cacheMisses.Add(1)
	var gate AccordGate
	err := s.store.withLocked(goalID, func(tx checkpointTx) error {
		record, err := s.loadWith(tx, goalID)
		if err != nil {
			return err
		}
		var ok bool
		gate, ok = record.gate(gateID)
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
		return AccordGate{}, err
	}
	return detachedGate(gate, goalID, gateID)
}

func validateGateResolution(res GateResolution, goalID, gateID, expectedAccordID string) error {
	if !validUTF8NoControl(res.GoalID) || !validUTF8NoControl(res.GateID) ||
		!validUTF8NoControl(res.AccordID) || !validUTF8NoControl(res.Head) ||
		!validUTF8NoControl(string(res.Phase)) || !validUTF8NoControl(res.WinningOptionID) ||
		!validUTF8NoControl(res.WinningCommitment) || !validUTF8NoControl(string(res.DeadlockReason)) ||
		!validUTF8NoControl(res.OutcomeHash) {
		return ErrCorruptStore
	}
	if res.GoalID != goalID || !protocolHash(res.GoalID) ||
		res.GateID != gateID || !coordinationName(res.GateID) ||
		!protocolHash(res.AccordID) || !protocolHash(res.Head) ||
		!protocolHash(res.OutcomeHash) || res.ResolvedAtHeight == 0 {
		return ErrCorruptStore
	}
	if expectedAccordID != "" && res.AccordID != expectedAccordID {
		return ErrCorruptStore
	}
	switch res.Phase {
	case AccordPhaseDecided:
		if !validAccordID(res.WinningOptionID) || !protocolHash(res.WinningCommitment) || res.DeadlockReason != "" {
			return ErrCorruptStore
		}
	case AccordPhaseDeadlocked:
		if res.WinningOptionID != "" || res.WinningCommitment != "" || !validDeadlockReason(res.DeadlockReason) {
			return ErrCorruptStore
		}
	case AccordPhaseExpired:
		if res.WinningOptionID != "" || res.WinningCommitment != "" || res.DeadlockReason != "" {
			return ErrCorruptStore
		}
	default:
		return ErrCorruptStore
	}
	return nil
}

func validateGateCheckpoint(cp gateCheckpoint, goalID, gateID, expectedAccordID string) error {
	if cp.Version != gateCheckpointVersion {
		return ErrCorruptStore
	}
	return validateGateResolution(cp.Resolution, goalID, gateID, expectedAccordID)
}

func (s *CoordinationStore) loadGateWith(tx checkpointTx, goalID, gateID string) (GateResolution, error) {
	key := gateRecordKey(goalID, gateID)
	raw, _, err := s.store.readEncryptedWithMeta(tx, key)
	if err != nil {
		return GateResolution{}, err
	}
	s.store.replayValidationOps.Add(1)
	var cp gateCheckpoint
	if json.Unmarshal(raw, &cp) != nil || validateGateCheckpoint(cp, goalID, gateID, "") != nil {
		return GateResolution{}, ErrCorruptStore
	}
	return cp.Resolution, nil
}

func (s *CoordinationStore) loadGateAuthenticatedCached(tx checkpointTx, goalID, gateID, expectedAccordID string) (res GateResolution, fromCache bool, err error) {
	key := gateRecordKey(goalID, gateID)
	plainJSON, meta, err := s.store.readEncryptedWithMeta(tx, key)
	if err != nil {
		return GateResolution{}, false, err
	}
	plainDigest := sha256.Sum256(plainJSON)
	s.mu.Lock()
	entry, hit := s.gateCache[key]
	s.mu.Unlock()
	if hit && entry.meta.same(meta) && entry.plainDigest == plainDigest {
		if validateGateResolution(entry.resolution, goalID, gateID, expectedAccordID) != nil {
			return GateResolution{}, false, ErrCorruptStore
		}
		s.store.cacheHits.Add(1)
		return entry.resolution, true, nil
	}
	s.store.cacheMisses.Add(1)
	s.store.replayValidationOps.Add(1)
	var cp gateCheckpoint
	if json.Unmarshal(plainJSON, &cp) != nil || validateGateCheckpoint(cp, goalID, gateID, expectedAccordID) != nil {
		return GateResolution{}, false, ErrCorruptStore
	}
	s.mu.Lock()
	if s.gateCache == nil {
		s.gateCache = make(map[string]cachedGateCheckpoint)
	}
	if _, existed := s.gateCache[key]; !existed {
		if len(s.gateCacheOrder) >= maxCachedGates*2 {
			compacted := s.gateCacheOrder[:0]
			seen := make(map[string]struct{}, len(s.gateCache))
			for _, k := range s.gateCacheOrder {
				if _, live := s.gateCache[k]; live {
					if _, dup := seen[k]; !dup {
						seen[k] = struct{}{}
						compacted = append(compacted, k)
					}
				}
			}
			s.gateCacheOrder = compacted
		}
		for len(s.gateCache) >= maxCachedGates && len(s.gateCacheOrder) > 0 {
			evict := s.gateCacheOrder[0]
			s.gateCacheOrder = s.gateCacheOrder[1:]
			delete(s.gateCache, evict)
		}
		s.gateCacheOrder = append(s.gateCacheOrder, key)
	}
	s.gateCache[key] = cachedGateCheckpoint{
		meta:        meta,
		plainDigest: plainDigest,
		resolution:  cp.Resolution,
	}
	s.mu.Unlock()
	return cp.Resolution, false, nil
}

func (s *CoordinationStore) invalidateGateCacheLocked(key string) {
	s.mu.Lock()
	delete(s.gateCache, key)
	s.mu.Unlock()
}

// RecordAccord offline-verifies bundle against the goal's pinned AccordGate and
// expectedHead, enforces terminal phase and AllowedOptions, and durably persists
// the resulting GateResolution. Exact retries confirm durability and return the
// persisted GateResolution; conflicting terminal heads return ErrOperationConflict.
func (s *CoordinationStore) RecordAccord(goalID, gateID string, bundle AccordBundle, expectedHead string) (GateResolution, error) {
	gate, err := s.goals.Gate(goalID, gateID)
	if err != nil {
		return GateResolution{}, err
	}
	view, err := VerifyAccordBundle(bundle, gate.AccordID, expectedHead)
	if err != nil {
		return GateResolution{}, err
	}
	if view.Outcome == nil || view.Outcome.Phase != view.Phase || !isTerminalAccordPhase(view.Phase) {
		return GateResolution{}, fmt.Errorf("%w: accord phase %q is not terminal", ErrAccordPhase, view.Phase)
	}
	if view.Phase == AccordPhaseDecided && len(gate.AllowedOptions) > 0 &&
		!slices.Contains(gate.AllowedOptions, view.Outcome.WinningOptionID) {
		return GateResolution{}, fmt.Errorf("%w: winning option %q not in gate allowed_options", ErrAccordBinding, view.Outcome.WinningOptionID)
	}

	candidate := GateResolution{
		GoalID:            goalID,
		GateID:            gateID,
		AccordID:          gate.AccordID,
		Head:              view.Head,
		Phase:             view.Phase,
		WinningOptionID:   view.Outcome.WinningOptionID,
		WinningCommitment: view.Outcome.WinningCommitment,
		DeadlockReason:    view.Outcome.DeadlockReason,
		OutcomeHash:       view.Outcome.Hash(),
		ResolvedAtHeight:  view.Outcome.ResolvedAtHeight,
	}
	if err := validateGateResolution(candidate, goalID, gateID, gate.AccordID); err != nil {
		return GateResolution{}, fmt.Errorf("%w: invalid accord outcome", ErrAccordSpec)
	}

	key := gateRecordKey(goalID, gateID)
	var out GateResolution
	err = s.store.withLocked(key, func(tx checkpointTx) error {
		existing, loadErr := s.loadGateWith(tx, goalID, gateID)
		if loadErr == nil {
			if existing.AccordID == candidate.AccordID && existing.Head == candidate.Head {
				if existing != candidate {
					return ErrCorruptStore
				}
				if err := s.confirm(); err != nil {
					return err
				}
				out = existing
				return nil
			}
			return ErrOperationConflict
		}
		if !errors.Is(loadErr, ErrNotFound) {
			return loadErr
		}
		s.invalidateGateCacheLocked(key)
		cp := gateCheckpoint{Version: gateCheckpointVersion, Resolution: candidate}
		if err := s.store.writeWith(tx, key, cp); err != nil {
			return err
		}
		out = candidate
		return nil
	})
	if err != nil {
		return GateResolution{}, err
	}
	return out, nil
}

// GateStatus loads and validates the persisted GateResolution for (goalID, gateID),
// confirming durability, or returns ErrNotFound if unresolved.
func (s *CoordinationStore) GateStatus(goalID, gateID string) (GateResolution, error) {
	if err := validateStoreID(goalID); err != nil {
		return GateResolution{}, err
	}
	if !coordinationName(gateID) || !validUTF8NoControl(gateID) {
		return GateResolution{}, ErrPlan
	}
	key := gateRecordKey(goalID, gateID)
	var out GateResolution
	err := s.store.withLocked(key, func(tx checkpointTx) error {
		res, err := s.loadGateWith(tx, goalID, gateID)
		if err != nil {
			return err
		}
		if err := s.confirm(); err != nil {
			return err
		}
		out = res
		return nil
	})
	if err != nil {
		return GateResolution{}, err
	}
	return out, nil
}

func gateSatisfiesDependency(res GateResolution, dep TaskGateDependency) bool {
	if res.Phase != dep.RequiredPhase {
		return false
	}
	switch dep.RequiredPhase {
	case AccordPhaseDecided:
		if res.WinningOptionID != dep.OptionID {
			return false
		}
		if dep.ExpectedCommitment != "" && res.WinningCommitment != dep.ExpectedCommitment {
			return false
		}
		return true
	case AccordPhaseDeadlocked:
		if dep.ExpectedDeadlockReason != "" && res.DeadlockReason != dep.ExpectedDeadlockReason {
			return false
		}
		return true
	case AccordPhaseExpired:
		return true
	default:
		return false
	}
}

func (s *CoordinationStore) checkGateDependencies(task TaskSpec) error {
	for _, dep := range task.GateDependencies {
		res, err := s.GateStatus(task.GoalID, dep.GateID)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: gate %s", ErrTaskDependency, dep.GateID)
		}
		if err != nil {
			return err
		}
		if !gateSatisfiesDependency(res, dep) {
			return fmt.Errorf("%w: gate %s", ErrTaskDependency, dep.GateID)
		}
	}
	return nil
}
