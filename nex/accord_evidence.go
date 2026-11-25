package nex

import (
	"slices"
	"strings"
)

// EvidenceKind identifies the cryptographic proof format bound to an EvidenceSlot.
type EvidenceKind string

const (
	EvidenceTaskHandoff    EvidenceKind = "task_handoff"
	EvidenceProtocolBundle EvidenceKind = "protocol_bundle"
)

// EvidenceAssurance records that a fact was cryptographically replayed inside the kernel.
type EvidenceAssurance string

const (
	EvidenceFactsVerified EvidenceAssurance = "verified"
)

// EvidenceSlot declares a trust-pinned upstream artifact source in AccordSpec.
// Omitting ExpectedResultHash (on task_handoff) or ExpectedHead (on protocol_bundle)
// delegates finalized-generation selection to RequiredAttester, bounded by
// ExpectedAuthority, MinGeneration, and full ProtocolVersionV2 replay.
type EvidenceSlot struct {
	ID                 string       `json:"id"`
	Kind               EvidenceKind `json:"kind"`
	GoalID             string       `json:"goal_id,omitempty"`
	TaskID             string       `json:"task_id,omitempty"`
	ExpectedAuthority  string       `json:"expected_authority,omitempty"`
	ExpectedResultHash string       `json:"expected_result_hash,omitempty"`
	MinGeneration      uint64       `json:"min_generation,omitempty"`
	ProtocolID         string       `json:"protocol_id,omitempty"`
	ExpectedHead       string       `json:"expected_head,omitempty"`
	RequiredAttester   string       `json:"required_attester,omitempty"`
}

// VerifiedEvidenceFact is 100% kernel-derived by cryptographically replaying a
// pinned TaskHandoff or ProtocolBundle.
type VerifiedEvidenceFact struct {
	EvidenceID          string            `json:"evidence_id"`
	Kind                EvidenceKind      `json:"kind"`
	Assurance           EvidenceAssurance `json:"assurance"`
	ProofHash           string            `json:"proof_hash"`
	GoalID              string            `json:"goal_id,omitempty"`
	TaskID              string            `json:"task_id,omitempty"`
	AuthorityID         string            `json:"authority_id"`
	WorkerID            string            `json:"worker_id,omitempty"`
	ProtocolID          string            `json:"protocol_id"`
	ProtocolHead        string            `json:"protocol_head"`
	Generation          uint64            `json:"generation,omitempty"`
	ResultHash          string            `json:"result_hash,omitempty"`
	Outcome             TaskOutcome       `json:"outcome"`
	ProtocolPhase       string            `json:"protocol_phase"`
	WorkOutcome         WorkOutcome       `json:"work_outcome,omitempty"`
	ResolutionOutcome   string            `json:"resolution_outcome,omitempty"`
	Disposition         string            `json:"disposition,omitempty"`
	HasWitnessDissent   bool              `json:"has_witness_dissent"`
	DissentingWitnesses []string          `json:"dissenting_witnesses,omitempty"`
	ReviewingWitnesses  []string          `json:"reviewing_witnesses,omitempty"`
	MissingWitnesses    []string          `json:"missing_witnesses,omitempty"`
	Participants        []string          `json:"participants,omitempty"`
	Artifacts           []TaskArtifact    `json:"artifacts,omitempty"`
	ArtifactRefs        []NamedArtifact   `json:"artifact_refs,omitempty"`
	AttestedBy          string            `json:"attested_by"`
	AttestedAtHeight    uint64            `json:"attested_at_height"`
}

// GuardOp enumerates kernel-evaluated predicates over verified upstream evidence.
type GuardOp string

const (
	GuardAttested           GuardOp = "attested"
	GuardNotAttested        GuardOp = "not_attested"
	GuardOutcomeIn          GuardOp = "outcome_in"
	GuardArtifactSlot       GuardOp = "artifact_slot"
	GuardNoWitnessDissent   GuardOp = "no_witness_dissent"
	GuardHasWitnessDissent  GuardOp = "has_witness_dissent"
	GuardWitnessReviewed    GuardOp = "witness_reviewed"
	GuardWitnessApproved    GuardOp = "witness_approved"
	GuardParticipantPresent GuardOp = "participant_present"
	GuardAuthorityMatch     GuardOp = "authority_match"
	GuardDispositionIn      GuardOp = "disposition_in"
	GuardMinGeneration      GuardOp = "min_generation"
)

// EvidencePredicate evaluates one verified property of a declared EvidenceSlot.
// Unused fields MUST be zero/empty. Missing evidence fails closed (false) on
// every operator except GuardNotAttested.
type EvidencePredicate struct {
	EvidenceID    string        `json:"evidence_id"`
	Op            GuardOp       `json:"op"`
	Outcomes      []TaskOutcome `json:"outcomes,omitempty"`
	Slot          string        `json:"slot,omitempty"`
	Digest        string        `json:"digest,omitempty"`
	ActorID       string        `json:"actor_id,omitempty"`
	Dispositions  []string      `json:"dispositions,omitempty"`
	MinGeneration uint64        `json:"min_generation,omitempty"`
}

// OptionGuard is satisfied iff every AllOf predicate holds AND (when AnyOf is
// non-empty) at least one AnyOf predicate holds.
type OptionGuard struct {
	AllOf []EvidencePredicate `json:"all_of,omitempty"`
	AnyOf []EvidencePredicate `json:"any_of,omitempty"`
}

// PredicateFailure records one deterministic guard predicate failure.
type PredicateFailure struct {
	Clause     string  `json:"clause"`
	Index      int     `json:"index"`
	EvidenceID string  `json:"evidence_id"`
	Op         GuardOp `json:"op"`
	Reason     string  `json:"reason"`
}

// OptionGuardStatus summarizes guard evaluation for one candidate option.
type OptionGuardStatus struct {
	OptionID             string             `json:"option_id"`
	Passed               bool               `json:"passed"`
	SatisfiedEvidenceIDs []string           `json:"satisfied_evidence_ids,omitempty"`
	FailedPredicates     []PredicateFailure `json:"failed_predicates,omitempty"`
}

func accordProofHash(kind EvidenceKind, handoff *TaskHandoff, protocol *ProtocolBundle) string {
	return Hash(struct {
		Domain   string          `json:"domain"`
		Kind     EvidenceKind    `json:"kind"`
		Handoff  *TaskHandoff    `json:"handoff,omitempty"`
		Protocol *ProtocolBundle `json:"protocol,omitempty"`
	}{AccordProofHashDomain, kind, handoff, protocol})
}

func validateEvidenceSlot(slot EvidenceSlot, attesterActors map[string]bool) error {
	if !validAccordID(slot.ID) {
		return ErrAccordSpec
	}
	if slot.RequiredAttester != "" && !attesterActors[slot.RequiredAttester] {
		return ErrAccordSpec
	}
	switch slot.Kind {
	case EvidenceTaskHandoff:
		if !protocolHash(slot.GoalID) || !protocolHash(slot.TaskID) || !protocolHash(slot.ExpectedAuthority) {
			return ErrAccordSpec
		}
		if slot.ProtocolID != "" || slot.ExpectedHead != "" {
			return ErrAccordSpec
		}
		if slot.ExpectedResultHash != "" {
			if !protocolHash(slot.ExpectedResultHash) {
				return ErrAccordSpec
			}
		} else if slot.RequiredAttester == "" {
			return ErrAccordSpec
		}
		return nil

	case EvidenceProtocolBundle:
		if !protocolHash(slot.ProtocolID) || !protocolHash(slot.ExpectedAuthority) {
			return ErrAccordSpec
		}
		if slot.GoalID != "" || slot.TaskID != "" || slot.ExpectedResultHash != "" || slot.MinGeneration != 0 {
			return ErrAccordSpec
		}
		if slot.ExpectedHead != "" {
			if !protocolHash(slot.ExpectedHead) {
				return ErrAccordSpec
			}
		} else if slot.RequiredAttester == "" {
			return ErrAccordSpec
		}
		return nil

	default:
		return ErrAccordSpec
	}
}

func validTaskOutcomes(outcomes []TaskOutcome) bool {
	if len(outcomes) == 0 || len(outcomes) > 3 {
		return false
	}
	seen := make(map[TaskOutcome]bool, len(outcomes))
	for _, o := range outcomes {
		switch o {
		case TaskAccepted, TaskRejected, TaskIncomplete:
		default:
			return false
		}
		if seen[o] {
			return false
		}
		seen[o] = true
	}
	return true
}

func validProtocolDispositions(dispositions []string) bool {
	if len(dispositions) == 0 || len(dispositions) > 4 {
		return false
	}
	seen := make(map[string]bool, len(dispositions))
	for _, d := range dispositions {
		switch d {
		case "continue", "retry", "renegotiate", "refuse":
		default:
			return false
		}
		if seen[d] {
			return false
		}
		seen[d] = true
	}
	return true
}

func validateEvidencePredicate(p EvidencePredicate, evidenceByID map[string]EvidenceSlot) error {
	if !validAccordID(p.EvidenceID) {
		return ErrAccordSpec
	}
	slot, ok := evidenceByID[p.EvidenceID]
	if !ok {
		return ErrAccordSpec
	}
	switch p.Op {
	case GuardAttested, GuardNotAttested, GuardNoWitnessDissent, GuardHasWitnessDissent:
		if len(p.Outcomes) != 0 || p.Slot != "" || p.Digest != "" || p.ActorID != "" || len(p.Dispositions) != 0 || p.MinGeneration != 0 {
			return ErrAccordSpec
		}
		return nil

	case GuardOutcomeIn:
		if !validTaskOutcomes(p.Outcomes) || p.Slot != "" || p.Digest != "" || p.ActorID != "" || len(p.Dispositions) != 0 || p.MinGeneration != 0 {
			return ErrAccordSpec
		}
		return nil

	case GuardArtifactSlot:
		if !validTaskOutcomes(p.Outcomes) || !validAccordSlotName(p.Slot) || p.ActorID != "" || len(p.Dispositions) != 0 || p.MinGeneration != 0 {
			return ErrAccordSpec
		}
		if p.Digest != "" && !protocolHash(p.Digest) {
			return ErrAccordSpec
		}
		return nil

	case GuardWitnessReviewed, GuardWitnessApproved, GuardParticipantPresent, GuardAuthorityMatch:
		if !protocolHash(p.ActorID) || len(p.Outcomes) != 0 || p.Slot != "" || p.Digest != "" || len(p.Dispositions) != 0 || p.MinGeneration != 0 {
			return ErrAccordSpec
		}
		return nil

	case GuardDispositionIn:
		if !validProtocolDispositions(p.Dispositions) || len(p.Outcomes) != 0 || p.Slot != "" || p.Digest != "" || p.ActorID != "" || p.MinGeneration != 0 {
			return ErrAccordSpec
		}
		return nil

	case GuardMinGeneration:
		if slot.Kind != EvidenceTaskHandoff || p.MinGeneration < 1 ||
			len(p.Outcomes) != 0 || p.Slot != "" || p.Digest != "" || p.ActorID != "" || len(p.Dispositions) != 0 {
			return ErrAccordSpec
		}
		return nil

	default:
		return ErrAccordSpec
	}
}

func validateOptionGuard(g OptionGuard, evidenceByID map[string]EvidenceSlot) error {
	if len(g.AllOf) > maxAccordPredicates || len(g.AnyOf) > maxAccordPredicates {
		return ErrAccordSpec
	}
	for _, p := range g.AllOf {
		if err := validateEvidencePredicate(p, evidenceByID); err != nil {
			return err
		}
	}
	for _, p := range g.AnyOf {
		if err := validateEvidencePredicate(p, evidenceByID); err != nil {
			return err
		}
	}
	return nil
}

func verifyAttestEvidence(slot EvidenceSlot, payload AttestPayload, attester string, height uint64) (VerifiedEvidenceFact, error) {
	var (
		fact         VerifiedEvidenceFact
		view         ProtocolView
		protocolSpec ProtocolSpec
	)

	switch slot.Kind {
	case EvidenceTaskHandoff:
		if payload.Handoff == nil || payload.Protocol != nil {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		h := *payload.Handoff
		if h.Task.GoalID != slot.GoalID || h.Task.ID() != slot.TaskID ||
			h.Task.Authority.ID() != slot.ExpectedAuthority ||
			h.Protocol.Spec.Version != ProtocolVersionV2 {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		if slot.MinGeneration > 0 && h.Protocol.Spec.Generation < slot.MinGeneration {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		expectedResHash := slot.ExpectedResultHash
		if expectedResHash == "" {
			expectedResHash = Hash(h.Result)
		}
		verifiedResult, err := VerifyTaskHandoff(h, slot.TaskID, expectedResHash)
		if err != nil {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		view, err = VerifyProtocolBundle(h.Protocol, h.Claim.ProtocolID, verifiedResult.Head)
		if err != nil {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		protocolSpec = h.Protocol.Spec
		fact = VerifiedEvidenceFact{
			EvidenceID:   slot.ID,
			Kind:         slot.Kind,
			Assurance:    EvidenceFactsVerified,
			ProofHash:    accordProofHash(slot.Kind, payload.Handoff, nil),
			GoalID:       h.Task.GoalID,
			TaskID:       slot.TaskID,
			AuthorityID:  h.Task.Authority.ID(),
			WorkerID:     h.Claim.WorkerID,
			ProtocolID:   h.Claim.ProtocolID,
			ProtocolHead: verifiedResult.Head,
			Generation:   h.Protocol.Spec.Generation,
			ResultHash:   Hash(verifiedResult),
			Outcome:      verifiedResult.Outcome,
		}
		if len(verifiedResult.Artifacts) > 0 {
			fact.Artifacts = slices.Clone(verifiedResult.Artifacts)
		}

	case EvidenceProtocolBundle:
		if payload.Protocol == nil || payload.Handoff != nil {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		b := *payload.Protocol
		if b.Spec.Version != ProtocolVersionV2 || len(b.Events) == 0 || b.Spec.Initiator != slot.ExpectedAuthority {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		head := b.Events[len(b.Events)-1].ReceiptHash
		if !protocolHash(head) {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		if slot.ExpectedHead != "" && head != slot.ExpectedHead {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		var err error
		view, err = VerifyProtocolBundle(b, slot.ProtocolID, head)
		if err != nil {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		if view.Phase != "complete" && view.Phase != "incomplete" {
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}
		protocolSpec = b.Spec
		fact = VerifiedEvidenceFact{
			EvidenceID:   slot.ID,
			Kind:         slot.Kind,
			Assurance:    EvidenceFactsVerified,
			ProofHash:    accordProofHash(slot.Kind, nil, payload.Protocol),
			AuthorityID:  b.Spec.Initiator,
			ProtocolID:   slot.ProtocolID,
			ProtocolHead: head,
			Generation:   b.Spec.Generation,
		}
		switch {
		case view.Phase == "incomplete" && view.Incomplete != nil:
			fact.Outcome = TaskIncomplete
			for _, a := range view.Incomplete.Artifacts {
				fact.Artifacts = append(fact.Artifacts, TaskArtifact{Slot: a.Name, Digest: a.Ref.Digest})
			}
		case view.Phase == "complete" && view.Resolution != nil && view.Return != nil:
			switch view.Resolution.Outcome {
			case "accept":
				fact.Outcome = TaskAccepted
			case "reject", "breach":
				fact.Outcome = TaskRejected
			default:
				return VerifiedEvidenceFact{}, ErrAccordEvidence
			}
			for _, a := range view.Return.Artifacts {
				fact.Artifacts = append(fact.Artifacts, TaskArtifact{Slot: a.ID, Digest: a.Commitment})
			}
		default:
			return VerifiedEvidenceFact{}, ErrAccordEvidence
		}

	default:
		return VerifiedEvidenceFact{}, ErrAccordEvidence
	}

	fact.ProtocolPhase = view.Phase
	if view.Report != nil {
		fact.WorkOutcome = view.Report.Outcome
	}
	if view.Resolution != nil {
		fact.ResolutionOutcome = view.Resolution.Outcome
	}
	if view.Return != nil {
		fact.Disposition = view.Return.Disposition
	}
	for _, r := range view.Reviews {
		fact.ReviewingWitnesses = append(fact.ReviewingWitnesses, r.Actor)
		if r.Review.Dissent {
			fact.DissentingWitnesses = append(fact.DissentingWitnesses, r.Actor)
		}
	}
	slices.Sort(fact.ReviewingWitnesses)
	slices.Sort(fact.DissentingWitnesses)
	fact.HasWitnessDissent = len(fact.DissentingWitnesses) > 0

	if view.Incomplete != nil && len(view.Incomplete.MissingWitnesses) > 0 {
		fact.MissingWitnesses = slices.Clone(view.Incomplete.MissingWitnesses)
		slices.Sort(fact.MissingWitnesses)
	}
	if len(protocolSpec.Participants) > 0 {
		fact.Participants = make([]string, len(protocolSpec.Participants))
		for i, p := range protocolSpec.Participants {
			fact.Participants[i] = p.ID()
		}
		slices.Sort(fact.Participants)
	}

	slices.SortFunc(fact.Artifacts, func(a, b TaskArtifact) int {
		if c := strings.Compare(a.Slot, b.Slot); c != 0 {
			return c
		}
		return strings.Compare(a.Digest, b.Digest)
	})
	if len(fact.Artifacts) == 0 {
		fact.Artifacts = nil
	}

	var candidateRefs []NamedArtifact
	switch fact.Outcome {
	case TaskAccepted, TaskRejected:
		if view.Report != nil && view.Report.Manifest != nil {
			candidateRefs = view.Report.Manifest.Outputs
		}
	case TaskIncomplete:
		if view.Incomplete != nil {
			candidateRefs = view.Incomplete.Artifacts
		}
	}
	if len(candidateRefs) > 0 && len(fact.Artifacts) > 0 {
		for _, a := range candidateRefs {
			if slices.Contains(fact.Artifacts, TaskArtifact{Slot: a.Name, Digest: a.Ref.Digest}) {
				fact.ArtifactRefs = append(fact.ArtifactRefs, a)
			}
		}
	}
	if len(fact.ArtifactRefs) > 0 {
		slices.SortFunc(fact.ArtifactRefs, func(a, b NamedArtifact) int {
			return strings.Compare(a.Name, b.Name)
		})
	} else {
		fact.ArtifactRefs = nil
	}

	fact.AttestedBy = attester
	fact.AttestedAtHeight = height
	return fact, nil
}

func factsMapFromSlice(facts []VerifiedEvidenceFact) map[string]VerifiedEvidenceFact {
	m := make(map[string]VerifiedEvidenceFact, len(facts))
	for _, f := range facts {
		m[f.EvidenceID] = f
	}
	return m
}

func evaluateEvidencePredicate(p EvidencePredicate, facts map[string]VerifiedEvidenceFact) (passed bool, attestedRef bool, reason string) {
	fact, ok := facts[p.EvidenceID]
	switch p.Op {
	case GuardAttested:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		return true, true, ""

	case GuardNotAttested:
		if ok {
			return false, false, "evidence_already_attested"
		}
		return true, false, ""

	case GuardOutcomeIn:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if slices.Contains(p.Outcomes, fact.Outcome) {
			return true, true, ""
		}
		return false, false, "outcome_mismatch"

	case GuardArtifactSlot:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if !slices.Contains(p.Outcomes, fact.Outcome) {
			return false, false, "outcome_mismatch"
		}
		for _, a := range fact.Artifacts {
			if a.Slot == p.Slot && (p.Digest == "" || a.Digest == p.Digest) {
				return true, true, ""
			}
		}
		return false, false, "artifact_slot_missing"

	case GuardNoWitnessDissent:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if fact.ProtocolPhase != "complete" {
			return false, false, "protocol_not_complete"
		}
		if len(fact.MissingWitnesses) > 0 {
			return false, false, "missing_witnesses"
		}
		if fact.HasWitnessDissent {
			return false, false, "witness_dissent_present"
		}
		return true, true, ""

	case GuardHasWitnessDissent:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if fact.HasWitnessDissent {
			return true, true, ""
		}
		return false, false, "no_witness_dissent"

	case GuardWitnessReviewed:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if slices.Contains(fact.ReviewingWitnesses, p.ActorID) {
			return true, true, ""
		}
		return false, false, "witness_did_not_review"

	case GuardWitnessApproved:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if !slices.Contains(fact.ReviewingWitnesses, p.ActorID) {
			return false, false, "witness_did_not_review"
		}
		if slices.Contains(fact.DissentingWitnesses, p.ActorID) {
			return false, false, "witness_dissented"
		}
		return true, true, ""

	case GuardParticipantPresent:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if slices.Contains(fact.Participants, p.ActorID) {
			return true, true, ""
		}
		return false, false, "participant_not_present"

	case GuardAuthorityMatch:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if fact.AuthorityID == p.ActorID {
			return true, true, ""
		}
		return false, false, "authority_mismatch"

	case GuardDispositionIn:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if fact.Disposition != "" && slices.Contains(p.Dispositions, fact.Disposition) {
			return true, true, ""
		}
		return false, false, "disposition_mismatch"

	case GuardMinGeneration:
		if !ok {
			return false, false, "evidence_not_attested"
		}
		if fact.Generation >= p.MinGeneration {
			return true, true, ""
		}
		return false, false, "generation_below_minimum"

	default:
		return false, false, "evidence_not_attested"
	}
}

func evaluateOptionGuard(opt AccordOption, facts map[string]VerifiedEvidenceFact) OptionGuardStatus {
	status := OptionGuardStatus{
		OptionID: opt.ID,
		Passed:   true,
	}
	satisfiedSet := make(map[string]bool)

	for i, p := range opt.Guard.AllOf {
		ok, attestedRef, reason := evaluateEvidencePredicate(p, facts)
		if ok {
			if attestedRef {
				satisfiedSet[p.EvidenceID] = true
			}
		} else {
			status.Passed = false
			status.FailedPredicates = append(status.FailedPredicates, PredicateFailure{
				Clause:     "all_of",
				Index:      i,
				EvidenceID: p.EvidenceID,
				Op:         p.Op,
				Reason:     reason,
			})
		}
	}

	if len(opt.Guard.AnyOf) > 0 {
		anyPassed := false
		var anyFailures []PredicateFailure
		for i, p := range opt.Guard.AnyOf {
			ok, attestedRef, reason := evaluateEvidencePredicate(p, facts)
			if ok {
				anyPassed = true
				if attestedRef {
					satisfiedSet[p.EvidenceID] = true
				}
			} else {
				anyFailures = append(anyFailures, PredicateFailure{
					Clause:     "any_of",
					Index:      i,
					EvidenceID: p.EvidenceID,
					Op:         p.Op,
					Reason:     reason,
				})
			}
		}
		if !anyPassed {
			status.Passed = false
			status.FailedPredicates = append(status.FailedPredicates, anyFailures...)
		}
	}

	if len(satisfiedSet) > 0 {
		status.SatisfiedEvidenceIDs = make([]string, 0, len(satisfiedSet))
		for id := range satisfiedSet {
			status.SatisfiedEvidenceIDs = append(status.SatisfiedEvidenceIDs, id)
		}
		slices.Sort(status.SatisfiedEvidenceIDs)
	}
	if len(status.FailedPredicates) == 0 {
		status.FailedPredicates = nil
	}
	return status
}
