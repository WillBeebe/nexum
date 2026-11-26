package nex

import (
	"slices"
	"strings"
)

// BallotMode controls how many options a single participant may approve.
type BallotMode string

const (
	BallotSingleChoice BallotMode = "single_choice"
	BallotApproval     BallotMode = "approval"
)

// BallotPrivacy controls whether voter ballots are recorded as public
// plaintext votes or Paillier-sealed ciphertexts with zero-knowledge proofs.
type BallotPrivacy string

const (
	BallotPrivacyPublic         BallotPrivacy = "public"
	BallotPrivacySealedPaillier BallotPrivacy = "sealed_paillier"
)

// BallotPosition is a participant's explicit stance on one option.
type BallotPosition string

const (
	BallotApprove BallotPosition = "approve"
	BallotDissent BallotPosition = "dissent"
	BallotAbstain BallotPosition = "abstain"
)

// VetoMode configures whether bounded vetoes are disabled, blocking, or overridable.
type VetoMode string

const (
	VetoDisabled    VetoMode = "disabled"
	VetoBlocking    VetoMode = "blocking"
	VetoOverridable VetoMode = "overridable"
)

// TieBreakPolicy deterministically resolves or deadlocks equal top ApproveWeight contenders.
type TieBreakPolicy string

const (
	TieBreakDeadlock        TieBreakPolicy = "deadlock"
	TieBreakLowestPriority  TieBreakPolicy = "lowest_priority"
	TieBreakFewestDissents  TieBreakPolicy = "fewest_dissents"
	TieBreakLexicographicID TieBreakPolicy = "lexicographic_id"
)

// DeadlockReason records why resolution produced no winning option.
type DeadlockReason string

const (
	DeadlockNoQuorum                  DeadlockReason = "quorum_not_met"
	DeadlockNoOptions                 DeadlockReason = "no_options"
	DeadlockAllDisqualifiedByEvidence DeadlockReason = "all_options_disqualified_by_evidence"
	DeadlockAllVetoed                 DeadlockReason = "all_eligible_options_vetoed"
	DeadlockNoThresholdMet            DeadlockReason = "no_option_met_threshold"
	DeadlockTie                       DeadlockReason = "unbroken_tie"
)

// RoleRequirement mandates minimum approvals and optional weight from voters
// carrying a specific domain role on their AccordPermitVote grant.
type RoleRequirement struct {
	Role         string `json:"role"`
	MinApprovals uint64 `json:"min_approvals"`
	MinWeight    uint64 `json:"min_weight,omitempty"`
}

// VetoPolicy bounds veto authority, per-actor veto count, evidence citation,
// and optional supermajority weight override.
type VetoPolicy struct {
	Mode               VetoMode `json:"mode"`
	MaxVetoesPerActor  uint32   `json:"max_vetoes_per_actor,omitempty"`
	OverrideWeight     uint64   `json:"override_weight,omitempty"`
	RequireEvidence    bool     `json:"require_evidence,omitempty"`
	AllowedDomainRoles []string `json:"allowed_domain_roles,omitempty"`
}

// DecisionRules configures participation quorum, approval thresholds, approval
// margin, mandatory domain roles, bounded veto policy, and tie-breaking.
type DecisionRules struct {
	BallotMode                 BallotMode        `json:"ballot_mode"`
	BallotPrivacy              BallotPrivacy     `json:"ballot_privacy,omitempty"`
	MinParticipationCount      uint64            `json:"min_participation_count,omitempty"`
	MinParticipationWeight     uint64            `json:"min_participation_weight,omitempty"`
	MinApprovalCount           uint64            `json:"min_approval_count"`
	MinApprovalWeight          uint64            `json:"min_approval_weight"`
	MinApprovalMarginWeight    uint64            `json:"min_approval_margin_weight,omitempty"`
	MandatoryRoles             []RoleRequirement `json:"mandatory_roles,omitempty"`
	Veto                       VetoPolicy        `json:"veto"`
	TieBreak                   TieBreakPolicy    `json:"tie_break"`
	RequireIndependentResolver bool              `json:"require_independent_resolver,omitempty"`
}

// OptionTally records the complete deterministic evaluation of one candidate option.
type OptionTally struct {
	OptionID                string             `json:"option_id"`
	Priority                uint32             `json:"priority,omitempty"`
	GuardPassed             bool               `json:"guard_passed"`
	SatisfiedEvidenceIDs    []string           `json:"satisfied_evidence_ids,omitempty"`
	FailedPredicates        []PredicateFailure `json:"failed_predicates,omitempty"`
	ApproveCount            uint64             `json:"approve_count"`
	ApproveWeight           uint64             `json:"approve_weight"`
	Approvers               []string           `json:"approvers,omitempty"`
	DissentCount            uint64             `json:"dissent_count"`
	DissentWeight           uint64             `json:"dissent_weight"`
	Dissenters              []string           `json:"dissenters,omitempty"`
	AbstainCount            uint64             `json:"abstain_count"`
	AbstainWeight           uint64             `json:"abstain_weight"`
	Abstainers              []string           `json:"abstainers,omitempty"`
	MissingRoles            []string           `json:"missing_roles,omitempty"`
	Vetoed                  bool               `json:"vetoed"`
	VetoOverridden          bool               `json:"veto_overridden"`
	VetoEffective           bool               `json:"veto_effective"`
	Vetoers                 []string           `json:"vetoers,omitempty"`
	Eligible                bool               `json:"eligible"`
	DisqualificationReasons []string           `json:"disqualification_reasons,omitempty"`
}

// AccordOutcome records the terminal decided, deadlocked, or expired result,
// preserving full tallies, verified evidence summary, minority dissents, and
// overridden vetoes.
type AccordOutcome struct {
	Phase                 AccordPhase            `json:"phase"`
	WinningOptionID       string                 `json:"winning_option_id,omitempty"`
	WinningBinding        *OptionBinding         `json:"winning_binding,omitempty"`
	WinningCommitment     string                 `json:"winning_commitment,omitempty"`
	ParticipatingCount    uint64                 `json:"participating_count"`
	ParticipatingWeight   uint64                 `json:"participating_weight"`
	Tallies               []OptionTally          `json:"tallies,omitempty"`
	WinningOptionDissents []RecordedVote         `json:"winning_option_dissents,omitempty"`
	WinningOptionVetoes   []RecordedVeto         `json:"winning_option_vetoes,omitempty"`
	EvidenceSummary       []VerifiedEvidenceFact `json:"evidence_summary,omitempty"`
	DeadlockReason        DeadlockReason         `json:"deadlock_reason,omitempty"`
	TiedOptionIDs         []string               `json:"tied_option_ids,omitempty"`
	ExpiredReasonHash     string                 `json:"expired_reason_hash,omitempty"`
	ResolvedBy            string                 `json:"resolved_by"`
	ResolvedAtHeight      uint64                 `json:"resolved_at_height"`
	ReasonHash            string                 `json:"reason_hash"`
}

// Hash returns the domain-separated SHA-256 commitment for this outcome.
func (o AccordOutcome) Hash() string {
	return Hash(struct {
		Domain  string        `json:"domain"`
		Outcome AccordOutcome `json:"outcome"`
	}{AccordOutcomeHashDomain, o})
}

func allowedBallotPosition(pos BallotPosition) bool {
	return pos == BallotApprove || pos == BallotDissent || pos == BallotAbstain
}

func validateVetoPolicyBasic(vp VetoPolicy, evidenceCount int) error {
	switch vp.Mode {
	case VetoDisabled:
		if vp.MaxVetoesPerActor != 0 || vp.OverrideWeight != 0 || vp.RequireEvidence || len(vp.AllowedDomainRoles) != 0 {
			return ErrAccordSpec
		}
		return nil
	case VetoBlocking:
		if vp.MaxVetoesPerActor < 1 || vp.MaxVetoesPerActor > maxAccordOptions || vp.OverrideWeight != 0 {
			return ErrAccordSpec
		}
	case VetoOverridable:
		if vp.MaxVetoesPerActor < 1 || vp.MaxVetoesPerActor > maxAccordOptions {
			return ErrAccordSpec
		}
	default:
		return ErrAccordSpec
	}
	if vp.RequireEvidence && evidenceCount < 1 {
		return ErrAccordSpec
	}
	if !uniqueStrings(vp.AllowedDomainRoles, maxAccordDomainRoles, validAccordID) {
		return ErrAccordSpec
	}
	return nil
}

func validateRoleRequirements(reqs []RoleRequirement, roleVoterCount, roleVoterWeight map[string]uint64) error {
	if len(reqs) > maxAccordDomainRoles {
		return ErrAccordSpec
	}
	seen := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		if !validAccordID(r.Role) || seen[r.Role] || r.MinApprovals < 1 {
			return ErrAccordSpec
		}
		if roleVoterCount[r.Role] < r.MinApprovals || roleVoterWeight[r.Role] < r.MinWeight {
			return ErrAccordSpec
		}
		seen[r.Role] = true
	}
	return nil
}

func validateDecisionRules(r DecisionRules, voterCount, totalWeight uint64, roleVoterCount, roleVoterWeight map[string]uint64) error {
	switch r.BallotMode {
	case BallotSingleChoice, BallotApproval:
	default:
		return ErrAccordSpec
	}
	switch r.BallotPrivacy {
	case "", BallotPrivacyPublic, BallotPrivacySealedPaillier:
	default:
		return ErrAccordSpec
	}
	switch r.TieBreak {
	case TieBreakDeadlock, TieBreakLowestPriority, TieBreakFewestDissents, TieBreakLexicographicID:
	default:
		return ErrAccordSpec
	}
	if r.MinParticipationCount > voterCount || r.MinParticipationWeight > totalWeight {
		return ErrAccordSpec
	}
	if r.MinApprovalCount < 1 || r.MinApprovalCount > voterCount ||
		r.MinApprovalWeight < 1 || r.MinApprovalWeight > totalWeight ||
		r.MinApprovalMarginWeight > totalWeight {
		return ErrAccordSpec
	}
	if r.Veto.Mode == VetoOverridable {
		if r.Veto.OverrideWeight <= r.MinApprovalWeight || r.Veto.OverrideWeight > totalWeight {
			return ErrAccordSpec
		}
	}
	return validateRoleRequirements(r.MandatoryRoles, roleVoterCount, roleVoterWeight)
}

func computeParticipation(votes []RecordedVote) (count uint64, weight uint64) {
	seen := make(map[string]uint64)
	for _, v := range votes {
		if _, ok := seen[v.Actor]; !ok {
			seen[v.Actor] = v.Weight
			count++
			weight += v.Weight
		}
	}
	return count, weight
}

func mergeMandatoryRoles(global, extra []RoleRequirement) []RoleRequirement {
	if len(global) == 0 && len(extra) == 0 {
		return nil
	}
	merged := make(map[string]RoleRequirement, len(global)+len(extra))
	for _, r := range global {
		merged[r.Role] = r
	}
	for _, r := range extra {
		if cur, ok := merged[r.Role]; ok {
			if r.MinApprovals > cur.MinApprovals {
				cur.MinApprovals = r.MinApprovals
			}
			if r.MinWeight > cur.MinWeight {
				cur.MinWeight = r.MinWeight
			}
			merged[r.Role] = cur
		} else {
			merged[r.Role] = r
		}
	}
	out := make([]RoleRequirement, 0, len(merged))
	for _, r := range merged {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b RoleRequirement) int {
		return strings.Compare(a.Role, b.Role)
	})
	return out
}

func buildOptionTallies(spec AccordSpec, view AccordView) ([]OptionTally, map[string]bool) {
	if len(view.Options) == 0 {
		return nil, nil
	}
	facts := factsMapFromSlice(view.Evidence)
	votesByOption := make(map[string][]RecordedVote, len(view.Options))
	for _, v := range view.Votes {
		votesByOption[v.OptionID] = append(votesByOption[v.OptionID], v)
	}
	vetoesByOption := make(map[string][]RecordedVeto, len(view.Options))
	for _, vt := range view.Vetoes {
		vetoesByOption[vt.OptionID] = append(vetoesByOption[vt.OptionID], vt)
	}

	tallies := make([]OptionTally, len(view.Options))
	passedWithoutVeto := make(map[string]bool, len(view.Options))
	rules := spec.Rules

	for i, ro := range view.Options {
		opt := ro.Option
		gs := evaluateOptionGuard(opt, facts)

		tally := OptionTally{
			OptionID:             opt.ID,
			Priority:             opt.Priority,
			GuardPassed:          gs.Passed,
			SatisfiedEvidenceIDs: gs.SatisfiedEvidenceIDs,
			FailedPredicates:     gs.FailedPredicates,
		}

		roleApprovals := make(map[string]uint64)
		roleWeights := make(map[string]uint64)
		for _, v := range votesByOption[opt.ID] {
			switch v.Position {
			case BallotApprove:
				tally.ApproveCount++
				tally.ApproveWeight += v.Weight
				tally.Approvers = append(tally.Approvers, v.Actor)
				for _, dr := range v.DomainRoles {
					roleApprovals[dr]++
					roleWeights[dr] += v.Weight
				}
			case BallotDissent:
				tally.DissentCount++
				tally.DissentWeight += v.Weight
				tally.Dissenters = append(tally.Dissenters, v.Actor)
			case BallotAbstain:
				tally.AbstainCount++
				tally.AbstainWeight += v.Weight
				tally.Abstainers = append(tally.Abstainers, v.Actor)
			}
		}
		slices.Sort(tally.Approvers)
		slices.Sort(tally.Dissenters)
		slices.Sort(tally.Abstainers)

		requiredRoles := mergeMandatoryRoles(rules.MandatoryRoles, opt.ExtraMandatoryRoles)
		for _, req := range requiredRoles {
			if roleApprovals[req.Role] < req.MinApprovals || roleWeights[req.Role] < req.MinWeight {
				tally.MissingRoles = append(tally.MissingRoles, req.Role)
			}
		}
		slices.Sort(tally.MissingRoles)

		tally, nonVetoOK := finalizeOptionTally(tally, vetoesByOption[opt.ID], rules)
		passedWithoutVeto[opt.ID] = nonVetoOK
		tallies[i] = tally
	}
	return tallies, passedWithoutVeto
}

func finalizeOptionTally(tally OptionTally, optVetoes []RecordedVeto, rules DecisionRules) (OptionTally, bool) {
	if len(optVetoes) > 0 {
		tally.Vetoed = true
		tally.Vetoers = make([]string, len(optVetoes))
		for j, vt := range optVetoes {
			tally.Vetoers[j] = vt.Actor
		}
		slices.Sort(tally.Vetoers)
		switch rules.Veto.Mode {
		case VetoBlocking:
			tally.VetoEffective = true
		case VetoOverridable:
			tally.VetoOverridden = tally.ApproveWeight >= rules.Veto.OverrideWeight
			tally.VetoEffective = !tally.VetoOverridden
		}
	}

	marginOK := tally.ApproveWeight >= tally.DissentWeight &&
		tally.ApproveWeight-tally.DissentWeight >= rules.MinApprovalMarginWeight
	countOK := tally.ApproveCount >= rules.MinApprovalCount
	weightOK := tally.ApproveWeight >= rules.MinApprovalWeight
	rolesOK := len(tally.MissingRoles) == 0

	// Fixed canonical DisqualificationReasons order.
	if !tally.GuardPassed {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "guard_failed")
	}
	if tally.VetoEffective {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "vetoed")
	}
	if !countOK {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "below_approval_count")
	}
	if !weightOK {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "below_approval_weight")
	}
	if !marginOK {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "below_approval_margin")
	}
	if !rolesOK {
		tally.DisqualificationReasons = append(tally.DisqualificationReasons, "missing_mandatory_role")
	}

	nonVetoOK := tally.GuardPassed && countOK && weightOK && marginOK && rolesOK
	tally.Eligible = nonVetoOK && !tally.VetoEffective
	return tally, nonVetoOK
}

func cloneEvidenceSummary(facts []VerifiedEvidenceFact) []VerifiedEvidenceFact {
	if len(facts) == 0 {
		return nil
	}
	out := make([]VerifiedEvidenceFact, len(facts))
	for i, f := range facts {
		out[i] = cloneVerifiedEvidenceFact(f)
	}
	sortVerifiedEvidenceFacts(out)
	return out
}

func evaluateExpiredOutcome(spec AccordSpec, view AccordView, actor string, height uint64, reasonHash string) AccordOutcome {
	var partCount, partWeight uint64
	var tallies []OptionTally
	if spec.Rules.BallotPrivacy == BallotPrivacySealedPaillier {
		partCount, partWeight = computeSealedParticipation(view.SealedBallots)
	} else {
		partCount, partWeight = computeParticipation(view.Votes)
		tallies, _ = buildOptionTallies(spec, view)
	}
	return AccordOutcome{
		Phase:               AccordPhaseExpired,
		ParticipatingCount:  partCount,
		ParticipatingWeight: partWeight,
		Tallies:             tallies,
		EvidenceSummary:     cloneEvidenceSummary(view.Evidence),
		ExpiredReasonHash:   reasonHash,
		ResolvedBy:          actor,
		ResolvedAtHeight:    height,
		ReasonHash:          reasonHash,
	}
}

func evaluateAccordOutcome(spec AccordSpec, view AccordView, actor string, height uint64, reasonHash string) AccordOutcome {
	partCount, partWeight := computeParticipation(view.Votes)
	tallies, passedWithoutVeto := buildOptionTallies(spec, view)
	return evaluateAccordOutcomeFromTallies(spec, view, partCount, partWeight, tallies, passedWithoutVeto, actor, height, reasonHash)
}

func evaluateAccordOutcomeFromTallies(
	spec AccordSpec,
	view AccordView,
	partCount, partWeight uint64,
	tallies []OptionTally,
	passedWithoutVeto map[string]bool,
	actor string,
	height uint64,
	reasonHash string,
) AccordOutcome {
	outcome := AccordOutcome{
		ParticipatingCount:  partCount,
		ParticipatingWeight: partWeight,
		Tallies:             tallies,
		EvidenceSummary:     cloneEvidenceSummary(view.Evidence),
		ResolvedBy:          actor,
		ResolvedAtHeight:    height,
		ReasonHash:          reasonHash,
	}

	// Zero-winner DeadlockReason precedence #1: no options.
	if len(view.Options) == 0 {
		outcome.Phase = AccordPhaseDeadlocked
		outcome.DeadlockReason = DeadlockNoOptions
		return outcome
	}

	// Zero-winner DeadlockReason precedence #2: participation quorum unmet.
	if partCount < spec.Rules.MinParticipationCount || partWeight < spec.Rules.MinParticipationWeight {
		outcome.Phase = AccordPhaseDeadlocked
		outcome.DeadlockReason = DeadlockNoQuorum
		return outcome
	}

	var eligible []OptionTally
	anyGuardPassed := false
	anyBlockedOnlyByVeto := false
	for _, t := range tallies {
		if t.GuardPassed {
			anyGuardPassed = true
		}
		if t.Eligible {
			eligible = append(eligible, t)
		} else if passedWithoutVeto[t.OptionID] && t.VetoEffective {
			anyBlockedOnlyByVeto = true
		}
	}

	if len(eligible) == 0 {
		outcome.Phase = AccordPhaseDeadlocked
		switch {
		case !anyGuardPassed:
			outcome.DeadlockReason = DeadlockAllDisqualifiedByEvidence
		case anyBlockedOnlyByVeto:
			outcome.DeadlockReason = DeadlockAllVetoed
		default:
			outcome.DeadlockReason = DeadlockNoThresholdMet
		}
		return outcome
	}

	// Filter eligible options to max ApproveWeight.
	var maxWeight uint64
	for _, t := range eligible {
		if t.ApproveWeight > maxWeight {
			maxWeight = t.ApproveWeight
		}
	}
	contenders := make([]OptionTally, 0, len(eligible))
	for _, t := range eligible {
		if t.ApproveWeight == maxWeight {
			contenders = append(contenders, t)
		}
	}

	if len(contenders) > 1 {
		switch spec.Rules.TieBreak {
		case TieBreakDeadlock:
			outcome.Phase = AccordPhaseDeadlocked
			outcome.DeadlockReason = DeadlockTie
			outcome.TiedOptionIDs = sortedTallyIDs(contenders)
			return outcome

		case TieBreakLowestPriority:
			minPrio := contenders[0].Priority
			for _, t := range contenders[1:] {
				if t.Priority < minPrio {
					minPrio = t.Priority
				}
			}
			narrowed := make([]OptionTally, 0, len(contenders))
			for _, t := range contenders {
				if t.Priority == minPrio {
					narrowed = append(narrowed, t)
				}
			}
			contenders = narrowed
			if len(contenders) > 1 {
				outcome.Phase = AccordPhaseDeadlocked
				outcome.DeadlockReason = DeadlockTie
				outcome.TiedOptionIDs = sortedTallyIDs(contenders)
				return outcome
			}

		case TieBreakFewestDissents:
			minDissentWeight := contenders[0].DissentWeight
			for _, t := range contenders[1:] {
				if t.DissentWeight < minDissentWeight {
					minDissentWeight = t.DissentWeight
				}
			}
			narrowed := make([]OptionTally, 0, len(contenders))
			for _, t := range contenders {
				if t.DissentWeight == minDissentWeight {
					narrowed = append(narrowed, t)
				}
			}
			contenders = narrowed
			if len(contenders) > 1 {
				minDissentCount := contenders[0].DissentCount
				for _, t := range contenders[1:] {
					if t.DissentCount < minDissentCount {
						minDissentCount = t.DissentCount
					}
				}
				narrowed2 := make([]OptionTally, 0, len(contenders))
				for _, t := range contenders {
					if t.DissentCount == minDissentCount {
						narrowed2 = append(narrowed2, t)
					}
				}
				contenders = narrowed2
			}
			if len(contenders) > 1 {
				outcome.Phase = AccordPhaseDeadlocked
				outcome.DeadlockReason = DeadlockTie
				outcome.TiedOptionIDs = sortedTallyIDs(contenders)
				return outcome
			}

		case TieBreakLexicographicID:
			// contenders is already sorted by OptionID (inherited from tallies).
			contenders = contenders[:1]
		}
	}

	winnerID := contenders[0].OptionID
	var winnerOpt AccordOption
	for _, ro := range view.Options {
		if ro.Option.ID == winnerID {
			winnerOpt = ro.Option
			break
		}
	}
	binding := cloneOptionBinding(winnerOpt.Binding)
	outcome.Phase = AccordPhaseDecided
	outcome.WinningOptionID = winnerID
	outcome.WinningBinding = &binding
	outcome.WinningCommitment = binding.Commitment()

	for _, v := range view.Votes {
		if v.OptionID == winnerID && v.Position == BallotDissent {
			outcome.WinningOptionDissents = append(outcome.WinningOptionDissents, cloneRecordedVote(v))
		}
	}
	sortRecordedVotes(outcome.WinningOptionDissents)

	for _, vt := range view.Vetoes {
		if vt.OptionID == winnerID {
			outcome.WinningOptionVetoes = append(outcome.WinningOptionVetoes, cloneRecordedVeto(vt))
		}
	}
	sortRecordedVetoes(outcome.WinningOptionVetoes)

	return outcome
}

func sortedTallyIDs(tallies []OptionTally) []string {
	if len(tallies) == 0 {
		return nil
	}
	out := make([]string, len(tallies))
	for i, t := range tallies {
		out[i] = t.OptionID
	}
	slices.Sort(out)
	return out
}
