package nex

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	AccordVersion = 1

	AccordSpecHashDomain    = "accord-spec/v1"
	AccordCommandDomain     = "accord-command/v1"
	AccordReceiptHashDomain = "accord-receipt/v1"
	AccordBindingHashDomain = "accord-binding/v1"
	AccordProofHashDomain   = "accord-evidence/v1"
	AccordOutcomeHashDomain = "accord-outcome/v1"

	maxAccordParticipants = 64
	maxAccordRoles        = 128
	maxAccordDomainRoles  = 16
	maxAccordEvidence     = 16
	maxAccordOptions      = 32
	maxAccordPredicates   = 32
	maxAccordVetoEvidence = 16
	maxAccordEvents       = 1024
	minAccordEvents       = 8
	maxAccordSpecBytes    = 256 << 10 // 256 KiB
	maxAccordCommandBytes = 64 << 10  // 64 KiB (non-attest)
	maxAttestCommandBytes = 512 << 10 // 512 KiB (attest)
	maxSealedCommandBytes = 512 << 10 // 512 KiB (sealed vote/resolve)
	maxAccordTotalWeight  = uint64(1) << 50
	maxCachedAccords      = 256
	accordStoreVersion    = 1
)

var (
	ErrAccordSpec         = errors.New("nex: invalid accord specification")
	ErrAccordAuthority    = errors.New("nex: accord permission outside declared role, scope, or expiry")
	ErrAccordPhase        = errors.New("nex: illegal accord transition or height window")
	ErrAccordEvidence     = errors.New("nex: invalid, unpinned, or mismatched accord evidence")
	ErrAccordStale        = errors.New("nex: stale or foreign accord command")
	ErrAccordEquivocation = errors.New("nex: conflicting or duplicate accord ballot")
	ErrAccordBinding      = errors.New("nex: downstream artifact does not match decided accord binding")
)

// AccordPermission scopes what an admitted participant may sign inside an Accord.
type AccordPermission string

const (
	AccordPermitPropose AccordPermission = "propose"
	AccordPermitAttest  AccordPermission = "attest"
	AccordPermitVote    AccordPermission = "vote"
	AccordPermitVeto    AccordPermission = "veto"
	AccordPermitResolve AccordPermission = "resolve"
)

// AccordPhase is the lifecycle state of an Accord.
type AccordPhase string

const (
	AccordPhaseOpen       AccordPhase = "open"
	AccordPhaseDecided    AccordPhase = "decided"
	AccordPhaseDeadlocked AccordPhase = "deadlocked"
	AccordPhaseExpired    AccordPhase = "expired"
)

// AccordRoleGrant grants scoped permissions, optional domain roles, and optional
// voting weight to a single admitted participant.
type AccordRoleGrant struct {
	ID              string             `json:"id"`
	Actor           string             `json:"actor"`
	Scope           string             `json:"scope"`
	DomainRoles     []string           `json:"domain_roles,omitempty"`
	Permissions     []AccordPermission `json:"permissions"`
	Weight          uint64             `json:"weight,omitempty"`
	ExpiresAtHeight uint64             `json:"expires_at_height"`
	LimitsHash      string             `json:"limits_hash"`
}

// BindingKind identifies what concrete downstream artifact an option authorizes.
type BindingKind string

const (
	BindingProtocolSpec BindingKind = "protocol_spec"
	BindingTaskSpec     BindingKind = "task_spec"
	BindingDisposition  BindingKind = "disposition"
)

// OptionBinding commits an option to an enforceable downstream ProtocolSpec,
// TaskSpec, or policy disposition.
type OptionBinding struct {
	Kind           BindingKind   `json:"kind"`
	ProtocolSpec   *ProtocolSpec `json:"protocol_spec,omitempty"`
	TaskSpec       *TaskSpec     `json:"task_spec,omitempty"`
	Disposition    string        `json:"disposition,omitempty"`
	ActionHash     string        `json:"action_hash,omitempty"`
	ParametersHash string        `json:"parameters_hash,omitempty"`
}

// Commitment returns the canonical downstream commitment for a valid binding,
// or "" if the binding is invalid or zero.
func (b OptionBinding) Commitment() string {
	if !validOptionBindingStrings(b) || b.validate() != nil {
		return ""
	}
	switch b.Kind {
	case BindingProtocolSpec:
		return Hash(*b.ProtocolSpec)
	case BindingTaskSpec:
		return b.TaskSpec.ID()
	case BindingDisposition:
		return Hash(struct {
			Domain  string        `json:"domain"`
			Binding OptionBinding `json:"binding"`
		}{AccordBindingHashDomain, b})
	default:
		return ""
	}
}

// AccordOption defines one competing candidate decision with verified evidence
// guards, optional extra mandatory roles, and a concrete downstream binding.
type AccordOption struct {
	ID                  string            `json:"id"`
	Title               string            `json:"title"`
	Priority            uint32            `json:"priority,omitempty"`
	Guard               OptionGuard       `json:"guard,omitempty"`
	ExtraMandatoryRoles []RoleRequirement `json:"extra_mandatory_roles,omitempty"`
	Binding             OptionBinding     `json:"binding"`
}

// AccordSpec fixes the immutable participants, role grants, pinned evidence
// slots, genesis options, height windows, and collective decision rules.
type AccordSpec struct {
	Version          int                `json:"version"`
	Nonce            string             `json:"nonce"`
	Purpose          string             `json:"purpose"`
	Scope            string             `json:"scope"`
	PolicyHash       string             `json:"policy_hash"`
	Participants     []Public           `json:"participants"`
	Roles            []AccordRoleGrant  `json:"roles"`
	Evidence         []EvidenceSlot     `json:"evidence,omitempty"`
	Options          []AccordOption     `json:"options,omitempty"`
	AllowProposals   bool               `json:"allow_proposals,omitempty"`
	ProposalByHeight uint64             `json:"proposal_by_height,omitempty"`
	VoteByHeight     uint64             `json:"vote_by_height"`
	ResolveByHeight  uint64             `json:"resolve_by_height"`
	Rules            DecisionRules      `json:"rules"`
	SealedTally      *SealedTallyConfig `json:"sealed_tally,omitempty"`
	MaxEvents        uint32             `json:"max_events"`
}

// ID returns the domain-separated SHA-256 commitment for this specification.
func (s AccordSpec) ID() string {
	return Hash(struct {
		Domain string     `json:"domain"`
		Spec   AccordSpec `json:"spec"`
	}{AccordSpecHashDomain, s})
}

// Validate checks every structural, cryptographic-key, liveness, UTF-8, and
// size invariant on s before canonicalization or hashing.
func (s AccordSpec) Validate() error {
	if !validAccordSpecStrings(s) {
		return ErrAccordSpec
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > maxAccordSpecBytes {
		return ErrAccordSpec
	}
	if s.Version != AccordVersion || !validAccordID(s.Nonce) || !validAccordText(s.Purpose) ||
		!validAccordID(s.Scope) || !protocolHash(s.PolicyHash) {
		return ErrAccordSpec
	}
	if s.AllowProposals {
		if s.ProposalByHeight < 2 || s.VoteByHeight <= s.ProposalByHeight || s.ResolveByHeight <= s.VoteByHeight {
			return ErrAccordSpec
		}
	} else {
		if s.ProposalByHeight != 0 || s.VoteByHeight < 2 || s.ResolveByHeight <= s.VoteByHeight || len(s.Options) < 1 {
			return ErrAccordSpec
		}
	}
	if len(s.Participants) < 2 || len(s.Participants) > maxAccordParticipants ||
		len(s.Roles) < 1 || len(s.Roles) > maxAccordRoles ||
		len(s.Evidence) > maxAccordEvidence || len(s.Options) > maxAccordOptions {
		return ErrAccordSpec
	}
	if s.MaxEvents < minAccordEvents || s.MaxEvents > maxAccordEvents || int(s.MaxEvents) < len(s.Evidence)+2 {
		return ErrAccordSpec
	}

	parties := make(map[string]bool, len(s.Participants))
	signingKeys := make(map[string]bool, len(s.Participants))
	for _, p := range s.Participants {
		if p.Validate() != nil || parties[p.ID()] || signingKeys[string(p.Signing)] {
			return ErrAccordSpec
		}
		parties[p.ID()] = true
		signingKeys[string(p.Signing)] = true
	}

	if err := validateVetoPolicyBasic(s.Rules.Veto, len(s.Evidence)); err != nil {
		return err
	}

	grantIDs := make(map[string]bool, len(s.Roles))
	actorPerms := make(map[string]map[AccordPermission]bool, len(s.Participants))
	voters := make(map[string]uint64)
	roleVoterCount := make(map[string]uint64)
	roleVoterWeight := make(map[string]uint64)
	attesterActors := make(map[string]bool)
	resolverActors := make(map[string]bool)
	proposerGrants := 0
	eligibleVetoGrants := 0
	canExpire := false
	var totalWeight uint64

	for _, g := range s.Roles {
		if !validAccordID(g.ID) || grantIDs[g.ID] || !parties[g.Actor] || g.Scope != s.Scope ||
			!protocolHash(g.LimitsHash) || g.ExpiresAtHeight < 2 || g.ExpiresAtHeight > s.ResolveByHeight ||
			!uniqueStrings(g.DomainRoles, maxAccordDomainRoles, validAccordID) ||
			len(g.Permissions) == 0 || len(g.Permissions) > 5 {
			return ErrAccordSpec
		}
		grantIDs[g.ID] = true
		if actorPerms[g.Actor] == nil {
			actorPerms[g.Actor] = make(map[AccordPermission]bool, 5)
		}
		seenPerm := make(map[AccordPermission]bool, len(g.Permissions))
		for _, perm := range g.Permissions {
			if !allowedAccordPermission(perm) || seenPerm[perm] || actorPerms[g.Actor][perm] {
				return ErrAccordSpec
			}
			seenPerm[perm] = true
			actorPerms[g.Actor][perm] = true
		}

		if seenPerm[AccordPermitVote] {
			if g.Weight == 0 || g.ExpiresAtHeight <= s.ProposalByHeight {
				return ErrAccordSpec
			}
			if g.Weight > maxAccordTotalWeight || totalWeight > maxAccordTotalWeight-g.Weight {
				return ErrAccordSpec
			}
			totalWeight += g.Weight
			voters[g.Actor] = g.Weight
			for _, dr := range g.DomainRoles {
				roleVoterCount[dr]++
				roleVoterWeight[dr] += g.Weight
			}
		} else if g.Weight != 0 {
			return ErrAccordSpec
		}

		if seenPerm[AccordPermitPropose] {
			if !s.AllowProposals {
				return ErrAccordSpec
			}
			proposerGrants++
		}
		if seenPerm[AccordPermitAttest] {
			if len(s.Evidence) == 0 {
				return ErrAccordSpec
			}
			attesterActors[g.Actor] = true
		}
		if seenPerm[AccordPermitVeto] {
			if s.Rules.Veto.Mode == VetoDisabled || g.ExpiresAtHeight <= s.ProposalByHeight {
				return ErrAccordSpec
			}
			if len(s.Rules.Veto.AllowedDomainRoles) == 0 || slicesIntersect(g.DomainRoles, s.Rules.Veto.AllowedDomainRoles) {
				eligibleVetoGrants++
			}
		}
		if seenPerm[AccordPermitResolve] {
			if g.ExpiresAtHeight <= s.VoteByHeight {
				return ErrAccordSpec
			}
			if g.ExpiresAtHeight == s.ResolveByHeight {
				canExpire = true
			}
			resolverActors[g.Actor] = true
		}
	}

	if len(voters) == 0 || !canExpire {
		return ErrAccordSpec
	}
	if s.AllowProposals && proposerGrants == 0 {
		return ErrAccordSpec
	}
	if len(s.Evidence) > 0 && len(attesterActors) == 0 {
		return ErrAccordSpec
	}
	if s.Rules.Veto.Mode != VetoDisabled && eligibleVetoGrants == 0 {
		return ErrAccordSpec
	}
	if s.Rules.RequireIndependentResolver {
		for actor := range resolverActors {
			perms := actorPerms[actor]
			if perms[AccordPermitPropose] || perms[AccordPermitVote] || perms[AccordPermitVeto] {
				return ErrAccordSpec
			}
		}
	}

	evidenceByID := make(map[string]EvidenceSlot, len(s.Evidence))
	for _, slot := range s.Evidence {
		if !validAccordID(slot.ID) {
			return ErrAccordSpec
		}
		if _, dup := evidenceByID[slot.ID]; dup {
			return ErrAccordSpec
		}
		if err := validateEvidenceSlot(slot, attesterActors); err != nil {
			return err
		}
		evidenceByID[slot.ID] = slot
	}

	if err := validateDecisionRules(s.Rules, uint64(len(voters)), totalWeight, roleVoterCount, roleVoterWeight); err != nil {
		return err
	}
	if err := validateSealedAccordSpec(s, parties, actorPerms); err != nil {
		return err
	}

	optionIDs := make(map[string]bool, len(s.Options))
	for _, opt := range s.Options {
		if !validAccordID(opt.ID) || optionIDs[opt.ID] {
			return ErrAccordSpec
		}
		if err := validateAccordOption(opt, evidenceByID, roleVoterCount, roleVoterWeight); err != nil {
			return err
		}
		optionIDs[opt.ID] = true
	}
	return nil
}

// ProposePayload adds a candidate option before ProposalByHeight.
type ProposePayload struct {
	Option AccordOption `json:"option"`
}

// AttestPayload supplies a pinned upstream TaskHandoff or ProtocolBundle proof.
type AttestPayload struct {
	EvidenceID string          `json:"evidence_id"`
	Handoff    *TaskHandoff    `json:"handoff,omitempty"`
	Protocol   *ProtocolBundle `json:"protocol,omitempty"`
}

// VotePayload records one participant's signed ballot on a candidate option,
// or a Paillier-sealed full ballot when BallotPrivacySealedPaillier is enabled.
type VotePayload struct {
	OptionID      string               `json:"option_id"`
	Position      BallotPosition       `json:"position"`
	RationaleHash string               `json:"rationale_hash"`
	Sealed        *SealedBallotPayload `json:"sealed,omitempty"`
}

// VetoPayload records one participant's signed bounded veto on an option.
type VetoPayload struct {
	OptionID    string   `json:"option_id"`
	ReasonHash  string   `json:"reason_hash"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// ResolvePayload triggers deterministic collective resolution at [VoteByHeight, ResolveByHeight).
type ResolvePayload struct {
	ReasonHash  string            `json:"reason_hash"`
	SealedTally *SealedTallyProof `json:"sealed_tally,omitempty"`
}

// ExpirePayload closes an unresolved Accord at height >= ResolveByHeight.
type ExpirePayload struct {
	ReasonHash string `json:"reason_hash"`
}

// AccordCommand is one signed, hash-linked transition command for an Accord.
type AccordCommand struct {
	RequestID string          `json:"request_id"`
	AccordID  string          `json:"accord_id"`
	Head      string          `json:"head"`
	Actor     string          `json:"actor"`
	GrantID   string          `json:"grant_id"`
	Scope     string          `json:"scope"`
	Action    string          `json:"action"`
	Height    uint64          `json:"height"`
	Propose   *ProposePayload `json:"propose,omitempty"`
	Attest    *AttestPayload  `json:"attest,omitempty"`
	Vote      *VotePayload    `json:"vote,omitempty"`
	Veto      *VetoPayload    `json:"veto,omitempty"`
	Resolve   *ResolvePayload `json:"resolve,omitempty"`
	Expire    *ExpirePayload  `json:"expire,omitempty"`
}

// AccordEvent pairs a signed command with its domain-separated receipt hash.
type AccordEvent struct {
	Command     AccordCommand `json:"command"`
	Signature   []byte        `json:"signature"`
	ReceiptHash string        `json:"receipt_hash"`
}

// AccordBundle is a self-contained offline-verifiable deliberation proof.
type AccordBundle struct {
	Spec   AccordSpec    `json:"spec"`
	Events []AccordEvent `json:"events,omitempty"`
}

// RecordedOption pairs a candidate option with optional dynamic proposal provenance.
type RecordedOption struct {
	Option           AccordOption `json:"option"`
	ProposedBy       string       `json:"proposed_by,omitempty"`
	ProposedAtHeight uint64       `json:"proposed_at_height,omitempty"`
}

// RecordedVote preserves one participant's verified ballot and rationale digest.
type RecordedVote struct {
	Actor         string         `json:"actor"`
	GrantID       string         `json:"grant_id"`
	OptionID      string         `json:"option_id"`
	Position      BallotPosition `json:"position"`
	Weight        uint64         `json:"weight"`
	DomainRoles   []string       `json:"domain_roles,omitempty"`
	RationaleHash string         `json:"rationale_hash"`
	Height        uint64         `json:"height"`
	ReceiptHash   string         `json:"receipt_hash"`
}

// RecordedVeto preserves one participant's verified veto, reason digest, and cited evidence.
type RecordedVeto struct {
	Actor       string   `json:"actor"`
	GrantID     string   `json:"grant_id"`
	OptionID    string   `json:"option_id"`
	DomainRoles []string `json:"domain_roles,omitempty"`
	ReasonHash  string   `json:"reason_hash"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Height      uint64   `json:"height"`
	ReceiptHash string   `json:"receipt_hash"`
}

// AccordView is a detached canonical projection of an Accord's current state.
type AccordView struct {
	ID               string                 `json:"id"`
	Head             string                 `json:"head"`
	Phase            AccordPhase            `json:"phase"`
	Height           uint64                 `json:"height"`
	AllowProposals   bool                   `json:"allow_proposals,omitempty"`
	ProposalByHeight uint64                 `json:"proposal_by_height,omitempty"`
	VoteByHeight     uint64                 `json:"vote_by_height"`
	ResolveByHeight  uint64                 `json:"resolve_by_height"`
	Options          []RecordedOption       `json:"options,omitempty"`
	Evidence         []VerifiedEvidenceFact `json:"evidence,omitempty"`
	Votes            []RecordedVote         `json:"votes,omitempty"`
	SealedBallots    []RecordedSealedBallot `json:"sealed_ballots,omitempty"`
	Vetoes           []RecordedVeto         `json:"vetoes,omitempty"`
	Outcome          *AccordOutcome         `json:"outcome,omitempty"`
}

// StageAt reports the active height stage or terminal phase of v at height.
func (v AccordView) StageAt(height uint64) string {
	if v.Phase != AccordPhaseOpen {
		return string(v.Phase)
	}
	if height == 0 {
		return "invalid"
	}
	if v.AllowProposals && height < v.ProposalByHeight {
		return "proposing"
	}
	if height < v.VoteByHeight {
		return "voting"
	}
	if height < v.ResolveByHeight {
		return "resolving"
	}
	return "expirable"
}

// Accord is a local, deterministic, authenticated collective deliberation engine.
// Hosts supply authoritative monotone heights; Accord is not a distributed consensus engine.
type Accord struct {
	mu              sync.Mutex
	spec            AccordSpec
	events          []AccordEvent
	view            AccordView
	evidenceByID    map[string]EvidenceSlot
	roleVoterCount  map[string]uint64
	roleVoterWeight map[string]uint64
}

// NewAccord validates and initializes a new Accord from spec.
func NewAccord(spec AccordSpec) (*Accord, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	spec = cloneAccordSpec(spec)
	id := spec.ID()

	evidenceByID := make(map[string]EvidenceSlot, len(spec.Evidence))
	for _, slot := range spec.Evidence {
		evidenceByID[slot.ID] = slot
	}
	roleVoterCount := make(map[string]uint64)
	roleVoterWeight := make(map[string]uint64)
	for _, g := range spec.Roles {
		if hasAccordPermission(g, AccordPermitVote) {
			for _, dr := range g.DomainRoles {
				roleVoterCount[dr]++
				roleVoterWeight[dr] += g.Weight
			}
		}
	}

	var opts []RecordedOption
	if len(spec.Options) > 0 {
		opts = make([]RecordedOption, len(spec.Options))
		for i, o := range spec.Options {
			opts[i] = RecordedOption{Option: cloneAccordOption(o)}
		}
		sortRecordedOptions(opts)
	}

	view := AccordView{
		ID:               id,
		Head:             id,
		Phase:            AccordPhaseOpen,
		AllowProposals:   spec.AllowProposals,
		ProposalByHeight: spec.ProposalByHeight,
		VoteByHeight:     spec.VoteByHeight,
		ResolveByHeight:  spec.ResolveByHeight,
		Options:          opts,
	}
	return &Accord{
		spec:            spec,
		view:            view,
		evidenceByID:    evidenceByID,
		roleVoterCount:  roleVoterCount,
		roleVoterWeight: roleVoterWeight,
	}, nil
}

// SignAccordCommand validates UTF-8, shape, and size of cmd before signing it
// under AccordCommandDomain.
func SignAccordCommand(id Identity, cmd AccordCommand) ([]byte, error) {
	if _, err := id.Public(); err != nil {
		return nil, err
	}
	if !validAccordCommandStrings(cmd) || !accordCommandShape(cmd) {
		return nil, ErrAccordSpec
	}
	if err := checkAccordCommandSize(cmd); err != nil {
		return nil, err
	}
	return Sign(id, AccordCommandDomain, cmd), nil
}

// View returns a detached copy of the current canonical AccordView.
func (a *Accord) View() AccordView {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneAccordView(a.view)
}

// Bundle returns a detached portable offline-verifiable AccordBundle.
func (a *Accord) Bundle() AccordBundle {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AccordBundle{
		Spec:   cloneAccordSpec(a.spec),
		Events: cloneAccordEvents(a.events),
	}
}

// EvaluateGuards evaluates every registered option's evidence guard against
// currently attested facts, sorted canonically by OptionID.
func (a *Accord) EvaluateGuards() []OptionGuardStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.view.Options) == 0 {
		return nil
	}
	facts := factsMapFromSlice(a.view.Evidence)
	out := make([]OptionGuardStatus, len(a.view.Options))
	for i, ro := range a.view.Options {
		out[i] = evaluateOptionGuard(ro.Option, facts)
	}
	return out
}

// Prepare builds a command skeleton bound to the Accord's current ID and Head.
func (a *Accord) Prepare(actor, grant, scope, action, requestID string, height uint64) AccordCommand {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AccordCommand{
		RequestID: requestID,
		AccordID:  a.view.ID,
		Head:      a.view.Head,
		Actor:     actor,
		GrantID:   grant,
		Scope:     scope,
		Action:    action,
		Height:    height,
	}
}

// Apply verifies identity, signature, role authorization, height window, and
// payload invariants before atomically committing the command. Exact signed
// (Actor, RequestID) retries return the original receipt even after completion.
func (a *Accord) Apply(cmd AccordCommand, signature []byte, height uint64) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Recursive UTF-8 + NUL/control validation BEFORE any JSON marshal/len/Hash.
	if !validAccordCommandStrings(cmd) {
		return "", ErrAccordSpec
	}
	// 2. Shape + RequestID + Height > 0.
	if !accordCommandShape(cmd) {
		return "", ErrAccordSpec
	}
	// 3. Serialized JSON byte bound.
	if err := checkAccordCommandSize(cmd); err != nil {
		return "", err
	}
	// 4. Explicit typed deep clone of cmd (preserves nil vs [] on embedded structs).
	cmd = cloneAccordCommand(cmd)

	// 5. Actor lookup -> Ed25519 signature length & verification -> AccordID check.
	actor, ok := a.public(cmd.Actor)
	if !ok {
		return "", ErrAccordAuthority
	}
	if len(signature) != ed25519.SignatureSize {
		return "", errors.New("invalid signature")
	}
	sig := slices.Clone(signature)
	if err := Verify(actor, AccordCommandDomain, cmd, sig); err != nil {
		return "", err
	}
	if cmd.AccordID != a.view.ID {
		return "", ErrAccordStale
	}

	// 6. Exact signed (Actor, RequestID) retry lookup before stale/terminal checks.
	cmdHash := Hash(cmd)
	for _, e := range a.events {
		if e.Command.Actor == cmd.Actor && e.Command.RequestID == cmd.RequestID {
			if Hash(e.Command) == cmdHash && bytes.Equal(e.Signature, sig) {
				return e.ReceiptHash, nil
			}
			return "", ErrOperationConflict
		}
	}

	// 7. Stale head or non-monotone / mismatched height.
	if cmd.Head != a.view.Head || cmd.Height != height || height == 0 || height < a.view.Height {
		return "", ErrAccordStale
	}

	// 8. Phase & event cap.
	if a.view.Phase != AccordPhaseOpen || uint32(len(a.events)) >= a.spec.MaxEvents {
		return "", ErrAccordPhase
	}

	// 9. Grant authorization (scope, actor, permission, expiry).
	grant, err := a.authorize(cmd, height)
	if err != nil {
		return "", err
	}

	// 10. Action window, payload validation, and atomic commit on a cloned view.
	receipt := accordReceiptHash(a.view.ID, cmd, sig)
	v := cloneAccordView(a.view)

	switch cmd.Action {
	case "propose":
		if !a.spec.AllowProposals || height >= a.spec.ProposalByHeight || len(v.Options) >= maxAccordOptions {
			return "", ErrAccordPhase
		}
		opt := cmd.Propose.Option
		if err := validateAccordOption(opt, a.evidenceByID, a.roleVoterCount, a.roleVoterWeight); err != nil {
			return "", err
		}
		for _, existing := range v.Options {
			if existing.Option.ID == opt.ID {
				return "", ErrAccordSpec
			}
		}
		v.Options = append(v.Options, RecordedOption{
			Option:           cloneAccordOption(opt),
			ProposedBy:       cmd.Actor,
			ProposedAtHeight: height,
		})
		sortRecordedOptions(v.Options)

	case "attest":
		if height >= a.spec.VoteByHeight {
			return "", ErrAccordPhase
		}
		slot, exists := a.evidenceByID[cmd.Attest.EvidenceID]
		if !exists {
			return "", ErrAccordEvidence
		}
		for _, existing := range v.Evidence {
			if existing.EvidenceID == slot.ID {
				return "", ErrAccordPhase
			}
		}
		if slot.RequiredAttester != "" && cmd.Actor != slot.RequiredAttester {
			return "", ErrAccordAuthority
		}
		fact, err := verifyAttestEvidence(slot, *cmd.Attest, cmd.Actor, height)
		if err != nil {
			return "", err
		}
		v.Evidence = append(v.Evidence, fact)
		sortVerifiedEvidenceFacts(v.Evidence)

	case "vote":
		if height < a.spec.ProposalByHeight || height >= a.spec.VoteByHeight {
			return "", ErrAccordPhase
		}
		if a.spec.Rules.BallotPrivacy == BallotPrivacySealedPaillier {
			if err := a.applySealedVote(&v, cmd, grant, height, receipt); err != nil {
				return "", err
			}
			break
		}
		vp := cmd.Vote
		if vp.Sealed != nil {
			return "", ErrAccordSpec
		}
		if !validAccordID(vp.OptionID) || !allowedBallotPosition(vp.Position) || !protocolHash(vp.RationaleHash) {
			return "", ErrAccordSpec
		}
		if !hasRecordedOption(v.Options, vp.OptionID) {
			return "", ErrAccordPhase
		}
		for _, existing := range v.Votes {
			if existing.Actor == cmd.Actor && existing.OptionID == vp.OptionID {
				return "", ErrAccordEquivocation
			}
			if a.spec.Rules.BallotMode == BallotSingleChoice && vp.Position == BallotApprove &&
				existing.Actor == cmd.Actor && existing.Position == BallotApprove {
				return "", ErrAccordEquivocation
			}
		}
		if vp.Position == BallotApprove || vp.Position == BallotAbstain {
			for _, existingVeto := range v.Vetoes {
				if existingVeto.Actor == cmd.Actor && existingVeto.OptionID == vp.OptionID {
					return "", ErrAccordEquivocation
				}
			}
		}
		var roles []string
		if len(grant.DomainRoles) > 0 {
			roles = slices.Clone(grant.DomainRoles)
			slices.Sort(roles)
		}
		v.Votes = append(v.Votes, RecordedVote{
			Actor:         cmd.Actor,
			GrantID:       cmd.GrantID,
			OptionID:      vp.OptionID,
			Position:      vp.Position,
			Weight:        grant.Weight,
			DomainRoles:   roles,
			RationaleHash: vp.RationaleHash,
			Height:        height,
			ReceiptHash:   receipt,
		})
		sortRecordedVotes(v.Votes)

	case "veto":
		if height < a.spec.ProposalByHeight || height >= a.spec.VoteByHeight {
			return "", ErrAccordPhase
		}
		if a.spec.Rules.Veto.Mode == VetoDisabled {
			return "", ErrAccordAuthority
		}
		if len(a.spec.Rules.Veto.AllowedDomainRoles) > 0 && !slicesIntersect(grant.DomainRoles, a.spec.Rules.Veto.AllowedDomainRoles) {
			return "", ErrAccordAuthority
		}
		vp := cmd.Veto
		if !validAccordID(vp.OptionID) || !protocolHash(vp.ReasonHash) ||
			!uniqueStrings(vp.EvidenceIDs, maxAccordVetoEvidence, validAccordID) {
			return "", ErrAccordSpec
		}
		if !hasRecordedOption(v.Options, vp.OptionID) {
			return "", ErrAccordPhase
		}
		for _, existingVeto := range v.Vetoes {
			if existingVeto.Actor == cmd.Actor && existingVeto.OptionID == vp.OptionID {
				return "", ErrAccordEquivocation
			}
		}
		if a.spec.Rules.BallotPrivacy != BallotPrivacySealedPaillier {
			for _, existingVote := range v.Votes {
				if existingVote.Actor == cmd.Actor && existingVote.OptionID == vp.OptionID &&
					(existingVote.Position == BallotApprove || existingVote.Position == BallotAbstain) {
					return "", ErrAccordEquivocation
				}
			}
		}
		var priorVetoes uint32
		for _, existingVeto := range v.Vetoes {
			if existingVeto.Actor == cmd.Actor {
				priorVetoes++
			}
		}
		if priorVetoes >= a.spec.Rules.Veto.MaxVetoesPerActor {
			return "", ErrAccordAuthority
		}
		if a.spec.Rules.Veto.RequireEvidence && len(vp.EvidenceIDs) == 0 {
			return "", ErrAccordEvidence
		}
		attested := factsMapFromSlice(v.Evidence)
		for _, evID := range vp.EvidenceIDs {
			if _, ok := attested[evID]; !ok {
				return "", ErrAccordEvidence
			}
		}
		var roles []string
		if len(grant.DomainRoles) > 0 {
			roles = slices.Clone(grant.DomainRoles)
			slices.Sort(roles)
		}
		var evIDs []string
		if len(vp.EvidenceIDs) > 0 {
			evIDs = slices.Clone(vp.EvidenceIDs)
			slices.Sort(evIDs)
		}
		v.Vetoes = append(v.Vetoes, RecordedVeto{
			Actor:       cmd.Actor,
			GrantID:     cmd.GrantID,
			OptionID:    vp.OptionID,
			DomainRoles: roles,
			ReasonHash:  vp.ReasonHash,
			EvidenceIDs: evIDs,
			Height:      height,
			ReceiptHash: receipt,
		})
		sortRecordedVetoes(v.Vetoes)

	case "resolve":
		if height < a.spec.VoteByHeight || height >= a.spec.ResolveByHeight {
			return "", ErrAccordPhase
		}
		if !protocolHash(cmd.Resolve.ReasonHash) {
			return "", ErrAccordSpec
		}
		if a.spec.Rules.BallotPrivacy == BallotPrivacySealedPaillier {
			outcome, err := a.applySealedResolve(v, cmd, height)
			if err != nil {
				return "", err
			}
			v.Outcome = &outcome
			v.Phase = outcome.Phase
			break
		}
		if cmd.Resolve.SealedTally != nil {
			return "", ErrAccordSpec
		}
		outcome := evaluateAccordOutcome(a.spec, v, cmd.Actor, height, cmd.Resolve.ReasonHash)
		v.Outcome = &outcome
		v.Phase = outcome.Phase

	case "expire":
		if height < a.spec.ResolveByHeight {
			return "", ErrAccordPhase
		}
		if !protocolHash(cmd.Expire.ReasonHash) {
			return "", ErrAccordSpec
		}
		outcome := evaluateExpiredOutcome(a.spec, v, cmd.Actor, height, cmd.Expire.ReasonHash)
		v.Outcome = &outcome
		v.Phase = AccordPhaseExpired

	default:
		return "", ErrAccordPhase
	}

	v.Head = receipt
	v.Height = height
	a.events = append(a.events, AccordEvent{
		Command:     cmd,
		Signature:   sig,
		ReceiptHash: receipt,
	})
	a.view = v
	return receipt, nil
}

// VerifyAccordBundle replays an exported AccordBundle offline with zero private
// keys or store access, checking every signature, pinned evidence proof, guard,
// ballot, veto, and deterministic outcome against expectedAccordID and expectedHead.
func VerifyAccordBundle(bundle AccordBundle, expectedAccordID, expectedHead string) (AccordView, error) {
	a, err := replayAccordBundle(bundle, expectedAccordID, expectedHead)
	if err != nil {
		return AccordView{}, err
	}
	return a.View(), nil
}

func replayAccordBundle(bundle AccordBundle, expectedAccordID, expectedHead string) (*Accord, error) {
	if !protocolHash(expectedAccordID) || !protocolHash(expectedHead) {
		return nil, ErrAccordStale
	}
	if !validAccordBundleStrings(bundle) {
		return nil, ErrAccordSpec
	}
	a, err := NewAccord(bundle.Spec)
	if err != nil {
		return nil, err
	}
	if a.view.ID != expectedAccordID || len(bundle.Events) > int(bundle.Spec.MaxEvents) {
		return nil, ErrAccordStale
	}
	for _, e := range bundle.Events {
		before := len(a.events)
		head, err := a.Apply(e.Command, e.Signature, e.Command.Height)
		if err != nil {
			return nil, err
		}
		if head != e.ReceiptHash || len(a.events) != before+1 {
			return nil, ErrAccordStale
		}
	}
	if a.view.Head != expectedHead {
		return nil, ErrAccordStale
	}
	return a, nil
}

// AuthorizeProtocolFromAccord verifies bundle offline, confirms it decided on a
// BindingProtocolSpec whose commitment matches spec, and constructs the Protocol.
func AuthorizeProtocolFromAccord(bundle AccordBundle, expectedAccordID, expectedHead string, spec ProtocolSpec) (*Protocol, AccordView, error) {
	view, err := VerifyAccordBundle(bundle, expectedAccordID, expectedHead)
	if err != nil {
		return nil, AccordView{}, err
	}
	if view.Phase != AccordPhaseDecided || view.Outcome == nil || view.Outcome.WinningBinding == nil ||
		view.Outcome.WinningBinding.Kind != BindingProtocolSpec || view.Outcome.WinningBinding.ProtocolSpec == nil {
		return nil, AccordView{}, ErrAccordBinding
	}
	if !validProtocolSpecStrings(spec) || spec.Version != ProtocolVersionV2 || spec.validate() != nil {
		return nil, AccordView{}, ErrAccordBinding
	}
	if Hash(spec) != view.Outcome.WinningCommitment {
		return nil, AccordView{}, ErrAccordBinding
	}
	p, err := NewProtocol(spec)
	if err != nil {
		return nil, AccordView{}, ErrAccordBinding
	}
	return p, view, nil
}

// CreateProtocolFromAccord verifies bundle offline and creates the decided v2
// ProtocolSpec inside store, propagating store errors such as ErrExists unchanged.
func CreateProtocolFromAccord(store *ProtocolStore, bundle AccordBundle, expectedAccordID, expectedHead string) (string, AccordView, error) {
	if store == nil {
		return "", AccordView{}, ErrAccordBinding
	}
	view, err := VerifyAccordBundle(bundle, expectedAccordID, expectedHead)
	if err != nil {
		return "", AccordView{}, err
	}
	if view.Phase != AccordPhaseDecided || view.Outcome == nil || view.Outcome.WinningBinding == nil ||
		view.Outcome.WinningBinding.Kind != BindingProtocolSpec || view.Outcome.WinningBinding.ProtocolSpec == nil {
		return "", AccordView{}, ErrAccordBinding
	}
	spec := cloneProtocolSpec(*view.Outcome.WinningBinding.ProtocolSpec)
	if Hash(spec) != view.Outcome.WinningCommitment {
		return "", AccordView{}, ErrAccordBinding
	}
	id, err := store.Create(spec)
	if err != nil {
		return "", AccordView{}, err
	}
	return id, view, nil
}

// AuthorizeTaskFromAccord verifies bundle offline and confirms it decided on a
// BindingTaskSpec whose exact TaskID matches task.
func AuthorizeTaskFromAccord(bundle AccordBundle, expectedAccordID, expectedHead string, task TaskSpec) (AccordView, error) {
	view, err := VerifyAccordBundle(bundle, expectedAccordID, expectedHead)
	if err != nil {
		return AccordView{}, err
	}
	if view.Phase != AccordPhaseDecided || view.Outcome == nil || view.Outcome.WinningBinding == nil ||
		view.Outcome.WinningBinding.Kind != BindingTaskSpec || view.Outcome.WinningBinding.TaskSpec == nil {
		return AccordView{}, ErrAccordBinding
	}
	if !validTaskSpecStrings(task) || !protocolHash(task.GoalID) || task.validate(task.GoalID) != nil {
		return AccordView{}, ErrAccordBinding
	}
	if task.ID() != view.Outcome.WinningCommitment {
		return AccordView{}, ErrAccordBinding
	}
	return view, nil
}

// AuthorizeDispositionFromAccord verifies bundle offline and confirms it decided
// on a BindingDisposition matching the exact (disposition, actionHash, parametersHash).
func AuthorizeDispositionFromAccord(bundle AccordBundle, expectedAccordID, expectedHead string, disposition, actionHash, parametersHash string) (AccordView, error) {
	view, err := VerifyAccordBundle(bundle, expectedAccordID, expectedHead)
	if err != nil {
		return AccordView{}, err
	}
	if view.Phase != AccordPhaseDecided || view.Outcome == nil || view.Outcome.WinningBinding == nil ||
		view.Outcome.WinningBinding.Kind != BindingDisposition {
		return AccordView{}, ErrAccordBinding
	}
	candidate := OptionBinding{
		Kind:           BindingDisposition,
		Disposition:    disposition,
		ActionHash:     actionHash,
		ParametersHash: parametersHash,
	}
	if candidate.Commitment() == "" || candidate.Commitment() != view.Outcome.WinningCommitment {
		return AccordView{}, ErrAccordBinding
	}
	return view, nil
}

// --- Internal helpers, validators, and explicit typed deep-cloners ---

func accordReceiptHash(accordID string, cmd AccordCommand, sig []byte) string {
	return Hash(struct {
		Domain    string        `json:"domain"`
		AccordID  string        `json:"accord_id"`
		Command   AccordCommand `json:"command"`
		Signature []byte        `json:"signature"`
	}{AccordReceiptHashDomain, accordID, cmd, sig})
}

func (a *Accord) public(actor string) (Public, bool) {
	for _, p := range a.spec.Participants {
		if p.ID() == actor {
			return p, true
		}
	}
	return Public{}, false
}

func accordActionPermission(action string) AccordPermission {
	switch action {
	case "propose":
		return AccordPermitPropose
	case "attest":
		return AccordPermitAttest
	case "vote":
		return AccordPermitVote
	case "veto":
		return AccordPermitVeto
	case "resolve", "expire":
		return AccordPermitResolve
	default:
		return ""
	}
}

func allowedAccordPermission(p AccordPermission) bool {
	switch p {
	case AccordPermitPropose, AccordPermitAttest, AccordPermitVote, AccordPermitVeto, AccordPermitResolve:
		return true
	default:
		return false
	}
}

func hasAccordPermission(g AccordRoleGrant, p AccordPermission) bool {
	for _, perm := range g.Permissions {
		if perm == p {
			return true
		}
	}
	return false
}

func (a *Accord) authorize(cmd AccordCommand, height uint64) (AccordRoleGrant, error) {
	perm := accordActionPermission(cmd.Action)
	if perm == "" || cmd.Scope != a.spec.Scope {
		return AccordRoleGrant{}, ErrAccordAuthority
	}
	for _, g := range a.spec.Roles {
		if g.ID != cmd.GrantID || g.Actor != cmd.Actor || g.Scope != cmd.Scope || !hasAccordPermission(g, perm) {
			continue
		}
		if cmd.Action == "expire" {
			if height >= a.spec.ResolveByHeight && g.ExpiresAtHeight == a.spec.ResolveByHeight {
				return g, nil
			}
			return AccordRoleGrant{}, ErrAccordAuthority
		}
		if height < g.ExpiresAtHeight {
			return g, nil
		}
	}
	return AccordRoleGrant{}, ErrAccordAuthority
}

func accordCommandShape(cmd AccordCommand) bool {
	if !validAccordID(cmd.RequestID) || cmd.Height == 0 {
		return false
	}
	n := 0
	for _, set := range []bool{
		cmd.Propose != nil,
		cmd.Attest != nil,
		cmd.Vote != nil,
		cmd.Veto != nil,
		cmd.Resolve != nil,
		cmd.Expire != nil,
	} {
		if set {
			n++
		}
	}
	if n != 1 {
		return false
	}
	switch cmd.Action {
	case "propose":
		return cmd.Propose != nil
	case "attest":
		return cmd.Attest != nil && validAccordID(cmd.Attest.EvidenceID) && ((cmd.Attest.Handoff != nil) != (cmd.Attest.Protocol != nil))
	case "vote":
		return cmd.Vote != nil
	case "veto":
		return cmd.Veto != nil
	case "resolve":
		return cmd.Resolve != nil
	case "expire":
		return cmd.Expire != nil
	default:
		return false
	}
}

func checkAccordCommandSize(cmd AccordCommand) error {
	raw, err := json.Marshal(cmd)
	if err != nil {
		return ErrAccordSpec
	}
	limit := maxAccordCommandBytes
	switch cmd.Action {
	case "attest":
		limit = maxAttestCommandBytes
	case "vote":
		if cmd.Vote != nil && cmd.Vote.Sealed != nil {
			limit = maxSealedCommandBytes
		}
	case "resolve":
		if cmd.Resolve != nil && cmd.Resolve.SealedTally != nil {
			limit = maxSealedCommandBytes
		}
	}
	if len(raw) > limit {
		return ErrAccordSpec
	}
	return nil
}

func validAccordID(s string) bool {
	if !utf8.ValidString(s) || len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validAccordText(s string) bool {
	if !utf8.ValidString(s) || len(s) < 1 || len(s) > 4096 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validAccordSlotName(s string) bool {
	if !utf8.ValidString(s) || !coordinationName(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validUTF8NoControl(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validUTF8NoNUL(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsRune(s, 0)
}

func allowedBindingDisposition(d string) bool {
	switch d {
	case "continue", "retry", "renegotiate", "refuse", "hold", "remediate":
		return true
	default:
		return false
	}
}

func (b OptionBinding) validate() error {
	switch b.Kind {
	case BindingProtocolSpec:
		if b.ProtocolSpec == nil || b.TaskSpec != nil || b.Disposition != "" || b.ActionHash != "" || b.ParametersHash != "" {
			return ErrAccordSpec
		}
		if b.ProtocolSpec.Version != ProtocolVersionV2 || !validProtocolSpecStrings(*b.ProtocolSpec) || b.ProtocolSpec.validate() != nil {
			return ErrAccordSpec
		}
		return nil
	case BindingTaskSpec:
		if b.TaskSpec == nil || b.ProtocolSpec != nil || b.Disposition != "" || b.ActionHash != "" || b.ParametersHash != "" {
			return ErrAccordSpec
		}
		if !validTaskSpecStrings(*b.TaskSpec) || !protocolHash(b.TaskSpec.GoalID) || b.TaskSpec.validate(b.TaskSpec.GoalID) != nil {
			return ErrAccordSpec
		}
		return nil
	case BindingDisposition:
		if b.ProtocolSpec != nil || b.TaskSpec != nil || !allowedBindingDisposition(b.Disposition) || !protocolHash(b.ActionHash) {
			return ErrAccordSpec
		}
		if b.ParametersHash != "" && !protocolHash(b.ParametersHash) {
			return ErrAccordSpec
		}
		return nil
	default:
		return ErrAccordSpec
	}
}

func validateAccordOption(opt AccordOption, evidenceByID map[string]EvidenceSlot, roleVoterCount, roleVoterWeight map[string]uint64) error {
	if !validAccordOptionStrings(opt) || !validAccordID(opt.ID) || !validAccordText(opt.Title) {
		return ErrAccordSpec
	}
	if err := validateOptionGuard(opt.Guard, evidenceByID); err != nil {
		return err
	}
	if err := validateRoleRequirements(opt.ExtraMandatoryRoles, roleVoterCount, roleVoterWeight); err != nil {
		return err
	}
	return opt.Binding.validate()
}

func slicesIntersect(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func hasRecordedOption(opts []RecordedOption, id string) bool {
	for _, ro := range opts {
		if ro.Option.ID == id {
			return true
		}
	}
	return false
}

func sortRecordedOptions(opts []RecordedOption) {
	slices.SortFunc(opts, func(a, b RecordedOption) int {
		return strings.Compare(a.Option.ID, b.Option.ID)
	})
}

func sortVerifiedEvidenceFacts(facts []VerifiedEvidenceFact) {
	slices.SortFunc(facts, func(a, b VerifiedEvidenceFact) int {
		return strings.Compare(a.EvidenceID, b.EvidenceID)
	})
}

func sortRecordedVotes(votes []RecordedVote) {
	slices.SortFunc(votes, func(a, b RecordedVote) int {
		if c := strings.Compare(a.OptionID, b.OptionID); c != 0 {
			return c
		}
		return strings.Compare(a.Actor, b.Actor)
	})
}

func sortRecordedVetoes(vetoes []RecordedVeto) {
	slices.SortFunc(vetoes, func(a, b RecordedVeto) int {
		if c := strings.Compare(a.OptionID, b.OptionID); c != 0 {
			return c
		}
		return strings.Compare(a.Actor, b.Actor)
	})
}

// --- Recursive UTF-8 & NUL/control validators (run BEFORE len/uniqueness/json.Marshal) ---

func validAccordSpecStrings(s AccordSpec) bool {
	if !validUTF8NoControl(s.Nonce) || !validUTF8NoControl(s.Purpose) ||
		!validUTF8NoControl(s.Scope) || !validUTF8NoControl(s.PolicyHash) {
		return false
	}
	for _, g := range s.Roles {
		if !validUTF8NoControl(g.ID) || !validUTF8NoControl(g.Actor) || !validUTF8NoControl(g.Scope) || !validUTF8NoControl(g.LimitsHash) {
			return false
		}
		for _, dr := range g.DomainRoles {
			if !validUTF8NoControl(dr) {
				return false
			}
		}
		for _, perm := range g.Permissions {
			if !validUTF8NoControl(string(perm)) {
				return false
			}
		}
	}
	for _, slot := range s.Evidence {
		if !validUTF8NoControl(slot.ID) || !validUTF8NoControl(string(slot.Kind)) ||
			!validUTF8NoControl(slot.GoalID) || !validUTF8NoControl(slot.TaskID) ||
			!validUTF8NoControl(slot.ExpectedAuthority) || !validUTF8NoControl(slot.ExpectedResultHash) ||
			!validUTF8NoControl(slot.ProtocolID) || !validUTF8NoControl(slot.ExpectedHead) ||
			!validUTF8NoControl(slot.RequiredAttester) {
			return false
		}
	}
	for _, opt := range s.Options {
		if !validAccordOptionStrings(opt) {
			return false
		}
	}
	if !validUTF8NoControl(string(s.Rules.BallotMode)) || !validUTF8NoControl(string(s.Rules.BallotPrivacy)) ||
		!validUTF8NoControl(string(s.Rules.Veto.Mode)) || !validUTF8NoControl(string(s.Rules.TieBreak)) {
		return false
	}
	if !validSealedTallyConfigStrings(s.SealedTally) {
		return false
	}
	for _, mr := range s.Rules.MandatoryRoles {
		if !validUTF8NoControl(mr.Role) {
			return false
		}
	}
	for _, dr := range s.Rules.Veto.AllowedDomainRoles {
		if !validUTF8NoControl(dr) {
			return false
		}
	}
	return true
}

func validAccordOptionStrings(opt AccordOption) bool {
	if !validUTF8NoControl(opt.ID) || !validUTF8NoControl(opt.Title) {
		return false
	}
	for _, p := range opt.Guard.AllOf {
		if !validEvidencePredicateStrings(p) {
			return false
		}
	}
	for _, p := range opt.Guard.AnyOf {
		if !validEvidencePredicateStrings(p) {
			return false
		}
	}
	for _, mr := range opt.ExtraMandatoryRoles {
		if !validUTF8NoControl(mr.Role) {
			return false
		}
	}
	return validOptionBindingStrings(opt.Binding)
}

func validEvidencePredicateStrings(p EvidencePredicate) bool {
	if !validUTF8NoControl(p.EvidenceID) || !validUTF8NoControl(string(p.Op)) ||
		!validUTF8NoControl(p.Slot) || !validUTF8NoControl(p.Digest) || !validUTF8NoControl(p.ActorID) {
		return false
	}
	for _, o := range p.Outcomes {
		if !validUTF8NoControl(string(o)) {
			return false
		}
	}
	for _, d := range p.Dispositions {
		if !validUTF8NoControl(d) {
			return false
		}
	}
	return true
}

func validOptionBindingStrings(b OptionBinding) bool {
	if !validUTF8NoControl(string(b.Kind)) || !validUTF8NoControl(b.Disposition) ||
		!validUTF8NoControl(b.ActionHash) || !validUTF8NoControl(b.ParametersHash) {
		return false
	}
	if b.ProtocolSpec != nil && !validProtocolSpecStrings(*b.ProtocolSpec) {
		return false
	}
	if b.TaskSpec != nil && !validTaskSpecStrings(*b.TaskSpec) {
		return false
	}
	return true
}

func validAccordCommandStrings(cmd AccordCommand) bool {
	if !validUTF8NoControl(cmd.RequestID) || !validUTF8NoControl(cmd.AccordID) || !validUTF8NoControl(cmd.Head) ||
		!validUTF8NoControl(cmd.Actor) || !validUTF8NoControl(cmd.GrantID) || !validUTF8NoControl(cmd.Scope) ||
		!validUTF8NoControl(cmd.Action) {
		return false
	}
	if cmd.Propose != nil && !validAccordOptionStrings(cmd.Propose.Option) {
		return false
	}
	if cmd.Attest != nil {
		if !validUTF8NoControl(cmd.Attest.EvidenceID) {
			return false
		}
		if cmd.Attest.Handoff != nil && !validTaskHandoffStrings(*cmd.Attest.Handoff) {
			return false
		}
		if cmd.Attest.Protocol != nil && !validProtocolBundleStrings(*cmd.Attest.Protocol) {
			return false
		}
	}
	if cmd.Vote != nil {
		if !validUTF8NoControl(cmd.Vote.OptionID) || !validUTF8NoControl(string(cmd.Vote.Position)) || !validUTF8NoControl(cmd.Vote.RationaleHash) {
			return false
		}
		if !validSealedBallotStrings(cmd.Vote.Sealed) {
			return false
		}
	}
	if cmd.Veto != nil {
		if !validUTF8NoControl(cmd.Veto.OptionID) || !validUTF8NoControl(cmd.Veto.ReasonHash) {
			return false
		}
		for _, ev := range cmd.Veto.EvidenceIDs {
			if !validUTF8NoControl(ev) {
				return false
			}
		}
	}
	if cmd.Resolve != nil {
		if !validUTF8NoControl(cmd.Resolve.ReasonHash) || !validSealedTallyProofStrings(cmd.Resolve.SealedTally) {
			return false
		}
	}
	if cmd.Expire != nil && !validUTF8NoControl(cmd.Expire.ReasonHash) {
		return false
	}
	return true
}

func validAccordBundleStrings(b AccordBundle) bool {
	if !validAccordSpecStrings(b.Spec) {
		return false
	}
	for _, e := range b.Events {
		if !validUTF8NoControl(e.ReceiptHash) || !validAccordCommandStrings(e.Command) {
			return false
		}
	}
	return true
}

func validProtocolSpecStrings(s ProtocolSpec) bool {
	if !validUTF8NoNUL(s.Nonce) || !validUTF8NoNUL(s.Purpose) || !validUTF8NoNUL(s.IntendedOutcome) ||
		!validUTF8NoNUL(s.Scope) || !validUTF8NoNUL(s.SpecificationHash) || !validUTF8NoNUL(s.AcceptanceHash) ||
		!validUTF8NoNUL(s.FailurePolicyHash) || !validUTF8NoNUL(s.Initiator) || !validUTF8NoNUL(s.DissentPolicy) ||
		!validUTF8NoNUL(s.TaskID) {
		return false
	}
	for _, g := range s.Roles {
		if !validUTF8NoNUL(g.ID) || !validUTF8NoNUL(g.Actor) || !validUTF8NoNUL(g.Label) ||
			!validUTF8NoNUL(g.Scope) || !validUTF8NoNUL(g.LimitsHash) || !validUTF8NoNUL(g.EvidenceObligation) {
			return false
		}
		for _, perm := range g.Permissions {
			if !validUTF8NoNUL(string(perm)) {
				return false
			}
		}
	}
	for _, r := range s.Resources {
		if !validUTF8NoNUL(r.Resource) {
			return false
		}
	}
	for _, w := range s.RequiredWitnesses {
		if !validUTF8NoNUL(w) {
			return false
		}
	}
	for _, a := range s.Return.SuccessArtifacts {
		if !validUTF8NoNUL(a) {
			return false
		}
	}
	for _, a := range s.Return.FailureArtifacts {
		if !validUTF8NoNUL(a) {
			return false
		}
	}
	for _, d := range s.Return.AllowedDisposition {
		if !validUTF8NoNUL(d) {
			return false
		}
	}
	return true
}

func validTaskSpecStrings(t TaskSpec) bool {
	if !validUTF8NoNUL(t.GoalID) || !validUTF8NoNUL(t.Nonce) || !validUTF8NoNUL(t.Purpose) || !validUTF8NoNUL(t.Scope) ||
		!validUTF8NoNUL(t.SpecificationHash) || !validUTF8NoNUL(t.AcceptanceHash) || !validUTF8NoNUL(t.FailurePolicyHash) {
		return false
	}
	for _, o := range t.Outputs {
		if !validUTF8NoNUL(o) {
			return false
		}
	}
	for _, o := range t.FailureOutputs {
		if !validUTF8NoNUL(o) {
			return false
		}
	}
	for _, d := range t.Dependencies {
		if !validUTF8NoNUL(d.Input) || !validUTF8NoNUL(d.TaskID) || !validUTF8NoNUL(d.ProtocolID) ||
			!validUTF8NoNUL(d.Head) || !validUTF8NoNUL(d.Slot) || !validUTF8NoNUL(d.Digest) || !validUTF8NoNUL(string(d.Outcome)) {
			return false
		}
	}
	return true
}

func validNamedArtifactsStrings(arts []NamedArtifact) bool {
	for _, a := range arts {
		if !validUTF8NoNUL(a.Name) || !validUTF8NoNUL(a.Ref.Digest) || !validUTF8NoNUL(a.Ref.MediaType) {
			return false
		}
	}
	return true
}

func validProtocolBundleStrings(b ProtocolBundle) bool {
	if !validProtocolSpecStrings(b.Spec) {
		return false
	}
	for _, e := range b.Events {
		if !validUTF8NoNUL(e.ReceiptHash) {
			return false
		}
		c := e.Command
		if !validUTF8NoNUL(c.RequestID) || !validUTF8NoNUL(c.ProtocolID) || !validUTF8NoNUL(c.Head) ||
			!validUTF8NoNUL(c.Actor) || !validUTF8NoNUL(c.GrantID) || !validUTF8NoNUL(c.Scope) || !validUTF8NoNUL(c.Action) {
			return false
		}
		if c.Report != nil {
			if !validUTF8NoNUL(string(c.Report.Outcome)) || !validUTF8NoNUL(c.Report.Stage) || !validUTF8NoNUL(c.Report.ReasonHash) {
				return false
			}
			for _, ev := range c.Report.Evidence {
				if !validUTF8NoNUL(ev) {
					return false
				}
			}
			for _, r := range c.Report.Resources {
				if !validUTF8NoNUL(r.Resource) {
					return false
				}
			}
			for _, bc := range c.Report.BreachClaims {
				if !validUTF8NoNUL(bc.Actor) || !validUTF8NoNUL(bc.EvidenceHash) {
					return false
				}
			}
			if c.Report.Manifest != nil {
				if !validUTF8NoNUL(c.Report.Manifest.MethodHash) ||
					!validNamedArtifactsStrings(c.Report.Manifest.Inputs) ||
					!validNamedArtifactsStrings(c.Report.Manifest.Outputs) {
					return false
				}
				for _, cl := range c.Report.Manifest.Claims {
					if !validUTF8NoNUL(cl) {
						return false
					}
				}
			}
		}
		if c.Review != nil {
			if !validUTF8NoNUL(c.Review.ReportHash) || !validUTF8NoNUL(c.Review.AssessmentHash) {
				return false
			}
		}
		if c.Resolution != nil {
			if !validUTF8NoNUL(c.Resolution.ReportHash) || !validUTF8NoNUL(c.Resolution.Outcome) || !validUTF8NoNUL(c.Resolution.ReasonHash) {
				return false
			}
		}
		if c.Return != nil {
			if !validUTF8NoNUL(c.Return.ResolutionHash) || !validUTF8NoNUL(c.Return.ReviewsHash) ||
				!validUTF8NoNUL(c.Return.Uncertainty) || !validUTF8NoNUL(c.Return.Disposition) {
				return false
			}
			for _, ev := range c.Return.Evidence {
				if !validUTF8NoNUL(ev) {
					return false
				}
			}
			for _, r := range c.Return.Resources {
				if !validUTF8NoNUL(r.Resource) {
					return false
				}
			}
			for _, sa := range c.Return.SafeAssumptions {
				if !validUTF8NoNUL(sa) {
					return false
				}
			}
			for _, art := range c.Return.Artifacts {
				if !validUTF8NoNUL(art.ID) || !validUTF8NoNUL(art.Commitment) || !validUTF8NoNUL(art.ReuseRestrictions) {
					return false
				}
			}
			for _, ss := range c.Return.SuccessorSpecs {
				if !validUTF8NoNUL(ss) {
					return false
				}
			}
		}
		if c.Incomplete != nil {
			if !validUTF8NoNUL(c.Incomplete.ReasonHash) || !validNamedArtifactsStrings(c.Incomplete.Artifacts) {
				return false
			}
			for _, ev := range c.Incomplete.Evidence {
				if !validUTF8NoNUL(ev) {
					return false
				}
			}
		}
	}
	return true
}

func validTaskHandoffStrings(h TaskHandoff) bool {
	if !validTaskSpecStrings(h.Task) || !validProtocolBundleStrings(h.Protocol) {
		return false
	}
	if !validUTF8NoNUL(h.Claim.GoalID) || !validUTF8NoNUL(h.Claim.TaskID) || !validUTF8NoNUL(h.Claim.WorkerID) ||
		!validUTF8NoNUL(h.Claim.RequestID) || !validUTF8NoNUL(h.Claim.ProtocolID) {
		return false
	}
	if !validUTF8NoNUL(h.Result.Lease.GoalID) || !validUTF8NoNUL(h.Result.Lease.TaskID) ||
		!validUTF8NoNUL(h.Result.Lease.ProtocolID) || !validUTF8NoNUL(h.Result.Lease.WorkerID) ||
		!validUTF8NoNUL(h.Result.Lease.RequestID) || !validUTF8NoNUL(h.Result.Head) ||
		!validUTF8NoNUL(string(h.Result.Outcome)) {
		return false
	}
	for _, a := range h.Result.Artifacts {
		if !validUTF8NoNUL(a.Slot) || !validUTF8NoNUL(a.Digest) {
			return false
		}
	}
	return true
}

// --- Explicit typed deep cloners (zero JSON round-trip; preserves nil vs [] on embedded structs) ---

func cloneProtocolSpec(s ProtocolSpec) ProtocolSpec {
	out := s
	if s.Participants != nil {
		out.Participants = make([]Public, len(s.Participants))
		for i, p := range s.Participants {
			out.Participants[i] = clonePublic(p)
		}
	}
	if s.Roles != nil {
		out.Roles = make([]RoleGrant, len(s.Roles))
		for i, r := range s.Roles {
			r.Permissions = slices.Clone(r.Permissions)
			out.Roles[i] = r
		}
	}
	out.Resources = slices.Clone(s.Resources)
	out.RequiredWitnesses = slices.Clone(s.RequiredWitnesses)
	out.Return.SuccessArtifacts = slices.Clone(s.Return.SuccessArtifacts)
	out.Return.FailureArtifacts = slices.Clone(s.Return.FailureArtifacts)
	out.Return.AllowedDisposition = slices.Clone(s.Return.AllowedDisposition)
	return out
}

func cloneProtocolBundle(b ProtocolBundle) ProtocolBundle {
	out := ProtocolBundle{Spec: cloneProtocolSpec(b.Spec)}
	if b.Events != nil {
		out.Events = make([]ProtocolEvent, len(b.Events))
		for i, e := range b.Events {
			ce := ProtocolEvent{
				Command:     e.Command,
				Signature:   slices.Clone(e.Signature),
				ReceiptHash: e.ReceiptHash,
			}
			if e.Command.Report != nil {
				r := *e.Command.Report
				r.Evidence = slices.Clone(r.Evidence)
				r.Resources = slices.Clone(r.Resources)
				r.BreachClaims = slices.Clone(r.BreachClaims)
				if r.Manifest != nil {
					m := *r.Manifest
					m.Inputs = slices.Clone(m.Inputs)
					m.Outputs = slices.Clone(m.Outputs)
					m.Claims = slices.Clone(m.Claims)
					r.Manifest = &m
				}
				ce.Command.Report = &r
			}
			if e.Command.Review != nil {
				rv := *e.Command.Review
				ce.Command.Review = &rv
			}
			if e.Command.Resolution != nil {
				res := *e.Command.Resolution
				ce.Command.Resolution = &res
			}
			if e.Command.Return != nil {
				ret := *e.Command.Return
				ret.Evidence = slices.Clone(ret.Evidence)
				ret.Resources = slices.Clone(ret.Resources)
				ret.SafeAssumptions = slices.Clone(ret.SafeAssumptions)
				ret.Artifacts = slices.Clone(ret.Artifacts)
				ret.SuccessorSpecs = slices.Clone(ret.SuccessorSpecs)
				ce.Command.Return = &ret
			}
			if e.Command.Incomplete != nil {
				inc := *e.Command.Incomplete
				inc.Evidence = slices.Clone(inc.Evidence)
				inc.Artifacts = slices.Clone(inc.Artifacts)
				ce.Command.Incomplete = &inc
			}
			out.Events[i] = ce
		}
	}
	return out
}

func cloneTaskSpec(t TaskSpec) TaskSpec {
	out := t
	out.Authority = clonePublic(t.Authority)
	out.Outputs = slices.Clone(t.Outputs)
	out.FailureOutputs = slices.Clone(t.FailureOutputs)
	out.Dependencies = slices.Clone(t.Dependencies)
	return out
}

func cloneTaskHandoff(h TaskHandoff) TaskHandoff {
	out := h
	out.Task = cloneTaskSpec(h.Task)
	out.ClaimSignature = slices.Clone(h.ClaimSignature)
	out.Protocol = cloneProtocolBundle(h.Protocol)
	out.Result.Artifacts = slices.Clone(h.Result.Artifacts)
	return out
}

func cloneEvidencePredicate(p EvidencePredicate) EvidencePredicate {
	out := p
	out.Outcomes = slices.Clone(p.Outcomes)
	out.Dispositions = slices.Clone(p.Dispositions)
	return out
}

func cloneOptionGuard(g OptionGuard) OptionGuard {
	var out OptionGuard
	if len(g.AllOf) > 0 {
		out.AllOf = make([]EvidencePredicate, len(g.AllOf))
		for i, p := range g.AllOf {
			out.AllOf[i] = cloneEvidencePredicate(p)
		}
	}
	if len(g.AnyOf) > 0 {
		out.AnyOf = make([]EvidencePredicate, len(g.AnyOf))
		for i, p := range g.AnyOf {
			out.AnyOf[i] = cloneEvidencePredicate(p)
		}
	}
	return out
}

func cloneOptionBinding(b OptionBinding) OptionBinding {
	out := b
	if b.ProtocolSpec != nil {
		ps := cloneProtocolSpec(*b.ProtocolSpec)
		out.ProtocolSpec = &ps
	}
	if b.TaskSpec != nil {
		ts := cloneTaskSpec(*b.TaskSpec)
		out.TaskSpec = &ts
	}
	return out
}

func cloneAccordOption(o AccordOption) AccordOption {
	out := o
	out.Guard = cloneOptionGuard(o.Guard)
	if len(o.ExtraMandatoryRoles) > 0 {
		out.ExtraMandatoryRoles = slices.Clone(o.ExtraMandatoryRoles)
	} else {
		out.ExtraMandatoryRoles = nil
	}
	out.Binding = cloneOptionBinding(o.Binding)
	return out
}

func cloneDecisionRules(r DecisionRules) DecisionRules {
	out := r
	if len(r.MandatoryRoles) > 0 {
		out.MandatoryRoles = slices.Clone(r.MandatoryRoles)
	} else {
		out.MandatoryRoles = nil
	}
	if len(r.Veto.AllowedDomainRoles) > 0 {
		out.Veto.AllowedDomainRoles = slices.Clone(r.Veto.AllowedDomainRoles)
	} else {
		out.Veto.AllowedDomainRoles = nil
	}
	return out
}

func cloneAccordSpec(s AccordSpec) AccordSpec {
	out := s
	if len(s.Participants) > 0 {
		out.Participants = make([]Public, len(s.Participants))
		for i, p := range s.Participants {
			out.Participants[i] = clonePublic(p)
		}
	} else {
		out.Participants = nil
	}
	if len(s.Roles) > 0 {
		out.Roles = make([]AccordRoleGrant, len(s.Roles))
		for i, g := range s.Roles {
			cg := g
			if len(g.DomainRoles) > 0 {
				cg.DomainRoles = slices.Clone(g.DomainRoles)
			} else {
				cg.DomainRoles = nil
			}
			cg.Permissions = slices.Clone(g.Permissions)
			out.Roles[i] = cg
		}
	} else {
		out.Roles = nil
	}
	if len(s.Evidence) > 0 {
		out.Evidence = slices.Clone(s.Evidence)
	} else {
		out.Evidence = nil
	}
	if len(s.Options) > 0 {
		out.Options = make([]AccordOption, len(s.Options))
		for i, o := range s.Options {
			out.Options[i] = cloneAccordOption(o)
		}
	} else {
		out.Options = nil
	}
	out.Rules = cloneDecisionRules(s.Rules)
	out.SealedTally = cloneSealedTallyConfig(s.SealedTally)
	return out
}

func cloneAccordCommand(c AccordCommand) AccordCommand {
	out := c
	if c.Propose != nil {
		p := ProposePayload{Option: cloneAccordOption(c.Propose.Option)}
		out.Propose = &p
	}
	if c.Attest != nil {
		a := AttestPayload{EvidenceID: c.Attest.EvidenceID}
		if c.Attest.Handoff != nil {
			h := cloneTaskHandoff(*c.Attest.Handoff)
			a.Handoff = &h
		}
		if c.Attest.Protocol != nil {
			pb := cloneProtocolBundle(*c.Attest.Protocol)
			a.Protocol = &pb
		}
		out.Attest = &a
	}
	if c.Vote != nil {
		v := *c.Vote
		v.Sealed = cloneSealedBallotPayload(c.Vote.Sealed)
		out.Vote = &v
	}
	if c.Veto != nil {
		v := *c.Veto
		if len(v.EvidenceIDs) > 0 {
			v.EvidenceIDs = slices.Clone(v.EvidenceIDs)
		} else {
			v.EvidenceIDs = nil
		}
		out.Veto = &v
	}
	if c.Resolve != nil {
		r := *c.Resolve
		r.SealedTally = cloneSealedTallyProof(c.Resolve.SealedTally)
		out.Resolve = &r
	}
	if c.Expire != nil {
		ex := *c.Expire
		out.Expire = &ex
	}
	return out
}

func cloneAccordEvents(events []AccordEvent) []AccordEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]AccordEvent, len(events))
	for i, e := range events {
		out[i] = AccordEvent{
			Command:     cloneAccordCommand(e.Command),
			Signature:   slices.Clone(e.Signature),
			ReceiptHash: e.ReceiptHash,
		}
	}
	return out
}

func cloneVerifiedEvidenceFact(f VerifiedEvidenceFact) VerifiedEvidenceFact {
	out := f
	out.DissentingWitnesses = cloneNonEmptyStrings(f.DissentingWitnesses)
	out.ReviewingWitnesses = cloneNonEmptyStrings(f.ReviewingWitnesses)
	out.MissingWitnesses = cloneNonEmptyStrings(f.MissingWitnesses)
	out.Participants = cloneNonEmptyStrings(f.Participants)
	if len(f.Artifacts) > 0 {
		out.Artifacts = slices.Clone(f.Artifacts)
	} else {
		out.Artifacts = nil
	}
	if len(f.ArtifactRefs) > 0 {
		out.ArtifactRefs = slices.Clone(f.ArtifactRefs)
	} else {
		out.ArtifactRefs = nil
	}
	return out
}

func cloneRecordedVote(v RecordedVote) RecordedVote {
	out := v
	out.DomainRoles = cloneNonEmptyStrings(v.DomainRoles)
	return out
}

func cloneRecordedVeto(v RecordedVeto) RecordedVeto {
	out := v
	out.DomainRoles = cloneNonEmptyStrings(v.DomainRoles)
	out.EvidenceIDs = cloneNonEmptyStrings(v.EvidenceIDs)
	return out
}

func cloneOptionTally(t OptionTally) OptionTally {
	out := t
	out.SatisfiedEvidenceIDs = cloneNonEmptyStrings(t.SatisfiedEvidenceIDs)
	if len(t.FailedPredicates) > 0 {
		out.FailedPredicates = slices.Clone(t.FailedPredicates)
	} else {
		out.FailedPredicates = nil
	}
	out.Approvers = cloneNonEmptyStrings(t.Approvers)
	out.Dissenters = cloneNonEmptyStrings(t.Dissenters)
	out.Abstainers = cloneNonEmptyStrings(t.Abstainers)
	out.MissingRoles = cloneNonEmptyStrings(t.MissingRoles)
	out.Vetoers = cloneNonEmptyStrings(t.Vetoers)
	out.DisqualificationReasons = cloneNonEmptyStrings(t.DisqualificationReasons)
	return out
}

func cloneAccordOutcome(o *AccordOutcome) *AccordOutcome {
	if o == nil {
		return nil
	}
	out := *o
	if o.WinningBinding != nil {
		wb := cloneOptionBinding(*o.WinningBinding)
		out.WinningBinding = &wb
	}
	if len(o.Tallies) > 0 {
		out.Tallies = make([]OptionTally, len(o.Tallies))
		for i, t := range o.Tallies {
			out.Tallies[i] = cloneOptionTally(t)
		}
	} else {
		out.Tallies = nil
	}
	if len(o.WinningOptionDissents) > 0 {
		out.WinningOptionDissents = make([]RecordedVote, len(o.WinningOptionDissents))
		for i, v := range o.WinningOptionDissents {
			out.WinningOptionDissents[i] = cloneRecordedVote(v)
		}
	} else {
		out.WinningOptionDissents = nil
	}
	if len(o.WinningOptionVetoes) > 0 {
		out.WinningOptionVetoes = make([]RecordedVeto, len(o.WinningOptionVetoes))
		for i, v := range o.WinningOptionVetoes {
			out.WinningOptionVetoes[i] = cloneRecordedVeto(v)
		}
	} else {
		out.WinningOptionVetoes = nil
	}
	if len(o.EvidenceSummary) > 0 {
		out.EvidenceSummary = make([]VerifiedEvidenceFact, len(o.EvidenceSummary))
		for i, f := range o.EvidenceSummary {
			out.EvidenceSummary[i] = cloneVerifiedEvidenceFact(f)
		}
	} else {
		out.EvidenceSummary = nil
	}
	out.TiedOptionIDs = cloneNonEmptyStrings(o.TiedOptionIDs)
	return &out
}

func cloneAccordView(v AccordView) AccordView {
	out := v
	if len(v.Options) > 0 {
		out.Options = make([]RecordedOption, len(v.Options))
		for i, ro := range v.Options {
			out.Options[i] = RecordedOption{
				Option:           cloneAccordOption(ro.Option),
				ProposedBy:       ro.ProposedBy,
				ProposedAtHeight: ro.ProposedAtHeight,
			}
		}
	} else {
		out.Options = nil
	}
	if len(v.Evidence) > 0 {
		out.Evidence = make([]VerifiedEvidenceFact, len(v.Evidence))
		for i, f := range v.Evidence {
			out.Evidence[i] = cloneVerifiedEvidenceFact(f)
		}
	} else {
		out.Evidence = nil
	}
	if len(v.Votes) > 0 {
		out.Votes = make([]RecordedVote, len(v.Votes))
		for i, vote := range v.Votes {
			out.Votes[i] = cloneRecordedVote(vote)
		}
	} else {
		out.Votes = nil
	}
	out.SealedBallots = cloneRecordedSealedBallots(v.SealedBallots)
	if len(v.Vetoes) > 0 {
		out.Vetoes = make([]RecordedVeto, len(v.Vetoes))
		for i, veto := range v.Vetoes {
			out.Vetoes[i] = cloneRecordedVeto(veto)
		}
	} else {
		out.Vetoes = nil
	}
	out.Outcome = cloneAccordOutcome(v.Outcome)
	return out
}

func cloneNonEmptyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return slices.Clone(in)
}
