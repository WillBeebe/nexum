package nex

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"unicode/utf8"
)

// Protocol is an agreement/delegation language with no amount or token field.
// It uses existing Nexum identities and signed, hash-linked commands. The local
// host supplies authoritative heights; it is not a distributed consensus engine.
// Evidence fields commit private artifacts; a hash does not verify their truth.
const ProtocolVersion = 1

// ProtocolVersionV2 adds reviewed artifacts and explicit incomplete returns.
const ProtocolVersionV2 = 2

type ProtocolPermission string

const (
	PermitCommit ProtocolPermission = "commit"
	PermitWork   ProtocolPermission = "work"
	PermitReview ProtocolPermission = "review"
	PermitDecide ProtocolPermission = "decide"
	PermitReturn ProtocolPermission = "return"
)

type RoleGrant struct {
	ID, Actor, Label, Scope        string
	Permissions                    []ProtocolPermission
	ExpiresAtHeight                uint64
	LimitsHash, EvidenceObligation string
}
type ResourceLimit struct {
	Resource string
	Maximum  uint64
}
type ResourceUse struct {
	Resource string
	Used     uint64
	Unknown  bool // Unknown usage is evidence of uncertainty, never a fresh allowance.
}
type ReturnRequirements struct {
	SuccessArtifacts, FailureArtifacts []string
	AllowedDisposition                 []string // continue | retry | renegotiate | refuse
	AllowSuccessors                    bool
}
type ProtocolSpec struct {
	Version                                              int
	Nonce, Purpose, IntendedOutcome                      string
	Scope                                                string
	SpecificationHash, AcceptanceHash, FailurePolicyHash string
	Initiator                                            string
	Participants                                         []Public
	Roles                                                []RoleGrant
	Resources                                            []ResourceLimit
	WorkByHeight, ReturnByHeight                         uint64
	RequiredWitnesses                                    []string
	DissentPolicy                                        string // record | block
	Return                                               ReturnRequirements
	MaxEvents                                            uint32
	// TaskID and Generation optionally bind a v2 protocol to a task lease.
	TaskID     string `json:",omitempty"`
	Generation uint64 `json:",omitempty"`
}

type WorkOutcome string

const (
	WorkCompleted    WorkOutcome = "completed"
	WorkAttempted    WorkOutcome = "attempted"
	WorkRejected     WorkOutcome = "rejected"
	WorkFailedSafely WorkOutcome = "failed_safely"
	WorkViolated     WorkOutcome = "violation_reported"
	WorkSpecDefect   WorkOutcome = "specification_defect_reported"
	WorkUnreported   WorkOutcome = "unreported_at_deadline"
)

type BreachClaim struct{ Actor, EvidenceHash string }
type WorkReport struct {
	Outcome           WorkOutcome
	Stage, ReasonHash string
	Evidence          []string
	Resources         []ResourceUse
	BreachClaims      []BreachClaim
	Manifest          *EvidenceManifest `json:",omitempty"`
}
type WitnessReview struct {
	ReportHash     string
	AssessmentHash string
	Dissent        bool
}
type Resolution struct {
	ReportHash string
	Outcome    string // accept | reject | breach
	ReasonHash string
}
type ReturnArtifact struct{ ID, Commitment, ReuseRestrictions string }
type ReturnManifest struct {
	ResolutionHash, ReviewsHash string
	Evidence                    []string
	Resources                   []ResourceUse
	Uncertainty                 string
	SafeAssumptions             []string
	Artifacts                   []ReturnArtifact
	Disposition                 string
	SuccessorSpecs              []string // proposals only: no admission or inherited authority
}

type ProtocolCommand struct {
	RequestID, ProtocolID, Head, Actor, GrantID, Scope, Action string
	Height                                                     uint64
	Report                                                     *WorkReport
	Review                                                     *WitnessReview
	Resolution                                                 *Resolution
	Return                                                     *ReturnManifest
	Incomplete                                                 *IncompleteReturn `json:",omitempty"`
}
type ProtocolEvent struct {
	Command     ProtocolCommand
	Signature   []byte
	ReceiptHash string
}
type ProtocolBundle struct {
	Spec   ProtocolSpec
	Events []ProtocolEvent
}
type RecordedReview struct {
	Actor  string
	Review WitnessReview
}
type ProtocolView struct {
	ID, Head, Phase string
	Height          uint64
	Admitted        []string
	Report          *WorkReport
	Reviews         []RecordedReview
	Resolution      *Resolution
	Return          *ReturnManifest
	Incomplete      *IncompleteState `json:",omitempty"`
}

type Protocol struct {
	mu     sync.Mutex
	spec   ProtocolSpec
	events []ProtocolEvent
	view   ProtocolView
}

var (
	ErrProtocolSpec      = errors.New("nex: invalid agreement specification")
	ErrProtocolAuthority = errors.New("nex: permission outside declared role, scope or expiry")
	ErrProtocolPhase     = errors.New("nex: illegal agreement transition")
	ErrProtocolEvidence  = errors.New("nex: required evidence or return obligation missing")
	ErrProtocolStale     = errors.New("nex: stale or foreign agreement command")
)

func protocolHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func small(s string) bool { return len(s) > 0 && len(s) <= 4096 && utf8.ValidString(s) }

func validNamedArtifactsUTF8(arts []NamedArtifact) bool {
	for _, a := range arts {
		if !utf8.ValidString(a.Name) || !utf8.ValidString(a.Ref.Digest) || !utf8.ValidString(a.Ref.MediaType) {
			return false
		}
	}
	return true
}

func validProtocolSpecUTF8(s ProtocolSpec) bool {
	if !utf8.ValidString(s.Nonce) || !utf8.ValidString(s.Purpose) || !utf8.ValidString(s.IntendedOutcome) ||
		!utf8.ValidString(s.Scope) || !utf8.ValidString(s.SpecificationHash) || !utf8.ValidString(s.AcceptanceHash) ||
		!utf8.ValidString(s.FailurePolicyHash) || !utf8.ValidString(s.Initiator) || !utf8.ValidString(s.DissentPolicy) ||
		!utf8.ValidString(s.TaskID) {
		return false
	}
	for _, g := range s.Roles {
		if !utf8.ValidString(g.ID) || !utf8.ValidString(g.Actor) || !utf8.ValidString(g.Label) ||
			!utf8.ValidString(g.Scope) || !utf8.ValidString(g.LimitsHash) || !utf8.ValidString(g.EvidenceObligation) {
			return false
		}
		for _, perm := range g.Permissions {
			if !utf8.ValidString(string(perm)) {
				return false
			}
		}
	}
	for _, r := range s.Resources {
		if !utf8.ValidString(r.Resource) {
			return false
		}
	}
	for _, w := range s.RequiredWitnesses {
		if !utf8.ValidString(w) {
			return false
		}
	}
	for _, a := range s.Return.SuccessArtifacts {
		if !utf8.ValidString(a) {
			return false
		}
	}
	for _, a := range s.Return.FailureArtifacts {
		if !utf8.ValidString(a) {
			return false
		}
	}
	for _, d := range s.Return.AllowedDisposition {
		if !utf8.ValidString(d) {
			return false
		}
	}
	return true
}

func validProtocolCommandUTF8(c ProtocolCommand) bool {
	if !utf8.ValidString(c.RequestID) || !utf8.ValidString(c.ProtocolID) || !utf8.ValidString(c.Head) ||
		!utf8.ValidString(c.Actor) || !utf8.ValidString(c.GrantID) || !utf8.ValidString(c.Scope) ||
		!utf8.ValidString(c.Action) {
		return false
	}
	if c.Report != nil {
		if !utf8.ValidString(string(c.Report.Outcome)) || !utf8.ValidString(c.Report.Stage) || !utf8.ValidString(c.Report.ReasonHash) {
			return false
		}
		for _, ev := range c.Report.Evidence {
			if !utf8.ValidString(ev) {
				return false
			}
		}
		for _, r := range c.Report.Resources {
			if !utf8.ValidString(r.Resource) {
				return false
			}
		}
		for _, bc := range c.Report.BreachClaims {
			if !utf8.ValidString(bc.Actor) || !utf8.ValidString(bc.EvidenceHash) {
				return false
			}
		}
		if c.Report.Manifest != nil {
			if !utf8.ValidString(c.Report.Manifest.MethodHash) ||
				!validNamedArtifactsUTF8(c.Report.Manifest.Inputs) ||
				!validNamedArtifactsUTF8(c.Report.Manifest.Outputs) {
				return false
			}
			for _, cl := range c.Report.Manifest.Claims {
				if !utf8.ValidString(cl) {
					return false
				}
			}
		}
	}
	if c.Review != nil {
		if !utf8.ValidString(c.Review.ReportHash) || !utf8.ValidString(c.Review.AssessmentHash) {
			return false
		}
	}
	if c.Resolution != nil {
		if !utf8.ValidString(c.Resolution.ReportHash) || !utf8.ValidString(c.Resolution.Outcome) || !utf8.ValidString(c.Resolution.ReasonHash) {
			return false
		}
	}
	if c.Return != nil {
		if !utf8.ValidString(c.Return.ResolutionHash) || !utf8.ValidString(c.Return.ReviewsHash) ||
			!utf8.ValidString(c.Return.Uncertainty) || !utf8.ValidString(c.Return.Disposition) {
			return false
		}
		for _, ev := range c.Return.Evidence {
			if !utf8.ValidString(ev) {
				return false
			}
		}
		for _, r := range c.Return.Resources {
			if !utf8.ValidString(r.Resource) {
				return false
			}
		}
		for _, sa := range c.Return.SafeAssumptions {
			if !utf8.ValidString(sa) {
				return false
			}
		}
		for _, a := range c.Return.Artifacts {
			if !utf8.ValidString(a.ID) || !utf8.ValidString(a.Commitment) || !utf8.ValidString(a.ReuseRestrictions) {
				return false
			}
		}
		for _, ss := range c.Return.SuccessorSpecs {
			if !utf8.ValidString(ss) {
				return false
			}
		}
	}
	if c.Incomplete != nil {
		if !utf8.ValidString(c.Incomplete.ReasonHash) || !validNamedArtifactsUTF8(c.Incomplete.Artifacts) {
			return false
		}
		for _, ev := range c.Incomplete.Evidence {
			if !utf8.ValidString(ev) {
				return false
			}
		}
	}
	return true
}

func sameResourceUse(a, b []ResourceUse) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	expected := make(map[string]ResourceUse, len(b))
	for _, u := range b {
		if _, dup := expected[u.Resource]; dup {
			return false
		}
		expected[u.Resource] = u
	}
	seen := make(map[string]bool, len(a))
	for _, u := range a {
		want, ok := expected[u.Resource]
		if !ok || seen[u.Resource] || u != want {
			return false
		}
		seen[u.Resource] = true
	}
	return len(seen) == len(expected)
}
func uniqueStrings(ss []string, max int, valid func(string) bool) bool {
	if len(ss) > max {
		return false
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if !valid(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func allowedPermission(p ProtocolPermission) bool {
	return p == PermitCommit || p == PermitWork || p == PermitReview || p == PermitDecide || p == PermitReturn
}
func hasPermission(g RoleGrant, p ProtocolPermission) bool {
	for _, v := range g.Permissions {
		if v == p {
			return true
		}
	}
	return false
}
func (s ProtocolSpec) validate() error {
	if !validProtocolSpecUTF8(s) || !small(s.Scope) {
		return ErrProtocolSpec
	}
	v2 := s.Version == ProtocolVersionV2
	if (s.Version != ProtocolVersion && !v2) || !small(s.Nonce) || !small(s.Purpose) || !small(s.IntendedOutcome) || !protocolHash(s.SpecificationHash) || !protocolHash(s.AcceptanceHash) || !protocolHash(s.FailurePolicyHash) || s.WorkByHeight == 0 || s.ReturnByHeight <= s.WorkByHeight || s.MaxEvents < 8 || s.MaxEvents > 1024 || len(s.Participants) < 2 || len(s.Participants) > 16 || len(s.Roles) == 0 || len(s.Roles) > 64 || len(s.Resources) > 16 {
		return ErrProtocolSpec
	}
	if s.TaskID != "" || s.Generation != 0 {
		if !v2 || !protocolHash(s.TaskID) || s.Generation == 0 {
			return ErrProtocolSpec
		}
	}
	if v2 && s.WorkByHeight < 2 {
		return ErrProtocolSpec
	}
	if s.DissentPolicy != "record" && s.DissentPolicy != "block" {
		return ErrProtocolSpec
	}
	parties := map[string]bool{}
	signingKeys := map[string]bool{}
	for _, p := range s.Participants {
		if p.Validate() != nil || parties[p.ID()] || (v2 && signingKeys[string(p.Signing)]) {
			return ErrProtocolSpec
		}
		parties[p.ID()] = true
		if v2 {
			signingKeys[string(p.Signing)] = true
		}
	}
	if !parties[s.Initiator] {
		return ErrProtocolSpec
	}
	ids := map[string]bool{}
	workers := map[string]bool{}
	reviewers := map[string]bool{}
	deciders := map[string]bool{}
	canCommit, canReturn, canClose := false, false, false
	for _, g := range s.Roles {
		if g.Scope != s.Scope {
			return ErrProtocolSpec
		}
		if !small(g.ID) || ids[g.ID] || !parties[g.Actor] || !small(g.Label) || !small(g.Scope) || g.ExpiresAtHeight == 0 || (v2 && g.ExpiresAtHeight < 2) || g.ExpiresAtHeight > s.ReturnByHeight || !protocolHash(g.LimitsHash) || !protocolHash(g.EvidenceObligation) || len(g.Permissions) == 0 || len(g.Permissions) > 5 {
			return ErrProtocolSpec
		}
		ids[g.ID] = true
		seen := map[ProtocolPermission]bool{}
		for _, p := range g.Permissions {
			if !allowedPermission(p) || seen[p] {
				return ErrProtocolSpec
			}
			seen[p] = true
		}
		if hasPermission(g, PermitWork) {
			workers[g.Actor] = true
		}
		if hasPermission(g, PermitReview) {
			reviewers[g.Actor] = true
		}
		if hasPermission(g, PermitDecide) {
			deciders[g.Actor] = true
		}
		if hasPermission(g, PermitCommit) && g.Actor == s.Initiator {
			canCommit = true
		}
		if hasPermission(g, PermitReturn) {
			canReturn = true
			canClose = canClose || g.ExpiresAtHeight == s.ReturnByHeight
		}
	}
	if !canCommit || !canReturn || (v2 && !canClose) || len(workers) == 0 || len(deciders) == 0 {
		return ErrProtocolSpec
	}
	if int(s.MaxEvents) < len(s.Participants)+len(reviewers)+4 {
		return ErrProtocolSpec
	}
	// Labels never supply authority. Review/decision independence is identity based.
	for p := range workers {
		if reviewers[p] || deciders[p] {
			return ErrProtocolSpec
		}
	}
	if !uniqueStrings(s.RequiredWitnesses, 16, func(p string) bool { return reviewers[p] }) {
		return ErrProtocolSpec
	}
	resources := map[string]bool{}
	for _, r := range s.Resources {
		if !small(r.Resource) || r.Maximum == 0 || resources[r.Resource] {
			return ErrProtocolSpec
		}
		resources[r.Resource] = true
	}
	validID := func(v string) bool { return len(v) > 0 && len(v) <= 128 && utf8.ValidString(v) }
	if !uniqueStrings(s.Return.SuccessArtifacts, 32, validID) || !uniqueStrings(s.Return.FailureArtifacts, 32, validID) || len(s.Return.AllowedDisposition) == 0 || !uniqueStrings(s.Return.AllowedDisposition, 4, func(v string) bool { return v == "continue" || v == "retry" || v == "renegotiate" || v == "refuse" }) {
		return ErrProtocolSpec
	}
	return nil
}
func cloneProtocol[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	json.Unmarshal(raw, &out)
	return out
}
func NewProtocol(spec ProtocolSpec) (*Protocol, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	spec = cloneProtocol(spec)
	if err := spec.validate(); err != nil {
		return nil, err
	}
	id := Hash(spec)
	return &Protocol{spec: spec, view: ProtocolView{ID: id, Head: id, Phase: "admission"}}, nil
}
func (p *Protocol) View() ProtocolView {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneProtocol(p.view)
}
func (p *Protocol) Bundle() ProtocolBundle {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneProtocol(ProtocolBundle{p.spec, p.events})
}
func (p *Protocol) Prepare(actor, grant, scope, action, request string, height uint64) ProtocolCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ProtocolCommand{RequestID: request, ProtocolID: p.view.ID, Head: p.view.Head, Actor: actor, GrantID: grant, Scope: scope, Action: action, Height: height}
}
func protocolPermission(action string) ProtocolPermission {
	switch action {
	case "commit":
		return PermitCommit
	case "report":
		return PermitWork
	case "review":
		return PermitReview
	case "resolve", "failure":
		return PermitDecide
	case "return", "incomplete":
		return PermitReturn
	}
	return ""
}
func (p *Protocol) public(actor string) (Public, bool) {
	for _, v := range p.spec.Participants {
		if v.ID() == actor {
			return v, true
		}
	}
	return Public{}, false
}
func (p *Protocol) authorize(c ProtocolCommand) error {
	if c.Action == "admit" {
		if c.GrantID != "" || c.Scope != "" {
			return ErrProtocolAuthority
		}
		return nil
	}
	permission := protocolPermission(c.Action)
	if permission == "" || c.Scope != p.spec.Scope {
		return ErrProtocolAuthority
	}
	for _, g := range p.spec.Roles {
		if g.ID != c.GrantID || g.Actor != c.Actor || g.Scope != c.Scope || !hasPermission(g, permission) {
			continue
		}
		if c.Action == "incomplete" {
			// A return grant that reaches the deadline includes administrative
			// closeout after it. This never extends authority for a normal return.
			if p.spec.Version == ProtocolVersionV2 && c.Height >= p.spec.ReturnByHeight && g.ExpiresAtHeight == p.spec.ReturnByHeight && slices.Contains(p.view.Admitted, c.Actor) {
				return nil
			}
			return ErrProtocolAuthority
		}
		if c.Height < g.ExpiresAtHeight {
			return nil
		}
	}
	return ErrProtocolAuthority
}
func validateReport(r WorkReport, s ProtocolSpec) error {
	if err := validateReportManifest(r, s); err != nil {
		return err
	}
	switch r.Outcome {
	case WorkCompleted, WorkAttempted, WorkRejected, WorkFailedSafely, WorkViolated, WorkSpecDefect, WorkUnreported:
	default:
		return ErrProtocolEvidence
	}
	if !small(r.Stage) || !protocolHash(r.ReasonHash) || len(r.Evidence) == 0 || !uniqueStrings(r.Evidence, 64, protocolHash) || len(r.Resources) != len(s.Resources) || len(r.BreachClaims) > 16 {
		return ErrProtocolEvidence
	}
	used := map[string]uint64{}
	for _, u := range r.Resources {
		if u.Unknown && (u.Used != 0 || r.Outcome == WorkCompleted) {
			return ErrProtocolEvidence
		}
		if _, ok := used[u.Resource]; ok {
			return ErrProtocolEvidence
		}
		used[u.Resource] = u.Used
	}
	for _, limit := range s.Resources {
		n, ok := used[limit.Resource]
		if !ok || n > limit.Maximum {
			return ErrProtocolEvidence
		}
	}
	for _, claim := range r.BreachClaims {
		if !protocolHash(claim.EvidenceHash) {
			return ErrProtocolEvidence
		}
		found := false
		for _, actor := range s.Participants {
			if actor.ID() == claim.Actor {
				found = true
			}
		}
		if !found {
			return ErrProtocolEvidence
		}
	}
	return nil
}
func validateReturn(m ReturnManifest, v ProtocolView, s ProtocolSpec) error {
	if m.ResolutionHash != Hash(v.Resolution) || m.ReviewsHash != Hash(v.Reviews) || !small(m.Uncertainty) || len(m.SafeAssumptions) == 0 || !uniqueStrings(m.SafeAssumptions, 32, small) || !uniqueStrings(m.Evidence, 128, protocolHash) || !sameResourceUse(m.Resources, v.Report.Resources) || len(m.Artifacts) > 64 {
		return ErrProtocolEvidence
	}
	evidence := map[string]bool{}
	for _, h := range m.Evidence {
		evidence[h] = true
	}
	for _, h := range v.Report.Evidence {
		if !evidence[h] {
			return ErrProtocolEvidence
		}
	}
	artifacts := map[string]bool{}
	for _, a := range m.Artifacts {
		if !small(a.ID) || artifacts[a.ID] || !protocolHash(a.Commitment) || !small(a.ReuseRestrictions) {
			return ErrProtocolEvidence
		}
		artifacts[a.ID] = true
	}
	required := s.Return.FailureArtifacts
	if v.Resolution.Outcome == "accept" {
		required = s.Return.SuccessArtifacts
	}
	for _, a := range required {
		if !artifacts[a] {
			return ErrProtocolEvidence
		}
	}
	if s.Version == ProtocolVersionV2 && v.Resolution.Outcome == "accept" {
		if err := validateReturnedOutputs(m, v.Report.Manifest); err != nil {
			return err
		}
	}
	allowed := false
	for _, d := range s.Return.AllowedDisposition {
		if d == m.Disposition {
			allowed = true
		}
	}
	if !allowed {
		return ErrProtocolEvidence
	}
	if (!s.Return.AllowSuccessors && len(m.SuccessorSpecs) > 0) || !uniqueStrings(m.SuccessorSpecs, 16, protocolHash) {
		return ErrProtocolEvidence
	}
	return nil
}
func commandShape(c ProtocolCommand) bool {
	if !small(c.RequestID) || c.Height == 0 {
		return false
	}
	n := 0
	for _, b := range []bool{c.Report != nil, c.Review != nil, c.Resolution != nil, c.Return != nil, c.Incomplete != nil} {
		if b {
			n++
		}
	}
	switch c.Action {
	case "admit", "commit":
		return n == 0
	case "report", "failure":
		return n == 1 && c.Report != nil
	case "review":
		return n == 1 && c.Review != nil
	case "resolve":
		return n == 1 && c.Resolution != nil
	case "return":
		return n == 1 && c.Return != nil
	case "incomplete":
		return n == 1 && c.Incomplete != nil
	}
	return false
}

// Apply verifies identity and declared scope before mutation. Hosts serialize
// authoritative heights; callers sign with Sign(identity,"protocol",command).
// Exact signed retries return the original receipt, even after completion.
func (p *Protocol) Apply(c ProtocolCommand, signature []byte, height uint64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !validProtocolCommandUTF8(c) || !commandShape(c) {
		return "", ErrProtocolSpec
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 64<<10 {
		return "", ErrProtocolSpec
	}
	c = cloneProtocol(c)
	if !validProtocolCommandUTF8(c) || !commandShape(c) {
		return "", ErrProtocolSpec
	}
	raw, err = json.Marshal(c)
	if err != nil || len(raw) > 64<<10 {
		return "", ErrProtocolSpec
	}
	signature = append([]byte(nil), signature...)
	actor, ok := p.public(c.Actor)
	if !ok {
		return "", ErrProtocolAuthority
	}
	if err := Verify(actor, "protocol", c, signature); err != nil {
		return "", err
	}
	if c.ProtocolID != p.view.ID {
		return "", ErrProtocolStale
	}
	for _, e := range p.events {
		if e.Command.Actor == c.Actor && e.Command.RequestID == c.RequestID {
			if Hash(e.Command) != Hash(c) {
				return "", ErrOperationConflict
			}
			return e.ReceiptHash, nil
		}
	}
	if c.Head != p.view.Head || c.Height != height || height < p.view.Height {
		return "", ErrProtocolStale
	}
	if err := p.authorize(c); err != nil {
		return "", err
	}
	if uint32(len(p.events)) >= p.spec.MaxEvents {
		return "", ErrProtocolPhase
	}
	if p.view.Phase == "complete" || p.view.Phase == "incomplete" {
		return "", ErrProtocolPhase
	}
	if height >= p.spec.ReturnByHeight && c.Action != "incomplete" {
		return "", ErrProtocolAuthority
	}
	v := cloneProtocol(p.view)
	switch c.Action {
	case "admit":
		if v.Phase != "admission" || height >= p.spec.WorkByHeight {
			return "", ErrProtocolPhase
		}
		for _, a := range v.Admitted {
			if a == c.Actor {
				return "", ErrProtocolPhase
			}
		}
		v.Admitted = append(v.Admitted, c.Actor)
	case "commit":
		if v.Phase != "admission" || c.Actor != p.spec.Initiator || len(v.Admitted) != len(p.spec.Participants) || height >= p.spec.WorkByHeight {
			return "", ErrProtocolPhase
		}
		v.Phase = "working"
	case "report", "failure":
		if v.Phase != "working" {
			return "", ErrProtocolPhase
		}
		if c.Action == "failure" && (height < p.spec.WorkByHeight || c.Report.Outcome != WorkUnreported) {
			return "", ErrProtocolPhase
		}
		if c.Action == "report" && c.Report.Outcome == WorkUnreported {
			return "", ErrProtocolPhase
		}
		if height >= p.spec.WorkByHeight && c.Report.Outcome == WorkCompleted {
			return "", ErrProtocolPhase
		}
		if err := validateReport(*c.Report, p.spec); err != nil {
			return "", err
		}
		v.Report = c.Report
		v.Phase = "review"
	case "review":
		if v.Phase != "review" {
			return "", ErrProtocolPhase
		}
		if c.Review.ReportHash != Hash(v.Report) || !protocolHash(c.Review.AssessmentHash) {
			return "", ErrProtocolEvidence
		}
		for _, r := range v.Reviews {
			if r.Actor == c.Actor {
				return "", ErrProtocolPhase
			}
		}
		v.Reviews = append(v.Reviews, RecordedReview{c.Actor, *c.Review})
	case "resolve":
		if v.Phase != "review" {
			return "", ErrProtocolPhase
		}
		if c.Resolution.ReportHash != Hash(v.Report) || !protocolHash(c.Resolution.ReasonHash) {
			return "", ErrProtocolEvidence
		}
		outcome := c.Resolution.Outcome
		if outcome != "accept" && outcome != "reject" && outcome != "breach" {
			return "", ErrProtocolEvidence
		}
		if outcome == "accept" && v.Report.Outcome != WorkCompleted {
			return "", ErrProtocolEvidence
		}
		seen := map[string]bool{}
		for _, r := range v.Reviews {
			seen[r.Actor] = true
			if r.Review.Dissent && p.spec.DissentPolicy == "block" && outcome == "accept" {
				return "", ErrProtocolEvidence
			}
		}
		for _, a := range p.spec.RequiredWitnesses {
			if !seen[a] {
				return "", ErrProtocolEvidence
			}
		}
		v.Resolution = c.Resolution
		v.Phase = "return_due"
	case "return":
		if v.Phase != "return_due" {
			return "", ErrProtocolPhase
		}
		if err := validateReturn(*c.Return, v, p.spec); err != nil {
			return "", err
		}
		v.Return = c.Return
		v.Phase = "complete"
	case "incomplete":
		if err := c.Incomplete.validate(); err != nil {
			return "", err
		}
		v.Incomplete = incompleteState(*c.Incomplete, v, p.spec)
		v.Phase = "incomplete"
	default:
		return "", ErrProtocolPhase
	}
	// Evidence and resource reports are claims unless separately verified by a
	// declared verifier. The signed resolution records who made that decision.
	receipt := Hash(struct {
		Command   ProtocolCommand
		Signature []byte
	}{c, signature})
	v.Head = receipt
	v.Height = height
	p.events = append(p.events, ProtocolEvent{c, signature, receipt})
	p.view = v
	return receipt, nil
}

// VerifyProtocolBundle replays signatures, admission, authority, evidence,
// dissent and return requirements. Pins prevent substitution and truncation.
func VerifyProtocolBundle(b ProtocolBundle, expectedID, expectedHead string) (ProtocolView, error) {
	p, err := replayProtocolBundle(b, expectedID, expectedHead)
	if err != nil {
		return ProtocolView{}, err
	}
	return p.View(), nil
}

func replayProtocolBundle(b ProtocolBundle, expectedID, expectedHead string) (*Protocol, error) {
	p, err := NewProtocol(b.Spec)
	if err != nil {
		return nil, err
	}
	if p.view.ID != expectedID || len(b.Events) > int(b.Spec.MaxEvents) {
		return nil, ErrProtocolStale
	}
	for _, e := range b.Events {
		before := len(p.events)
		head, err := p.Apply(e.Command, e.Signature, e.Command.Height)
		if err != nil {
			return nil, err
		}
		if head != e.ReceiptHash || len(p.events) != before+1 {
			return nil, ErrProtocolStale
		}
	}
	if p.view.Head != expectedHead {
		return nil, ErrProtocolStale
	}
	return p, nil
}
