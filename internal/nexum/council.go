package nexum

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KindCouncil is a 3–7 party agreement: codified requirements, then
// unanimous opt-in, then one execute. Trade-offs are the requirements.
const KindCouncil = "council.optin"

const (
	StatusReady    Status = "ready"    // all reqs satisfied, not yet unanimous
	StatusExecuted Status = "executed" // decision ran; terminal
	StatusRefused  Status = "refused"  // a party refused before execute; terminal
)

// Requirement is one party's codified condition. Satisfied is a
// ledger fact (citation), not a vibe.
type Requirement struct {
	ID        string `json:"id"`
	Holder    Party  `json:"holder"`
	Satisfied bool   `json:"satisfied"`
	Citation  string `json:"citation,omitempty"`
}

// Council is a Nexum among 3–7 agents. Execute is legal only when
// every requirement is satisfied AND every party has opted in.
// Format 0 receipts use human notes. FormatV2 commits Decision in the
// terms digest and a canonical event in each receipt. A different
// decision is a new council: the string is not edited in place.
type Council struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Parties   []Party        `json:"parties"`
	Reqs      []Requirement  `json:"requirements"`
	OptedIn   map[Party]bool `json:"opt_in"`
	Decision  string         `json:"decision"`
	Status    Status         `json:"status"`
	Meter     Meter          `json:"meter"`
	CreatedAt time.Time      `json:"created_at"`
	ClosedAt  *time.Time     `json:"closed_at,omitempty"`
	Receipts  []Receipt      `json:"receipts"`
	Format    int            `json:"format,omitempty"`
	steps     int
	// actorKeys maps Party to the signing key for new receipts; nil
	// keeps legacy unsigned local ledgers.
	actorKeys map[Party]ed25519.PrivateKey
}

// SignReceipts arms receipt signatures for council parties.
func (c *Council) SignReceipts(keys map[Party]ed25519.PrivateKey) error {
	if c == nil {
		return ErrInvalid
	}
	cloned, err := cloneActorKeys(keys, c.isParty)
	if err != nil {
		return err
	}
	c.actorKeys = cloned
	return nil
}

var (
	ErrPartyCount    = errors.New("nexum: council needs 3 to 7 distinct parties")
	ErrDupParty      = errors.New("nexum: duplicate party")
	ErrUnknownParty  = errors.New("nexum: party not on this council")
	ErrReqHolder     = errors.New("nexum: requirement holder not a party")
	ErrDupReq        = errors.New("nexum: duplicate requirement id")
	ErrNotSatisfied  = errors.New("nexum: party's requirements not satisfied")
	ErrNotUnanimous  = errors.New("nexum: execute requires every opt-in")
	ErrEmptyDecision = errors.New("nexum: decision required")
)

// OpenCouncil starts a format-v2 council. n must be 3–7. Each
// requirement's holder must be a party. Decision is bound at genesis.
// Zero requirements start ready: readiness is not consent, and execute
// still waits for every opt-in. Refusal after opt-in stays legal.
func OpenCouncil(id string, parties []Party, reqs []Requirement, decision string, meter Meter, now time.Time) (*Council, error) {
	return openCouncil(FormatV2, id, parties, reqs, decision, meter, now)
}

// openCouncil is the shared constructor. Format 0 keeps the historical
// open-until-first-transition zero-requirement status and human notes.
func openCouncil(format int, id string, parties []Party, reqs []Requirement, decision string, meter Meter, now time.Time) (*Council, error) {
	if !validSiblingFormat(format) {
		return nil, ErrInvalid
	}
	if n := len(parties); n < 3 || n > 7 {
		return nil, ErrPartyCount
	}
	if decision == "" {
		return nil, ErrEmptyDecision
	}
	seen := map[Party]bool{}
	for _, p := range parties {
		if p == "" {
			return nil, ErrMissingParty
		}
		if seen[p] {
			return nil, ErrDupParty
		}
		seen[p] = true
	}
	reqIDs := map[string]bool{}
	clean := make([]Requirement, len(reqs))
	for i, r := range reqs {
		if r.ID == "" {
			return nil, fmt.Errorf("nexum: requirement id required")
		}
		if format == FormatV2 && invalidV2ReqID(r.ID) {
			return nil, fmt.Errorf("nexum: invalid requirement id %q: %w", r.ID, ErrInvalid)
		}
		if reqIDs[r.ID] {
			return nil, ErrDupReq
		}
		reqIDs[r.ID] = true
		if !seen[r.Holder] {
			return nil, ErrReqHolder
		}
		r.Satisfied = false
		r.Citation = ""
		clean[i] = r
	}
	if !validMeterNumbers(meter) {
		return nil, ErrInvalid
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 32
	}
	if meter.MaxSteps > 128 {
		return nil, ErrInvalid
	}
	c := &Council{
		ID:        id,
		Kind:      KindCouncil,
		Parties:   append([]Party(nil), parties...),
		Reqs:      clean,
		OptedIn:   map[Party]bool{},
		Decision:  decision,
		Status:    StatusOpen,
		Meter:     meter,
		CreatedAt: now.UTC(),
		Format:    format,
	}
	sort.Slice(c.Parties, func(i, j int) bool { return c.Parties[i] < c.Parties[j] })
	// Format v2 agrees with readiness at genesis. Format 0 stays open
	// until the first satisfy or opt-in, and that genesis receipt is not
	// rewritten when the ledger is later read.
	if format == FormatV2 {
		c.refreshReady()
	}
	if err := c.append(c.Parties[0], "open", c.openNote(), now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Council) openNote() string {
	if c.Format != FormatV2 {
		return "council opened"
	}
	note, err := encodeSiblingEvent(siblingEvent{
		V:        FormatV2,
		Ledger:   ledgerCouncil,
		Action:   "open",
		Actor:    string(c.Parties[0]),
		Decision: c.Decision,
	})
	if err != nil {
		return ""
	}
	return note
}

func (c *Council) isParty(p Party) bool {
	for _, x := range c.Parties {
		if x == p {
			return true
		}
	}
	return false
}

func (c *Council) phase() (councilPhase, error) {
	ph, ok := councilPhaseOf(c.Status)
	if !ok {
		return "", ErrBadState
	}
	return ph, nil
}

func (c *Council) commit(fn func(*Council) error) error {
	next := c.clone()
	if err := fn(next); err != nil {
		return err
	}
	*c = *next
	return nil
}

func (c *Council) clone() *Council {
	next := *c
	next.Parties = append([]Party(nil), c.Parties...)
	next.Reqs = append([]Requirement(nil), c.Reqs...)
	next.Receipts = append([]Receipt(nil), c.Receipts...)
	next.OptedIn = make(map[Party]bool, len(c.OptedIn))
	for k, v := range c.OptedIn {
		next.OptedIn[k] = v
	}
	return &next
}

// Satisfy records that a holder's requirement is met, with a citation
// the network can check. Only the holder may satisfy their own req.
func (c *Council) Satisfy(actor Party, reqID, citation string, now time.Time) error {
	return c.commit(func(n *Council) error {
		return n.satisfy(actor, reqID, citation, now)
	})
}

func (c *Council) satisfy(actor Party, reqID, citation string, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	ph, err := c.phase()
	if err != nil {
		return err
	}
	if ph.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(councilPhaseTable, c.Format, "satisfy", c.Status) {
		return ErrBadState
	}
	if citation == "" {
		return ErrEmptyCitation
	}
	idx := -1
	for i := range c.Reqs {
		if c.Reqs[i].ID == reqID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("nexum: unknown requirement %q", reqID)
	}
	if c.Reqs[idx].Holder != actor {
		return ErrWrongParty
	}
	if c.Reqs[idx].Satisfied {
		return ErrBadState
	}
	note, err := c.satisfyNote(actor, reqID, citation)
	if err != nil {
		return err
	}
	if err := c.append(actor, "satisfy", note, now); err != nil {
		return err
	}
	c.Reqs[idx].Satisfied = true
	c.Reqs[idx].Citation = citation
	c.refreshReady()
	return nil
}

func (c *Council) satisfyNote(actor Party, reqID, citation string) (string, error) {
	if c.Format != FormatV2 {
		// Historical note. Format 0 matches against the committed requirement
		// roster for this actor without rewriting v1 hashes.
		return reqID + ":" + citation, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:                  FormatV2,
		Ledger:             ledgerCouncil,
		Action:             "satisfy",
		Actor:              string(actor),
		ReqID:              reqID,
		Citation:           citation,
		CitationCommitment: commitString("citation", citation),
	})
}

func (c *Council) partyReqsMet(p Party) bool {
	for _, r := range c.Reqs {
		if r.Holder == p && !r.Satisfied {
			return false
		}
	}
	return true
}

// OptIn is a party joining the execute set. Legal only after that
// party's requirements are satisfied. Unanimous opt-in is required
// to execute; opt-in is not execute. A later refusal remains legal
// and keeps the recorded consent.
func (c *Council) OptIn(actor Party, now time.Time) error {
	return c.commit(func(n *Council) error {
		return n.optIn(actor, now)
	})
}

func (c *Council) optIn(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	ph, err := c.phase()
	if err != nil {
		return err
	}
	if ph.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(councilPhaseTable, c.Format, "opt-in", c.Status) {
		return ErrBadState
	}
	if !c.partyReqsMet(actor) {
		return ErrNotSatisfied
	}
	if c.OptedIn[actor] {
		return ErrBadState
	}
	note, err := c.actorNote(actor, "opt-in", "opted in")
	if err != nil {
		return err
	}
	if err := c.append(actor, "opt-in", note, now); err != nil {
		return err
	}
	c.OptedIn[actor] = true
	c.refreshReady()
	return nil
}

// Refuse is a party killing the council before execute. Terminal.
// Legal after opt-in: consent already given stays in the history.
func (c *Council) Refuse(actor Party, now time.Time) error {
	return c.commit(func(n *Council) error {
		return n.refuse(actor, now)
	})
}

func (c *Council) refuse(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	ph, err := c.phase()
	if err != nil {
		return err
	}
	if ph.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(councilPhaseTable, c.Format, "refuse", c.Status) {
		return ErrBadState
	}
	note, err := c.actorNote(actor, "refuse", "refused before execute")
	if err != nil {
		return err
	}
	if err := c.append(actor, "refuse", note, now); err != nil {
		return err
	}
	t := now.UTC()
	c.ClosedAt = &t
	c.Status = StatusRefused
	return nil
}

func (c *Council) actorNote(actor Party, action, legacy string) (string, error) {
	if c.Format != FormatV2 {
		return legacy, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:      FormatV2,
		Ledger: ledgerCouncil,
		Action: action,
		Actor:  string(actor),
	})
}

// Execute runs the decision. Legal only when every requirement is
// satisfied and every party has opted in. After this, refuse and
// takeback are ErrTakeback. The v2 decision is the genesis value;
// this does not accept a substitute string.
func (c *Council) Execute(actor Party, now time.Time) error {
	return c.commit(func(n *Council) error {
		return n.execute(actor, now)
	})
}

func (c *Council) execute(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	ph, err := c.phase()
	if err != nil {
		return err
	}
	if ph.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(councilPhaseTable, c.Format, "execute", c.Status) {
		return ErrBadState
	}
	for _, r := range c.Reqs {
		if !r.Satisfied {
			return ErrNotSatisfied
		}
	}
	for _, p := range c.Parties {
		if !c.OptedIn[p] {
			return ErrNotUnanimous
		}
	}
	note, err := c.executeNote(actor)
	if err != nil {
		return err
	}
	if err := c.append(actor, "execute", note, now); err != nil {
		return err
	}
	t := now.UTC()
	c.ClosedAt = &t
	c.Status = StatusExecuted
	return nil
}

func (c *Council) executeNote(actor Party) (string, error) {
	if c.Format != FormatV2 {
		return c.Decision, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:        FormatV2,
		Ledger:   ledgerCouncil,
		Action:   "execute",
		Actor:    string(actor),
		Decision: c.Decision,
	})
}

func (c *Council) refreshReady() {
	c.Status = councilAfterEvidence(c.Status, c.Reqs)
}

func councilAfterEvidence(status Status, reqs []Requirement) Status {
	if status != StatusOpen {
		return status
	}
	for _, r := range reqs {
		if !r.Satisfied {
			return status
		}
	}
	return StatusReady
}

func (c *Council) ledger() receiptLedger {
	return receiptLedger{
		format:      c.Format,
		maxSteps:    c.Meter.MaxSteps,
		budget:      c.Meter.BudgetUSD,
		cost:        c.Meter.CostUSD,
		checkBudget: true,
		steps:       &c.steps,
		receipts:    &c.Receipts,
		terms:       c.termsDigest,
		hashKind:    hashCouncilReceipt,
		keys:        c.actorKeys,
	}
}

func (c *Council) append(actor Party, action, note string, now time.Time) error {
	return c.ledger().append(actor, action, note, now)
}

// VerifyReceipts checks the hash chain and replays roles, requirements,
// consent, close time and the snapshot. Format 0 prefix-matches satisfy
// notes against the committed requirement roster; an empty receipt list
// cannot establish a terminal council.
func (c *Council) VerifyReceipts() error {
	if _, err := c.classify(); err != nil {
		return err
	}
	return nil
}

// ReceiptAssurance reports state-replay or legacy-chain-only (when a
// single format 0 holder had prefix-colliding requirement IDs with
// multiple valid assignments). Cryptographic signatures are checked when
// present; an embedded key does not admit the actor.
func (c *Council) ReceiptAssurance() (string, error) {
	return c.classify()
}

func (c *Council) classify() (string, error) {
	if c == nil || len(c.Receipts) == 0 {
		return "", ErrInvalid
	}
	if !validSiblingFormat(c.Format) || c.Kind != KindCouncil || !validMeterNumbers(c.Meter) {
		return "", ErrInvalid
	}
	if err := validateCouncilRoster(c); err != nil {
		return "", err
	}
	if err := verifySiblingChain(c.Receipts, c.termsDigest(), hashCouncilReceipt); err != nil {
		return "", err
	}
	if err := validateCouncilGenesis(c); err != nil {
		return "", err
	}
	return replayCouncil(c)
}

func invalidV2ReqID(id string) bool {
	return strings.TrimSpace(id) != id || strings.Contains(id, ":")
}

func validateCouncilRoster(c *Council) error {
	if n := len(c.Parties); n < 3 || n > 7 {
		return ErrPartyCount
	}
	seen := map[Party]bool{}
	for _, p := range c.Parties {
		if p == "" {
			return ErrMissingParty
		}
		if seen[p] {
			return ErrDupParty
		}
		seen[p] = true
	}
	ids := map[string]bool{}
	for _, r := range c.Reqs {
		if r.ID == "" {
			return fmt.Errorf("nexum: requirement id required")
		}
		if c.Format == FormatV2 && invalidV2ReqID(r.ID) {
			return fmt.Errorf("nexum: invalid requirement id %q: %w", r.ID, ErrInvalid)
		}
		if ids[r.ID] {
			return ErrDupReq
		}
		ids[r.ID] = true
		if !seen[r.Holder] {
			return ErrReqHolder
		}
	}
	if c.Decision == "" {
		return ErrEmptyDecision
	}
	return nil
}

func validateCouncilGenesis(c *Council) error {
	r := c.Receipts[0]
	if r.Action != "open" || r.Seq != 1 || len(c.Parties) == 0 || r.Actor != c.Parties[0] || !r.At.Equal(c.CreatedAt) {
		return fmt.Errorf("nexum: council genesis: %w", ErrBadState)
	}
	if !c.isParty(r.Actor) {
		return ErrUnknownParty
	}
	return nil
}

type councilView struct {
	status   Status
	reqs     []Requirement
	opted    map[Party]bool
	closed   *time.Time
	decision string
	// compareDecision is false until a format-0 execute note, or always
	// for v2 where genesis binds the decision.
	compareDecision bool
	heldReqs        map[Party][]Requirement
	legacyNotes     map[Party][]string
	legacyMatch     map[Party][]int
	satisfiedBy     map[Party]int
	totalSatisfied  int
}

func replayCouncil(c *Council) (string, error) {
	view := councilView{
		status: StatusOpen,
		reqs:   append([]Requirement(nil), c.Reqs...),
		opted:  map[Party]bool{},
	}
	for i := range view.reqs {
		view.reqs[i].Satisfied = false
		view.reqs[i].Citation = ""
	}
	if c.Format == FormatV2 {
		view.decision = c.Decision
		view.compareDecision = true
		view.status = councilAfterEvidence(StatusOpen, view.reqs)
	} else {
		view.heldReqs = make(map[Party][]Requirement, len(c.Parties))
		view.legacyNotes = make(map[Party][]string, len(c.Parties))
		view.legacyMatch = make(map[Party][]int, len(c.Parties))
		view.satisfiedBy = make(map[Party]int, len(c.Parties))
		for _, r := range c.Reqs {
			view.heldReqs[r.Holder] = append(view.heldReqs[r.Holder], r)
		}
		for p, held := range view.heldReqs {
			m := make([]int, len(held))
			for i := range m {
				m[i] = -1
			}
			view.legacyMatch[p] = m
		}
	}
	for i, r := range c.Receipts {
		if err := applyCouncilReceipt(c, &view, r, i == 0); err != nil {
			return "", fmt.Errorf("nexum: receipt %d: %w", r.Seq, err)
		}
	}
	if view.status != c.Status || !sameConsent(view.opted, c.OptedIn) || !sameReceiptTime(view.closed, c.ClosedAt) {
		return "", snapshotMismatch(ErrInvalid)
	}
	if view.compareDecision && view.decision != c.Decision {
		return "", snapshotMismatch(ErrInvalid)
	}
	if _, ok := councilPhaseOf(c.Status); !ok {
		return "", snapshotMismatch(ErrBadState)
	}
	if c.Format == FormatV2 {
		if !sameReqs(view.reqs, c.Reqs) {
			return "", snapshotMismatch(ErrInvalid)
		}
		return AssuranceStateReplay, nil
	}
	return verifyLegacyCouncilReqs(c, &view)
}

func applyCouncilReceipt(c *Council, view *councilView, r Receipt, genesis bool) error {
	if !c.isParty(r.Actor) {
		return ErrUnknownParty
	}
	var ev siblingEvent
	if c.Format == FormatV2 {
		parsed, err := parseSiblingEvent(r.Note)
		if err != nil {
			return err
		}
		if err := eventMatchesReceipt(parsed, ledgerCouncil, r); err != nil {
			return err
		}
		ev = parsed
	}
	if genesis {
		if r.Action != "open" {
			return ErrBadState
		}
		if c.Format == FormatV2 && ev.Decision != c.Decision {
			return ErrInvalid
		}
		return nil
	}
	if view.status == StatusExecuted || view.status == StatusRefused {
		return ErrBadState
	}
	if !phaseAllows(councilPhaseTable, c.Format, r.Action, view.status) {
		return ErrBadState
	}
	switch r.Action {
	case "satisfy":
		return applyCouncilSatisfy(c, view, r, ev)
	case "opt-in":
		if c.Format == FormatV2 {
			if !partyReqsMet(view.reqs, r.Actor) || view.opted[r.Actor] {
				return ErrBadState
			}
			view.opted[r.Actor] = true
			view.status = councilAfterEvidence(view.status, view.reqs)
			return nil
		}
		if view.satisfiedBy[r.Actor] != len(view.heldReqs[r.Actor]) || view.opted[r.Actor] {
			return ErrBadState
		}
		view.opted[r.Actor] = true
		if view.status == StatusOpen && view.totalSatisfied == len(c.Reqs) {
			view.status = StatusReady
		}
	case "refuse":
		t := r.At.UTC()
		view.closed = &t
		view.status = StatusRefused
	case "execute":
		if c.Format == FormatV2 {
			for _, req := range view.reqs {
				if !req.Satisfied {
					return ErrNotSatisfied
				}
			}
		} else if view.totalSatisfied != len(c.Reqs) {
			return ErrNotSatisfied
		}
		for _, p := range c.Parties {
			if !view.opted[p] {
				return ErrNotUnanimous
			}
		}
		if c.Format == FormatV2 {
			if ev.Decision != c.Decision {
				return ErrInvalid
			}
		} else {
			// The whole note is the decision that ran. No delimiter.
			view.decision = r.Note
			view.compareDecision = true
		}
		t := r.At.UTC()
		view.closed = &t
		view.status = StatusExecuted
	default:
		return ErrInvalid
	}
	return nil
}

func applyCouncilSatisfy(c *Council, view *councilView, r Receipt, ev siblingEvent) error {
	if c.Format != FormatV2 {
		return applyLegacyCouncilSatisfy(c, view, r)
	}
	reqID := ev.ReqID
	citation := ev.Citation
	if reqID == "" || citation == "" || ev.CitationCommitment != commitString("citation", citation) {
		return ErrInvalid
	}
	for i := range view.reqs {
		if view.reqs[i].ID != reqID {
			continue
		}
		if view.reqs[i].Holder != r.Actor {
			return ErrWrongParty
		}
		if view.reqs[i].Satisfied {
			return ErrBadState
		}
		view.reqs[i].Satisfied = true
		view.reqs[i].Citation = citation
		view.status = councilAfterEvidence(view.status, view.reqs)
		return nil
	}
	return fmt.Errorf("nexum: unknown requirement %q", reqID)
}

func legacySatisfyMatches(note, reqID string) bool {
	return len(note) > len(reqID)+1 && strings.HasPrefix(note, reqID+":")
}

func augmentLegacySatisfy(nj int, notes []string, held []Requirement, reqToNote []int, visited []bool) bool {
	for u := range held {
		if visited[u] || !legacySatisfyMatches(notes[nj], held[u].ID) {
			continue
		}
		visited[u] = true
		if reqToNote[u] == -1 || augmentLegacySatisfy(reqToNote[u], notes, held, reqToNote, visited) {
			reqToNote[u] = nj
			return true
		}
	}
	return false
}

func applyLegacyCouncilSatisfy(c *Council, view *councilView, r Receipt) error {
	held := view.heldReqs[r.Actor]
	if len(held) == 0 {
		return ErrBadState
	}
	anyMatch := false
	for i := range held {
		if legacySatisfyMatches(r.Note, held[i].ID) {
			anyMatch = true
			break
		}
	}
	if !anyMatch {
		return ErrBadState
	}
	notes := append(view.legacyNotes[r.Actor], r.Note)
	nj := len(notes) - 1
	if !augmentLegacySatisfy(nj, notes, held, view.legacyMatch[r.Actor], make([]bool, len(held))) {
		return ErrBadState
	}
	view.legacyNotes[r.Actor] = notes
	view.satisfiedBy[r.Actor]++
	view.totalSatisfied++
	if view.status == StatusOpen && view.totalSatisfied == len(c.Reqs) {
		view.status = StatusReady
	}
	return nil
}

func verifyLegacyCouncilReqs(c *Council, view *councilView) (string, error) {
	ambiguous := false
	for _, p := range c.Parties {
		held := view.heldReqs[p]
		notes := view.legacyNotes[p]
		want := make(map[string]int, len(notes))
		satCount := 0
		for _, req := range held {
			if !req.Satisfied {
				if req.Citation != "" {
					return "", snapshotMismatch(ErrInvalid)
				}
				continue
			}
			if req.Citation == "" {
				return "", snapshotMismatch(ErrInvalid)
			}
			satCount++
			want[req.ID+":"+req.Citation]++
		}
		if satCount != len(notes) {
			return "", snapshotMismatch(ErrInvalid)
		}
		got := make(map[string]int, len(notes))
		for _, n := range notes {
			got[n]++
		}
		for k, v := range want {
			if got[k] != v {
				return "", snapshotMismatch(ErrInvalid)
			}
		}
		if ambiguous || len(notes) == 0 {
			continue
		}
		noteToReq := make([]int, len(notes))
		reqToNote := make([]int, len(held))
		for i := range reqToNote {
			reqToNote[i] = -1
		}
		for j, n := range notes {
			matched := false
			for u, req := range held {
				if reqToNote[u] == -1 && req.Satisfied && req.ID+":"+req.Citation == n {
					noteToReq[j] = u
					reqToNote[u] = j
					matched = true
					break
				}
			}
			if !matched {
				return "", snapshotMismatch(ErrInvalid)
			}
		}
		for j, n := range notes {
			if ambiguous {
				break
			}
			for u, req := range held {
				if !legacySatisfyMatches(n, req.ID) {
					continue
				}
				if req.Satisfied && req.ID+":"+req.Citation == n {
					continue
				}
				if reqToNote[u] == -1 {
					ambiguous = true
					break
				}
				j1 := reqToNote[u]
				rt := append([]int(nil), reqToNote...)
				rt[noteToReq[j]] = -1
				rt[u] = j
				visited := make([]bool, len(held))
				visited[u] = true
				if augmentLegacySatisfy(j1, notes, held, rt, visited) {
					ambiguous = true
					break
				}
			}
		}
	}
	if ambiguous {
		return AssuranceLegacyChain, nil
	}
	return AssuranceStateReplay, nil
}

func partyReqsMet(reqs []Requirement, p Party) bool {
	for _, r := range reqs {
		if r.Holder == p && !r.Satisfied {
			return false
		}
	}
	return true
}

// termsDigest commits the council's immutable binding terms into every
// receipt hash. Format 0 omits Decision, matching historical hashes.
// Format v2 binds Decision and the meter policy. Status, consent and
// citations stay out: each change is itself a chained receipt.
func (c *Council) termsDigest() string {
	if c.Format == FormatV2 {
		sum := sha256.Sum256(wireDigestV2("council-terms", struct {
			ID          string    `json:"id"`
			Kind        string    `json:"kind"`
			Parties     []Party   `json:"parties"`
			Reqs        []reqTerm `json:"requirements"`
			Decision    string    `json:"decision"`
			CreatedAt   time.Time `json:"created_at"`
			Format      int       `json:"format"`
			MeterPolicy string    `json:"meter_policy"`
		}{c.ID, c.Kind, c.Parties, c.reqTerms(), c.Decision, c.CreatedAt, c.Format, meterPolicyCostAndSteps}))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(wireDigest("council-terms", struct {
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		Parties   []Party   `json:"parties"`
		Reqs      []reqTerm `json:"requirements"`
		CreatedAt time.Time `json:"created_at"`
	}{c.ID, c.Kind, c.Parties, c.reqTerms(), c.CreatedAt}))
	return hex.EncodeToString(sum[:])
}

// reqTerms is the immutable view of a requirement: satisfaction and its
// citation are ledger facts that change, so they stay out of the digest.
type reqTerm struct {
	ID     string `json:"id"`
	Holder Party  `json:"holder"`
}

func (c *Council) reqTerms() []reqTerm {
	out := make([]reqTerm, len(c.Reqs))
	for i, r := range c.Reqs {
		out[i] = reqTerm{r.ID, r.Holder}
	}
	return out
}
