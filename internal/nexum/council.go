package nexum

import (
	"errors"
	"fmt"
	"sort"
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
	steps     int
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

// OpenCouncil starts a multi-party Nexum. n must be 3–7. Each
// requirement's holder must be a party. Decision is the action that
// runs on execute (a citation, not prose).
func OpenCouncil(id string, parties []Party, reqs []Requirement, decision string, meter Meter, now time.Time) (*Council, error) {
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
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 32
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
	}
	sort.Slice(c.Parties, func(i, j int) bool { return c.Parties[i] < c.Parties[j] })
	if err := c.append(c.Parties[0], "open", "council opened", now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Council) isParty(p Party) bool {
	for _, x := range c.Parties {
		if x == p {
			return true
		}
	}
	return false
}

// Satisfy records that a holder's requirement is met, with a citation
// the network can check. Only the holder may satisfy their own req.
func (c *Council) Satisfy(actor Party, reqID, citation string, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	if c.terminal() {
		return ErrTakeback
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
	if err := c.append(actor, "satisfy", reqID+":"+citation, now); err != nil {
		return err
	}
	c.Reqs[idx].Satisfied = true
	c.Reqs[idx].Citation = citation
	c.refreshReady()
	return nil
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
// to execute; opt-in is not execute.
func (c *Council) OptIn(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	if c.terminal() {
		return ErrTakeback
	}
	if c.Status != StatusOpen && c.Status != StatusReady {
		return ErrBadState
	}
	if !c.partyReqsMet(actor) {
		return ErrNotSatisfied
	}
	if c.OptedIn[actor] {
		return ErrBadState
	}
	if err := c.append(actor, "opt-in", "opted in", now); err != nil {
		return err
	}
	c.OptedIn[actor] = true
	c.refreshReady()
	return nil
}

// Refuse is a party killing the council before execute. Terminal.
func (c *Council) Refuse(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	if c.terminal() {
		return ErrTakeback
	}
	if err := c.append(actor, "refuse", "refused before execute", now); err != nil {
		return err
	}
	t := now.UTC()
	c.ClosedAt = &t
	c.Status = StatusRefused
	return nil
}

// Execute runs the decision. Legal only when every requirement is
// satisfied and every party has opted in. After this, refuse and
// takeback are ErrTakeback.
func (c *Council) Execute(actor Party, now time.Time) error {
	if !c.isParty(actor) {
		return ErrUnknownParty
	}
	if c.terminal() {
		return ErrTakeback
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
	if err := c.append(actor, "execute", c.Decision, now); err != nil {
		return err
	}
	t := now.UTC()
	c.ClosedAt = &t
	c.Status = StatusExecuted
	return nil
}

func (c *Council) refreshReady() {
	if c.Status != StatusOpen {
		return
	}
	for _, r := range c.Reqs {
		if !r.Satisfied {
			return
		}
	}
	c.Status = StatusReady
}

func (c *Council) terminal() bool {
	switch c.Status {
	case StatusExecuted, StatusRefused:
		return true
	default:
		return false
	}
}

func (c *Council) append(actor Party, action, note string, now time.Time) error {
	c.steps++
	if c.steps > c.Meter.MaxSteps {
		return ErrDoS
	}
	if c.Meter.BudgetUSD > 0 && c.Meter.CostUSD > c.Meter.BudgetUSD {
		return ErrBudget
	}
	prev := ""
	if n := len(c.Receipts); n > 0 {
		prev = c.Receipts[n-1].Hash
	}
	r := Receipt{
		Seq:      len(c.Receipts) + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	r.Hash = hashReceipt(c.ID, r)
	c.Receipts = append(c.Receipts, r)
	return nil
}

// VerifyReceipts checks the hash chain.
func (c *Council) VerifyReceipts() error {
	var prev string
	for i, r := range c.Receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		if r.Hash != hashReceipt(c.ID, r) {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}
