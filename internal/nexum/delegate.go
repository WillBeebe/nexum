package nexum

import (
	"errors"
	"fmt"
	"time"
)

// KindDelegate is a parent offering work to an intern. Reward moves
// when the work is proven done (citation on the ledger).
const KindDelegate = "delegate.intern"

const (
	StatusOffered Status = "offered"
	StatusClaimed Status = "claimed"
	StatusProven  Status = "proven"
	StatusPaid    Status = "paid"
)

// Task is the work being offered. ProofKind v1 is "citation": a
// ledger note the parent accepts. Not a vibe.
type Task struct {
	Offer     string `json:"offer"`
	ProofKind string `json:"proof_kind"` // citation
}

// Delegate is a Nexum: parent → intern, reward on proven work.
type Delegate struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Parent     Party      `json:"parent"`
	Intern     Party      `json:"intern"`
	Reward     int64      `json:"reward"`
	Unit       Unit       `json:"unit,omitempty"`
	Task       Task       `json:"task"`
	Status     Status     `json:"status"`
	Proof      string     `json:"proof,omitempty"`
	Meter      Meter      `json:"meter"`
	CreatedAt  time.Time  `json:"created_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	ReleasedTo Party      `json:"released_to,omitempty"`
	Receipts   []Receipt  `json:"receipts"`
	steps      int
}

var (
	ErrEmptyOffer = errors.New("nexum: task offer required")
	ErrNoProof    = errors.New("nexum: proof citation required")
	ErrNotClaimed = errors.New("nexum: intern has not claimed")
)

// OpenDelegate is a parent offering work. Intern has not claimed yet.
func OpenDelegate(id string, parent, intern Party, reward int64, task Task, meter Meter, now time.Time) (*Delegate, error) {
	if parent == "" || intern == "" {
		return nil, ErrMissingParty
	}
	if parent == intern {
		return nil, ErrSameParty
	}
	if reward <= 0 {
		return nil, ErrZeroAmount
	}
	if task.Offer == "" {
		return nil, ErrEmptyOffer
	}
	if task.ProofKind == "" {
		task.ProofKind = "citation"
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 16
	}
	d := &Delegate{
		ID:        id,
		Kind:      KindDelegate,
		Parent:    parent,
		Intern:    intern,
		Reward:    reward,
		Task:      task,
		Status:    StatusOffered,
		Meter:     meter,
		CreatedAt: now.UTC(),
	}
	if err := d.append(parent, "offer", task.Offer, now); err != nil {
		return nil, err
	}
	return d, nil
}

// Claim is the intern taking the work. Cancel is illegal after this.
func (d *Delegate) Claim(actor Party, now time.Time) error {
	if actor != d.Intern {
		return ErrWrongParty
	}
	if d.terminal() {
		return ErrTakeback
	}
	if d.Status != StatusOffered {
		return ErrBadState
	}
	if err := d.append(actor, "claim", "intern claimed", now); err != nil {
		return err
	}
	d.Status = StatusClaimed
	return nil
}

// SubmitProof is the intern citing evidence the work is done.
func (d *Delegate) SubmitProof(actor Party, citation string, now time.Time) error {
	if actor != d.Intern {
		return ErrWrongParty
	}
	if d.Status != StatusClaimed {
		return ErrNotClaimed
	}
	if citation == "" {
		return ErrNoProof
	}
	if err := d.append(actor, "proof", citation, now); err != nil {
		return err
	}
	d.Proof = citation
	d.Status = StatusProven
	return nil
}

// AcceptProof is the parent releasing the reward. Terminal. No takeback.
func (d *Delegate) AcceptProof(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if d.terminal() {
		return ErrTakeback
	}
	if d.Status != StatusProven {
		return ErrBadState
	}
	if err := d.append(actor, "pay", fmt.Sprintf("reward %d released to intern", d.Reward), now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Intern
	d.Status = StatusPaid
	return nil
}

// RejectProof is the parent refusing the proof. No reward. Terminal.
func (d *Delegate) RejectProof(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if d.Status != StatusProven && d.Status != StatusClaimed {
		if d.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := d.append(actor, "reject-proof", "proof refused, no reward", now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Parent
	d.Status = StatusRejected
	return nil
}

// Cancel is the parent pulling the offer. Legal only before claim.
func (d *Delegate) Cancel(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if d.Status != StatusOffered {
		return ErrTakeback
	}
	if err := d.append(actor, "cancel", "offer cancelled before claim", now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Parent
	d.Status = StatusRejected
	return nil
}

func (d *Delegate) terminal() bool {
	switch d.Status {
	case StatusPaid, StatusRejected:
		return true
	default:
		return false
	}
}

func (d *Delegate) append(actor Party, action, note string, now time.Time) error {
	d.steps++
	if d.steps > d.Meter.MaxSteps {
		return ErrDoS
	}
	if d.Meter.BudgetUSD > 0 && d.Meter.CostUSD > d.Meter.BudgetUSD {
		return ErrBudget
	}
	prev := ""
	if n := len(d.Receipts); n > 0 {
		prev = d.Receipts[n-1].Hash
	}
	r := Receipt{
		Seq:      len(d.Receipts) + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	r.Hash = hashReceipt(d.ID, r)
	d.Receipts = append(d.Receipts, r)
	return nil
}

// VerifyReceipts checks the hash chain.
func (d *Delegate) VerifyReceipts() error {
	var prev string
	for i, r := range d.Receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		if r.Hash != hashReceipt(d.ID, r) {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}
