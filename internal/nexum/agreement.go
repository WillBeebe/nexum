// Package nexum is the agreement kernel: binding obligations with
// a hash-chained ledger. Metering is cost / effort / budget.
// Do not import Ethereum's fee-unit name into these types.
package nexum

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/WillBeebe/nexum/internal/settle"
)

// Status is the life of a Nexum. Terminal states do not reopen.
type Status string

const (
	StatusOpen     Status = "open"
	StatusLocked   Status = "locked"
	StatusAccepted Status = "accepted"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
)

// Kind names the contract shape. House escrow is the acceptance test.
const KindHouseEscrow = "escrow.house"

// Meter is inference spent on the user's behalf. Not a fee market.
type Meter struct {
	CostUSD   float64 `json:"cost_usd"`
	Effort    string  `json:"effort"` // flash | max | …
	BudgetUSD float64 `json:"budget_usd"`
	MaxSteps  int     `json:"max_steps"` // DoS bound
}

// Party is an agent or human identifier. Not a chain address.
type Party string

// Receipt is one irreversible step on the agreement.
type Receipt struct {
	Seq      int       `json:"seq"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Actor    Party     `json:"actor"`
	Note     string    `json:"note,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Agreement is a Nexum: a binding obligation.
type Agreement struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Buyer      Party      `json:"buyer"`
	Seller     Party      `json:"seller"`
	Amount     int64      `json:"amount"` // integer units of Unit (or untyped)
	Unit       Unit       `json:"unit,omitempty"`
	Status     Status     `json:"status"`
	Meter      Meter      `json:"meter"`
	Deadline   time.Time  `json:"deadline,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LockedAt   *time.Time `json:"locked_at,omitempty"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	ReleasedTo Party      `json:"released_to,omitempty"`
	Receipts   []Receipt  `json:"receipts"`
	// Sealed escrow: value lives as Paillier ciphertext. The
	// key never leaves the ledger; the kernel sees only ciphertext.
	Sealed      *settle.EncryptedLedger `json:"-"`                      // owns the key; never serialized
	SealedLocks [][]byte                `json:"sealed_locks,omitempty"` // ciphertext partials
	SealedSum   []byte                  `json:"sealed_sum,omitempty"`   // ciphertext aggregate
	steps       int
}

var (
	ErrWrongParty    = errors.New("nexum: wrong party")
	ErrBadState      = errors.New("nexum: illegal state transition")
	ErrTakeback      = errors.New("nexum: takeback refused")
	ErrBudget        = errors.New("nexum: budget exceeded")
	ErrDoS           = errors.New("nexum: step bound exceeded")
	ErrZeroAmount    = errors.New("nexum: amount must be positive")
	ErrSameParty     = errors.New("nexum: buyer and seller must differ")
	ErrMissingParty  = errors.New("nexum: buyer and seller required")
	ErrNotYet        = errors.New("nexum: deadline not reached")
	ErrNoDeadline    = errors.New("nexum: no deadline set")
	ErrEmptyCitation = errors.New("nexum: evidence citation required")
	ErrNoSeal        = errors.New("nexum: sealed escrow not armed; call StartSealed first")
)

// OpenEscrow preserves the house-escrow acceptance example and its receipt format.
func OpenEscrow(id string, buyer, seller Party, amount int64, meter Meter, now time.Time) (*Agreement, error) {
	return openAgreement(id, KindHouseEscrow, buyer, seller, amount, meter, now, "escrow opened")
}

// OpenAgreement starts a bilateral agreement with its final kind.
func OpenAgreement(id, kind string, buyer, seller Party, amount int64, meter Meter, now time.Time) (*Agreement, error) {
	if kind == "" {
		return nil, errors.New("nexum: agreement kind required")
	}
	return openAgreement(id, kind, buyer, seller, amount, meter, now, "agreement opened")
}
func openAgreement(id, kind string, buyer, seller Party, amount int64, meter Meter, now time.Time, note string) (*Agreement, error) {
	if buyer == "" || seller == "" {
		return nil, ErrMissingParty
	}
	if buyer == seller {
		return nil, ErrSameParty
	}
	if amount <= 0 {
		return nil, ErrZeroAmount
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 8
	}
	if meter.Effort == "" {
		meter.Effort = "flash"
	}
	a := &Agreement{
		ID:        id,
		Kind:      kind,
		Buyer:     buyer,
		Seller:    seller,
		Amount:    amount,
		Status:    StatusOpen,
		Meter:     meter,
		CreatedAt: now.UTC(),
	}
	if err := a.append(buyer, "open", note, now); err != nil {
		return nil, err
	}
	return a, nil
}

// Lock is the buyer placing value. After this, the buyer cannot
// unwind except by the seller's reject (or expiry, later).
func (a *Agreement) Lock(actor Party, now time.Time) error {
	if actor != a.Buyer {
		return ErrWrongParty
	}
	if a.Status != StatusOpen {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "lock", "value locked", now); err != nil {
		return err
	}
	t := now.UTC()
	a.LockedAt = &t
	a.Status = StatusLocked
	return nil
}

// Accept releases locked value, checking the equality proof when sealed. Terminal.
func (a *Agreement) Accept(actor Party, now time.Time) error {
	if a.isSealed() {
		return a.acceptSealed(actor, now)
	}
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusLocked {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "accept", "released to seller", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Seller
	a.Status = StatusAccepted
	return nil
}

// Reject is the seller returning the locked value to the buyer. Terminal.
func (a *Agreement) Reject(actor Party, now time.Time) error {
	if a.isSealed() {
		return a.rejectSealed(actor, now)
	}
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusLocked {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "reject", "returned to buyer", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Buyer
	a.Status = StatusRejected
	return nil
}

// SetDeadline fixes the expiry time. A deadline is a material term,
// so it goes on the ledger, not a silent struct write. Either party
// may set or extend it before terminal state; the step bound applies.
func (a *Agreement) SetDeadline(actor Party, deadline, now time.Time) error {
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if !deadline.After(now) {
		return ErrNotYet
	}
	if err := a.append(actor, "deadline", deadline.UTC().Format(time.RFC3339), now); err != nil {
		return err
	}
	a.Deadline = deadline.UTC()
	return nil
}

// Expire is time running out on the agreement. Either party
// may call it, but only after the deadline, and it is terminal:
// value returns to whoever locked it. There is no state where
// expiry reopens the obligation.
func (a *Agreement) Expire(actor Party, now time.Time) error {
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusOpen && a.Status != StatusLocked {
		return ErrTakeback
	}
	if a.Deadline.IsZero() {
		return ErrNoDeadline
	}
	if now.Before(a.Deadline) {
		return ErrNotYet
	}
	if err := a.append(actor, "expire", "deadline passed, value unlocked", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Buyer
	a.Status = StatusExpired
	return nil
}

// Note is evidence: an agent recording what it saw before deciding.
// No gas, no fee market — a citation the network can check later.
func (a *Agreement) Note(actor Party, action, citation string, now time.Time) error {
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if citation == "" {
		return ErrEmptyCitation
	}
	if action != "evidence" {
		return fmt.Errorf("nexum: note action must be evidence, got %q", action)
	}
	if err := a.append(actor, action, citation, now); err != nil {
		return err
	}
	return nil
}

func (a *Agreement) terminal() bool {
	switch a.Status {
	case StatusAccepted, StatusRejected, StatusExpired:
		return true
	default:
		return false
	}
}

func (a *Agreement) append(actor Party, action, note string, now time.Time) error {
	if a.steps >= a.Meter.MaxSteps {
		return ErrDoS
	}
	if a.Meter.BudgetUSD > 0 && a.Meter.CostUSD > a.Meter.BudgetUSD {
		return ErrBudget
	}
	prev := ""
	if n := len(a.Receipts); n > 0 {
		prev = a.Receipts[n-1].Hash
	}
	r := Receipt{
		Seq:      len(a.Receipts) + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	r.Hash = hashReceipt(a.ID, r)
	a.Receipts = append(a.Receipts, r)
	a.steps++
	return nil
}

func hashReceipt(id string, r Receipt) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		id, r.Seq, r.At.UTC().Format(time.RFC3339Nano), r.Action, r.Actor, r.Note, r.PrevHash)))
	return hex.EncodeToString(sum[:])
}

// VerifyReceipts checks the hash chain. False means the ledger was rewritten.
func (a *Agreement) VerifyReceipts() error {
	var prev string
	for i, r := range a.Receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		want := hashReceipt(a.ID, r)
		if r.Hash != want {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}

// AcceptWithEvidence records evidence and accepts as one in-memory transition.
// Callers must serialize access. Failed proof or metering checks change no state.
func (a *Agreement) AcceptWithEvidence(author, actor Party, citation string, now time.Time) error {
	next := *a
	// Note and Accept only append receipts and replace scalar/pointer fields.
	// Equality proving reads the ledger; it does not mutate it.
	next.Receipts = append([]Receipt(nil), a.Receipts...)
	if err := next.Note(author, "evidence", citation, now); err != nil {
		return err
	}
	if err := next.Accept(actor, now); err != nil {
		return err
	}
	*a = next
	return nil
}
