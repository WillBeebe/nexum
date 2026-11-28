package nex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
)

// Contract is owned by a trusted local adapter. Callers must serialize access.
// Signatures bind immutable terms and the current receipt head. Actual currency
// custody and cross-process identity admission remain application responsibilities.
type Contract struct {
	agreement     *nexum.Agreement
	terms         string
	buyer, seller Public
	agreed        bool
	consent       []ConsentEvent
	definition    Terms
}

// ConsentEvent is recorded consent. Agree followed by reject or expiry keeps
// the earlier consent. Agreed reports that historical fact. Phase reports
// the current lifecycle, including agreed only while the escrow is still locked.
type ConsentEvent struct {
	Action string
	Head   string
}
type Command struct{ Terms, Head, Action, Evidence string }

// Terms is the immutable agreement definition committed by Contract.ID.
// Buyer and Seller are public identity IDs. Spec is JSON, not executable code.
type Terms struct {
	Kind              string
	Buyer, Seller     string
	Amount            int64
	Spec              json.RawMessage
	Created, Deadline time.Time
}

func New(kind string, buyer, seller Public, amount int64, spec any, now, deadline time.Time) (*Contract, error) {
	if !utf8.ValidString(kind) || strings.ContainsRune(kind, 0) {
		return nil, errors.New("nex: agreement kind must be valid UTF-8 without NUL bytes")
	}
	if err := buyer.Validate(); err != nil {
		return nil, err
	}
	if err := seller.Validate(); err != nil {
		return nil, err
	}
	if buyer.ID() == seller.ID() || bytes.Equal(buyer.Signing, seller.Signing) {
		return nil, nexum.ErrSameParty
	}
	now = now.UTC()
	deadline = deadline.UTC()
	if _, err := now.MarshalJSON(); err != nil {
		return nil, fmt.Errorf("contract timestamp: %w", err)
	}
	if _, err := deadline.MarshalJSON(); err != nil {
		return nil, fmt.Errorf("contract deadline: %w", err)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("contract specification: %w", err)
	}
	definition := Terms{kind, buyer.ID(), seller.ID(), amount, raw, now, deadline}
	if _, err := json.Marshal(definition); err != nil {
		return nil, fmt.Errorf("contract terms: %w", err)
	}
	id := Hash(definition)
	a, err := nexum.OpenAgreement(id, kind, nexum.Party(buyer.ID()), nexum.Party(seller.ID()), amount, nexum.Meter{MaxSteps: 128}, now)
	if err != nil {
		return nil, err
	}
	if err = a.SetDeadline(a.Buyer, deadline, now); err != nil {
		return nil, err
	}
	if err = a.StartSealed(2048); err != nil {
		return nil, err
	}
	// Own the key slices rather than retaining caller-mutable identity data.
	buyer = clonePublic(buyer)
	seller = clonePublic(seller)
	return &Contract{agreement: a, terms: id, buyer: buyer, seller: seller, definition: definition}, nil
}

func clonePublic(p Public) Public {
	p.Signing = append(p.Signing[:0:0], p.Signing...)
	p.Encryption = append(p.Encryption[:0:0], p.Encryption...)
	return p
}

func (c *Contract) ID() string { return c.terms }

// Agreed reports that seller consent was recorded. Rejection and expiry do
// not erase that fact.
func (c *Contract) Agreed() bool { return c != nil && c.agreed }

// Phase is the current wrapper phase. It is derived from status plus whether
// consent is the latest open decision, not a second stored lifecycle.
func (c *Contract) Phase() string {
	if c == nil || c.agreement == nil {
		return ""
	}
	if c.agreement.Status == nexum.StatusLocked && c.agreed {
		return "agreed"
	}
	return string(c.agreement.Status)
}

// ConsentHistory returns recorded consent events in order.
func (c *Contract) ConsentHistory() []ConsentEvent {
	if c == nil {
		return nil
	}
	return append([]ConsentEvent(nil), c.consent...)
}
func (c *Contract) Command(action, evidence string) Command {
	return Command{c.terms, c.Head(), action, evidence}
}
func (c *Contract) Head() string          { r := c.agreement.Receipts; return r[len(r)-1].Hash }
func (c *Contract) Status() nexum.Status  { return c.agreement.Status }
func (c *Contract) VerifyReceipts() error { return c.agreement.VerifyReceipts() }
func (c *Contract) Apply(cmd Command, sig []byte, now time.Time) error {
	if err := Verify(c.signer(cmd.Action), "contract", cmd, sig); err != nil {
		return err
	}
	return c.applyVerified(cmd, sig, now)
}

func (c *Contract) signer(action string) Public {
	if action == "agree" || action == "reject" {
		return c.seller
	}
	return c.buyer
}

func (c *Contract) applyVerified(cmd Command, sig []byte, now time.Time) error {
	a := c.agreement
	if cmd.Terms != c.terms || cmd.Head != c.Head() {
		return errors.New("stale or foreign command")
	}
	if cmd.Action == "expire" {
		if err := a.Expire(a.Buyer, now); err != nil {
			return err
		}
		if c.agreed {
			c.consent = append(c.consent, ConsentEvent{Action: "expire", Head: c.Head()})
		}
		return nil
	}
	if now.Before(a.CreatedAt) || !now.Before(a.Deadline) {
		return errors.New("outside agreement time window")
	}
	switch cmd.Action {
	case "lock":
		if a.Status != nexum.StatusOpen {
			return errors.New("already locked")
		}
		return a.Apply(nexum.Move{Actor: a.Buyer, Action: "seal", Partial: a.Amount}, now)
	case "agree":
		if a.Status != nexum.StatusLocked || c.agreed {
			return errors.New("cannot agree")
		}
		if err := a.Note(a.Seller, "evidence", "signed-consent:"+Hash(sig), now); err != nil {
			return err
		}
		c.agreed = true
		c.consent = append(c.consent, ConsentEvent{Action: "agree", Head: c.Head()})
		return nil
	case "settle":
		if !c.agreed || cmd.Evidence == "" || a.Status != nexum.StatusLocked {
			return errors.New("consent and verified evidence required")
		}
		// The adapter authorizes kernel acceptance only after buyer verification.
		return a.AcceptWithEvidence(a.Buyer, a.Seller, cmd.Evidence, now)
	case "reject":
		if err := a.Apply(nexum.Move{Actor: a.Seller, Action: "reject"}, now); err != nil {
			return err
		}
		if c.agreed {
			c.consent = append(c.consent, ConsentEvent{Action: "reject", Head: c.Head()})
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd.Action)
	}
}
func (c *Contract) rebuildConsent() {
	if c == nil || c.agreement == nil {
		return
	}
	c.consent = nil
	agreed := false
	for _, r := range c.agreement.Receipts {
		switch {
		case r.Action == "evidence" && r.Actor == c.agreement.Seller && !agreed && strings.HasPrefix(r.Note, "signed-consent:"):
			c.consent = append(c.consent, ConsentEvent{Action: "agree", Head: r.Hash})
			agreed = true
		case r.Action == "reject" && agreed:
			c.consent = append(c.consent, ConsentEvent{Action: "reject", Head: r.Hash})
		case r.Action == "expire" && agreed:
			c.consent = append(c.consent, ConsentEvent{Action: "expire", Head: r.Hash})
		}
	}
}

func (c *Contract) Execute(i Identity, action, evidence string, now time.Time) error {
	cmd := c.Command(action, evidence)
	return c.Apply(cmd, Sign(i, "contract", cmd), now)
}
