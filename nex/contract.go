package nex

import (
	"errors"
	"fmt"
	"github.com/WillBeebe/nexum/internal/nexum"
	"time"
)

// Contract is owned by a trusted local adapter. Callers must serialize access.
// Signatures bind immutable terms and the current receipt head. Actual currency
// custody, persistence and cross-process identity admission are outside this lab.
type Contract struct {
	agreement     *nexum.Agreement
	terms         string
	buyer, seller Public
	agreed        bool
}
type Command struct{ Terms, Head, Action, Evidence string }

func New(kind string, buyer, seller Public, amount int64, spec any, now, deadline time.Time) (*Contract, error) {
	if err := buyer.Validate(); err != nil {
		return nil, err
	}
	if err := seller.Validate(); err != nil {
		return nil, err
	}
	id := Hash(struct {
		Kind              string
		Buyer, Seller     string
		Amount            int64
		Spec              any
		Created, Deadline time.Time
	}{kind, buyer.ID(), seller.ID(), amount, spec, now, deadline})
	a, err := nexum.OpenEscrow(id, nexum.Party(buyer.ID()), nexum.Party(seller.ID()), amount, nexum.Meter{MaxSteps: 128}, now)
	if err != nil {
		return nil, err
	}
	if err = a.SetDeadline(a.Buyer, deadline, now); err != nil {
		return nil, err
	}
	a.Kind = kind
	if err = a.StartSealed(2048); err != nil {
		return nil, err
	}
	return &Contract{agreement: a, terms: id, buyer: buyer, seller: seller}, nil
}
func (c *Contract) Command(action, evidence string) Command {
	return Command{c.terms, c.Head(), action, evidence}
}
func (c *Contract) Head() string          { r := c.agreement.Receipts; return r[len(r)-1].Hash }
func (c *Contract) Status() nexum.Status  { return c.agreement.Status }
func (c *Contract) VerifyReceipts() error { return c.agreement.VerifyReceipts() }
func (c *Contract) Apply(cmd Command, sig []byte, now time.Time) error {
	a := c.agreement
	if cmd.Terms != c.terms || cmd.Head != c.Head() {
		return errors.New("stale or foreign command")
	}
	signer := c.buyer
	if cmd.Action == "agree" || cmd.Action == "reject" {
		signer = c.seller
	}
	if err := Verify(signer, "contract", cmd, sig); err != nil {
		return err
	}
	if cmd.Action == "expire" {
		return a.Expire(a.Buyer, now)
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
		return nil
	case "settle":
		if !c.agreed || cmd.Evidence == "" || a.Status != nexum.StatusLocked {
			return errors.New("consent and verified evidence required")
		}
		if err := a.Note(a.Buyer, "evidence", cmd.Evidence, now); err != nil {
			return err
		}
		// The adapter authorizes the seller's kernel acceptance only after buyer verification.
		return a.Apply(nexum.Move{Actor: a.Seller, Action: "accept"}, now)
	case "reject":
		return a.Apply(nexum.Move{Actor: a.Seller, Action: "reject"}, now)
	default:
		return fmt.Errorf("unknown command %q", cmd.Action)
	}
}
func (c *Contract) Execute(i Identity, action, evidence string, now time.Time) error {
	cmd := c.Command(action, evidence)
	return c.Apply(cmd, Sign(i, "contract", cmd), now)
}
