package message

import (
	"fmt"
	"time"
)

type SendOptions struct {
	KeySuite       string     `json:"key_suite,omitempty"`
	ConversationID string     `json:"conversation_id,omitempty"`
	ReplyTo        string     `json:"reply_to,omitempty"`
	Trade          *TradeLink `json:"trade,omitempty"`
}

// TradeLink reveals the operation and ordering, but commits to salted,
// encrypted terms. A message is the trade operation, not a notification of one.
type TradeLink struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Parent     string `json:"parent,omitempty"`
	Commitment string `json:"commitment"`
}

func (t TradeLink) Validate() error {
	if !validID(t.ID) || !validID(t.Commitment) {
		return ErrInvalid
	}
	switch t.Action {
	case "request":
		if t.Parent != "" {
			return ErrInvalid
		}
	case "offer", "counteroffer", "accept", "reject", "fulfill", "settle":
		if !validID(t.Parent) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Obligation struct {
	Description string    `json:"description"`
	Units       int64     `json:"units,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Budget      int64     `json:"budget,omitempty"`
	Deadline    time.Time `json:"deadline,omitempty"`
}
type TradePayload struct {
	Version       int          `json:"version"`
	TradeID       string       `json:"trade_id"`
	Action        string       `json:"action"`
	Parent        string       `json:"parent,omitempty"`
	Salt          []byte       `json:"salt"`
	Text          string       `json:"text"`
	Obligations   []Obligation `json:"obligations,omitempty"`
	SettlementRef string       `json:"settlement_ref,omitempty"`
}

func (p TradePayload) Commitment() string { return digest("trade-terms", p) }
func (p TradePayload) Validate(link TradeLink) error {
	if p.Version != 1 || len(p.Salt) != 32 || p.TradeID != link.ID || p.Action != link.Action || p.Parent != link.Parent || p.Commitment() != link.Commitment {
		return ErrInvalid
	}
	if len(p.Obligations) > 64 {
		return ErrInvalid
	}
	for _, obligation := range p.Obligations {
		if obligation.Description == "" || obligation.Units < 0 || obligation.Budget < 0 {
			return ErrInvalid
		}
	}
	if p.Action == "settle" && p.SettlementRef == "" {
		return fmt.Errorf("message: settlement evidence reference required")
	}
	return link.Validate()
}

// ValidateTradeSuccessor enforces turn ownership and the only legal sequence.
// The prior message must have been released before another operation can bind
// it; the receiving agent validates the decrypted payload before responding.
func ValidateTradeSuccessor(parent Record, child Offer) error {
	p, c := parent.Offer.Terms.Trade, child.Terms.Trade
	if p == nil || c == nil || c.ID != p.ID || c.Parent != parent.Offer.Hash() || child.Terms.ReplyTo != parent.Offer.Terms.ID || child.Terms.ConversationID != parent.Offer.Terms.ConversationID ||
		child.Terms.Sender.ID() != parent.Offer.Terms.Recipient.ID() || child.Terms.Recipient.ID() != parent.Offer.Terms.Sender.ID() || parent.Release == nil {
		return ErrState
	}
	allowed := map[string][]string{"request": {"offer", "reject"}, "offer": {"counteroffer", "accept", "reject"}, "counteroffer": {"counteroffer", "accept", "reject"}, "accept": {"fulfill"}, "fulfill": {"settle"}}
	for _, action := range allowed[p.Action] {
		if action == c.Action {
			return nil
		}
	}
	return ErrState
}
